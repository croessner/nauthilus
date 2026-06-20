// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package lualib

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib/luastack"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/util"

	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// DNSManager manages DNS operations for Lua.
type DNSManager struct {
	*BaseManager
}

type dnsStringLookupFunc func(context.Context, string) ([]string, error)

// NewDNSManager creates a new DNSManager.
func NewDNSManager(ctx context.Context, cfg config.File, logger *slog.Logger) *DNSManager {
	return &DNSManager{
		BaseManager: NewBaseManager(ctx, cfg, logger),
	}
}

func (m *DNSManager) currentContext(L *lua.LState) context.Context {
	return RequireRuntimeContext(L, definitions.LuaModDNS)
}

// Resolve performs a DNS record lookup for the specified domain and record type using Lua and the provided context.
// It supports record types such as A, AAAA, MX, NS, TXT, CNAME, and PTR and returns the result or an error to Lua.
func (m *DNSManager) Resolve(L *lua.LState) int {
	stack := luastack.NewManager(L)
	domain := stack.CheckString(1)
	recordType := strings.ToUpper(stack.OptString(2, "A"))
	ctx := m.currentContext(L)

	util.DebugModuleWithCfg(ctx, m.Cfg, m.Logger, definitions.DbgLua,
		"domain", domain,
		"kind", recordType,
	)

	result, err := lookupRecord(ctx, m.Cfg, L, domain, recordType)
	if err != nil {
		return stack.PushError(err)
	}

	return stack.PushResults(result, lua.LNil)
}

// lookupRecord performs a DNS lookup for the specified domain and record type, returning the results as an LValue.
// It supports record types like A, AAAA, MX, NS, TXT, CNAME, and PTR.
// The context controls the timeout for the DNS request, while Lua state handles the returned data format.
func lookupRecord(ctx context.Context, cfg config.File, L *lua.LState, domain, kind string) (lua.LValue, error) {
	ctxTimeout, cancel := context.WithDeadline(ctx, time.Now().Add(cfg.GetServer().GetDNS().GetTimeout()))

	defer cancel()

	resolver := util.NewDNSResolver(cfg)

	switch kind {
	case "A", luaDNSRecordAAAA:
		return lookupDNSIPRecords(ctxTimeout, cfg, L, domain, kind, resolver)
	case "MX":
		return lookupDNSMXRecords(ctxTimeout, L, domain, resolver)
	case "NS":
		return lookupDNSNSRecords(ctxTimeout, L, domain, resolver)
	case "TXT":
		return lookupDNSStringRecords(ctxTimeout, L, domain, "TXT", resolver.LookupTXT)
	case "CNAME":
		return lookupDNSCNAMERecord(ctxTimeout, domain, resolver)
	case "PTR":
		return lookupDNSStringRecords(ctxTimeout, L, domain, "PTR", resolver.LookupAddr)
	default:
		return nil, fmt.Errorf("unsupported record type: %s", kind)
	}
}

// lookupDNSIPRecords resolves A or AAAA records and filters the IP family.
func lookupDNSIPRecords(
	ctx context.Context,
	cfg config.File,
	L *lua.LState,
	domain string,
	recordType string,
	resolver *net.Resolver,
) (lua.LValue, error) {
	tctx, tsp := startDNSLookupTrace(ctx, cfg, domain, recordType, true)

	ips, err := resolver.LookupIP(tctx, "ip", domain)
	if err != nil {
		tsp.RecordError(err)
		tsp.End()

		return nil, err
	}

	tbl := L.NewTable()

	for _, ip := range ips {
		if dnsIPMatchesRecordType(ip, recordType) {
			tbl.Append(lua.LString(ip.String()))
		}
	}

	finishDNSLookupTrace(tsp, tbl.Len())

	return tbl, nil
}

// dnsIPMatchesRecordType reports whether an IP belongs to the requested record family.
func dnsIPMatchesRecordType(ip net.IP, recordType string) bool {
	return (recordType == "A" && ip.To4() != nil) || (recordType == luaDNSRecordAAAA && ip.To4() == nil)
}

// lookupDNSMXRecords resolves MX records into Lua tables.
func lookupDNSMXRecords(ctx context.Context, L *lua.LState, domain string, resolver *net.Resolver) (lua.LValue, error) {
	tctx, tsp := startDNSLookupTrace(ctx, nil, domain, "MX", false)

	mxs, err := resolver.LookupMX(tctx, domain)
	if err != nil {
		tsp.RecordError(err)
		tsp.End()

		return nil, err
	}

	tbl := L.NewTable()
	for _, mx := range mxs {
		rec := L.NewTable()
		rec.RawSetString("host", lua.LString(mx.Host))
		rec.RawSetString("pref", lua.LNumber(mx.Pref))
		tbl.Append(rec)
	}

	finishDNSLookupTrace(tsp, tbl.Len())

	return tbl, nil
}

// lookupDNSNSRecords resolves NS records into a Lua table.
func lookupDNSNSRecords(ctx context.Context, L *lua.LState, domain string, resolver *net.Resolver) (lua.LValue, error) {
	tctx, tsp := startDNSLookupTrace(ctx, nil, domain, "NS", false)

	nss, err := resolver.LookupNS(tctx, domain)
	if err != nil {
		tsp.RecordError(err)
		tsp.End()

		return nil, err
	}

	tbl := L.NewTable()
	for _, ns := range nss {
		tbl.Append(lua.LString(ns.Host))
	}

	finishDNSLookupTrace(tsp, tbl.Len())

	return tbl, nil
}

// lookupDNSCNAMERecord resolves a CNAME record into a Lua string.
func lookupDNSCNAMERecord(ctx context.Context, domain string, resolver *net.Resolver) (lua.LValue, error) {
	tctx, tsp := startDNSLookupTrace(ctx, nil, domain, "CNAME", false)

	cname, err := resolver.LookupCNAME(tctx, domain)
	if err != nil {
		tsp.RecordError(err)
		tsp.End()

		return nil, err
	}

	finishDNSLookupTrace(tsp, dnsCNAMEAnswerCount(cname))

	return lua.LString(cname), nil
}

// dnsCNAMEAnswerCount returns the trace answer count for a CNAME response.
func dnsCNAMEAnswerCount(cname string) int {
	if cname != "" {
		return 1
	}

	return 0
}

// lookupDNSStringRecords traces DNS lookups that return a plain string slice.
func lookupDNSStringRecords(
	ctx context.Context,
	L *lua.LState,
	domain string,
	recordType string,
	lookup dnsStringLookupFunc,
) (lua.LValue, error) {
	tctx, tsp := startDNSLookupTrace(ctx, nil, domain, recordType, false)

	records, err := lookup(tctx, domain)
	if err != nil {
		tsp.RecordError(err)
		tsp.End()

		return nil, err
	}

	tbl := L.NewTable()

	for _, record := range records {
		tbl.Append(lua.LString(record))
	}

	finishDNSLookupTrace(tsp, tbl.Len())

	return tbl, nil
}

// startDNSLookupTrace starts a tracing span for a DNS lookup.
func startDNSLookupTrace(ctx context.Context, cfg config.File, domain, recordType string, includePeer bool) (context.Context, trace.Span) {
	tr := monittrace.New("nauthilus/dns")
	tctx, tsp := tr.StartClient(ctx, "dns.lookup",
		attribute.String("rpc.system", "dns"),
		semconv.PeerService("dns"),
		attribute.String("dns.question.name", domain),
		attribute.String("dns.question.type", recordType),
	)

	if includePeer {
		setDNSResolverPeerAttributes(tsp, cfg)
	}

	return tctx, tsp
}

// setDNSResolverPeerAttributes adds resolver peer attributes when a custom resolver is configured.
func setDNSResolverPeerAttributes(tsp trace.Span, cfg config.File) {
	host, port, ok := util.DNSResolverPeer(cfg)
	if !ok {
		return
	}

	tsp.SetAttributes(
		attribute.String("peer.hostname", host),
		attribute.Int("peer.port", port),
	)
}

// finishDNSLookupTrace records the DNS answer count and ends the span.
func finishDNSLookupTrace(tsp trace.Span, answerCount int) {
	tsp.SetAttributes(attribute.Int("dns.answer.count", answerCount))
	tsp.End()
}

// LoaderModDNS initializes and loads the DNS module for Lua, providing functions for DNS lookups and managing records.
func LoaderModDNS(ctx context.Context, cfg config.File, logger *slog.Logger) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewDNSManager(ctx, cfg, logger)

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			"resolve": manager.Resolve,
		})

		if ctx != nil {
			BindRequestRuntimeContext(ctx, L, mod)
		}

		return stack.PushResult(mod)
	}
}

// LoaderDNSStateless returns an empty, stateless module placeholder for nauthilus_dns.
// It allows require("nauthilus_dns") to succeed before per-request binding replaces it
// with a context-aware version via BindModuleIntoReq.
func LoaderDNSStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)

		return stack.PushResult(L.NewTable())
	}
}

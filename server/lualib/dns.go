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
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/util"

	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// DNSManager manages DNS operations for Lua.
type DNSManager struct {
	*BaseManager
}

// NewDNSManager creates a new DNSManager.
func NewDNSManager(ctx context.Context, cfg config.File, logger *slog.Logger) *DNSManager {
	return &DNSManager{
		BaseManager: NewBaseManager(ctx, cfg, logger),
	}
}

// Resolve performs a DNS record lookup for the specified domain and record type using Lua and the provided context.
// It supports record types such as A, AAAA, MX, NS, TXT, CNAME, and PTR and returns the result or an error to Lua.
func (m *DNSManager) Resolve(L *lua.LState) int {
	stack := luastack.NewManager(L)
	domain := stack.CheckString(1)
	recordType := strings.ToUpper(stack.OptString(2, "A"))

	util.DebugModuleWithCfg(m.Ctx, m.Cfg, m.Logger, definitions.DbgLua,
		"domain", domain,
		"kind", recordType,
	)

	result, err := lookupRecord(m.Ctx, m.Cfg, L, domain, recordType)
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

	resolver := util.NewDNSResolverWithCfg(cfg)

	switch kind {
	case "A", "AAAA":
		tr := monittrace.New("nauthilus/dns")
		tctx, tsp := tr.StartClient(ctxTimeout, "dns.lookup",
			attribute.String("rpc.system", "dns"),
			attribute.String("peer.service", "dns"),
			attribute.String("dns.question.name", domain),
			attribute.String("dns.question.type", kind),
		)

		host, port, ok := util.DNSResolverPeer(cfg)
		if ok {
			tsp.SetAttributes(
				attribute.String("peer.hostname", host),
				attribute.Int("peer.port", port),
			)
		}

		ips, err := resolver.LookupIP(tctx, "ip", domain)
		if err != nil {
			tsp.RecordError(err)
			tsp.End()
			return nil, err
		}

		tbl := L.NewTable()

		for _, ip := range ips {
			if (kind == "A" && ip.To4() != nil) || (kind == "AAAA" && ip.To4() == nil) {
				tbl.Append(lua.LString(ip.String()))
			}
		}

		tsp.SetAttributes(attribute.Int("dns.answer.count", tbl.Len()))
		tsp.End()

		return tbl, nil
	case "MX":
		tr := monittrace.New("nauthilus/dns")
		tctx, tsp := tr.StartClient(ctxTimeout, "dns.lookup",
			attribute.String("rpc.system", "dns"),
			semconv.PeerService("dns"),
			attribute.String("dns.question.name", domain),
			attribute.String("dns.question.type", "MX"),
		)

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

		tsp.SetAttributes(attribute.Int("dns.answer.count", tbl.Len()))
		tsp.End()

		return tbl, nil
	case "NS":
		tr := monittrace.New("nauthilus/dns")
		tctx, tsp := tr.StartClient(ctxTimeout, "dns.lookup",
			attribute.String("rpc.system", "dns"),
			semconv.PeerService("dns"),
			attribute.String("dns.question.name", domain),
			attribute.String("dns.question.type", "NS"),
		)

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

		tsp.SetAttributes(attribute.Int("dns.answer.count", tbl.Len()))
		tsp.End()

		return tbl, nil
	case "TXT":
		tr := monittrace.New("nauthilus/dns")
		tctx, tsp := tr.StartClient(ctxTimeout, "dns.lookup",
			attribute.String("rpc.system", "dns"),
			semconv.PeerService("dns"),
			attribute.String("dns.question.name", domain),
			attribute.String("dns.question.type", "TXT"),
		)

		txts, err := resolver.LookupTXT(tctx, domain)
		if err != nil {
			tsp.RecordError(err)
			tsp.End()

			return nil, err
		}

		tbl := L.NewTable()

		for _, txt := range txts {
			tbl.Append(lua.LString(txt))
		}

		tsp.SetAttributes(attribute.Int("dns.answer.count", tbl.Len()))
		tsp.End()

		return tbl, nil
	case "CNAME":
		tr := monittrace.New("nauthilus/dns")
		tctx, tsp := tr.StartClient(ctxTimeout, "dns.lookup",
			attribute.String("rpc.system", "dns"),
			semconv.PeerService("dns"),
			attribute.String("dns.question.name", domain),
			attribute.String("dns.question.type", "CNAME"),
		)

		cname, err := resolver.LookupCNAME(tctx, domain)
		if err != nil {
			tsp.RecordError(err)
			tsp.End()

			return nil, err
		}

		tsp.SetAttributes(attribute.Int("dns.answer.count", func() int {
			if cname != "" {
				return 1
			}

			return 0
		}()))
		tsp.End()

		return lua.LString(cname), nil
	case "PTR":
		tr := monittrace.New("nauthilus/dns")
		tctx, tsp := tr.StartClient(ctxTimeout, "dns.lookup",
			attribute.String("rpc.system", "dns"),
			semconv.PeerService("dns"),
			attribute.String("dns.question.name", domain),
			attribute.String("dns.question.type", "PTR"),
		)

		ptrs, err := resolver.LookupAddr(tctx, domain)
		if err != nil {
			tsp.RecordError(err)
			tsp.End()

			return nil, err
		}

		tbl := L.NewTable()

		for _, ptr := range ptrs {
			tbl.Append(lua.LString(ptr))
		}

		tsp.SetAttributes(attribute.Int("dns.answer.count", tbl.Len()))
		tsp.End()

		return tbl, nil
	default:
		return nil, fmt.Errorf("unsupported record type: %s", kind)
	}
}

// LoaderModDNS initializes and loads the DNS module for Lua, providing functions for DNS lookups and managing records.
func LoaderModDNS(ctx context.Context, cfg config.File, logger *slog.Logger) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewDNSManager(ctx, cfg, logger)

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			"resolve": manager.Resolve,
		})

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

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
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/util"

	lua "github.com/yuin/gopher-lua"
)

// Resolve performs a DNS record lookup for the specified domain and record type using Lua and the provided context.
// It supports record types such as A, AAAA, MX, NS, TXT, CNAME, and PTR and returns the result or an error to Lua.
func Resolve(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		domain := L.CheckString(1)
		recordType := strings.ToUpper(L.OptString(2, "A"))

		result, err := lookupRecord(ctx, L, domain, recordType)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		L.Push(result)

		return 1
	}
}

// lookupRecord performs a DNS lookup for the specified domain and record type, returning the results as an LValue.
// It supports record types like A, AAAA, MX, NS, TXT, CNAME, and PTR.
// The context controls the timeout for the DNS request, while Lua state handles the returned data format.
func lookupRecord(ctx context.Context, L *lua.LState, domain, kind string) (lua.LValue, error) {
	ctxTimeut, cancel := context.WithDeadline(ctx, time.Now().Add(config.GetFile().GetServer().GetDNS().GetTimeout()*time.Second))

	defer cancel()

	resolver := util.NewDNSResolver()

	switch kind {
	case "A", "AAAA":
		ips, err := resolver.LookupIP(ctxTimeut, "ip", domain)
		if err != nil {
			return nil, err
		}

		tbl := L.NewTable()

		for _, ip := range ips {
			if (kind == "A" && ip.To4() != nil) || (kind == "AAAA" && ip.To4() == nil) {
				tbl.Append(lua.LString(ip.String()))
			}
		}

		return tbl, nil
	case "MX":
		mxs, err := resolver.LookupMX(ctxTimeut, domain)
		if err != nil {
			return nil, err
		}

		tbl := L.NewTable()

		for _, mx := range mxs {
			rec := L.NewTable()
			rec.RawSetString("host", lua.LString(mx.Host))
			rec.RawSetString("pref", lua.LNumber(mx.Pref))
			tbl.Append(rec)
		}

		return tbl, nil
	case "NS":
		nss, err := resolver.LookupNS(ctxTimeut, domain)
		if err != nil {
			return nil, err
		}

		tbl := L.NewTable()

		for _, ns := range nss {
			tbl.Append(lua.LString(ns.Host))
		}

		return tbl, nil
	case "TXT":
		txts, err := resolver.LookupTXT(ctxTimeut, domain)
		if err != nil {
			return nil, err
		}

		tbl := L.NewTable()

		for _, txt := range txts {
			tbl.Append(lua.LString(txt))
		}

		return tbl, nil
	case "CNAME":
		cname, err := resolver.LookupCNAME(ctxTimeut, domain)
		if err != nil {
			return nil, err
		}

		return lua.LString(cname), nil
	case "PTR":
		ptrs, err := resolver.LookupAddr(ctxTimeut, domain)
		if err != nil {
			return nil, err
		}

		tbl := L.NewTable()

		for _, ptr := range ptrs {
			tbl.Append(lua.LString(ptr))
		}

		return tbl, nil
	default:
		return nil, fmt.Errorf("unsupported record type: %s", kind)
	}
}

// LoaderModDNS initializes and loads the DNS module for Lua, providing functions for DNS lookups and managing records.
func LoaderModDNS(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnDNSResolve: Resolve(ctx),
		})

		L.Push(mod)

		return 1
	}
}

// LoaderDNSStateless returns an empty, stateless module placeholder for nauthilus_dns.
// It allows require("nauthilus_dns") to succeed before per-request binding replaces it
// with a context-aware version via BindModuleIntoReq.
func LoaderDNSStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		L.Push(L.NewTable())

		return 1
	}
}

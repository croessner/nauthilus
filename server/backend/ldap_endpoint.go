// Copyright (C) 2025 Christian Rößner
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

package backend

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

// LuaLDAPEndpoint provides the exported LuaLDAPEndpoint function.
func LuaLDAPEndpoint(cfg config.File) lua.LGFunction {
	return func(L *lua.LState) int {
		poolName := luaLDAPEndpointPoolName(L)

		uris, ok := ldapEndpointURIs(cfg, poolName)
		if !ok {
			return pushLDAPEndpointError(L, "ldap pool config not found: "+poolName)
		}

		if len(uris) == 0 {
			return pushLDAPEndpointError(L, "no LDAP server_uri configured for pool: "+poolName)
		}

		ustr := strings.TrimSpace(uris[0])

		u, err := url.Parse(ustr)
		if err != nil {
			return pushLDAPEndpointError(L, "invalid LDAP server_uri: "+ustr)
		}

		if strings.EqualFold(u.Scheme, "ldapi") {
			return pushLDAPEndpointResult(L, ldapiEndpointHost(u), 0)
		}

		if u.Host == "" {
			return pushLDAPEndpointError(L, "invalid LDAP server_uri: "+ustr)
		}

		return pushLDAPEndpointResult(L, u.Hostname(), ldapEndpointPort(u))
	}
}

// luaLDAPEndpointPoolName resolves the optional Lua endpoint pool argument.
func luaLDAPEndpointPoolName(L *lua.LState) string {
	if L.GetTop() < 1 {
		return definitions.DefaultBackendName
	}

	poolNameArg := L.CheckString(1)
	if poolNameArg == "" || poolNameArg == luaLDAPPoolAliasDefault {
		return definitions.DefaultBackendName
	}

	return poolNameArg
}

// ldapEndpointURIs returns server URIs for the requested LDAP pool.
func ldapEndpointURIs(cfg config.File, poolName string) ([]string, bool) {
	if poolName == definitions.DefaultBackendName {
		return cfg.GetLDAPConfigServerURIs(), true
	}

	pools := cfg.GetLDAP().GetOptionalLDAPPools()
	if pools == nil || pools[poolName] == nil {
		return nil, false
	}

	return pools[poolName].GetServerURIs(), true
}

// ldapiEndpointHost returns the Unix-socket path or the existing empty value for unsupported forms.
func ldapiEndpointHost(u *url.URL) string {
	if u.Path != "" && strings.HasPrefix(u.Path, "/") {
		return u.Path
	}

	return ""
}

// ldapEndpointPort returns an explicit or scheme-derived LDAP endpoint port.
func ldapEndpointPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		if v, perr := strconv.ParseInt(p, 10, 16); perr == nil && v >= 0 && v <= 65535 {
			return int(v)
		}
	}

	if u.Scheme == "ldaps" {
		return 636
	}

	return 389
}

// pushLDAPEndpointError pushes the Lua endpoint error tuple.
func pushLDAPEndpointError(L *lua.LState, message string) int {
	L.Push(lua.LNil)
	L.Push(lua.LNil)
	L.Push(lua.LString(message))

	return 3
}

// pushLDAPEndpointResult pushes the Lua endpoint result tuple.
func pushLDAPEndpointResult(L *lua.LState, host string, port int) int {
	L.Push(lua.LString(host))
	L.Push(lua.LNumber(port))
	L.Push(lua.LNil)

	return 3
}

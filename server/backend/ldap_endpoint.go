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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

// LuaLDAPEndpoint exposes nauthilus_ldap.ldap_endpoint(pool_name?) → (server, port, err)
// It resolves the first configured server URI of the given pool and returns host and port.
// The function validates configuration only (no runtime "active" checks).
func LuaLDAPEndpoint(_ any) lua.LGFunction { // ctx currently not used, keep signature consistent with other loaders
	return func(L *lua.LState) int {
		poolName := definitions.DefaultBackendName
		if L.GetTop() >= 1 {
			poolNameArg := L.CheckString(1)
			if poolNameArg != "" && poolNameArg != "default" {
				poolName = poolNameArg
			}
		}

		// Load configuration for the pool
		var uris []string
		if poolName == definitions.DefaultBackendName {
			uris = config.GetFile().GetLDAPConfigServerURIs()
		} else {
			pools := config.GetFile().GetLDAP().GetOptionalLDAPPools()
			if pools == nil || pools[poolName] == nil {
				L.Push(lua.LNil)
				L.Push(lua.LNil)
				L.Push(lua.LString("ldap pool config not found: " + poolName))

				return 3
			}

			uris = pools[poolName].GetServerURIs()
		}

		if len(uris) == 0 {
			L.Push(lua.LNil)
			L.Push(lua.LNil)
			L.Push(lua.LString("no LDAP server_uri configured for pool: " + poolName))

			return 3
		}

		ustr := strings.TrimSpace(uris[0])

		u, err := url.Parse(ustr)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LNil)
			L.Push(lua.LString("invalid LDAP server_uri: " + ustr))

			return 3
		}

		// Support ldapi:///absolute/path (UNIX domain socket). For ldapi there is no host/port.
		if strings.EqualFold(u.Scheme, "ldapi") {
			// Accept only the non-escaped form with absolute path
			if u.Path != "" && strings.HasPrefix(u.Path, "/") {
				L.Push(lua.LString(u.Path))
				L.Push(lua.LNumber(0))
				L.Push(lua.LNil)

				return 3
			}

			// Unsupported ldapi form → return empty values without logging here
			L.Push(lua.LString(""))
			L.Push(lua.LNumber(0))
			L.Push(lua.LNil)

			return 3
		}

		// Standard ldap/ldaps handling with host/port
		if u.Host == "" {
			L.Push(lua.LNil)
			L.Push(lua.LNil)
			L.Push(lua.LString("invalid LDAP server_uri: " + ustr))

			return 3
		}

		host := u.Hostname()
		port := 0

		if p := u.Port(); p != "" {
			// parse int; ignore error since Port should be numeric
			if v, perr := strconv.Atoi(p); perr == nil {
				port = v
			}
		}

		if port == 0 {
			if u.Scheme == "ldaps" {
				port = 636
			} else {
				port = 389
			}
		}

		L.Push(lua.LString(host))
		L.Push(lua.LNumber(port))
		L.Push(lua.LNil)

		return 3
	}
}

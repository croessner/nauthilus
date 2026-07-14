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
	"errors"
	"strings"

	"github.com/croessner/nauthilus/v3/server/backend/ldapendpoint"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

var (
	errLDAPEndpointPoolNotFound = errors.New("LDAP endpoint pool not found")
	errLDAPEndpointUnavailable  = errors.New("LDAP endpoint is not configured")
)

// LDAPEndpointMetadata contains configured trace-safe LDAP endpoint fields.
type LDAPEndpointMetadata struct {
	PoolName string
	Scheme   string
	Host     string
	Port     int
}

// LDAPEndpoints returns all configured endpoints for a default or named pool.
func LDAPEndpoints(cfg config.File, poolName string) ([]LDAPEndpointMetadata, error) {
	poolName = normalizeLDAPEndpointPoolName(poolName)

	lookupPoolName := poolName

	if poolName == config.RemoteBackendDefaultName {
		lookupPoolName = definitions.DefaultBackendName
	}

	uris, ok := ldapEndpointURIs(cfg, lookupPoolName)
	if !ok {
		return nil, errLDAPEndpointPoolNotFound
	}

	if len(uris) == 0 {
		return nil, errLDAPEndpointUnavailable
	}

	endpoints := make([]LDAPEndpointMetadata, 0, len(uris))
	for _, rawURI := range uris {
		endpoint, err := ldapendpoint.Parse(rawURI)
		if err != nil {
			return nil, err
		}

		endpoints = append(endpoints, LDAPEndpointMetadata{
			PoolName: poolName,
			Scheme:   endpoint.Scheme,
			Host:     endpoint.Host,
			Port:     endpoint.Port,
		})
	}

	return endpoints, nil
}

// normalizeLDAPEndpointPoolName maps public default aliases to one stable value.
func normalizeLDAPEndpointPoolName(poolName string) string {
	poolName = strings.TrimSpace(poolName)
	if poolName == "" || poolName == definitions.DefaultBackendName {
		return config.RemoteBackendDefaultName
	}

	return poolName
}

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

		endpoint, err := ldapendpoint.Parse(uris[0])
		if err != nil {
			return pushLDAPEndpointError(L, "invalid LDAP server_uri")
		}

		return pushLDAPEndpointResult(L, endpoint.Host, endpoint.Port)
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

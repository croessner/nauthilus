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
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/monitoring"
	lua "github.com/yuin/gopher-lua"
)

// getNumberFromTable retrieves an integer value from a Lua table for the given key. If the key is missing or nil, returns 0.
//
// Parameters:
// - table: The Lua table to search in.
// - key: The key to look for in the table.
//
// Returns:
// - The integer value associated with the key, or 0 if the key is not present or value is nil.
func getNumberFromTable(table *lua.LTable, key string) int {
	value := table.RawGet(lua.LString(key))

	if value == nil {
		return 0
	}

	return int(value.(lua.LNumber))
}

// CheckBackendConnection attempts to verify the connection to a backend server using the provided monitor.
// It extracts necessary configuration details such as protocol, IP address, port, and credentials from the given Lua table.
// The function then calls the monitor's CheckBackendConnection method to perform the actual connectivity check.
// If the connection check encounters an error, this error is pushed onto the Lua stack.
// If the connection check is successful, a nil value is pushed onto the Lua stack.
// It returns an integer indicating the number of results pushed onto the Lua stack.
func CheckBackendConnection(monitor monitoring.Monitor) lua.LGFunction {
	return func(L *lua.LState) int {
		table := L.CheckTable(1)

		server := &config.BackendServer{}

		server.Protocol = getStringFromTable(table, "protocol")
		server.Host = getStringFromTable(table, "ip_address")
		server.Port = getNumberFromTable(table, "port")
		server.HAProxyV2 = getBoolFromTable(table, "haproxy_v2")
		server.TLS = getBoolFromTable(table, "tls")
		server.TLSSkipVerify = getBoolFromTable(table, "tls_skip_verify")
		server.TestUsername = getStringFromTable(table, "test_username")
		server.TestPassword = getStringFromTable(table, "test_password")
		server.RequestURI = getStringFromTable(table, "request_uri")
		server.DeepCheck = getBoolFromTable(table, "deep_check")

		if err := monitor.CheckBackendConnection(server); err != nil {
			L.Push(lua.LString(err.Error()))

			return 1
		}

		L.Push(lua.LNil)

		return 1
	}
}

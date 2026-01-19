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
	"log/slog"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/croessner/nauthilus/server/monitoring"
	lua "github.com/yuin/gopher-lua"
)

// BackendConnectionManager manages backend connection checks for Lua.
type BackendConnectionManager struct {
	*BaseManager
	monitor monitoring.Monitor
}

// NewBackendConnectionManager creates a new BackendConnectionManager.
func NewBackendConnectionManager(ctx context.Context, cfg config.File, logger *slog.Logger, monitor monitoring.Monitor) *BackendConnectionManager {
	return &BackendConnectionManager{
		BaseManager: NewBaseManager(ctx, cfg, logger),
		monitor:     monitor,
	}
}

// CheckBackendConnection verifies the connection to a backend server.
func (m *BackendConnectionManager) CheckBackendConnection(L *lua.LState) int {
	stack := luastack.NewManager(L)
	table := stack.CheckTable(1)

	server := &config.BackendServer{}

	server.Protocol = getStringFromTable(table, "protocol")
	server.Host = getStringFromTable(table, "host")
	server.Port = getNumberFromTable(table, "port")
	server.HAProxyV2 = getBoolFromTable(table, "haproxy_v2")
	server.TLS = getBoolFromTable(table, "tls")
	server.TLSSkipVerify = getBoolFromTable(table, "tls_skip_verify")
	server.TestUsername = getStringFromTable(table, "test_username")
	server.TestPassword = getStringFromTable(table, "test_password")
	server.RequestURI = getStringFromTable(table, "request_uri")
	server.DeepCheck = getBoolFromTable(table, "deep_check")

	if err := m.monitor.CheckBackendConnection(server); err != nil {
		return stack.PushResults(lua.LNil, lua.LString(err.Error()))
	}

	return stack.PushResults(lua.LBool(true), lua.LNil)
}

// LoaderModConnection initializes and loads the connection module for Lua.
func LoaderModConnection(ctx context.Context, cfg config.File, logger *slog.Logger, monitor monitoring.Monitor) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewBackendConnectionManager(ctx, cfg, logger, monitor)

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			"check": manager.CheckBackendConnection,
		})

		return stack.PushResult(mod)
	}
}

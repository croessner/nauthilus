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

package filter

import (
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/monitoring"
	lua "github.com/yuin/gopher-lua"
)

// LoaderBackendStateless returns an empty, stateless module table for nauthilus_backend.
// It is intended to be preloaded once per VM (base environment). Per-request bindings will later
// clone this table and inject bound functions via WithReq/WithPtr/WithList/WithMonitor factories.
func LoaderBackendStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		L.Push(L.NewTable())

		return 1
	}
}

// GetBackendServersWithReq returns the getBackendServers closure bound to the provided request.
func GetBackendServersWithReq(req *Request) lua.LGFunction {
	return getBackendServers(req.BackendServers)
}

// SelectBackendServerWithReq returns the selectBackendServer closure bound to the provided request.
func SelectBackendServerWithReq(req *Request) lua.LGFunction {
	return selectBackendServer(&req.UsedBackendAddress, &req.UsedBackendPort)
}

// ApplyBackendResultWithPtr binds the applyBackendResult closure to the provided backend result pointer.
func ApplyBackendResultWithPtr(backendResult **lualib.LuaBackendResult) lua.LGFunction {
	return applyBackendResult(backendResult)
}

// RemoveFromBackendResultWithList binds the removeFromBackendResult closure to the provided list pointer.
func RemoveFromBackendResultWithList(removeAttributes *[]string) lua.LGFunction {
	return removeFromBackendResult(removeAttributes)
}

// CheckBackendConnectionWithMonitor returns the CheckBackendConnection closure bound to the provided monitor.
func CheckBackendConnectionWithMonitor(monitor monitoring.Monitor) lua.LGFunction {
	return lualib.CheckBackendConnection(monitor)
}

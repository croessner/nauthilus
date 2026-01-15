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

package bruteforce

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/croessner/nauthilus/server/rediscli"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

// BruteForceManager manages brute force protection operations for Lua.
type BruteForceManager struct {
	*lualib.BaseManager
	redis    rediscli.Client
	tolerate tolerate.Tolerate
}

// NewBruteForceManager creates a new BruteForceManager.
func NewBruteForceManager(ctx context.Context, cfg config.File, logger *slog.Logger, redis rediscli.Client, t tolerate.Tolerate) *BruteForceManager {
	return &BruteForceManager{
		BaseManager: lualib.NewBaseManager(ctx, cfg, logger),
		redis:       redis,
		tolerate:    t,
	}
}

// SetCustomTolerations sets custom toleration configurations for IP-based limits from a Lua table parameter.
func (m *BruteForceManager) SetCustomTolerations(L *lua.LState) int {
	stack := luastack.NewManager(L)
	tolerations := stack.CheckTable(1)

	parsedTolerations := make([]config.Tolerate, 0)

	var err error

	tolerations.ForEach(func(_ lua.LValue, value lua.LValue) {
		tolerationTable, ok := value.(*lua.LTable)
		if !ok {
			err = errors.New("each toleration must be a table")

			return
		}

		ipAddress := tolerationTable.RawGetString("ip_address")
		toleratePercent := tolerationTable.RawGetString("tolerate_percent")
		tolerateTTL := tolerationTable.RawGetString("tolerate_ttl")

		ip := lua.LVAsString(ipAddress)
		percent := uint8(lua.LVAsNumber(toleratePercent))

		ttl, e := time.ParseDuration(lua.LVAsString(tolerateTTL))
		if e != nil {
			err = errors.New("invalid tolerate_ttl format")

			return
		}

		toleration := config.Tolerate{
			IPAddress:       ip,
			ToleratePercent: percent,
			TolerateTTL:     ttl,
		}

		parsedTolerations = append(parsedTolerations, toleration)
	})

	if err != nil {
		return stack.PushResults(lua.LNil, lua.LString(err.Error()))
	}

	tolerate.GetTolerate().SetCustomTolerations(parsedTolerations)

	return stack.PushResults(lua.LString("OK"), lua.LNil)
}

// SetCustomToleration sets a custom toleration for an IP address with a specific percentage and TTL using Lua inputs.
func (m *BruteForceManager) SetCustomToleration(L *lua.LState) int {
	stack := luastack.NewManager(L)
	tolerationTable := stack.CheckTable(1)

	ipAddress := tolerationTable.RawGetString("ip_address")
	toleratePercent := tolerationTable.RawGetString("tolerate_percent")
	tolerateTTL := tolerationTable.RawGetString("tolerate_ttl")

	ip := lua.LVAsString(ipAddress)
	percent := uint8(lua.LVAsNumber(toleratePercent))

	ttl, err := time.ParseDuration(lua.LVAsString(tolerateTTL))
	if err != nil {
		return stack.PushResults(lua.LNil, lua.LString("invalid tolerate_ttl format"))
	}

	tolerate.GetTolerate().SetCustomToleration(ip, percent, ttl)

	return stack.PushResults(lua.LString("OK"), lua.LNil)
}

// DeleteCustomToleration removes the custom toleration configuration for a given IP address from the system.
func (m *BruteForceManager) DeleteCustomToleration(L *lua.LState) int {
	stack := luastack.NewManager(L)
	ip := stack.CheckString(1)

	tolerate.GetTolerate().DeleteCustomToleration(ip)

	return stack.PushResults(lua.LString("OK"), lua.LNil)
}

// GetCustomTolerations retrieves custom toleration settings and returns them as a Lua table accessible to the Lua state.
func (m *BruteForceManager) GetCustomTolerations(L *lua.LState) int {
	stack := luastack.NewManager(L)
	tolerations := tolerate.GetTolerate().GetCustomTolerations()
	resultTable := L.NewTable()

	for _, toleration := range tolerations {
		tolerationTable := L.NewTable()

		tolerationTable.RawSetString("ip_address", lua.LString(toleration.IPAddress))
		tolerationTable.RawSetString("tolerate_percent", lua.LNumber(toleration.ToleratePercent))
		tolerationTable.RawSetString("tolerate_ttl", lua.LString(toleration.TolerateTTL.String()))

		resultTable.Append(tolerationTable)
	}

	return stack.PushResults(resultTable, lua.LNil)
}

// GetTolerateMap retrieves a Lua table containing authentication data for the provided IP address from the toleration system.
func (m *BruteForceManager) GetTolerateMap(L *lua.LState) int {
	stack := luastack.NewManager(L)
	ipAddress := stack.CheckString(1)

	mapping := m.tolerate.GetTolerateMap(m.Ctx, ipAddress)
	resultTable := L.NewTable()

	for label, value := range mapping {
		resultTable.RawSetString(label, lua.LNumber(value))
	}

	return stack.PushResults(resultTable, lua.LNil)
}

// IsIPAddressBlocked checks if an IP address is blocked and returns a list of buckets causing the block or nil if not blocked.
func (m *BruteForceManager) IsIPAddressBlocked(L *lua.LState) int {
	stack := luastack.NewManager(L)
	var guid string

	ipAddress := stack.CheckString(1)

	if ginCtx, ok := m.Ctx.(*gin.Context); ok {
		guid = ginCtx.GetString(definitions.CtxGUIDKey)
	}

	if guid == "" {
		guid = definitions.NotAvailable
	}

	bm := bruteforce.NewBucketManagerWithDeps(m.Ctx, guid, ipAddress, bruteforce.BucketManagerDeps{
		Cfg:      m.Cfg,
		Logger:   m.Logger,
		Redis:    m.redis,
		Tolerate: m.tolerate,
	})

	bucketsNames, found := bm.IsIPAddressBlocked()
	if !found {
		return stack.PushResults(lua.LNil, lua.LNil)
	}

	result := L.NewTable()
	for _, bucketName := range bucketsNames {
		result.Append(lua.LString(bucketName))
	}

	return stack.PushResults(result, lua.LNil)
}

// LoaderModBruteForce initializes the Lua module with functions for managing custom toleration settings and pushes it to the state.
func LoaderModBruteForce(ctx context.Context, cfg config.File, logger *slog.Logger, redis rediscli.Client, t tolerate.Tolerate) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewBruteForceManager(ctx, cfg, logger, redis, t)

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnBfSetCustomTolerations:   manager.SetCustomTolerations,
			definitions.LuaFnBfSetCustomToleration:    manager.SetCustomToleration,
			definitions.LuaFnBfDeleteCustomToleration: manager.DeleteCustomToleration,
			definitions.LuaFnBfGetCusotmTolerations:   manager.GetCustomTolerations,
			definitions.LuaFnBfGetTolerateMap:         manager.GetTolerateMap,
			definitions.LuaFnBfIsIPAddressBlocked:     manager.IsIPAddressBlocked,
		})

		return stack.PushResult(mod)
	}
}

// LoaderBruteForceStateless returns an empty, stateless module placeholder for nauthilus_brute_force.
// It allows require("nauthilus_brute_force") to succeed before per-request binding replaces it
// with a context-aware version via BindModuleIntoReq.
func LoaderBruteForceStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)

		return stack.PushResult(L.NewTable())
	}
}

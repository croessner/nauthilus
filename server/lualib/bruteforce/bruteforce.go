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
	"log/slog"
	"time"

	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

// SetCustomTolerations sets custom toleration configurations for IP-based limits from a Lua table parameter.
func SetCustomTolerations(L *lua.LState) int {
	tolerations := L.CheckTable(1)

	parsedTolerations := make([]config.Tolerate, 0)

	tolerations.ForEach(func(_ lua.LValue, value lua.LValue) {
		tolerationTable, ok := value.(*lua.LTable)
		if !ok {
			L.ArgError(1, "each toleration must be a table")

			return
		}

		ipAddress := tolerationTable.RawGetString("ip_address")
		toleratePercent := tolerationTable.RawGetString("tolerate_percent")
		tolerateTTL := tolerationTable.RawGetString("tolerate_ttl")

		ip := lua.LVAsString(ipAddress)
		percent := uint8(lua.LVAsNumber(toleratePercent))

		ttl, err := time.ParseDuration(lua.LVAsString(tolerateTTL))
		if err != nil {
			L.ArgError(1, "invalid tolerate_ttl format")
			return
		}

		toleration := config.Tolerate{
			IPAddress:       ip,
			ToleratePercent: percent,
			TolerateTTL:     ttl,
		}

		parsedTolerations = append(parsedTolerations, toleration)
	})

	tolerate.GetTolerate().SetCustomTolerations(parsedTolerations)

	return 0
}

// SetCustomToleration sets a custom toleration for an IP address with a specific percentage and TTL using Lua inputs.
func SetCustomToleration(L *lua.LState) int {
	tolerationTable := L.CheckTable(1)

	ipAddress := tolerationTable.RawGetString("ip_address")
	toleratePercent := tolerationTable.RawGetString("tolerate_percent")
	tolerateTTL := tolerationTable.RawGetString("tolerate_ttl")

	ip := lua.LVAsString(ipAddress)
	percent := uint8(lua.LVAsNumber(toleratePercent))

	ttl, err := time.ParseDuration(lua.LVAsString(tolerateTTL))
	if err != nil {
		L.ArgError(1, "invalid tolerate_ttl format")

		return 0
	}

	tolerate.GetTolerate().SetCustomToleration(ip, percent, ttl)

	return 0
}

// DeleteCustomToleration removes the custom toleration configuration for a given IP address from the system.
func DeleteCustomToleration(L *lua.LState) int {
	ip := L.CheckString(1)

	tolerate.GetTolerate().DeleteCustomToleration(ip)

	return 0
}

// GetCustomTolerations retrieves custom toleration settings and returns them as a Lua table accessible to the Lua state.
func GetCustomTolerations(L *lua.LState) int {
	tolerations := tolerate.GetTolerate().GetCustomTolerations()
	resultTable := L.NewTable()

	for _, toleration := range tolerations {
		tolerationTable := L.NewTable()

		tolerationTable.RawSetString("ip_address", lua.LString(toleration.IPAddress))
		tolerationTable.RawSetString("tolerate_percent", lua.LNumber(toleration.ToleratePercent))
		tolerationTable.RawSetString("tolerate_ttl", lua.LString(toleration.TolerateTTL.String()))

		resultTable.Append(tolerationTable)
	}

	L.Push(resultTable)

	return 1
}

// GetTolerateMap retrieves a Lua table containing authentication data for the provided IP address from the toleration system.
func GetTolerateMap(ctx context.Context, t tolerate.Tolerate) lua.LGFunction {
	return func(L *lua.LState) int {
		ipAddress := L.CheckString(1)

		mapping := t.GetTolerateMap(ctx, ipAddress)
		resultTable := L.NewTable()

		for label, value := range mapping {
			resultTable.RawSetString(label, lua.LNumber(value))
		}

		L.Push(resultTable)

		return 1
	}
}

// IsIPAddressBlocked checks if an IP address is blocked and returns a list of buckets causing the block or nil if not blocked.
func IsIPAddressBlocked(ctx context.Context, cfg config.File, logger *slog.Logger, redis rediscli.Client, t tolerate.Tolerate) lua.LGFunction {
	return func(L *lua.LState) int {
		var guid string

		ipAddress := L.CheckString(1)

		if ginCtx, ok := ctx.(*gin.Context); ok {
			guid = ginCtx.GetString(definitions.CtxGUIDKey)
		}

		if guid == "" {
			guid = definitions.NotAvailable
		}

		bm := bruteforce.NewBucketManagerWithDeps(ctx, guid, ipAddress, bruteforce.BucketManagerDeps{
			Cfg:      cfg,
			Logger:   logger,
			Redis:    redis,
			Tolerate: t,
		})

		bucketsNames, found := bm.IsIPAddressBlocked()
		if !found {
			L.Push(lua.LNil)

			return 1
		}

		result := L.NewTable()
		for _, bucketName := range bucketsNames {
			result.Append(lua.LString(bucketName))
		}

		L.Push(result)

		return 1
	}
}

// LoaderModBruteForce initializes the Lua module with functions for managing custom toleration settings and pushes it to the state.
func LoaderModBruteForce(ctx context.Context, cfg config.File, logger *slog.Logger, redis rediscli.Client, t tolerate.Tolerate) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnBfSetCustomTolerations:   SetCustomTolerations,
			definitions.LuaFnBfSetCustomToleration:    SetCustomToleration,
			definitions.LuaFnBfDeleteCustomToleration: DeleteCustomToleration,
			definitions.LuaFnBfGetCusotmTolerations:   GetCustomTolerations,
			definitions.LuaFnBfGetTolerateMap:         GetTolerateMap(ctx, t),
			definitions.LuaFnBfIsIPAddressBlocked:     IsIPAddressBlocked(ctx, cfg, logger, redis, t),
		})

		L.Push(mod)

		return 1
	}
}

// LoaderBruteForceStateless returns an empty, stateless module placeholder for nauthilus_brute_force.
// It allows require("nauthilus_brute_force") to succeed before per-request binding replaces it
// with a context-aware version via BindModuleIntoReq.
func LoaderBruteForceStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		L.Push(L.NewTable())

		return 1
	}
}

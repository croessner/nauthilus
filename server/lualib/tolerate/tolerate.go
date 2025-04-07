package tolerate

import (
	"context"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/definitions"
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
func GetTolerateMap(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		ipAddress := L.CheckString(1)

		mapping := tolerate.GetTolerate().GetTolerateMap(ctx, ipAddress)
		resultTable := L.NewTable()

		for label, value := range mapping {
			resultTable.RawSetString(label, lua.LNumber(value))
		}

		L.Push(resultTable)

		return 1
	}
}

// LoaderModBruteForce initializes the Lua module with functions for managing custom toleration settings and pushes it to the state.
func LoaderModBruteForce(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnBfSetCustomTolerations:   SetCustomTolerations,
			definitions.LuaFnBfSetCustomToleration:    SetCustomToleration,
			definitions.LuaFnBfDeleteCustomToleration: DeleteCustomToleration,
			definitions.LuaFnBfGetCusotmTolerations:   GetCustomTolerations,
			definitions.LuaFnBfGetTolerateMap:         GetTolerateMap(ctx),
		})

		L.Push(mod)

		return 1
	}
}

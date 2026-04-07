// Copyright (C) 2026 Christian Rößner
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
	"github.com/croessner/nauthilus/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

type builtinConstant struct {
	key   string
	value lua.LValue
}

var (
	actionBuiltinConstants = []builtinConstant{
		{key: definitions.LuaActionResultOk, value: lua.LNumber(0)},
		{key: definitions.LuaActionResultFail, value: lua.LNumber(1)},
	}
	backendBuiltinConstants = []builtinConstant{
		{key: definitions.LuaBackendResultOk, value: lua.LNumber(0)},
		{key: definitions.LuaBackendResultFail, value: lua.LNumber(1)},
	}
	filterBuiltinConstants = []builtinConstant{
		{key: definitions.LuaFilterAccept, value: lua.LBool(false)},
		{key: definitions.LuaFilterREJECT, value: lua.LBool(true)},
		{key: definitions.LuaFilterResultOk, value: lua.LNumber(0)},
		{key: definitions.LuaFilterResultFail, value: lua.LNumber(1)},
	}
	featureBuiltinConstants = []builtinConstant{
		{key: definitions.LuaFeatureTriggerNo, value: lua.LBool(false)},
		{key: definitions.LuaFeatureTriggerYes, value: lua.LBool(true)},
		{key: definitions.LuaFeatureAbortNo, value: lua.LBool(false)},
		{key: definitions.LuaFeatureAbortYes, value: lua.LBool(true)},
		{key: definitions.LuaFeatureResultOk, value: lua.LNumber(0)},
		{key: definitions.LuaFeatureResultFail, value: lua.LNumber(1)},
	}
	allBuiltinConstants = mergeBuiltinConstants(
		actionBuiltinConstants,
		backendBuiltinConstants,
		filterBuiltinConstants,
		featureBuiltinConstants,
	)
)

// SetBuiltinTableForAction configures the nauthilus_builtin table for action scripts.
func SetBuiltinTableForAction(L *lua.LState, addCustomLog lua.LGFunction) {
	setBuiltinTable(L, actionBuiltinConstants, addCustomLog, nil)
}

// SetBuiltinTableForBackend configures the nauthilus_builtin table for backend scripts.
func SetBuiltinTableForBackend(L *lua.LState, addCustomLog lua.LGFunction, status **string) {
	setBuiltinTable(L, backendBuiltinConstants, addCustomLog, status)
}

// SetBuiltinTableForFilter configures the nauthilus_builtin table for filter scripts.
func SetBuiltinTableForFilter(L *lua.LState, addCustomLog lua.LGFunction, status **string) {
	setBuiltinTable(L, filterBuiltinConstants, addCustomLog, status)
}

// SetBuiltinTableForFeature configures the nauthilus_builtin table for feature scripts.
func SetBuiltinTableForFeature(L *lua.LState, addCustomLog lua.LGFunction, status **string) {
	setBuiltinTable(L, featureBuiltinConstants, addCustomLog, status)
}

// SetBuiltinTableForCacheFlush configures the nauthilus_builtin table for cache flush scripts.
func SetBuiltinTableForCacheFlush(L *lua.LState, addCustomLog lua.LGFunction, status **string) {
	setBuiltinTable(L, nil, addCustomLog, status)
}

// SetBuiltinTableForAll configures the nauthilus_builtin table with all runtime constants.
func SetBuiltinTableForAll(L *lua.LState, addCustomLog lua.LGFunction, status **string) {
	setBuiltinTable(L, allBuiltinConstants, addCustomLog, status)
}

func setBuiltinTable(L *lua.LState, constants []builtinConstant, addCustomLog lua.LGFunction, status **string) {
	globals := L.NewTable()

	for index := range constants {
		globals.RawSetString(constants[index].key, constants[index].value)
	}

	if addCustomLog != nil {
		globals.RawSetString(definitions.LuaFnAddCustomLog, L.NewFunction(addCustomLog))
	}

	if status != nil {
		globals.RawSetString(definitions.LuaFnSetStatusMessage, L.NewFunction(SetStatusMessage(status)))
	}

	L.SetGlobal(definitions.LuaDefaultTable, globals)
}

func mergeBuiltinConstants(groups ...[]builtinConstant) []builtinConstant {
	total := 0

	for index := range groups {
		total += len(groups[index])
	}

	merged := make([]builtinConstant, 0, total)

	for index := range groups {
		merged = append(merged, groups[index]...)
	}

	return merged
}

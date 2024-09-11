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

package convert

import (
	"fmt"

	"github.com/croessner/nauthilus/server/global"
	"github.com/redis/go-redis/v9"
	"github.com/yuin/gopher-lua"
)

// LuaValue converts a Lua value to its corresponding Go type.
// It takes a lua.LValue as input and returns the converted value and an error.
// The function supports converting Lua strings to Go strings, Lua numbers to Go float64,
// Lua booleans to Go bool, and Lua nil to Go nil.
// If the Lua value is of any other type, it returns an error.
func LuaValue(lValue lua.LValue) (any, error) {
	switch lValue.Type() {
	case lua.LTString:
		return lua.LVAsString(lValue), nil
	case lua.LTNumber:
		return float64(lua.LVAsNumber(lValue)), nil
	case lua.LTBool:
		return lua.LVAsBool(lValue), nil
	case lua.LTNil:
		return nil, nil
	default:
		err := fmt.Errorf("unable to convert Lua value of type %s", lValue.Type())

		return nil, err
	}
}

// StringCmd attempts to convert a given *redis.StringCmd value into the specified type.
//
// Parameters:
// value: The redis.StringCmd value to be converted.
// valType: The type that the redis.StringCmd should be converted to. Acceptable values include:
//   - "string": converts the redis.StringCmd to a Lua string.
//   - "number": converts the redis.StringCmd to a Lua number. If the conversion fails, it returns an error.
//   - "boolean": converts the redis.StringCmd to a Lua boolean. If the conversion fails, it returns an error.
//
// L: The Lua state against which these conversions are made.
// This method pushes the converted value onto the L lua.LState if the conversion is successful.
//
// It returns nil if the conversion is successful.
// It returns an error if the conversion fails or if the conversion is attempted on an unsupported type.
//
// Example usage:
//
//	err := convertStringCmd(myStringCmd, "number", myLuaState)
//	if err != nil {
//	    log.Fatal(err)
//	}
func StringCmd(value *redis.StringCmd, valType string, L *lua.LState) error {
	if err := value.Err(); err != nil {
		return err
	}

	switch valType {
	case global.TypeString:
		if value.Val() == "" {
			L.Push(lua.LNil)

			return nil
		}

		L.Push(lua.LString(value.Val()))
	case global.TypeNumber:
		if value.Val() == "" {
			L.Push(lua.LNil)

			return nil
		}

		if result, err := value.Float64(); err == nil {
			L.Push(lua.LNumber(result))
		} else {
			return err
		}
	case global.TypeBoolean:
		if value.Val() == "" {
			L.Push(lua.LNil)

			return nil
		}

		if result, err := value.Bool(); err == nil {
			L.Push(lua.LBool(result))
		} else {
			return err
		}
	case global.TypeNil:
		L.Push(lua.LNil)
	default:
		return fmt.Errorf("unable to convert string command of type %s", valType)
	}

	return nil
}

// GoToLuaValue converts a Go value to a corresponding Lua value.
// It accepts an argument 'value' of type 'any' and returns a value of type 'lua.LValue'.
// If the input is a string, it returns a Lua string value (lua.LString).
// If the input is a float64 or an int, it returns a Lua number value (lua.LNumber).
// If the input is a boolean, it returns a Lua boolean value (lua.LBool).
// For any other types, it converts the value to a string and returns a Lua string value (lua.LString).
// The function uses the fmt.Sprintf method to convert values of any type to a string.
// This function is useful for converting Go values to their equivalent Lua values.
// The function is not safe for concurrent use.
func GoToLuaValue(L *lua.LState, value any) lua.LValue {
	switch v := value.(type) {
	case string:
		return lua.LString(v)
	case float64:
		return lua.LNumber(v)
	case int:
		return lua.LNumber(v)
	case bool:
		return lua.LBool(v)
	case map[any]any:
		return MapToLuaTable(L, v)
	default:
		return lua.LString(fmt.Sprintf("%v", value))
	}
}

// LuaTableToMap takes a lua.LTable as input and converts it into a map[any]any.
// The function iterates over each key-value pair in the table and converts the keys and values
// into their corresponding Go types. The converted key-value pairs are then added to a new map, which is
// returned as the result.
// If the input table is nil, the function returns nil.
func LuaTableToMap(table *lua.LTable) map[any]any {
	if table == nil {
		return nil
	}

	result := make(map[any]any)

	table.ForEach(func(key lua.LValue, value lua.LValue) {
		var (
			mapKey   any
			mapValue any
		)

		switch k := key.(type) {
		case lua.LBool:
			mapKey = bool(k)
		case lua.LNumber:
			mapKey = float64(k)
		case lua.LString:
			mapKey = k.String()
		default:
			return
		}

		switch v := value.(type) {
		case lua.LBool:
			mapValue = bool(v)
		case lua.LNumber:
			mapValue = float64(v)
		case *lua.LTable:
			mapValue = LuaTableToMap(v)
		default:
			mapValue = v.String()
		}

		result[mapKey] = mapValue
	})

	return result
}

// MapToLuaTable takes an *lua.LState and a map[any]any as input and converts it into a *lua.LTable.
// The function iterates over each key-value pair in the map and converts the keys and values
// into their corresponding lua.LValue types. The converted key-value pairs are then added to a new *lua.LTable,
// which is returned as the result.
// If the input map is nil, the function returns nil.
func MapToLuaTable(L *lua.LState, table map[any]any) *lua.LTable {
	var (
		key   lua.LValue
		value lua.LValue
	)

	lTable := L.NewTable()

	if table == nil {
		return nil
	}

	for k, v := range table {
		switch mapKey := k.(type) {
		case bool:
			key = lua.LBool(mapKey)
		case float64:
			key = lua.LNumber(mapKey)
		case string:
			key = lua.LString(mapKey)
		default:
			return nil
		}

		switch mapValue := v.(type) {
		case bool:
			value = lua.LBool(mapValue)
		case float64:
			value = lua.LNumber(mapValue)
		case string:
			value = lua.LString(mapValue)
		case []any:
			value = SliceToLuaTable(L, mapValue) // convert []any to *lua.LTable
		case map[any]any:
			value = MapToLuaTable(L, mapValue)
		default:
			return nil
		}

		L.RawSet(lTable, key, value)
	}

	return lTable
}

// SliceToLuaTable converts a slice into a Lua table using the provided Lua state.
// It accepts two parameters:
//   - L: a pointer to the Lua state
//   - slice: a slice of type `any`
//
// For each value in the slice, the function checks the type of the value.
// If the value is a boolean, it sets the Lua table's element at index `i+1` to a Lua boolean with the same value.
// If the value is a float64, it sets the Lua table's element at index `i+1` to a Lua number with the same value.
// If the value is a string, it sets the Lua table's element at the index `i+1` to a Lua string with the same value.
//
// If the value is of any other type, the function returns nil.
//
// Finally, the function returns a pointer to a Lua table that contains all valid values from the slice.
func SliceToLuaTable(L *lua.LState, slice []any) *lua.LTable {
	lTable := L.NewTable()
	for i, v := range slice {
		switch sliceValue := v.(type) {
		case bool:
			L.RawSetInt(lTable, i+1, lua.LBool(sliceValue))
		case float64:
			L.RawSetInt(lTable, i+1, lua.LNumber(sliceValue))
		case string:
			L.RawSetInt(lTable, i+1, lua.LString(sliceValue))
		default:
			return nil
		}
	}

	return lTable
}

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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// LuaValue converts a Lua LValue to its corresponding Go native type (string, float64, bool, or nil).
// Returns an error if the LValue type is unsupported.
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

// StringCmd processes a Redis StringCmd response, converts it to the specified Lua value type, and pushes it to Lua state.
// Supported types are "string", "number", "bool", and "nil". Returns an error if conversion or processing fails.
func StringCmd(value *redis.StringCmd, valType string, L *lua.LState) error {
	stack := luastack.NewManager(L)

	if err := value.Err(); err != nil {
		return err
	}

	switch valType {
	case definitions.TypeString:
		if value.Val() == "" {
			stack.PushResult(lua.LNil)
			L.Push(lua.LNil)

			return nil
		}

		stack.PushResult(lua.LString(value.Val()))
		L.Push(lua.LNil)

		return nil
	case definitions.TypeNumber:
		if value.Val() == "" {
			stack.PushResult(lua.LNil)
			L.Push(lua.LNil)

			return nil
		}

		if result, err := value.Float64(); err == nil {
			stack.PushResult(lua.LNumber(result))
			L.Push(lua.LNil)
		} else {
			return err
		}

	case definitions.TypeBoolean:
		if value.Val() == "" {
			stack.PushResult(lua.LNil)
			L.Push(lua.LNil)

			return nil
		}

		if result, err := value.Bool(); err == nil {
			stack.PushResult(lua.LBool(result))
			L.Push(lua.LNil)
		} else {
			return err
		}

	case definitions.TypeNil:
		stack.PushResult(lua.LNil)
		L.Push(lua.LNil)
	default:
		return fmt.Errorf("unable to convert string command of type %s", valType)
	}

	return nil
}

// GoToLuaValue converts a Go value to a corresponding Lua value suitable for Lua state operations.
func GoToLuaValue(L *lua.LState, value any) lua.LValue {
	switch v := value.(type) {
	case string:
		return lua.LString(v)
	case float64:
		return lua.LNumber(v)
	case int64:
		return lua.LNumber(v)
	case bool:
		return lua.LBool(v)
	case config.StringSet:
		tbl := L.NewTable()
		strSlice := v.GetStringSlice()

		for _, str := range strSlice {
			tbl.Append(lua.LString(str))
		}

		return tbl
	case []any:
		tbl := L.NewTable()

		for _, item := range v {
			tbl.Append(GoToLuaValue(L, item))
		}

		return tbl
	case map[string]any:
		tbl := L.NewTable()

		for k, item := range v {
			tbl.RawSetString(k, GoToLuaValue(L, item))
		}

		return tbl
	case map[any]any:
		tbl := L.NewTable()

		for k, item := range v {
			tbl.RawSet(GoToLuaValue(L, k), GoToLuaValue(L, item))
		}

		return tbl
	case nil:
		return lua.LNil
	default:
		return lua.LString(fmt.Sprintf("%v", value))
	}
}

// LuaValueToGo converts a lua.LValue to a corresponding Go value (nil, bool, float64, string, or map).
func LuaValueToGo(value lua.LValue) any {
	if value == lua.LNil {
		return nil
	}

	switch v := value.(type) {
	case lua.LBool:
		return bool(v)
	case lua.LNumber:
		return float64(v)
	case lua.LString:
		return v.String()
	case *lua.LTable:
		// Try to detect if it's an array or a map
		isArray := true

		mp := make(map[any]any)

		if v == nil {
			return mp
		}

		array := make([]any, 0, v.Len())

		v.ForEach(func(key lua.LValue, value lua.LValue) {
			if isArray && key.Type() == lua.LTNumber {
				index := int(key.(lua.LNumber))
				if index == len(array)+1 {
					array = append(array, LuaValueToGo(value))
				} else {
					isArray = false
				}
			} else {
				isArray = false
			}

			mp[LuaValueToGo(key)] = LuaValueToGo(value)
		})

		if isArray {
			return array
		}

		return mp
	default:
		return v.String()
	}
}

// ToGinH converts a map with any key and any value types into a gin.H type with string keys and converted values.
func ToGinH(value any) gin.H {
	result := make(gin.H)

	switch v := value.(type) {
	case map[any]any:
		for key, value := range v {
			keyStr := fmt.Sprintf("%v", key)
			result[keyStr] = ToGinValue(value)
		}
	default:
		return nil
	}

	return result
}

// ToGinValue converts a generic value into a format compatible with Gin, handling maps, slices, and other types.
func ToGinValue(value any) any {
	switch v := value.(type) {
	case map[any]any:
		return ToGinH(v)
	case []any:
		arr := make([]any, len(v))

		for i, item := range v {
			arr[i] = ToGinValue(item)
		}

		return arr
	default:
		return value
	}
}

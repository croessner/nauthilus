package redislib

import (
	"fmt"

	"github.com/croessner/nauthilus/server/global"
	"github.com/redis/go-redis/v9"
	"github.com/yuin/gopher-lua"
)

// ConvertLuaValue converts a Lua value to its corresponding Go type.
// It takes a lua.LValue as input and returns the converted value and an error.
// The function supports converting Lua strings to Go strings, Lua numbers to Go float64,
// Lua booleans to Go bool, and Lua nil to Go nil.
// If the Lua value is of any other type, it returns an error.
func ConvertLuaValue(lValue lua.LValue) (any, error) {
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

// ConvertStringCmd attempts to convert a given *redis.StringCmd value into the specified type.
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
func ConvertStringCmd(value *redis.StringCmd, valType string, L *lua.LState) error {
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

// ConvertGoToLuaValue converts a Go value to a corresponding Lua value.
// It accepts an argument 'value' of type 'any' and returns a value of type 'lua.LValue'.
// If the input is a string, it returns a Lua string value (lua.LString).
// If the input is a float64 or an int, it returns a Lua number value (lua.LNumber).
// If the input is a boolean, it returns a Lua boolean value (lua.LBool).
// For any other types, it converts the value to a string and returns a Lua string value (lua.LString).
// The function uses the fmt.Sprintf method to convert values of any type to a string.
// This function is useful for converting Go values to their equivalent Lua values.
// The function is not safe for concurrent use.
func ConvertGoToLuaValue(value any) lua.LValue {
	switch v := value.(type) {
	case string:
		return lua.LString(v)
	case float64:
		return lua.LNumber(v)
	case int:
		return lua.LNumber(v)
	case bool:
		return lua.LBool(v)
	default:
		return lua.LString(fmt.Sprintf("%v", value))
	}
}

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
	"fmt"
	"math"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/encoding/cborcodec"
	"github.com/croessner/nauthilus/v3/server/lualib/luastack"

	lua "github.com/yuin/gopher-lua"
)

type cborNull struct{}

type cborBytes []byte

// CBORManager manages CBOR encode and decode helpers exposed to Lua.
type CBORManager struct {
	nullValue *lua.LUserData
}

// NewCBORManager creates a Lua CBOR manager with a stable null sentinel.
func NewCBORManager(nullValue *lua.LUserData) *CBORManager {
	return &CBORManager{nullValue: nullValue}
}

// Decode converts a CBOR byte string into Lua values.
func (m *CBORManager) Decode(L *lua.LState) int {
	stack := luastack.NewManager(L)
	payload := []byte(stack.CheckString(1))

	var value any
	if err := cborcodec.Unmarshal(payload, &value); err != nil {
		return stack.PushResults(lua.LNil, lua.LString(err.Error()))
	}

	luaValue, err := m.toLuaValue(L, value)
	if err != nil {
		return stack.PushResults(lua.LNil, lua.LString(err.Error()))
	}

	return stack.PushResults(luaValue, lua.LNil)
}

// Encode converts a Lua value into a CBOR byte string.
func (m *CBORManager) Encode(L *lua.LState) int {
	stack := luastack.NewManager(L)

	value, err := m.fromLuaValue(L.CheckAny(1))
	if err != nil {
		return stack.PushResults(lua.LNil, lua.LString(err.Error()))
	}

	payload, err := cborcodec.Marshal(value)
	if err != nil {
		return stack.PushResults(lua.LNil, lua.LString(err.Error()))
	}

	return stack.PushResults(lua.LString(payload), lua.LNil)
}

// Bytes marks a Lua string for CBOR byte string encoding.
func (m *CBORManager) Bytes(L *lua.LState) int {
	stack := luastack.NewManager(L)
	payload := []byte(stack.CheckString(1))
	userData := L.NewUserData()
	userData.Value = cborBytes(payload)

	return stack.PushResult(userData)
}

func (m *CBORManager) toLuaValue(L *lua.LState, value any) (lua.LValue, error) {
	switch typed := value.(type) {
	case nil:
		return m.nullValue, nil
	case bool:
		return lua.LBool(typed), nil
	case string:
		return lua.LString(typed), nil
	case []byte:
		return lua.LString(typed), nil
	case uint64:
		return lua.LNumber(typed), nil
	case int64:
		return lua.LNumber(typed), nil
	case float64:
		return lua.LNumber(typed), nil
	case []any:
		table := L.NewTable()

		for _, item := range typed {
			luaValue, err := m.toLuaValue(L, item)
			if err != nil {
				return lua.LNil, err
			}

			table.Append(luaValue)
		}

		return table, nil
	case map[any]any:
		return m.mapToLuaTable(L, typed)
	case map[string]any:
		table := L.NewTable()

		for key, item := range typed {
			luaValue, err := m.toLuaValue(L, item)
			if err != nil {
				return lua.LNil, err
			}

			table.RawSetString(key, luaValue)
		}

		return table, nil
	default:
		return lua.LNil, fmt.Errorf("unsupported CBOR value type %T", value)
	}
}

func (m *CBORManager) mapToLuaTable(L *lua.LState, values map[any]any) (lua.LValue, error) {
	table := L.NewTable()

	for key, item := range values {
		luaKey, err := m.toLuaMapKey(key)
		if err != nil {
			return lua.LNil, err
		}

		luaValue, err := m.toLuaValue(L, item)
		if err != nil {
			return lua.LNil, err
		}

		table.RawSet(luaKey, luaValue)
	}

	return table, nil
}

func (m *CBORManager) toLuaMapKey(key any) (lua.LValue, error) {
	switch typed := key.(type) {
	case string:
		return lua.LString(typed), nil
	case uint64:
		return lua.LNumber(typed), nil
	case int64:
		return lua.LNumber(typed), nil
	default:
		return lua.LNil, fmt.Errorf("unsupported CBOR map key type %T", key)
	}
}

func (m *CBORManager) fromLuaValue(value lua.LValue) (any, error) {
	switch typed := value.(type) {
	case lua.LBool:
		return bool(typed), nil
	case lua.LNumber:
		number := float64(typed)
		if math.Trunc(number) == number {
			return int64(number), nil
		}

		return number, nil
	case lua.LString:
		return string(typed), nil
	case *lua.LTable:
		return m.fromLuaTable(typed)
	case *lua.LUserData:
		return m.fromLuaUserData(typed)
	case *lua.LNilType:
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported Lua value type %s", value.Type().String())
	}
}

func (m *CBORManager) fromLuaTable(table *lua.LTable) (any, error) {
	if m.isArrayTable(table) {
		values := make([]any, 0, table.Len())

		for i := 1; i <= table.Len(); i++ {
			value, err := m.fromLuaValue(table.RawGetInt(i))
			if err != nil {
				return nil, err
			}

			values = append(values, value)
		}

		return values, nil
	}

	values := make(map[string]any)
	var convErr error

	table.ForEach(func(key lua.LValue, value lua.LValue) {
		if convErr != nil {
			return
		}

		mapKey, err := luaMapKeyToString(key)
		if err != nil {
			convErr = err

			return
		}

		mapValue, err := m.fromLuaValue(value)
		if err != nil {
			convErr = err

			return
		}

		values[mapKey] = mapValue
	})

	if convErr != nil {
		return nil, convErr
	}

	return values, nil
}

func (m *CBORManager) isArrayTable(table *lua.LTable) bool {
	if table.Len() == 0 {
		return false
	}

	count := 0
	valid := true

	table.ForEach(func(key lua.LValue, _ lua.LValue) {
		if !valid {
			return
		}

		numberKey, ok := key.(lua.LNumber)
		if !ok {
			valid = false

			return
		}

		index := int(numberKey)
		if float64(numberKey) != float64(index) || index < 1 || index > table.Len() {
			valid = false

			return
		}

		count++
	})

	return valid && count == table.Len()
}

func (m *CBORManager) fromLuaUserData(userData *lua.LUserData) (any, error) {
	switch typed := userData.Value.(type) {
	case cborNull:
		return nil, nil
	case cborBytes:
		return []byte(typed), nil
	default:
		return nil, fmt.Errorf("unsupported CBOR userdata type %T", userData.Value)
	}
}

func luaMapKeyToString(key lua.LValue) (string, error) {
	switch typed := key.(type) {
	case lua.LString:
		return string(typed), nil
	case lua.LNumber:
		number := float64(typed)
		if math.Trunc(number) != number {
			return "", fmt.Errorf("CBOR map number key must be an integer: %v", number)
		}

		return fmt.Sprintf("%d", int64(number)), nil
	default:
		return "", fmt.Errorf("unsupported CBOR map key type %s", key.Type().String())
	}
}

// LoaderModCBOR loads CBOR encode and decode helpers into Lua.
func LoaderModCBOR() lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		nullValue := L.NewUserData()
		nullValue.Value = cborNull{}
		manager := NewCBORManager(nullValue)

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnCBORDecode: manager.Decode,
			definitions.LuaFnCBOREncode: manager.Encode,
			definitions.LuaFnCBORBytes:  manager.Bytes,
		})
		mod.RawSetString("null", nullValue)

		return stack.PushResult(mod)
	}
}

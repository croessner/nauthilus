package lualib

import (
	"github.com/croessner/nauthilus/server/util"
	"github.com/yuin/gopher-lua"
)

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

// Loader takes a *lua.LState as input and initializes a new module by setting the functions from `exports`
// into a new lua.LTable. The module table is then pushed onto the top of the stack.
// Finally, it returns 1 to indicate that one value has been returned to Lua.
func Loader(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exports)

	L.Push(mod)

	return 1
}

var exports = map[string]lua.LGFunction{
	"compare_passwords": comparePasswords,
}

// comparePasswords takes two strings, `hashPassword` and `plainPassword`, as input parameters.
// It checks if the number of arguments passed is equal to 2. If not, it returns false and an error message.
// It then uses the `util.ComparePasswords` function to compare the hashed and plain passwords.
// The result of the comparison is pushed onto the Lua stack as a boolean value.
// If there is an error during the comparison, the error message is pushed onto the Lua stack.
// The function returns 2 to indicate that it has pushed 2 values onto the Lua stack.
func comparePasswords(L *lua.LState) int {
	if L.GetTop() != 2 {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("wrong number of arguments"))

		return 2
	}

	hashPassword := L.CheckString(1)
	plainPassword := L.CheckString(2)

	passwordsMatched, err := util.ComparePasswords(hashPassword, plainPassword)

	L.Push(lua.LBool(passwordsMatched))

	if err != nil {
		L.Push(lua.LString(err.Error()))
	} else {
		L.Push(lua.LNil)
	}

	return 2
}

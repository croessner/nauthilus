package lualib

import (
	"github.com/croessner/nauthilus/server/util"
	"github.com/yuin/gopher-lua"
)

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

func Loader(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exports)

	L.Push(mod)

	return 1
}

var exports = map[string]lua.LGFunction{
	"compare_passwords": comparePasswords,
}

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

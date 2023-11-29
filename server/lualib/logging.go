package lualib

import lua "github.com/yuin/gopher-lua"

type CustomLogKeyValue []any

func AddCustomLog(keyval *CustomLogKeyValue) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)
		*keyval = append(*keyval, key)

		luaValue := L.Get(2)

		switch value := luaValue.(type) {
		case lua.LBool:
			*keyval = append(*keyval, bool(value))
		case lua.LNumber:
			*keyval = append(*keyval, float64(value))
		case lua.LString:
			*keyval = append(*keyval, value.String())
		default:
			*keyval = append(*keyval, "UNSUPPORTED")
		}

		return 0
	}
}

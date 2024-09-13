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

package lualib

import lua "github.com/yuin/gopher-lua"

type CustomLogKeyValue []any

// Set appends a key-value pair to the CustomLogKeyValue slice. If the receiver pointer c is nil, no action is taken.
// The key is appended to the slice followed by the value.
func (c *CustomLogKeyValue) Set(key string, value any) {
	if c == nil {
		return
	}

	*c = append(*c, key)
	*c = append(*c, value)
}

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

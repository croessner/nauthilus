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

package redislib

import (
	"fmt"
	"testing"

	"github.com/yuin/gopher-lua"
)

// checkLuaError is a helper function for testing Lua code that involves error handling.
// It compares the actual error (`gotErr`) with the expected error (`expectedErr`) and reports any differences.
// If `expectedErr` is not `lua.LNil`, it expects `gotErr` to be not `lua.LNil` and not `nil`.
// If `expectedErr` is `lua.LNil`, it expects `gotErr` to be `lua.LNil` or `nil`.
// If there is a mismatch between the types or string representations of `gotErr` and `expectedErr`,
// an error is reported using `t.Errorf`.
// This function is intended to be used in conjunction with the `testing.T` package.
func checkLuaError(t *testing.T, gotErr lua.LValue, expectedErr lua.LValue) {
	if expectedErr != lua.LNil {
		if gotErr == lua.LNil || gotErr == nil {
			t.Errorf("expected error but 'err' is nil")
		} else if gotErr.Type() != expectedErr.Type() || gotErr.String() != expectedErr.String() {
			t.Errorf("gotErr = %v, want %v", gotErr.String(), expectedErr.String())
		}
	} else if gotErr != lua.LNil && gotErr != nil {
		t.Errorf("expected no error but got 'err' = %v", gotErr.String())
	}
}

// formatLuaValue formats a Lua value as a string. It takes a value of type `any`
// and returns a string representation of the value. The function uses a switch
// statement to handle different value types, such as string, integer, float,
// boolean, and `lua.LValue`. For string values, it wraps the value in double quotes.
// For other value types, it uses the `fmt.Sprintf` function to convert the value
// to a string. If the value is of type `lua.LValue`, it calls the `String` method
// on the value object to get its string representation. If the value is of an
// unrecognized type, it returns the string "nil".
//
// Parameters:
// - val (any): The Lua value to format as a string.
//
// Returns:
// - string: The string representation of the Lua value.
func formatLuaValue(val any) string {
	switch v := val.(type) {
	case string:
		return fmt.Sprintf(`"%s"`, v)
	case int, int64, float64, bool:
		return fmt.Sprintf("%v", v)
	case lua.LValue:
		return v.String()
	default:
		return "nil"
	}
}

// createLuaTable creates a new Lua table using the provided values. Each value in the
// `values` slice is converted to a Lua string (LString) and appended to the table. The
// function returns a pointer to the created table.
func createLuaTable(values []string) *lua.LTable {
	tbl := &lua.LTable{}

	for _, val := range values {
		tbl.Append(lua.LString(val))
	}

	return tbl
}

// luaTablesAreEqual checks if two LTables are equal. It returns true if they have the same length and the same
// values. It returns false if either table is nil, if the tables have different lengths, or if they have different
// values.
func luaTablesAreEqual(tbl1, tbl2 *lua.LTable) bool {
	if tbl1 == nil || tbl2 == nil {
		return tbl1 == tbl2
	}

	if tbl1.Len() != tbl2.Len() {
		return false
	}

	tbl2Map := make(map[string]struct{}, tbl2.Len())

	tbl2.ForEach(func(_, v lua.LValue) {
		tbl2Map[v.String()] = struct{}{}
	})

	equal := true

	tbl1.ForEach(func(_, v lua.LValue) {
		if _, exists := tbl2Map[v.String()]; !exists {
			equal = false
		}
	})

	return equal
}

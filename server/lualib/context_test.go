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

import (
	"testing"

	"github.com/croessner/nauthilus/server/lualib/convert"
	lua "github.com/yuin/gopher-lua"
)

func TestContextSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     lua.LValue
		value   lua.LValue
		wantErr bool
	}{
		{
			name:    "String",
			key:     lua.LString("key"),
			value:   lua.LString("value"),
			wantErr: false,
		},
		{
			name:    "Bool",
			key:     lua.LString("key"),
			value:   lua.LBool(true),
			wantErr: false,
		},
		{
			name:    "Number",
			key:     lua.LString("key"),
			value:   lua.LNumber(123),
			wantErr: false,
		},
		{
			name:    "Table",
			key:     lua.LString("key"),
			value:   &lua.LTable{},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := NewContext()
			L := lua.NewState()

			defer L.Close()

			L.Push(tc.key)
			L.Push(tc.value)

			ContextSet(ctx)(L)

			val := convert.GoToLuaValue(L, ctx.Get(lua.LVAsString(tc.key)))

			if val.Type() != tc.value.Type() && val.String() != tc.value.String() {
				if !tc.wantErr {
					t.Errorf("ContextSet(%v) value mismatch; got %v, want %v", tc.name, val, tc.value)
				}
			}
		})
	}
}

func TestContextGet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		key   lua.LValue
		value lua.LValue
	}{
		{
			name:  "Existing String",
			key:   lua.LString("key"),
			value: lua.LString("value"),
		},
		{
			name:  "Existing Bool",
			key:   lua.LString("bkey"),
			value: lua.LBool(true),
		},
		{
			name:  "Existing Number",
			key:   lua.LString("nkey"),
			value: lua.LNumber(123),
		},
		{
			name:  "Non-existent Key",
			key:   lua.LString("nokey"),
			value: lua.LNil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContext()
			L := lua.NewState()

			defer L.Close()

			if tt.name != "Non-existent Key" {
				L.Push(tt.key)
				L.Push(tt.value)

				ContextSet(ctx)(L)
			}

			L.Push(tt.key)

			ContextGet(ctx)(L)

			val := L.Get(-1)
			if val != tt.value {
				t.Errorf("ContextGet(%v): got %v, want %v", tt.name, val, tt.value)
			}
		})
	}
}

func TestContextDelete(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		key               lua.LValue
		preSets, postSets map[lua.LValue]lua.LValue
	}{
		{
			name: "Existing Key",
			key:  lua.LString("key"),
			preSets: map[lua.LValue]lua.LValue{
				lua.LString("key"): lua.LString("value"),
			},
			postSets: map[lua.LValue]lua.LValue{},
		},
		{
			name:     "Non-Existing Key",
			key:      lua.LString("key"),
			preSets:  map[lua.LValue]lua.LValue{},
			postSets: map[lua.LValue]lua.LValue{},
		},
		{
			name: "Mixed Keys",
			key:  lua.LString("key1"),
			preSets: map[lua.LValue]lua.LValue{
				lua.LString("key1"): lua.LString("value1"),
				lua.LString("key2"): lua.LString("value2"),
			},
			postSets: map[lua.LValue]lua.LValue{
				lua.LString("key2"): lua.LString("value2"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContext()
			L := lua.NewState()

			defer L.Close()

			for key, value := range tt.preSets {
				ctx.Set(lua.LVAsString(key), value)
			}

			L.Push(tt.key)

			ContextDelete(ctx)(L)

			for key, expectedValue := range tt.postSets {
				val := ctx.Get(lua.LVAsString(key)).(lua.LValue)
				if val.Type() != expectedValue.Type() && val.String() != expectedValue.String() {
					t.Errorf("ContextGet(%v): got %v, want %v", key, val, expectedValue)
				}
			}
		})
	}
}

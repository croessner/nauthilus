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
		{
			name:    "Nil",
			key:     lua.LNil,
			value:   lua.LNil,
			wantErr: true,
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

			val := convert.GoToLuaValue(L, ctx.Get(tc.key))

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

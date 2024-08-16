package lualib

import (
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func TestValidatePassword(t *testing.T) {
	// Define the test cases
	tests := []struct {
		name     string
		password string
		table    *lua.LTable
		want     bool
	}{
		{
			name:     "WeakPassword",
			password: "weak",
			table: func() *lua.LTable {
				tbl := lua.LTable{}

				tbl.RawSetString("min_length", lua.LNumber(8))
				tbl.RawSetString("min_upper", lua.LNumber(1))
				tbl.RawSetString("min_lower", lua.LNumber(1))
				tbl.RawSetString("min_number", lua.LNumber(1))
				tbl.RawSetString("min_special", lua.LNumber(1))

				return &tbl
			}(),
			want: false,
		},
		{
			name:     "StrongPassword",
			password: "Strong1@",
			table: func() *lua.LTable {
				tbl := lua.LTable{}

				tbl.RawSetString("min_length", lua.LNumber(8))
				tbl.RawSetString("min_upper", lua.LNumber(1))
				tbl.RawSetString("min_lower", lua.LNumber(1))
				tbl.RawSetString("min_number", lua.LNumber(1))
				tbl.RawSetString("min_special", lua.LNumber(1))

				return &tbl
			}(),
			want: true,
		},
		{
			name:     "PasswordWithoutNumber",
			password: "Strong@",
			table: func() *lua.LTable {
				tbl := lua.LTable{}

				tbl.RawSetString("min_length", lua.LNumber(8))
				tbl.RawSetString("min_upper", lua.LNumber(1))
				tbl.RawSetString("min_lower", lua.LNumber(1))
				tbl.RawSetString("min_number", lua.LNumber(1))
				tbl.RawSetString("min_special", lua.LNumber(1))

				return &tbl
			}(),
			want: false,
		},
		{
			name:     "PasswordWithoutSpecialChar",
			password: "Strong1",
			table: func() *lua.LTable {
				tbl := lua.LTable{}

				tbl.RawSetString("min_length", lua.LNumber(8))
				tbl.RawSetString("min_upper", lua.LNumber(1))
				tbl.RawSetString("min_lower", lua.LNumber(1))
				tbl.RawSetString("min_number", lua.LNumber(1))
				tbl.RawSetString("min_special", lua.LNumber(1))

				return &tbl
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			L := lua.NewState()

			defer L.Close()

			L.SetGlobal("passwordPolicy", tt.table)
			L.Push(tt.table)
			L.Push(lua.LString(tt.password))
			validatePassword(L)

			got := L.ToBool(-1)
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetCountryName(t *testing.T) {
	// Define the test cases
	tests := []struct {
		name    string
		isoCode string
		want    string
	}{
		{
			name:    "TestWithValidISOCodeUS",
			isoCode: "US",
			want:    "United States",
		},
		{
			name:    "TestWithValidISOCodeGB",
			isoCode: "GB",
			want:    "United Kingdom",
		},
		{
			name:    "TestWithInvalidISOCodeXYZ",
			isoCode: "XYZ",
			want:    "Unknown",
		},
		{
			name:    "TestWithEmptyISOCode",
			isoCode: "",
			want:    "Unknown",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			L := lua.NewState()

			defer L.Close()

			L.Push(lua.LString(tt.isoCode))
			getCountryName(L)

			got := L.ToString(-1)
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

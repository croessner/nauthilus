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

func TestWaitRandom(t *testing.T) {
	tests := []struct {
		name    string
		minWait lua.LNumber
		maxWait lua.LNumber
		err     bool
	}{
		{
			name:    "TestValidRange",
			minWait: 100,
			maxWait: 500,
			err:     false,
		},
		{
			name:    "TestNegativeMinWait",
			minWait: -100,
			maxWait: 500,
			err:     true,
		},
		{
			name:    "TestNegativeMaxWait",
			minWait: 100,
			maxWait: -500,
			err:     true,
		},
		{
			name:    "TestMinWaitGreaterThanMaxWait",
			minWait: 1000,
			maxWait: 500,
			err:     true,
		},
		{
			name:    "TestEqualMinAndMaxWait",
			minWait: 500,
			maxWait: 500,
			err:     true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			L := lua.NewState()

			defer L.Close()

			L.Push(tt.minWait)
			L.Push(tt.maxWait)
			waitRandom(L)

			hasError := L.Get(-1) == lua.LNil
			if hasError != tt.err {
				t.Errorf("Unexpected result, got error: %v, want error: %v", hasError, tt.err)
			}

			if !tt.err {
				value := L.ToInt(-1)

				if value < int(tt.minWait) || value > int(tt.maxWait) {
					t.Errorf("Returned value is outside the given range. Got: %d, Range: (%d - %d)", value, tt.minWait, tt.maxWait)
				}
			}
		})
	}
}

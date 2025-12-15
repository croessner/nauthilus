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

package definitions

import "testing"

func TestLuaAction_String(t *testing.T) {
	tests := []struct {
		name string
		a    LuaAction
		want string
	}{
		{name: "none", a: LuaActionNone, want: ""},
		{name: "brute_force", a: LuaActionBruteForce, want: LuaActionBruteForceName},
		{name: "rbl", a: LuaActionRBL, want: LuaActionRBLName},
		{name: "tls_encryption", a: LuaActionTLS, want: LuaActionTLSName},
		{name: "relay_domains", a: LuaActionRelayDomains, want: LuaActionRelayDomainsName},
		{name: "lua", a: LuaActionLua, want: LuaActionLuaName},
		{name: "post", a: LuaActionPost, want: LuaActionPostName},
		{name: "unknown", a: LuaAction(255), want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.String(); got != tt.want {
				t.Fatalf("LuaAction(%d).String() = %q, want %q", tt.a, got, tt.want)
			}
		})
	}
}

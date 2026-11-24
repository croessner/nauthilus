// Copyright (C) 2026 Christian Rößner
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

package core

import (
	"slices"
	"testing"

	"github.com/croessner/nauthilus/v4/server/lualib"
)

// TestAccountsFromLuaBackendResultKeepsLuaArrayOrder verifies that list-accounts keeps the order of the Lua
// array returned by nauthilus_backend_list_accounts and drops later duplicates.
func TestAccountsFromLuaBackendResultKeepsLuaArrayOrder(t *testing.T) {
	result := &lualib.LuaBackendResult{Attributes: map[any]any{
		1: "zeta@example.test",
		2: "alpha@example.test",
		3: "zeta@example.test",
		4: "mid@example.test",
		5: 42,
		6: "beta@example.test",
	}}
	want := AccountList{"zeta@example.test", "alpha@example.test", "mid@example.test", "beta@example.test"}

	// Map iteration is randomized, so a set-based conversion fails within a few rounds.
	for round := 0; round < 50; round++ {
		if got := accountsFromLuaBackendResult(result); !slices.Equal(got, want) {
			t.Fatalf("round %d: accounts = %v, want %v", round, got, want)
		}
	}
}

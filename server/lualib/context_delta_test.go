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

import "testing"

func TestContextDeltaAppliesOnlyChanges(t *testing.T) {
	ctx := NewContext()
	ctx.Set("keep", "base")
	ctx.Set("delete", "gone")

	local := ctx.Clone()
	before := local.Snapshot()
	local.Set("new", "value")
	local.Delete("delete")

	delta := local.Diff(before)

	unchanged := ctx.Clone()
	unchangedDelta := unchanged.Diff(unchanged.Snapshot())

	ctx.ApplyDelta(delta)
	ctx.ApplyDelta(unchangedDelta)

	if got := ctx.Get("keep"); got != "base" {
		t.Fatalf("expected keep=base, got %v", got)
	}

	if got := ctx.Get("new"); got != "value" {
		t.Fatalf("expected new=value, got %v", got)
	}

	if got := ctx.Get("delete"); got != nil {
		t.Fatalf("expected delete to be removed, got %v", got)
	}
}

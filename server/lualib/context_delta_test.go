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

func TestContextDeltaMergesSharedMapValues(t *testing.T) {
	ctx := NewContext()

	first := ctx.Clone()
	firstBefore := first.Snapshot()
	first.Set("rt", map[any]any{
		"first": true,
		"nested": map[any]any{
			"first": "value",
		},
	})

	second := ctx.Clone()
	secondBefore := second.Snapshot()
	second.Set("rt", map[any]any{
		"second": true,
		"nested": map[any]any{
			"second": "value",
		},
	})

	ctx.ApplyDelta(first.Diff(firstBefore))
	ctx.ApplyDelta(second.Diff(secondBefore))

	rt, ok := ctx.Get("rt").(map[any]any)
	if !ok {
		t.Fatalf("expected rt map, got %T", ctx.Get("rt"))
	}

	if got := rt["first"]; got != true {
		t.Fatalf("expected first=true, got %v", got)
	}

	if got := rt["second"]; got != true {
		t.Fatalf("expected second=true, got %v", got)
	}

	nested, ok := rt["nested"].(map[any]any)
	if !ok {
		t.Fatalf("expected nested map, got %T", rt["nested"])
	}

	if got := nested["first"]; got != "value" {
		t.Fatalf("expected nested.first=value, got %v", got)
	}

	if got := nested["second"]; got != "value" {
		t.Fatalf("expected nested.second=value, got %v", got)
	}
}

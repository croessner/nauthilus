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

package windowsource

import (
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportops"
)

// assertTiles checks that spans cover window exactly, oldest first, without gaps or overlap, and none longer than
// longest.
func assertTiles(t *testing.T, spans []supportops.Window, window supportops.Window, longest time.Duration) {
	t.Helper()

	if len(spans) == 0 || !spans[0].From.Equal(window.From) || !spans[len(spans)-1].Until.Equal(window.Until) {
		t.Fatalf("%v do not cover %v", spans, window)
	}

	for index, span := range spans {
		if !span.From.Before(span.Until) || span.Until.Sub(span.From) > longest {
			t.Fatalf("span %d = %v, longest %v", index, span, longest)
		}

		if index > 0 && !span.From.Equal(spans[index-1].Until) {
			t.Fatalf("span %d starts at %v after %v", index, span.From, spans[index-1].Until)
		}
	}
}

// TestWindowsTileExactly pins the window parts and the bucket grid: both cover the window exactly with millisecond
// bounds, the parts never exceed the part length, and every bucket but the first spans the same whole seconds.
func TestWindowsTileExactly(t *testing.T) {
	base := time.Date(2026, time.November, 25, 15, 38, 17, 250_000_000, time.UTC)

	for _, length := range []time.Duration{time.Millisecond, 90 * time.Second, time.Hour, 12*time.Hour + 125*time.Millisecond} {
		window := supportops.Window{From: base, Until: base.Add(length)}

		assertTiles(t, SplitWindow(window, time.Hour), window, time.Hour)

		grid := BucketGrid(window, 12)
		assertTiles(t, grid, window, grid[len(grid)-1].Until.Sub(grid[len(grid)-1].From))

		if len(grid) > 12 {
			t.Fatalf("%v: %d buckets", length, len(grid))
		}

		for index := 1; index < len(grid); index++ {
			if width := grid[index].Until.Sub(grid[index].From); width%time.Second != 0 || width != grid[1].Until.Sub(grid[1].From) {
				t.Fatalf("%v: bucket %d spans %v", length, index, width)
			}
		}
	}
}

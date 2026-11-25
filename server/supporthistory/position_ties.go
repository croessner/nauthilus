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

package supporthistory

// Inner-list continuations page ordered items by a keyset position that is not unique: legacy rows without event id
// can share their whole position. A cursor therefore carries the position of the last listed item together with the
// number of items at exactly that position listed so far (its ties). A continuation reads from the position
// inclusively, in the same deterministic order, and steps over those ties, so every item is listed exactly once.

// listedTies returns the ties of a non-empty ordered page: the items at its end that share the whole position of
// its last item, plus the ties listed before the page when that position is the one the page continued from.
func listedTies[T any](page []T, same func(a, b T) bool, continued func(T) bool, earlier int) int {
	last := page[len(page)-1]
	ties := 0

	for index := len(page) - 1; index >= 0 && same(page[index], last); index-- {
		ties++
	}

	if continued(last) {
		ties += earlier
	}

	return ties
}

// skipListed drops the leading items of an inclusive continuation read that sit at the continued position and were
// already listed: at most ties of them.
func skipListed[T any](items []T, ties int, continued func(T) bool) []T {
	skip := 0
	for skip < len(items) && skip < ties && continued(items[skip]) {
		skip++
	}

	return items[skip:]
}

// cursorTies validates the ties of a decoded cursor. A cursor always lists at least its own last item; more ties than
// MaxEqualPositionRows are refused as too broad, so a continuation never silently skips part of a group.
func cursorTies(ties int64) (int, *Error) {
	if ties <= 0 {
		return 0, invalid(CodeInvalidCursor)
	}

	if ties > MaxEqualPositionRows {
		return 0, invalid(CodeQueryTooBroad)
	}

	return int(ties), nil
}

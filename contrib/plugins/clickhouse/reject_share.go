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

package main

import "strings"

// bruteForceRejectOutcomeMarker is the outcome marker of requests rejected because of an active brute-force ban.
const bruteForceRejectOutcomeMarker = "auth.outcome.brute_force_reject"

// bruteForceRejectRowField is the exact compact JSON member that encodeRequestRow writes for such a request.
const bruteForceRejectRowField = `"outcome_marker":"` + bruteForceRejectOutcomeMarker + `"`

// isBruteForceRejectRow classifies one buffered login row. Buffered rows stay plain encoded strings so they survive
// requeues and plugin reloads unchanged; the class is therefore derived from the row itself, never stored beside it.
func isBruteForceRejectRow(row any) bool {
	switch typed := row.(type) {
	case string:
		return strings.Contains(typed, bruteForceRejectRowField)
	case []byte:
		return strings.Contains(string(typed), bruteForceRejectRowField)
	default:
		return false
	}
}

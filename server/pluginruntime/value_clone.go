// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import "slices"

// cloneStringSliceMap deep-copies string-slice maps while preserving slice nilness.
func cloneStringSliceMap(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return map[string][]string{}
	}

	cloned := make(map[string][]string, len(values))
	for key, entries := range values {
		cloned[key] = slices.Clone(entries)
	}

	return cloned
}

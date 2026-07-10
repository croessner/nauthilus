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

import "testing"

func TestCloneStringSliceMapPreservesShapeAndOwnership(t *testing.T) {
	values := []string{"one", "two"}
	source := map[string][]string{
		"nil":    nil,
		"empty":  {},
		"values": values,
	}

	cloned := cloneStringSliceMap(source)
	if cloned == nil {
		t.Fatal("cloneStringSliceMap() returned a nil map")
	}

	if cloned["nil"] != nil {
		t.Fatalf("nil slice clone = %#v, want nil", cloned["nil"])
	}

	if cloned["empty"] == nil || len(cloned["empty"]) != 0 {
		t.Fatalf("empty slice clone = %#v, want non-nil empty slice", cloned["empty"])
	}

	source["values"][0] = "source-mutated"
	cloned["values"][1] = "clone-mutated"
	source["source-only"] = []string{"source"}
	cloned["clone-only"] = []string{"clone"}

	if cloned["values"][0] != "one" || source["values"][1] != "two" {
		t.Fatalf("slice storage is shared: source=%#v clone=%#v", source["values"], cloned["values"])
	}

	if _, ok := cloned["source-only"]; ok {
		t.Fatal("source map mutation reached clone")
	}

	if _, ok := source["clone-only"]; ok {
		t.Fatal("clone map mutation reached source")
	}

	if empty := cloneStringSliceMap(nil); empty == nil || len(empty) != 0 {
		t.Fatalf("nil map clone = %#v, want non-nil empty map", empty)
	}
}

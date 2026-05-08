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

package runtime

import (
	"testing"

	"github.com/croessner/nauthilus/server/policy"
	"github.com/croessner/nauthilus/server/policy/registry"
)

func TestSnapshotStorePublishesDetachedCopies(t *testing.T) {
	original := &Snapshot{
		Generation: 3,
		AttributeRegistry: map[string]registry.AttributeDefinition{
			"request.operation": {
				ID:         "request.operation",
				Stage:      policy.StagePreAuth,
				Operations: []policy.Operation{policy.OperationAuthenticate},
				Type:       registry.AttributeTypeString,
			},
		},
	}

	store := NewSnapshotStore(original)
	original.AttributeRegistry["request.operation"] = registry.AttributeDefinition{ID: "changed"}

	active := store.Active()
	if active.AttributeRegistry["request.operation"].ID != "request.operation" {
		t.Fatalf("active registry was mutated: %#v", active.AttributeRegistry["request.operation"])
	}

	active.AttributeRegistry["request.operation"] = registry.AttributeDefinition{ID: "mutated"}

	next := store.Active()
	if next.AttributeRegistry["request.operation"].ID != "request.operation" {
		t.Fatalf("store returned mutable active snapshot: %#v", next.AttributeRegistry["request.operation"])
	}
}

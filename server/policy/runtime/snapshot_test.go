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

import "testing"

func TestSnapshotStoreKeepsPreviousSnapshotOnRejectedActivation(t *testing.T) {
	store := NewSnapshotStore(&Snapshot{Generation: 7})

	if err := store.Activate(nil); err == nil {
		t.Fatal("nil snapshot activation succeeded")
	}

	active := store.Active()
	if active == nil {
		t.Fatal("active snapshot is nil")
	}

	if active.Generation != 7 {
		t.Fatalf("generation = %d, want 7", active.Generation)
	}
}

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

// Package runtime contains policy snapshot activation primitives.
package runtime

import (
	"errors"
	"sync/atomic"
	"time"
)

// ErrNilSnapshot is returned when activation receives no candidate snapshot.
var ErrNilSnapshot = errors.New("policy snapshot is nil")

// Snapshot is the immutable request-time policy runtime handle.
type Snapshot struct {
	CreatedAt  time.Time
	Generation uint64
}

// Clone returns a detached copy of the snapshot value.
func (s *Snapshot) Clone() *Snapshot {
	if s == nil {
		return nil
	}

	cloned := *s

	return &cloned
}

// SnapshotStore publishes complete snapshots atomically.
type SnapshotStore struct {
	active atomic.Pointer[Snapshot]
}

// NewSnapshotStore returns a store initialized with the provided snapshot.
func NewSnapshotStore(initial *Snapshot) *SnapshotStore {
	store := &SnapshotStore{}
	if initial != nil {
		store.active.Store(initial.Clone())
	}

	return store
}

// Active returns the currently active snapshot.
func (s *SnapshotStore) Active() *Snapshot {
	return s.active.Load().Clone()
}

// Activate publishes a complete candidate snapshot.
func (s *SnapshotStore) Activate(candidate *Snapshot) error {
	if candidate == nil {
		return ErrNilSnapshot
	}

	s.active.Store(candidate.Clone())

	return nil
}

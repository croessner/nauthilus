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

package opsfx

import "sync"

// Gate serializes operational actions like reload, restart, and shutdown.
//
// It is intentionally small: the goal is to make it easy to reason about
// mutual exclusion across managers.
type Gate struct {
	mu sync.Mutex
}

// NewGate constructs a new Gate.
func NewGate() *Gate {
	return &Gate{}
}

// WithLock executes fn while holding the gate lock.
//
// It is used to ensure that operational actions like reload/restart do not overlap.
func (g *Gate) WithLock(fn func() error) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	return fn()
}

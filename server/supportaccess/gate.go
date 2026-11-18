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

package supportaccess

import (
	"context"
	"sync"
	"time"
)

// Gate bounds concurrent operations globally and per principal identity. A service owns its gate, so a second
// transport cannot bypass it; a transport may add its own, stricter gate in front.
type Gate struct {
	slots     chan struct{}
	perCaller map[string]int
	mu        sync.Mutex
	wait      time.Duration
	limit     int
}

// NewGate creates a gate with global and per-identity bounds and the longest wait for a free global slot.
// Non-positive bounds are raised to one.
func NewGate(global, perIdentity int, wait time.Duration) *Gate {
	return &Gate{slots: make(chan struct{}, max(global, 1)), perCaller: map[string]int{}, limit: max(perIdentity, 1),
		wait: max(wait, 0)}
}

// Acquire takes a slot for identity and returns its release function. It reports false, without waiting, when the
// identity already holds its share, and after the wait or cancellation when the global bound stays full.
func (g *Gate) Acquire(ctx context.Context, identity string) (func(), bool) {
	g.mu.Lock()
	if g.perCaller[identity] >= g.limit {
		g.mu.Unlock()

		return nil, false
	}

	g.perCaller[identity]++
	g.mu.Unlock()

	timer := time.NewTimer(g.wait)
	defer timer.Stop()

	select {
	case g.slots <- struct{}{}:
		var once sync.Once

		return func() { once.Do(func() { g.release(identity) }) }, true
	case <-timer.C:
	case <-ctx.Done():
	}

	g.leave(identity)

	return nil, false
}

// release frees the global slot and the identity share.
func (g *Gate) release(identity string) {
	<-g.slots
	g.leave(identity)
}

// leave frees the identity share.
func (g *Gate) leave(identity string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.perCaller[identity]--; g.perCaller[identity] <= 0 {
		delete(g.perCaller, identity)
	}
}

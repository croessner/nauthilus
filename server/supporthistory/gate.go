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

import (
	"context"
	"sync"
	"time"
)

// gate bounds concurrent history operations globally and per caller identity. It is owned by the service, so a
// second transport cannot bypass it.
type gate struct {
	slots     chan struct{}
	perCaller map[string]int
	mu        sync.Mutex
	limit     int
}

// newGate creates a gate with the shared bounds.
func newGate(global, perCaller int) *gate {
	return &gate{slots: make(chan struct{}, global), perCaller: map[string]int{}, limit: perCaller}
}

// acquire waits briefly for a slot and returns its release function; it fails with HISTORY_BUSY.
func (g *gate) acquire(ctx context.Context, identity string) (func(), *Error) {
	g.mu.Lock()
	if g.perCaller[identity] >= g.limit {
		g.mu.Unlock()

		return nil, newError(CodeBusy, nil)
	}

	g.perCaller[identity]++
	g.mu.Unlock()

	timer := time.NewTimer(gateWait)
	defer timer.Stop()

	select {
	case g.slots <- struct{}{}:
		return func() { g.release(identity) }, nil
	case <-timer.C:
	case <-ctx.Done():
	}

	g.leave(identity)

	return nil, newError(CodeBusy, nil)
}

// release frees the global slot and the caller share.
func (g *gate) release(identity string) {
	<-g.slots
	g.leave(identity)
}

// leave frees the caller share.
func (g *gate) leave(identity string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.perCaller[identity]--; g.perCaller[identity] <= 0 {
		delete(g.perCaller, identity)
	}
}

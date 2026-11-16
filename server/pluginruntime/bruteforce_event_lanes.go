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

package pluginruntime

import (
	"context"
	"errors"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/bruteforce"
)

const (
	// DefaultBruteForceHitQueueCapacity bounds ban hit events per process; hits never share the counted budget.
	DefaultBruteForceHitQueueCapacity = 4096

	authEventLaneBruteForceCounted = "bruteforce_counted"
	authEventLaneBruteForceHits    = "bruteforce_hits"
)

// bruteForceEventLanes separates rare lifecycle transitions, counted contributions, and ban hits into independent
// bounded queues, so a flood of one kind can never evict another.
type bruteForceEventLanes struct {
	lifecycle *BruteForceEventDispatcher
	counted   *BruteForceEventDispatcher
	hits      *BruteForceEventDispatcher
}

// newBruteForceEventLanes starts the lanes for registered brute-force sinks, or returns nil without sinks.
func newBruteForceEventLanes(runner *Runner) *bruteForceEventLanes {
	lanes := &bruteForceEventLanes{
		lifecycle: NewBruteForceEventDispatcher(runner, DefaultBruteForceLifecycleQueueCapacity,
			authEventLaneBruteForceLifecycle),
		counted: NewBruteForceEventDispatcher(runner, DefaultBruteForceCountedQueueCapacity, authEventLaneBruteForceCounted),
		hits:    NewBruteForceEventDispatcher(runner, DefaultBruteForceHitQueueCapacity, authEventLaneBruteForceHits),
	}

	if lanes.lifecycle == nil {
		return nil
	}

	lanes.lifecycle.Start()
	lanes.counted.Start()
	lanes.hits.Start()

	return lanes
}

// route returns the lane of one event kind.
func (l *bruteForceEventLanes) route(kind pluginapi.BruteForceEventKind) *BruteForceEventDispatcher {
	if l == nil {
		return nil
	}

	switch {
	case kind.Lifecycle():
		return l.lifecycle
	case kind == pluginapi.BruteForceBanHit:
		return l.hits
	default:
		return l.counted
	}
}

// stop drains every lane within ctx.
func (l *bruteForceEventLanes) stop(ctx context.Context) error {
	if l == nil {
		return nil
	}

	return errors.Join(l.lifecycle.Stop(ctx), l.counted.Stop(ctx), l.hits.Stop(ctx))
}

// EmitBruteForceEvent hands one brute-force event to its lane without blocking the caller. It is a no-op when no sink
// is registered or the runner is not started.
func (r *Runner) EmitBruteForceEvent(ctx context.Context, event pluginapi.BruteForceEvent) {
	if r == nil {
		return
	}

	r.bruteForceEvents.Load().route(event.Kind).EmitAuthEvent(ctx, event)
}

// BruteForceEventEmitter returns the runner as brute-force event emitter when a brute-force sink is registered, and
// nil otherwise, so the counting path builds no events nobody receives.
func BruteForceEventEmitter(r *Runner) bruteforce.EventEmitter {
	if r == nil || r.registry == nil || len(r.registry.BruteForceEventSinks()) == 0 {
		return nil
	}

	return r
}

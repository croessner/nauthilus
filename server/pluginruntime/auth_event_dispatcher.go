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
	"sync"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/stats"
)

const (
	// DefaultAuthEventQueueCapacity bounds host step events waiting for delivery per process.
	DefaultAuthEventQueueCapacity = 1024

	// DefaultBruteForceLifecycleQueueCapacity bounds rare ban lifecycle events per process.
	DefaultBruteForceLifecycleQueueCapacity = 1024

	// DefaultBruteForceCountedQueueCapacity bounds counted and tolerated brute-force events per process.
	DefaultBruteForceCountedQueueCapacity = 8192

	authEventLaneMFA                 = "mfa"
	authEventLaneBruteForceLifecycle = "bruteforce_lifecycle"

	authEventDeliveryTimeout = 2 * time.Second
	authEventOutcomeQueued   = "queued"
	authEventOutcomeDropped  = "dropped"
	authEventOutcomeFailed   = "failed"
	authEventOutcomeDelivery = "delivered"
)

// authEventCounter records one bounded delivery outcome.
type authEventCounter func(outcome string)

// AuthEventDispatcher delivers host-observed step events to registered sinks from one bounded queue.
type AuthEventDispatcher = eventDispatcher[pluginapi.AuthEvent]

// BruteForceEventDispatcher delivers brute-force events of one lane to registered sinks from one bounded queue.
type BruteForceEventDispatcher = eventDispatcher[pluginapi.BruteForceEvent]

// eventDispatcher delivers host events of one lane to registered sinks from one bounded queue. Emitting never blocks
// the caller: a full or stopped dispatcher drops the event and counts it.
type eventDispatcher[E any] struct {
	deliver  func(context.Context, string, E) error
	count    authEventCounter
	queue    chan E
	stop     chan struct{}
	done     chan struct{}
	sinks    []string
	mu       sync.RWMutex
	stopOnce sync.Once
	started  bool
	stopped  bool
}

// NewAuthEventDispatcher returns a dispatcher for the step-event sinks registered with runner. It returns nil when no
// sink is registered, which callers treat as a disabled event path.
func NewAuthEventDispatcher(runner *Runner, capacity int) *AuthEventDispatcher {
	if runner == nil || runner.registry == nil {
		return nil
	}

	return newLaneDispatcher(sinkNames(runner.registry.AuthEventSinks()), capacity, runner.deliverAuthEvent,
		laneCounter(authEventLaneMFA))
}

// NewBruteForceEventDispatcher returns a dispatcher of one brute-force lane, or nil without registered sinks.
func NewBruteForceEventDispatcher(runner *Runner, capacity int, lane string) *BruteForceEventDispatcher {
	if runner == nil || runner.registry == nil {
		return nil
	}

	return newLaneDispatcher(sinkNames(runner.registry.BruteForceEventSinks()), capacity, runner.deliverBruteForceEvent,
		laneCounter(lane))
}

// sinkNames returns the qualified names of registered sink components.
func sinkNames(components []pluginregistry.Component) []string {
	sinks := make([]string, 0, len(components))
	for _, component := range components {
		sinks = append(sinks, component.QualifiedName)
	}

	return sinks
}

// newLaneDispatcher returns a dispatcher for the given sinks, or nil when no sink is registered.
func newLaneDispatcher[E any](
	sinks []string,
	capacity int,
	deliver func(context.Context, string, E) error,
	count authEventCounter,
) *eventDispatcher[E] {
	if len(sinks) == 0 {
		return nil
	}

	return newEventDispatcher(sinks, capacity, deliver, count)
}

// newAuthEventDispatcher builds an MFA-lane dispatcher around explicit delivery and metric functions.
func newAuthEventDispatcher(
	sinks []string,
	capacity int,
	deliver func(context.Context, string, pluginapi.AuthEvent) error,
	count authEventCounter,
) *AuthEventDispatcher {
	return newEventDispatcher(sinks, capacity, deliver, count)
}

// newEventDispatcher builds a dispatcher around explicit delivery and metric functions.
func newEventDispatcher[E any](
	sinks []string,
	capacity int,
	deliver func(context.Context, string, E) error,
	count authEventCounter,
) *eventDispatcher[E] {
	if capacity <= 0 {
		capacity = DefaultAuthEventQueueCapacity
	}

	return &eventDispatcher[E]{
		deliver: deliver,
		count:   count,
		queue:   make(chan E, capacity),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		sinks:   sinks,
	}
}

// Start launches the single delivery goroutine once.
func (d *eventDispatcher[E]) Start() {
	if d == nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.started || d.stopped {
		return
	}

	d.started = true

	go d.run()
}

// EmitAuthEvent enqueues one event without waiting; it drops the event when the queue is full or stopped.
func (d *eventDispatcher[E]) EmitAuthEvent(_ context.Context, event E) {
	if d == nil {
		return
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.stopped {
		d.count(authEventOutcomeDropped)

		return
	}

	select {
	case d.queue <- event:
		d.count(authEventOutcomeQueued)
	default:
		d.count(authEventOutcomeDropped)
	}
}

// Stop ends intake and drains queued events until ctx expires; undelivered events are counted as dropped.
func (d *eventDispatcher[E]) Stop(ctx context.Context) error {
	if d == nil {
		return nil
	}

	d.stopOnce.Do(func() {
		d.mu.Lock()
		d.stopped = true
		started := d.started
		d.mu.Unlock()

		close(d.stop)

		if !started {
			close(d.done)
		}
	})

	select {
	case <-d.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// run delivers queued events until Stop, then drains what is left.
func (d *eventDispatcher[E]) run() {
	defer close(d.done)

	for {
		select {
		case event := <-d.queue:
			d.deliverToSinks(event)
		case <-d.stop:
			d.drain()

			return
		}
	}
}

// drain delivers events that were queued before intake stopped.
func (d *eventDispatcher[E]) drain() {
	for {
		select {
		case event := <-d.queue:
			d.deliverToSinks(event)
		default:
			return
		}
	}
}

// deliverToSinks hands one event to every sink with a bounded per-call context.
func (d *eventDispatcher[E]) deliverToSinks(event E) {
	for _, sink := range d.sinks {
		ctx, cancel := context.WithTimeout(context.Background(), authEventDeliveryTimeout)
		err := d.deliver(ctx, sink, event)

		cancel()

		if err != nil {
			d.count(authEventOutcomeFailed)

			continue
		}

		d.count(authEventOutcomeDelivery)
	}
}

// deliverAuthEvent invokes one ready sink behind the host panic boundary.
func (r *Runner) deliverAuthEvent(ctx context.Context, qualifiedName string, event pluginapi.AuthEvent) error {
	_, err := invokeTypedComponent(ctx, r, qualifiedName, pluginregistry.ComponentKindAuthEventSink, "ObserveAuthEvent",
		func(callCtx context.Context, sink pluginapi.AuthEventSink) (struct{}, error) {
			return struct{}{}, sink.ObserveAuthEvent(callCtx, event)
		})

	return err
}

// deliverBruteForceEvent invokes one ready brute-force sink behind the host panic boundary.
func (r *Runner) deliverBruteForceEvent(ctx context.Context, qualifiedName string, event pluginapi.BruteForceEvent) error {
	_, err := invokeTypedComponent(ctx, r, qualifiedName, pluginregistry.ComponentKindBruteForceEventSink,
		"ObserveBruteForceEvent",
		func(callCtx context.Context, sink pluginapi.BruteForceEventSink) (struct{}, error) {
			return struct{}{}, sink.ObserveBruteForceEvent(callCtx, event)
		})

	return err
}

// laneCounter records delivery outcomes of one lane in the process metrics.
func laneCounter(lane string) authEventCounter {
	return func(outcome string) {
		if metrics := stats.GetMetrics(); metrics != nil {
			if counter := metrics.GetPluginAuthEventsTotal(); counter != nil {
				counter.WithLabelValues(outcome, lane).Inc()
			}
		}
	}
}

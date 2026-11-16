// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginruntime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// authEventProbe records deliveries and outcome counts for dispatcher tests.
type authEventProbe struct {
	release   chan struct{}
	outcomes  map[string]int
	delivered []string
	mu        sync.Mutex
	fail      bool
}

// deliver records one delivered event ID, optionally after waiting for release.
func (p *authEventProbe) deliver(_ context.Context, _ string, event pluginapi.AuthEvent) error {
	if p.release != nil {
		<-p.release
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.fail {
		return errors.New("sink failed")
	}

	p.delivered = append(p.delivered, event.EventID)

	return nil
}

// count records one bounded outcome.
func (p *authEventProbe) count(outcome string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.outcomes[outcome]++
}

// snapshot returns detached copies of the probe state.
func (p *authEventProbe) snapshot() ([]string, map[string]int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	outcomes := make(map[string]int, len(p.outcomes))
	for key, value := range p.outcomes {
		outcomes[key] = value
	}

	return append([]string(nil), p.delivered...), outcomes
}

// TestAuthEventDispatcherDropsWhenFullAndDrainsOnStop pins non-blocking emission, bounded queueing, and draining.
func TestAuthEventDispatcherDropsWhenFullAndDrainsOnStop(t *testing.T) {
	probe := &authEventProbe{release: make(chan struct{}), outcomes: map[string]int{}}
	dispatcher := newAuthEventDispatcher([]string{"clickhouse.events"}, 2, probe.deliver, probe.count)
	dispatcher.Start()

	for _, id := range []string{"first", "second", "third", "fourth"} {
		done := make(chan struct{})

		go func() {
			dispatcher.EmitAuthEvent(t.Context(), pluginapi.AuthEvent{EventID: id})
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("EmitAuthEvent(%s) blocked", id)
		}
	}

	close(probe.release)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	if err := dispatcher.Stop(ctx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	dispatcher.EmitAuthEvent(t.Context(), pluginapi.AuthEvent{EventID: "after-stop"})

	delivered, outcomes := probe.snapshot()
	if len(delivered) < 2 || len(delivered) > 3 || delivered[0] != "first" {
		t.Fatalf("delivered = %#v, want the first events in order within the queue bound", delivered)
	}

	if outcomes[authEventOutcomeDropped] < 2 || outcomes[authEventOutcomeDelivery] != len(delivered) {
		t.Fatalf("outcomes = %#v, want dropped overflow and post-stop events", outcomes)
	}
}

// TestAuthEventDispatcherCountsSinkFailures pins that sink errors are contained and counted.
func TestAuthEventDispatcherCountsSinkFailures(t *testing.T) {
	probe := &authEventProbe{outcomes: map[string]int{}, fail: true}
	dispatcher := newAuthEventDispatcher([]string{"clickhouse.events"}, 4, probe.deliver, probe.count)
	dispatcher.Start()
	dispatcher.EmitAuthEvent(t.Context(), pluginapi.AuthEvent{EventID: "failing"})

	if err := dispatcher.Stop(t.Context()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	if _, outcomes := probe.snapshot(); outcomes[authEventOutcomeFailed] != 1 {
		t.Fatalf("outcomes = %#v, want one failed delivery", outcomes)
	}
}

// TestAuthEventDispatcherWithoutSinksIsDisabled pins the nil dispatcher contract used without event sinks.
func TestAuthEventDispatcherWithoutSinksIsDisabled(t *testing.T) {
	var dispatcher *AuthEventDispatcher

	dispatcher.Start()
	dispatcher.EmitAuthEvent(t.Context(), pluginapi.AuthEvent{})

	if err := dispatcher.Stop(t.Context()); err != nil {
		t.Fatalf("nil Stop() error = %v", err)
	}

	if NewAuthEventDispatcher(NewRunner(nil), 0) != nil {
		t.Fatal("NewAuthEventDispatcher() without sinks returned an active dispatcher")
	}
}

// TestBruteForceLanesKeepLifecycleUnderVolumeFlood pins that a flood of counted and hit events cannot evict a ban
// lifecycle event, because every kind has its own bounded lane.
func TestBruteForceLanesKeepLifecycleUnderVolumeFlood(t *testing.T) {
	release := make(chan struct{})
	delivered := make(chan pluginapi.BruteForceEventKind, 16)
	deliver := func(_ context.Context, _ string, event pluginapi.BruteForceEvent) error {
		if event.Kind != pluginapi.BruteForceBanActivated {
			<-release
		}

		delivered <- event.Kind

		return nil
	}

	lanes := &bruteForceEventLanes{
		lifecycle: newEventDispatcher([]string{"sink"}, 1, deliver, func(string) {}),
		counted:   newEventDispatcher([]string{"sink"}, 1, deliver, func(string) {}),
		hits:      newEventDispatcher([]string{"sink"}, 1, deliver, func(string) {}),
	}
	lanes.lifecycle.Start()
	lanes.counted.Start()
	lanes.hits.Start()

	for range 100 {
		lanes.route(pluginapi.BruteForceCounted).EmitAuthEvent(t.Context(), pluginapi.BruteForceEvent{Kind: pluginapi.BruteForceCounted})
		lanes.route(pluginapi.BruteForceBanHit).EmitAuthEvent(t.Context(), pluginapi.BruteForceEvent{Kind: pluginapi.BruteForceBanHit})
	}

	lanes.route(pluginapi.BruteForceBanActivated).EmitAuthEvent(t.Context(),
		pluginapi.BruteForceEvent{Kind: pluginapi.BruteForceBanActivated})

	select {
	case kind := <-delivered:
		if kind != pluginapi.BruteForceBanActivated {
			t.Fatalf("first delivered kind = %s, want the lifecycle event", kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle event was blocked by the volume flood")
	}

	close(release)

	if err := lanes.stop(t.Context()); err != nil {
		t.Fatalf("stop error = %v", err)
	}
}

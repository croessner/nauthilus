// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package bruteforce

import (
	"context"
	"slices"
	"sync"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// recordingEvents captures emitted brute-force events.
type recordingEvents struct {
	events []pluginapi.BruteForceEvent
	mu     sync.Mutex
}

// EmitBruteForceEvent records one event.
func (r *recordingEvents) EmitBruteForceEvent(_ context.Context, event pluginapi.BruteForceEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)
}

// TestConcurrentThresholdRequestsCreateOneBanInstance pins that two requests that both read the exceeded counter
// create exactly one ban instance: the SETNX winner reports the activation, the loser reports an activation race hit.
func TestConcurrentThresholdRequestsCreateOneBanInstance(t *testing.T) {
	fixture := newPreAuthFixture(t, "192.0.2.50")
	fixture.seedFailures(t, 6)

	recorder := &recordingEvents{}
	first, second := fixture.manager(""), fixture.manager("")
	first.deps.Events, second.deps.Events = recorder, recorder

	for _, manager := range []*bucketManagerImpl{first, second} {
		if outcome := fixture.check(manager, true); !outcome.ruleTriggered || outcome.alreadyTriggered {
			t.Fatalf("pre-check outcome = %+v, want an over-limit trigger without an existing ban", outcome)
		}
	}

	rules := fixture.rules()

	network, err := first.getNetwork(&rules[0])
	if err != nil {
		t.Fatalf("getNetwork() error = %v", err)
	}

	for _, manager := range []*bucketManagerImpl{first, second} {
		if !manager.ProcessBruteForce(true, false, &rules[0], network, "", func() {}) {
			t.Fatal("ProcessBruteForce() = false, want an enforced ban")
		}
	}

	want := []raceEventShape{
		{kind: pluginapi.BruteForceBanActivated, bucketID: recorder.events[0].BucketID},
		{kind: pluginapi.BruteForceBanHit, hitSource: pluginapi.BruteForceHitActivationRace, bucketID: recorder.events[0].BucketID},
	}

	if got := raceShapesOf(recorder.events); recorder.events[0].BucketID == "" || !slices.Equal(got, want) {
		t.Fatalf("events = %+v, want one activation and one activation-race hit on one bucket", recorder.events)
	}
}

// raceEventShape is the comparable projection of one event of the concurrent activation scenario.
type raceEventShape struct {
	kind      pluginapi.BruteForceEventKind
	hitSource string
	bucketID  string
}

// raceShapesOf projects the recorded events of the concurrent activation scenario.
func raceShapesOf(events []pluginapi.BruteForceEvent) []raceEventShape {
	shapes := make([]raceEventShape, 0, len(events))
	for _, event := range events {
		shapes = append(shapes, raceEventShape{kind: event.Kind, hitSource: event.HitSource, bucketID: event.BucketID})
	}

	return shapes
}

// TestSlidingWindowReplyCarriesWindowCounts pins the extended counter reply used for loss detection.
func TestSlidingWindowReplyCarriesWindowCounts(t *testing.T) {
	result, ok := parseSlidingWindowResult([]any{"3.5", int64(1), "2", int64(3), int64(1)}, 0)
	if !ok || result.current == nil || *result.current != 3 || result.previous == nil || *result.previous != 1 ||
		!result.exceeded || result.limit != 2 || result.total != 3.5 {
		t.Fatalf("parsed reply = %+v, want total 3.5, limit 2, current 3, previous 1", result)
	}

	legacy, ok := parseSlidingWindowResult([]any{"1", int64(0), "4"}, 0)
	if !ok || legacy.current != nil || legacy.previous != nil {
		t.Fatalf("legacy reply = %+v, want no window counts", legacy)
	}
}

// TestBucketIdentityMatchesWindowKeys pins that flushed window keys resolve to the bucket identity of counted events.
func TestBucketIdentityMatchesWindowKeys(t *testing.T) {
	base := "nt_bf:{198.51.100.0/24}:3600:24:3:4:198.51.100.0/24"

	if got := BucketIdentityFromKey(base + ":win:493112"); got == "" || got != bucketIdentity(base) {
		t.Fatalf("BucketIdentityFromKey() = %q, want %q", got, bucketIdentity(base))
	}

	if BucketIdentityFromKey(base) != "" {
		t.Fatal("a key without window suffix must not resolve to a bucket")
	}
}

// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package effectsupervisor

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

// TestBestEffortPlansCannotConsumeMandatoryReserve reproduces a flood of best-effort terminal completions: they may
// occupy at most half of the supervisor capacity (rounded up), so mandatory plans of other requests still find
// capacity instead of failing their decision with a saturation tempfail.
func TestBestEffortPlansCannotConsumeMandatoryReserve(t *testing.T) {
	supervisor := newTestSupervisor(t, 4, 1, &recordingProvider{}, nil)
	gate := newTestGate(t, BoundaryHTTPCommit)

	t.Cleanup(gate.Complete)

	for index := range 2 {
		if _, err := supervisor.Accept(context.Background(), newBestEffortTestPlan(t, gate)); err != nil {
			t.Fatalf("Accept(best-effort %d) error = %v", index, err)
		}
	}

	if _, err := supervisor.Accept(context.Background(), newBestEffortTestPlan(t, gate)); !errors.Is(err, ErrSaturated) {
		t.Fatalf("Accept(best-effort beyond share) error = %v, want ErrSaturated", err)
	}

	for index := range 2 {
		mandatory := newTestPlan(t, testProviderID, newTestWork("mandatory"), gate)
		if _, err := supervisor.Accept(context.Background(), mandatory); err != nil {
			t.Fatalf("Accept(mandatory %d) inside the reserve error = %v", index, err)
		}
	}

	mandatory := newTestPlan(t, testProviderID, newTestWork("mandatory"), gate)
	if _, err := supervisor.Accept(context.Background(), mandatory); !errors.Is(err, ErrSaturated) {
		t.Fatalf("Accept(mandatory beyond capacity) error = %v, want ErrSaturated", err)
	}
}

// TestBestEffortShareKeepsOneSlotForSmallCapacity keeps a one-slot supervisor usable for best-effort work.
func TestBestEffortShareKeepsOneSlotForSmallCapacity(t *testing.T) {
	for capacity, want := range map[int]int{1: 1, 2: 1, 3: 2, 4: 2, 9: 5} {
		if got := bestEffortCapacity(capacity); got != want {
			t.Fatalf("bestEffortCapacity(%d) = %d, want %d", capacity, got, want)
		}
	}
}

// newBestEffortTestPlan constructs one best-effort plan held back by an open finalization gate.
func newBestEffortTestPlan(t *testing.T, gate FinalizationGate) Plan {
	t.Helper()

	plan, err := NewPlan(PlanInput{
		DecisionID: testDecisionID, EffectOrdinal: 1, Target: "authn/authenticate", Provider: testProviderID,
		DeadlineBudget: time.Second, Gate: gate, BestEffort: true,
		Observability: ObservabilityMetadata{RuntimeGeneration: 42, Source: "authn"}, Work: newTestWork("best-effort"),
	})
	if err != nil {
		t.Fatalf("NewPlan(best-effort) error = %v", err)
	}

	return plan
}

// TestBestEffortSaturationIsLoggedAtDebug keeps a flood of rejected best-effort completions out of warning logs and
// audit warnings; the acceptance-failure counter remains the signal. Other failures stay warnings.
func TestBestEffortSaturationIsLoggedAtDebug(t *testing.T) {
	quiet := Event{State: StateFailed, Phase: PhaseAcceptance, ErrorClass: bestEffortSaturatedErrorClass}
	if eventLogLevel(quiet) != slog.LevelDebug || eventAuditLogLevel(quiet) != slog.LevelDebug {
		t.Fatalf("best-effort saturation levels = %v/%v, want debug", eventLogLevel(quiet), eventAuditLogLevel(quiet))
	}

	loud := Event{State: StateFailed, Phase: PhaseAcceptance, ErrorClass: "saturated"}
	if eventLogLevel(loud) != slog.LevelWarn || eventAuditLogLevel(loud) != slog.LevelWarn {
		t.Fatalf("mandatory saturation levels = %v/%v, want warn", eventLogLevel(loud), eventAuditLogLevel(loud))
	}
}

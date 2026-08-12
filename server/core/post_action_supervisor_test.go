// Copyright (C) 2026 Christian Roessner
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

package core

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
)

type loggingPostActionWork struct{}

// Validate accepts the bounded logger-injection test work.
func (*loggingPostActionWork) Validate() error {
	return nil
}

// Execute returns a known result for logger-injection verification.
func (*loggingPostActionWork) Execute(context.Context) effectsupervisor.Result {
	return effectsupervisor.Succeeded()
}

// Cleanup releases the stateless logger-injection test work.
func (*loggingPostActionWork) Cleanup() {}

func TestPostActionPlanStepReleaseIsIdempotentAcrossOwnershipCopies(t *testing.T) {
	var cleanupCalls atomic.Int32

	step := NewLuaPostActionPlanStep("lua_post_action", recordingPlanPostAction{}, func() {
		cleanupCalls.Add(1)
	})
	copied := step

	step.Release()
	copied.Release()
	ReleasePostActionPlanSteps([]PostActionPlanStep{step, copied})

	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func TestPostActionSupervisorUsesConfiguredCoreLoggerForStateAndAudit(t *testing.T) {
	previousLogger := optionalDefaultLogger()
	defer SetDefaultLogger(previousLogger)

	var output bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelInfo}))
	SetDefaultLogger(logger)

	supervisor := NewPostActionSupervisor(context.Background())

	gate, err := effectsupervisor.NewGate(effectsupervisor.BoundaryHTTPCommit)
	if err != nil {
		t.Fatalf("NewGate() error = %v", err)
	}

	gate.Complete()

	plan, err := effectsupervisor.NewPlan(effectsupervisor.PlanInput{
		DecisionID:     "decision-configured-logger",
		EffectOrdinal:  3,
		Target:         "authn/test",
		Provider:       authPostActionProvider,
		DeadlineBudget: time.Second,
		Gate:           gate,
		Observability: effectsupervisor.ObservabilityMetadata{
			Source: "test",
		},
		Work: &loggingPostActionWork{},
	})
	if err != nil {
		t.Fatalf("NewPlan() error = %v", err)
	}

	if _, err := supervisor.supervisor.Accept(context.Background(), plan); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}

	waitCtx, cancelWait := context.WithTimeout(context.Background(), time.Second)
	defer cancelWait()

	if err := supervisor.WaitIdle(waitCtx); err != nil {
		t.Fatalf("WaitIdle() error = %v", err)
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()

	if err := supervisor.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	logOutput := output.String()
	if !strings.Contains(logOutput, "decision-configured-logger") ||
		!strings.Contains(logOutput, `"audit_class":"policy_effect"`) ||
		!strings.Contains(logOutput, `"effect_state":"accepted"`) ||
		!strings.Contains(logOutput, `"effect_state":"succeeded"`) {
		t.Fatalf("configured logger output = %q, want state and audit records", logOutput)
	}
}

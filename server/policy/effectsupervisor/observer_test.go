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

package effectsupervisor

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestOperationalObserverKeepsCorrelationOutOfMetricLabels(t *testing.T) {
	var logs bytes.Buffer

	states := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_post_action_effect_states_total",
		Help: "Test supervisor states.",
	}, []string{"state", "phase", "boundary"})

	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	observer := NewOperationalObserver(logger, states, NewLoggingAuditSink(logger))

	observer.Observe(context.Background(), Event{
		DecisionID:    testDecisionID,
		EffectOrdinal: 7,
		Target:        "authn/authenticate",
		Provider:      testProviderID,
		State:         StateOutcomeUnknown,
		Phase:         PhaseExecution,
		Boundary:      BoundaryHTTPCommit,
		ErrorClass:    "dispatch_ambiguous",
		Source:        "authn",
	})

	description := states.WithLabelValues("outcome_unknown", "execution", "http_commit").Desc().String()
	if strings.Contains(description, "decision_id") || strings.Contains(description, "effect_ordinal") {
		t.Fatalf("metric description contains correlation labels: %s", description)
	}

	logOutput := logs.String()
	if !strings.Contains(logOutput, testDecisionID) || !strings.Contains(logOutput, `"effect_ordinal":7`) {
		t.Fatalf("structured log lacks decision correlation: %s", logOutput)
	}

	if !strings.Contains(logOutput, `"audit_class":"policy_effect"`) {
		t.Fatalf("controlled audit lacks effect classification: %s", logOutput)
	}
}

func TestOperationalObserverLogsFailureOnceWithSharedAuditLogger(t *testing.T) {
	for _, state := range []State{StateFailed, StateOutcomeUnknown} {
		t.Run(string(state), func(t *testing.T) {
			var logs bytes.Buffer

			logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
			observer := NewOperationalObserver(logger, nil, NewLoggingAuditSink(logger))
			observer.Observe(t.Context(), Event{State: state, DecisionID: testDecisionID, ErrorClass: "saturated"})

			if got := strings.Count(logs.String(), "\n"); got != 1 {
				t.Fatalf("one failed transition produced %d log records, want one", got)
			}

			if !strings.Contains(logs.String(), `"audit_class":"policy_effect"`) {
				t.Fatal("deduplicated failure lost its audit classification")
			}
		})
	}
}

func TestOperationalObserverPreservesSeparateLoggingDestinations(t *testing.T) {
	var operational, audit bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&operational, nil))
	auditLogger := slog.New(slog.NewJSONHandler(&audit, nil))
	observer := NewOperationalObserver(logger, nil, NewLoggingAuditSink(auditLogger))
	observer.Observe(t.Context(), Event{State: StateFailed, DecisionID: testDecisionID})

	for name, output := range map[string]string{"operational": operational.String(), "audit": audit.String()} {
		if strings.Count(output, "\n") != 1 {
			t.Fatalf("%s destination did not receive exactly one failure", name)
		}
	}
}

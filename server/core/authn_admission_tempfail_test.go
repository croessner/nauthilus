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

package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/admission"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/stats"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// capacityAdmissionError mirrors the Decision Service chain for one rejected capacity category.
func capacityAdmissionError(category error) error {
	return fmt.Errorf("candidate session: %w", errors.Join(decisionservice.ErrDecisionAdmission, category))
}

// newCapacityRejectingAuthnAdapter builds one candidate adapter whose session admission always fails.
func newCapacityRejectingAuthnAdapter(
	t *testing.T,
	openErr error,
	logs *bytes.Buffer,
) (AuthApplicationService, *recordingAuthApplicationService) {
	t.Helper()

	current := newRecordingAuthApplicationService()
	factory := &recordingAuthnDecisionSessionFactory{openErr: openErr}

	adapter, err := NewAuthnCandidateApplicationService(current, factory, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	adapter.(*authnPolicyApplicationService).admissionRejections.logger = slog.New(
		slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}),
	)

	return adapter, current
}

func TestAuthnCapacityAdmissionRejectionAnswersTempFail(t *testing.T) {
	categories := []struct {
		err    error
		reason string
	}{
		{err: admission.ErrConcurrencyLimitExceeded, reason: admission.CapacityReasonConcurrency},
		{err: admission.ErrRateLimitExceeded, reason: admission.CapacityReasonRate},
	}

	for _, test := range authnApplicationOperationCases() {
		for _, category := range categories {
			t.Run(test.name+"/"+category.reason, func(t *testing.T) {
				var logs bytes.Buffer

				adapter, current := newCapacityRejectingAuthnAdapter(t, capacityAdmissionError(category.err), &logs)
				counter := stats.GetMetrics().GetPolicyAuthnAdmissionRejectionsTotal().WithLabelValues(category.reason)
				before := testutil.ToFloat64(counter)

				input := authnApplicationTestInput(test.mode)
				input.CorrelationID = "capacity-correlation"

				result, err := test.runForDecision(context.Background(), adapter, input)
				if err != nil {
					t.Fatalf("operation error = %v, want tempfail outcome", err)
				}

				if result.decision != AuthDecisionTempFail || result.status != definitions.TempFailDefault ||
					result.session != input.CorrelationID {
					t.Fatalf("capacity rejection result = %+v, want default tempfail with correlation session", result)
				}

				if current.totalCalls() != 0 {
					t.Fatalf("current pipeline calls = %d, want 0 without admission", current.totalCalls())
				}

				if delta := testutil.ToFloat64(counter) - before; delta != 1 {
					t.Fatalf("admission rejection counter delta = %v, want 1", delta)
				}

				assertAuthnAdmissionRejectionLog(t, logs.String(), category.reason, string(test.operation))
			})
		}
	}
}

// assertAuthnAdmissionRejectionLog verifies one bounded warn record without the fail-closed error message.
func assertAuthnAdmissionRejectionLog(t *testing.T, logs string, reason string, operation string) {
	t.Helper()

	for _, want := range []string{
		"level=WARN", "Internal authentication rejected by Policy admission capacity",
		"reason=" + reason, "operation=" + operation, "entry_point=default", "capacity-correlation",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("admission rejection log = %q, want %q", logs, want)
		}
	}

	if strings.Contains(logs, "Authentication application failed") || strings.Contains(logs, "level=ERROR") {
		t.Fatalf("admission rejection log = %q, want no error-level application failure", logs)
	}
}

func TestAuthnCapacityAdmissionTempFailProjectsRequestSurface(t *testing.T) {
	var logs bytes.Buffer

	adapter, _ := newCapacityRejectingAuthnAdapter(t, capacityAdmissionError(admission.ErrConcurrencyLimitExceeded), &logs)
	input := authnApplicationTestInput(AuthModeAuthenticate)

	ctx, gate := authnCandidateTestContext(context.Background(), input)
	defer gate.Complete()

	outcome, err := adapter.Authenticate(ctx, input)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if outcome.Protocol != input.Context.Protocol || outcome.Error != definitions.TempFailDefault ||
		outcome.TerminalState != string(authFSMStateAuthTempFail) || outcome.HTTPStatus != 500 {
		t.Fatalf("capacity tempfail outcome = %#v, want complete tempfail surface", outcome)
	}

	if outcome.Session == "" {
		t.Fatal("capacity tempfail outcome without correlation ID has no generated session")
	}
}

func TestAuthnNonCapacityAdmissionFailuresStayFailClosed(t *testing.T) {
	failures := []struct {
		err  error
		name string
	}{
		{name: "permission", err: errors.Join(decisionservice.ErrDecisionAdmission, admission.ErrPermissionDenied)},
		{name: "request limit", err: errors.Join(decisionservice.ErrDecisionAdmission, admission.ErrRequestLimitExceeded)},
		{name: "capacity without admission boundary", err: admission.ErrConcurrencyLimitExceeded},
	}

	for _, failure := range failures {
		t.Run(failure.name, func(t *testing.T) {
			var logs bytes.Buffer

			adapter, _ := newCapacityRejectingAuthnAdapter(t, failure.err, &logs)

			outcome, err := authenticateAuthnCandidateForTest(
				context.Background(), adapter, authnApplicationTestInput(AuthModeAuthenticate),
			)
			if !errors.Is(err, failure.err) || outcome != nil {
				t.Fatalf("Authenticate() = %#v / %v, want fail-closed %v", outcome, err, failure.err)
			}
		})
	}
}

func TestAuthnCapacityErrorInsideAdmittedSessionStaysFailClosed(t *testing.T) {
	current := newRecordingAuthApplicationService()
	session := newRecordingAuthnDecisionSession([]string{string(policy.StagePreAuth), string(policy.StageAuthDecision)})
	session.evaluateErr = capacityAdmissionError(admission.ErrConcurrencyLimitExceeded)
	factory := &recordingAuthnDecisionSessionFactory{session: session}

	adapter, err := NewAuthnCandidateApplicationService(current, factory, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	outcome, err := authenticateAuthnCandidateForTest(
		context.Background(), adapter, authnApplicationTestInput(AuthModeAuthenticate),
	)
	if !errors.Is(err, admission.ErrConcurrencyLimitExceeded) || outcome != nil {
		t.Fatalf("Authenticate() = %#v / %v, want error from inside the admitted session", outcome, err)
	}
}

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
	"net/http"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/conncause"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/monitoring/authmetrics"
	"github.com/croessner/nauthilus/v4/server/stats"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// errApplicationFailureCause mirrors one unexpected host-provider failure below the application boundary.
var errApplicationFailureCause = errors.New(
	`authn Policy decision session: execute authn host provider "plugin_subject": backend_temporary_failure`,
)

// newRecordingAuthApplicationFailures returns failure handling whose error log is captured in logs.
func newRecordingAuthApplicationFailures(logs *bytes.Buffer, transport string) AuthApplicationFailures {
	return NewAuthApplicationFailures(
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		transport,
	)
}

func TestAuthApplicationFailureAnswersFailClosedTempFail(t *testing.T) {
	for _, transport := range []string{authmetrics.TransportHTTP, authmetrics.TransportGRPC} {
		t.Run(transport, func(t *testing.T) {
			var logs bytes.Buffer

			counter := stats.GetMetrics().GetAuthApplicationErrorsTotal().WithLabelValues(transport)
			before := testutil.ToFloat64(counter)
			input := authnApplicationTestInput(AuthModeAuthenticate)
			input.CorrelationID = "application-failure-correlation"

			outcome := newRecordingAuthApplicationFailures(&logs, transport).TempFail(t.Context(), input, errApplicationFailureCause)

			if outcome == nil || outcome.Decision != AuthDecisionTempFail ||
				outcome.StatusMessage != definitions.TempFailDefault || outcome.Error != definitions.TempFailDefault ||
				outcome.TerminalState != string(authFSMStateAuthTempFail) ||
				outcome.HTTPStatus != http.StatusInternalServerError ||
				outcome.Session != input.CorrelationID || outcome.Protocol != input.Context.Protocol {
				t.Fatalf("TempFail() = %#v, want complete fail-closed tempfail surface", outcome)
			}

			if delta := testutil.ToFloat64(counter) - before; delta != 1 {
				t.Fatalf("application error counter delta = %v, want 1", delta)
			}

			assertAuthApplicationFailureLog(t, logs.String(), transport, input.CorrelationID)
		})
	}
}

func TestAuthApplicationFailureAnswersListAccountsTempFail(t *testing.T) {
	var logs bytes.Buffer

	input := authnApplicationTestInput(AuthModeListAccounts)
	input.CorrelationID = "application-failure-list"

	outcome := newRecordingAuthApplicationFailures(&logs, authmetrics.TransportGRPC).
		ListAccountsTempFail(t.Context(), input, errApplicationFailureCause)

	if outcome == nil || outcome.Decision != AuthDecisionTempFail || len(outcome.Accounts) != 0 ||
		outcome.StatusMessage != definitions.TempFailDefault || outcome.Session != input.CorrelationID {
		t.Fatalf("ListAccountsTempFail() = %#v, want empty tempfail listing with correlation session", outcome)
	}

	assertAuthApplicationFailureLog(t, logs.String(), authmetrics.TransportGRPC, input.CorrelationID)
}

func TestAuthApplicationFailureBoundsTransportLabel(t *testing.T) {
	var logs bytes.Buffer

	counter := stats.GetMetrics().GetAuthApplicationErrorsTotal().WithLabelValues(authmetrics.TransportOther)
	before := testutil.ToFloat64(counter)
	input := authnApplicationTestInput(AuthModeAuthenticate)

	outcome := newRecordingAuthApplicationFailures(&logs, "caller-controlled-value").TempFail(t.Context(), input, errApplicationFailureCause)

	if outcome.Session == "" {
		t.Fatal("tempfail outcome without correlation ID has no generated session")
	}

	if delta := testutil.ToFloat64(counter) - before; delta != 1 {
		t.Fatalf("bounded application error counter delta = %v, want 1", delta)
	}
}

// TestAuthApplicationFailureLogsOwnRequestContextState reproduces both observed cancellation patterns: a request whose
// own context ended, and a request that received a cancellation from shared work while its own context stayed active.
func TestAuthApplicationFailureLogsOwnRequestContextState(t *testing.T) {
	canceledRequest, cancel := context.WithCancelCause(context.Background())
	cancel(conncause.ErrClientDisconnected)

	tests := []struct {
		requestCtx context.Context
		err        error
		name       string
		want       []string
	}{
		{
			name:       "foreign cancel",
			requestCtx: context.Background(),
			err:        fmt.Errorf("native plugin refresh_user_data: %w", context.Canceled),
			want:       []string{"cancel_source=foreign", `request_context_error=""`, `request_context_cause=""`},
		},
		{
			name:       "own request canceled",
			requestCtx: canceledRequest,
			err:        fmt.Errorf("native plugin refresh_user_data: %w", context.Canceled),
			want: []string{
				"cancel_source=request", `request_context_error="context canceled"`,
				`request_context_cause="client disconnected"`,
			},
		},
		{
			name:       "no cancellation",
			requestCtx: context.Background(),
			err:        errApplicationFailureCause,
			want:       []string{`cancel_source=""`, `request_context_error=""`},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer

			input := authnApplicationTestInput(AuthModeAuthenticate)

			newRecordingAuthApplicationFailures(&logs, authmetrics.TransportHTTP).TempFail(test.requestCtx, input, test.err)

			for _, want := range test.want {
				if !strings.Contains(logs.String(), want) {
					t.Fatalf("application failure log = %q, want %q", logs.String(), want)
				}
			}
		})
	}
}

// assertAuthApplicationFailureLog verifies one error-level record carrying the exact cause and correlation.
func assertAuthApplicationFailureLog(t *testing.T, logs string, transport string, session string) {
	t.Helper()

	for _, want := range []string{
		"level=ERROR", "Authentication application failed", "backend_temporary_failure",
		"transport=" + transport, session,
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("application failure log = %q, want %q", logs, want)
		}
	}
}

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
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

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

			outcome := newRecordingAuthApplicationFailures(&logs, transport).TempFail(input, errApplicationFailureCause)

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
		ListAccountsTempFail(input, errApplicationFailureCause)

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

	outcome := newRecordingAuthApplicationFailures(&logs, "caller-controlled-value").TempFail(input, errApplicationFailureCause)

	if outcome.Session == "" {
		t.Fatal("tempfail outcome without correlation ID has no generated session")
	}

	if delta := testutil.ToFloat64(counter) - before; delta != 1 {
		t.Fatalf("bounded application error counter delta = %v, want 1", delta)
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

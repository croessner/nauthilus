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
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/conncause"
	"github.com/croessner/nauthilus/v4/server/definitions"

	"github.com/gin-gonic/gin"
)

// TestTempFailLogCarriesOwnRequestContextState reproduces both cancellation patterns on the terminal tempfail line:
// a technical error that wraps a cancellation while the own request stays active is foreign, an ended own request is
// request, and the state is read from the anchored transport request rather than from a derived context.
func TestTempFailLogCarriesOwnRequestContextState(t *testing.T) {
	canceledRequest, cancel := context.WithCancelCause(context.Background())
	cancel(conncause.ErrClientDisconnected)

	sharedCancel := fmt.Errorf("brute force burst gate: %w", context.Canceled)

	tests := []struct {
		requestCtx    context.Context
		err           error
		name          string
		want          []string
		cancelDerived bool
	}{
		{
			name: "foreign cancel", requestCtx: context.Background(), err: sharedCancel,
			want: []string{"cancel_source=foreign", `request_context_error=""`, `request_context_cause=""`},
		},
		{
			name: "own request canceled", requestCtx: canceledRequest, err: sharedCancel,
			want: []string{
				"cancel_source=request", `request_context_error="context canceled"`,
				`request_context_cause="client disconnected"`,
			},
		},
		{
			name: "derived context canceled internally", requestCtx: context.Background(), err: sharedCancel,
			cancelDerived: true,
			want:          []string{"cancel_source=foreign", `request_context_error=""`},
		},
		{
			name: "no technical error", requestCtx: context.Background(),
			want: []string{`cancel_source=""`, `request_context_error=""`},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer

			ginCtx, cancelDerived := newTempFailCancelGinContext(test.requestCtx, t)
			if test.cancelDerived {
				cancelDerived()
			}

			auth := newTempFailCancelAuthState(t, ginCtx, &logs)

			auth.recordTempFailError(test.err)
			auth.recordTempFailCause(authTempFailCause{reason: tempFailReasonBruteForce})
			auth.logAuthTempFail(ginCtx, nil)

			line := logs.String()
			for _, want := range append(test.want, "tempfail_reason=brute_force_error") {
				if !strings.Contains(line, want) {
					t.Fatalf("tempfail line = %q, want %q", line, want)
				}
			}
		})
	}
}

// TestRecordTempFailErrorKeepsTheFirstError pins that the first technical error explains the temporary failure and a
// later nil error does not erase it.
func TestRecordTempFailErrorKeepsTheFirstError(t *testing.T) {
	auth := &AuthState{}
	first := fmt.Errorf("first: %w", context.Canceled)

	auth.recordTempFailError(first)
	auth.recordTempFailError(nil)
	auth.recordTempFailError(fmt.Errorf("second"))

	if auth.Runtime.tempFailErr != first {
		t.Fatalf("tempFailErr = %v, want %v", auth.Runtime.tempFailErr, first)
	}
}

// newTempFailCancelGinContext builds a request context the way the application host does: the request context is
// derived from the anchored transport request context, here with an extra cancelable layer whose cancel is returned.
func newTempFailCancelGinContext(transportCtx context.Context, t *testing.T) (*gin.Context, context.CancelFunc) {
	t.Helper()

	derived, cancel := context.WithCancel(conncause.WithRequestContext(transportCtx))
	t.Cleanup(cancel)

	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Request = httptest.NewRequestWithContext(derived, http.MethodPost, "/api/v1/auth/json", nil)

	return ginCtx, cancel
}

// newTempFailCancelAuthState returns an auth state whose logs are captured in logs.
func newTempFailCancelAuthState(t *testing.T, ginCtx *gin.Context, logs *bytes.Buffer) *AuthState {
	t.Helper()

	auth, ok := NewAuthStateFromContextWithDeps(ginCtx, AuthDeps{
		Cfg:    newCurrentBehaviorConfig(t),
		Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}).(*AuthState)
	if !ok {
		t.Fatal("auth state has an unexpected type")
	}

	auth.Runtime.GUID = "tempfail-cancel-session"
	auth.Runtime.StatusMessage = definitions.TempFailDefault

	return auth
}

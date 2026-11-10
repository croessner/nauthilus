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

package conncause

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// errBackendFailure is an unrelated application error that is not a cancellation.
var errBackendFailure = errors.New("backend failed")

// TestDiagnoseCancel pins the classification of a failure against the state of the own request context.
func TestDiagnoseCancel(t *testing.T) {
	active := context.Background()

	tests := []struct {
		requestCtx context.Context
		err        error
		want       CancelDiagnostics
		name       string
	}{
		{
			name:       "foreign cancel while own request is active",
			requestCtx: active,
			err:        fmt.Errorf("shared lookup: %w", context.Canceled),
			want:       CancelDiagnostics{Source: CancelSourceForeign},
		},
		{
			name:       "foreign deadline while own request is active",
			requestCtx: active,
			err:        fmt.Errorf("shared lookup: %w", context.DeadlineExceeded),
			want:       CancelDiagnostics{Source: CancelSourceForeign},
		},
		{
			name:       "own request canceled by client disconnect",
			requestCtx: contextCanceledWith(fmt.Errorf("%w: %w", ErrClientDisconnected, errBackendFailure)),
			err:        context.Canceled,
			want: CancelDiagnostics{
				RequestErr:   context.Canceled.Error(),
				RequestCause: "client disconnected: backend failed",
				Source:       CancelSourceRequest,
			},
		},
		{
			name:       "own request canceled without cause",
			requestCtx: contextCanceledWith(nil),
			err:        errBackendFailure,
			want: CancelDiagnostics{
				RequestErr:   context.Canceled.Error(),
				RequestCause: context.Canceled.Error(),
				Source:       CancelSourceRequest,
			},
		},
		{name: "unrelated failure", requestCtx: active, err: errBackendFailure},
		{name: "unknown request context", err: context.Canceled},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, DiagnoseCancel(test.requestCtx, test.err))
		})
	}
}

// TestCancelDiagnosticsLogValues pins the stable log field names shared with the Lua cancel diagnostics.
func TestCancelDiagnosticsLogValues(t *testing.T) {
	diagnostics := CancelDiagnostics{RequestErr: "context canceled", RequestCause: "client disconnected", Source: CancelSourceRequest}

	assert.Equal(t, []any{
		LogKeyCancelSource, CancelSourceRequest,
		LogKeyRequestContextError, "context canceled",
		LogKeyRequestContextCause, "client disconnected",
	}, diagnostics.LogValues())
	assert.Equal(t, "cancel_source", LogKeyCancelSource)
	assert.Equal(t, "request_context_error", LogKeyRequestContextError)
	assert.Equal(t, "request_context_cause", LogKeyRequestContextCause)
}

// TestDiagnoseCallCancel pins that work derived from an anchored request context is diagnosed against that request,
// while unanchored and detached work reports nothing instead of a misleading source.
func TestDiagnoseCallCancel(t *testing.T) {
	t.Run("derived work sees a foreign cancel", func(t *testing.T) {
		callCtx, cancel := context.WithTimeout(WithRequestContext(context.Background()), time.Hour)
		defer cancel()

		diagnostics, ok := DiagnoseCallCancel(callCtx, context.Canceled)

		assert.True(t, ok)
		assert.Equal(t, CancelSourceForeign, diagnostics.Source)
		assert.Empty(t, diagnostics.RequestErr)
	})

	t.Run("derived work sees its own request cancel", func(t *testing.T) {
		requestCtx, cancelRequest := context.WithCancelCause(context.Background())
		callCtx, cancel := context.WithCancel(WithRequestContext(requestCtx))

		defer cancel()

		cancelRequest(ErrClientDisconnected)

		diagnostics, ok := DiagnoseCallCancel(callCtx, context.Canceled)

		assert.True(t, ok)
		assert.Equal(t, CancelSourceRequest, diagnostics.Source)
		assert.Equal(t, ErrClientDisconnected.Error(), diagnostics.RequestCause)
	})

	t.Run("detached work is not attributed to the ended request", func(t *testing.T) {
		requestCtx, cancelRequest := context.WithCancel(context.Background())
		detached := context.WithoutCancel(WithRequestContext(requestCtx))

		cancelRequest()

		_, ok := DiagnoseCallCancel(detached, context.DeadlineExceeded)

		assert.False(t, ok)
	})

	t.Run("work detached with its own deadline is not attributed to the request", func(t *testing.T) {
		requestCtx, cancelRequest := context.WithCancel(context.Background())
		workCtx, cancel := context.WithTimeout(DetachRequestContext(WithRequestContext(requestCtx)), time.Nanosecond)

		defer cancel()

		cancelRequest()
		<-workCtx.Done()

		_, ok := DiagnoseCallCancel(workCtx, context.DeadlineExceeded)

		assert.False(t, ok)
	})

	t.Run("unanchored work", func(t *testing.T) {
		_, ok := DiagnoseCallCancel(context.Background(), context.Canceled)

		assert.False(t, ok)
	})
}

// TestWithRequestContextKeepsTheOutermostAnchor pins that nested anchoring cannot replace the transport request
// context with a derived one.
func TestWithRequestContextKeepsTheOutermostAnchor(t *testing.T) {
	outer := WithRequestContext(context.Background())
	derived, cancel := context.WithCancel(outer)

	cancel()

	anchored, ok := RequestContext(WithRequestContext(derived))

	assert.True(t, ok)
	assert.NoError(t, anchored.Err())
}

// TestRequestHandlerAnchorsTheRequestContext pins that the HTTP entry handler makes the request context discoverable
// from contexts derived inside the handler chain.
func TestRequestHandlerAnchorsTheRequestContext(t *testing.T) {
	var found bool

	handler := RequestHandler(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		derived, cancel := context.WithCancel(request.Context())
		defer cancel()

		_, found = RequestContext(derived)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	assert.True(t, found)
}

// TestOwnRequestContextPrefersTheAnchor pins that a derived context resolves to the anchored request context and
// that an unanchored context resolves to itself.
func TestOwnRequestContextPrefersTheAnchor(t *testing.T) {
	anchored := WithRequestContext(context.Background())
	derived, cancel := context.WithCancel(anchored)

	cancel()

	assert.NoError(t, OwnRequestContext(derived).Err())

	plain := context.Background()

	assert.Equal(t, plain, OwnRequestContext(plain))
}

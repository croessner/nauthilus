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

package pluginruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/conncause"
)

// errRefreshUserData mirrors a native plugin call that returned a cancellation received through shared work.
var errRefreshUserData = fmt.Errorf("refresh_user_data: %w", context.Canceled)

// TestInvokePluginCallRecordsRequestCancellation pins that a failed request-bound plugin call is classified against
// the anchored request context, and that calls without an anchored request carry no classification.
func TestInvokePluginCallRecordsRequestCancellation(t *testing.T) {
	canceledRequest, cancel := context.WithCancelCause(context.Background())
	cancel(conncause.ErrClientDisconnected)

	tests := []struct {
		ctx        context.Context
		callErr    error
		name       string
		wantSource string
		wantRecord bool
	}{
		{
			name:       "foreign cancel while own request is active",
			ctx:        conncause.WithRequestContext(context.Background()),
			callErr:    errRefreshUserData,
			wantSource: conncause.CancelSourceForeign,
			wantRecord: true,
		},
		{
			name:       "own request canceled",
			ctx:        conncause.WithRequestContext(canceledRequest),
			callErr:    errRefreshUserData,
			wantSource: conncause.CancelSourceRequest,
			wantRecord: true,
		},
		{name: "unanchored call", ctx: context.Background(), callErr: errRefreshUserData},
		{name: "successful call", ctx: conncause.WithRequestContext(context.Background())},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer := &recordingObserver{}

			_ = invokePluginCall(test.ctx, observer, invokeSpec{moduleName: "mailde_auth", method: "Evaluate"}, func(context.Context) error {
				return test.callErr
			})

			if len(observer.records) != 1 {
				t.Fatalf("records = %#v, want one call", observer.records)
			}

			cancellation := observer.records[0].Cancellation
			if got := cancellation != nil; got != test.wantRecord {
				t.Fatalf("cancellation = %#v, want present=%v", cancellation, test.wantRecord)
			}

			if test.wantRecord && cancellation.Source != test.wantSource {
				t.Fatalf("cancel source = %q, want %q", cancellation.Source, test.wantSource)
			}
		})
	}
}

// TestOperationalObserverLogsRequestCancellation pins that the failure log carries the request cancellation fields
// and that failures without a classification log none of them.
func TestOperationalObserverLogsRequestCancellation(t *testing.T) {
	tests := []struct {
		cancellation *conncause.CancelDiagnostics
		name         string
		want         []string
		unwanted     []string
	}{
		{
			name:         "foreign cancel",
			cancellation: &conncause.CancelDiagnostics{Source: conncause.CancelSourceForeign},
			want:         []string{`"cancel_source":"foreign"`, `"request_context_error":""`, `"request_context_cause":""`},
		},
		{
			name:     "unclassified failure",
			unwanted: []string{conncause.LogKeyCancelSource, conncause.LogKeyRequestContextError},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer

			observer := NewOperationalObserver(slog.New(slog.NewJSONHandler(&buf, nil)), WithOperationalObserverMetrics(nil))
			observer.ObservePluginCall(CallRecord{
				Err: errors.New("failed"), Cancellation: test.cancellation, ModuleName: "mailde_auth",
				ComponentName: "policy", ExtensionPoint: "subject_source", Method: "Evaluate",
			})

			line := buf.String()
			for _, want := range test.want {
				if !strings.Contains(line, want) {
					t.Fatalf("plugin failure log = %s, want %s", line, want)
				}
			}

			for _, unwanted := range test.unwanted {
				if strings.Contains(line, unwanted) {
					t.Fatalf("plugin failure log = %s, must not contain %s", line, unwanted)
				}
			}
		})
	}
}

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
	"log/slog"
	"net/http"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const testCallSession = "2x7Q9callSessionGUID"

// TestOperationalObserverLogsRequestSession pins that a failed request-bound plugin call log names the request
// session, and that calls without a request session do not log an empty session key.
func TestOperationalObserverLogsRequestSession(t *testing.T) {
	tests := []struct {
		name    string
		session string
		want    bool
	}{
		{name: "request-bound call", session: testCallSession, want: true},
		{name: "lifecycle call", session: "", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer

			observer := NewOperationalObserver(slog.New(slog.NewJSONHandler(&buf, nil)), WithOperationalObserverMetrics(nil))
			observer.ObservePluginCall(CallRecord{
				Err: errors.New("failed"), ModuleName: "mailde_auth", ComponentName: "policy",
				ExtensionPoint: "subject_source", Method: "Evaluate", Session: test.session,
			})

			line := buf.String()
			if got := strings.Contains(line, `"session":"`+testCallSession+`"`); got != test.want {
				t.Fatalf("session logged = %v, want %v: %s", got, test.want, line)
			}

			if !test.want && strings.Contains(line, `"session"`) {
				t.Fatalf("observer logged an empty session key: %s", line)
			}
		})
	}
}

// TestInvokePluginCallRecordsContextSession pins that the shared call boundary copies the attached request session
// into the call observation.
func TestInvokePluginCallRecordsContextSession(t *testing.T) {
	observer := &recordingObserver{}
	ctx := withPluginCallSession(context.Background(), testCallSession)

	_ = invokePluginCall(ctx, observer, invokeSpec{moduleName: "example", method: "Evaluate"}, func(context.Context) error {
		return nil
	})

	assertRecordedCallSession(t, observer)
}

// TestRunnerServeHookRecordsSnapshotSession pins that hook calls are attributed to the request snapshot session.
func TestRunnerServeHookRecordsSnapshotSession(t *testing.T) {
	observer := &recordingObserver{}
	hook := &runtimeHook{name: testRuntimeHookName, response: pluginapi.HookResponse{StatusCode: http.StatusOK}}
	runner := newTestRunner(t, &runtimePlugin{}, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterHook(hook)
	}, WithObserver(observer))

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	observer.records = nil

	if _, err := runner.ServeHook(context.Background(), testRuntimeHookQualified, pluginapi.HookRequest{
		Snapshot: pluginapi.RequestSnapshot{Session: testCallSession},
		Method:   http.MethodPost,
		Path:     testRuntimeHookPath,
	}); err != nil {
		t.Fatalf("ServeHook() error = %v", err)
	}

	assertRecordedCallSession(t, observer)
}

// TestNativeAuthnSourcesRecordSnapshotSession pins that environment and subject source calls are attributed to the
// request snapshot session.
func TestNativeAuthnSourcesRecordSnapshotSession(t *testing.T) {
	snapshot := pluginapi.RequestSnapshot{Session: testCallSession}

	tests := []struct {
		call func(nativeAuthnComponentCall) error
		name string
	}{
		{name: "environment", call: func(call nativeAuthnComponentCall) error {
			provider := &nativeAuthnEnvironmentProvider{provider: &recordingAuthnEnvironmentSource{}, call: call}
			_, err := provider.EvaluateEnvironment(t.Context(), pluginapi.EnvironmentRequest{Snapshot: snapshot})

			return err
		}},
		{name: "subject", call: func(call nativeAuthnComponentCall) error {
			provider := &nativeAuthnSubjectProvider{provider: &recordingAuthnSubjectSource{}, call: call}
			_, err := provider.EvaluateSubject(t.Context(), pluginapi.SubjectRequest{Snapshot: snapshot})

			return err
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer := &recordingObserver{}

			if err := test.call(nativeAuthnComponentCall{observer: observer, spec: invokeSpec{moduleName: "example"}}); err != nil {
				t.Fatalf("source call error = %v", err)
			}

			assertRecordedCallSession(t, observer)
		})
	}
}

// assertRecordedCallSession checks that exactly one observation carries the test request session.
func assertRecordedCallSession(t *testing.T, observer *recordingObserver) {
	t.Helper()

	if len(observer.records) != 1 || observer.records[0].Session != testCallSession {
		t.Fatalf("records = %#v, want one call with session %q", observer.records, testCallSession)
	}
}

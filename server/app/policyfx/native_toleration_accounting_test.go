// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/errors"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"

	"github.com/go-redis/redismock/v9"
)

// tolerationAccountingCall is one recorded positive or negative toleration observation.
type tolerationAccountingCall struct {
	ip            string
	username      string
	authenticated bool
}

// recordingToleration records toleration accounting without touching Redis.
type recordingToleration struct {
	tolerate.Tolerate
	calls []tolerationAccountingCall
	mu    sync.Mutex
}

// newRecordingToleration wraps a Redis-less toleration owner so every other method stays safe to call.
func newRecordingToleration() *recordingToleration {
	database, _ := redismock.NewClientMock()

	return &recordingToleration{Tolerate: tolerate.NewTolerateWithDeps(
		&config.FileSettings{}, slog.New(slog.NewTextHandler(io.Discard, nil)), rediscli.NewTestClient(database), 0,
	)}
}

// SetIPAddress records one accounting call.
func (r *recordingToleration) SetIPAddress(_ context.Context, ip string, username string, authenticated bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls = append(r.calls, tolerationAccountingCall{ip: ip, username: username, authenticated: authenticated})
}

// snapshot returns the recorded calls.
func (r *recordingToleration) snapshot() []tolerationAccountingCall {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]tolerationAccountingCall(nil), r.calls...)
}

// TestTolerationAccountsAuthenticationOutcomes reproduces the toleration regression: since the Policy authority cutover
// no production path recorded positive or negative toleration observations, so toleration and the reputation-scaled
// brute-force limits could never become active. Credential outcomes must be accounted exactly once per request.
func TestTolerationAccountsAuthenticationOutcomes(t *testing.T) {
	core.InitPassDBResultPool()
	core.SetDefaultLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))

	testCases := []struct {
		name     string
		verifier nativeAuthOutcomeVerifier
		want     []tolerationAccountingCall
		tls      bool
	}{
		{name: "success counts positive", tls: true, verifier: nativeAuthOutcomeVerifier{authenticated: true},
			want: []tolerationAccountingCall{{ip: "192.0.2.35", username: "terminal@example.test", authenticated: true}}},
		{name: "credential failure counts negative", tls: true, verifier: nativeAuthOutcomeVerifier{},
			want: []tolerationAccountingCall{{ip: "192.0.2.35", username: "terminal@example.test"}}},
		{name: "backend tempfail is not accounted", tls: true,
			verifier: nativeAuthOutcomeVerifier{err: errors.ErrBackendTemporaryFailure}},
		{name: "pre-auth tempfail is not accounted", verifier: nativeAuthOutcomeVerifier{authenticated: true}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := newRecordingToleration()

			runTolerationAccountingRequest(t, testCase.verifier, testCase.tls, recorder)

			got := recorder.snapshot()
			if len(got) != len(testCase.want) {
				t.Fatalf("toleration accounting = %#v, want %#v", got, testCase.want)
			}

			for index := range got {
				if got[index] != testCase.want[index] {
					t.Fatalf("toleration accounting = %#v, want %#v", got, testCase.want)
				}
			}
		})
	}
}

// runTolerationAccountingRequest answers one gRPC authentication request with the given toleration owner.
func runTolerationAccountingRequest(
	t *testing.T,
	verifier nativeAuthOutcomeVerifier,
	tls bool,
	toleration tolerate.Tolerate,
) {
	t.Helper()

	probe := &nativeAuthExecutionProbe{postActionRequests: make(chan pluginapi.PostActionRequest, 1)}
	configured, state := nativeAuthGenerationCandidateFromFixture(t, nativeTerminalOutcomeFixture, probe)
	enableTerminalOutcomeTLSControl(t, configured)

	runtime := newNativeAuthGenerationRuntime(t, configured, state)
	application := newNativeAuthApplicationWithDeps(t, configured, runtime.service, verifier,
		slog.New(slog.NewTextHandler(io.Discard, nil)), func(deps *core.AuthDeps) { deps.Tolerate = toleration })

	requestContext, finalization := core.ContextWithPostActionExecutionGate(t.Context())

	options := []core.AuthContextOption{core.WithProtocol(definitions.ProtoIMAP), core.WithClientIP("192.0.2.35")}
	if tls {
		options = append(options, core.WithXSSL("on"), core.WithXSSLProtocol("TLSv1.3"))
	}

	if _, err := application.Authenticate(requestContext, core.AuthInput{
		Credentials: core.NewCredentials(
			core.WithUsername("terminal@example.test"),
			core.WithPassword(secret.FromBytes([]byte("toleration-accounting-password"))),
		),
		Context:       core.NewAuthContext(options...),
		CorrelationID: "toleration-accounting",
		EntryPoint:    core.AuthnEntryBackchannel,
		Service:       definitions.ServGRPC,
	}); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	finalization.Complete()

	select {
	case <-probe.postActionRequests:
	case <-time.After(5 * time.Second):
		t.Fatal("selected post-action was not executed")
	}
}

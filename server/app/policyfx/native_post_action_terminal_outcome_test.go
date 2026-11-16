// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/errors"
	"github.com/croessner/nauthilus/v4/server/secret"
)

// nativeTerminalOutcomeFixture mirrors the production TLS enforcement and terminal rules that select the analytics
// post-action, so the captured post-action request can be compared with the answered terminal result.
const nativeTerminalOutcomeFixture = `policy:
  namespaces:
    authn:
      domain_plans:
        configured:
          checkpoints:
            pre_auth:
              providers:
                - {name: tls_encryption, use: authn/builtin/tls_encryption, actions: [authenticate]}
            auth_backend:
              providers:
                - {name: ldap_backend, use: authn/builtin/ldap_backend}
            auth_decision: {providers: []}
      policy_sets:
        configured:
          rules:
            - name: standard_tls_enforcement
              checkpoint: pre_auth
              actions: [authenticate]
              require_providers: [tls_encryption]
              if: {attribute: nauthilus.auth.tls.secure, is: false}
              then:
                decision: tempfail
                outcome_marker: auth.outcome.tls_required
                fsm_event_marker: auth.fsm.event.pre_auth_tempfail
                response_marker: auth.response.tempfail.no_tls
                obligations: [{id: authn/plugin.example.post_action}]
            - name: standard_backend_tempfail
              checkpoint: auth_decision
              actions: [authenticate]
              if: {attribute: nauthilus.auth.backend.tempfail, is: true}
              then:
                decision: tempfail
                outcome_marker: auth.outcome.backend_tempfail
                fsm_event_marker: auth.fsm.event.auth_tempfail
                response_marker: auth.response.tempfail
                obligations: [{id: authn/plugin.example.post_action}]
            - name: standard_auth_failure
              checkpoint: auth_decision
              actions: [authenticate]
              if: {attribute: backend.authenticated, is: false}
              then:
                decision: deny
                outcome_marker: auth.outcome.auth_failure
                fsm_event_marker: auth.fsm.event.auth_deny
                response_marker: auth.response.fail
                obligations: [{id: authn/plugin.example.post_action}]
            - name: standard_auth_success
              checkpoint: auth_decision
              actions: [authenticate]
              if: {attribute: backend.authenticated, is: true}
              then:
                decision: permit
                outcome_marker: auth.outcome.auth_success
                fsm_event_marker: auth.fsm.event.auth_permit
                response_marker: auth.response.ok
                obligations: [{id: authn/plugin.example.post_action}]
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
      default_policy: authn/standard_auth
      plans:
        pre_auth: {policy_sets: [authn/configured]}
        auth_decision: {policy_sets: [authn/configured]}
`

// terminalOutcomeFixturePath is the shared diagnostic contract fixture that the ClickHouse integration test replays.
const terminalOutcomeFixturePath = "../../../contrib/plugins/clickhouse/testdata/diagnostic_contract/terminal_outcomes.json"

// terminalOutcomeCase describes one request shape whose bound outcome is pinned by the shared fixture.
type terminalOutcomeCase struct {
	name       string
	verifier   nativeAuthOutcomeVerifier
	wantResult core.AuthDecision
	tls        bool
}

// terminalOutcomeFixture is the decoded shared terminal outcome contract.
type terminalOutcomeFixture struct {
	Cases []struct {
		Name    string                `json:"name"`
		Outcome pluginapi.AuthOutcome `json:"outcome"`
	} `json:"cases"`
}

// TestNativePostActionSeesAnsweredTerminalOutcome reproduces the production finding where a TLS-required tempfail
// (HTTP 500) was projected into the analytics post-action as a credential failure (403, "Invalid login or password").
// The bound outcome must equal the shared contract fixture exactly.
func TestNativePostActionSeesAnsweredTerminalOutcome(t *testing.T) {
	core.InitPassDBResultPool()
	core.SetDefaultLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))

	want := loadTerminalOutcomeFixture(t)
	testCases := []terminalOutcomeCase{
		{name: "tls required tempfail", verifier: nativeAuthOutcomeVerifier{authenticated: true},
			wantResult: core.AuthDecisionTempFail},
		{name: "backend tempfail", tls: true, verifier: nativeAuthOutcomeVerifier{err: errors.ErrBackendTemporaryFailure},
			wantResult: core.AuthDecisionTempFail},
		{name: "credential failure", tls: true, verifier: nativeAuthOutcomeVerifier{}, wantResult: core.AuthDecisionFail},
		{name: "success", tls: true, verifier: nativeAuthOutcomeVerifier{authenticated: true}, wantResult: core.AuthDecisionOK},
	}

	if len(testCases) != len(want) {
		t.Fatalf("fixture cases = %d, test cases = %d", len(want), len(testCases))
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			expected, found := want[testCase.name]
			if !found {
				t.Fatalf("fixture lacks case %q", testCase.name)
			}

			request, outcome := runTerminalOutcomeRequest(t, testCase)
			if outcome.Decision != testCase.wantResult {
				t.Fatalf("answered decision = %q, want %q", outcome.Decision, testCase.wantResult)
			}

			if request.Outcome != expected {
				t.Fatalf("post-action outcome = %+v, want fixture %+v", request.Outcome, expected)
			}

			diagnostics := request.Snapshot.Diagnostics
			if diagnostics.HTTPStatus != outcome.HTTPStatus || diagnostics.StatusMessage != outcome.StatusMessage ||
				diagnostics.HTTPStatus != expected.HTTPStatus || diagnostics.StatusMessage != expected.StatusMessage {
				t.Fatalf("post-action diagnostics = %d/%q, answered %d/%q, want %d/%q",
					diagnostics.HTTPStatus, diagnostics.StatusMessage, outcome.HTTPStatus, outcome.StatusMessage,
					expected.HTTPStatus, expected.StatusMessage)
			}
		})
	}
}

// loadTerminalOutcomeFixture decodes the shared terminal outcome contract keyed by case name.
func loadTerminalOutcomeFixture(t *testing.T) map[string]pluginapi.AuthOutcome {
	t.Helper()

	content, err := os.ReadFile(terminalOutcomeFixturePath)
	if err != nil {
		t.Fatalf("read terminal outcome fixture: %v", err)
	}

	var fixture terminalOutcomeFixture
	if err = json.Unmarshal(content, &fixture); err != nil {
		t.Fatalf("decode terminal outcome fixture: %v", err)
	}

	cases := make(map[string]pluginapi.AuthOutcome, len(fixture.Cases))
	for _, fixtureCase := range fixture.Cases {
		cases[fixtureCase.Name] = fixtureCase.Outcome
	}

	return cases
}

// runTerminalOutcomeRequest answers one request through the production application and returns the post-action
// request observed after the finalization boundary.
func runTerminalOutcomeRequest(
	t *testing.T,
	testCase terminalOutcomeCase,
) (pluginapi.PostActionRequest, *core.AuthOutcome) {
	t.Helper()

	probe := &nativeAuthExecutionProbe{postActionRequests: make(chan pluginapi.PostActionRequest, 1)}
	configured, state := nativeAuthGenerationCandidateFromFixture(t, nativeTerminalOutcomeFixture, probe)
	enableTerminalOutcomeTLSControl(t, configured)

	runtime := newNativeAuthGenerationRuntime(t, configured, state)
	application := newNativeAuthApplicationWithVerifier(t, configured, runtime.service, testCase.verifier)

	requestContext, finalization := core.ContextWithPostActionExecutionGate(t.Context())

	options := []core.AuthContextOption{
		core.WithProtocol(definitions.ProtoIMAP),
		core.WithClientIP("192.0.2.35"),
	}
	if testCase.tls {
		options = append(options, core.WithXSSL("on"), core.WithXSSLProtocol("TLSv1.3"))
	}

	outcome, err := application.Authenticate(requestContext, core.AuthInput{
		Credentials: core.NewCredentials(
			core.WithUsername("terminal@example.test"),
			core.WithPassword(secret.FromBytes([]byte("terminal-outcome-test-password"))),
		),
		Context:       core.NewAuthContext(options...),
		CorrelationID: "terminal-outcome-" + testCase.name,
		EntryPoint:    core.AuthnEntryBackchannel,
		Service:       definitions.ServGRPC,
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	finalization.Complete()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	select {
	case request := <-probe.postActionRequests:
		return request, outcome
	case <-ctx.Done():
		t.Fatalf("post-action was not executed for %q (answered %#v)", testCase.name, outcome)
	}

	return pluginapi.PostActionRequest{}, nil
}

// enableTerminalOutcomeTLSControl enables the TLS runtime module the production TLS enforcement rule depends on.
func enableTerminalOutcomeTLSControl(t *testing.T, configured *config.FileSettings) {
	t.Helper()

	var runtimeModule config.RuntimeModule
	if err := runtimeModule.Set(definitions.ControlTLSEncryption); err != nil {
		t.Fatalf("set TLS control: %v", err)
	}

	configured.Server.RuntimeModules = []*config.RuntimeModule{&runtimeModule}
}

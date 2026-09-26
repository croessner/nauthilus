// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/errors"
	"github.com/croessner/nauthilus/v4/server/secret"

	"github.com/gin-gonic/gin"
)

// nativeSubjectBackendFixture schedules one native subject source after a separate backend checkpoint.
const nativeSubjectBackendFixture = `policy:
  namespaces:
    authn:
      providers:
        plugin.example.subject.risk:
          kind: plugin
          module: example
          targets: [{action: authenticate}]
          executions: [host_sync]
      domain_plans:
        configured:
          checkpoints:
            auth_backend:
              providers:
                - {name: ldap_backend, use: authn/builtin/ldap_backend}
            subject_analysis:
              providers:
                - name: native_subject
                  use: authn/plugin.example.subject.risk
                  actions: [authenticate]
%s
            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
      default_policy: authn/standard_auth
`

// nativeSubjectRunIf renders the optional run_if block of the subject provider instance.
func nativeSubjectRunIf(authState string) string {
	if authState == "" {
		return ""
	}

	return fmt.Sprintf("                  run_if: {auth_state: %s}", authState)
}

// nativeAuthOutcomeVerifier returns one fixed backend outcome without contacting a real backend.
type nativeAuthOutcomeVerifier struct {
	err           error
	authenticated bool
}

// Verify returns either the configured backend error or one typed LDAP result.
func (v nativeAuthOutcomeVerifier) Verify(
	_ *gin.Context,
	auth *core.AuthState,
	_ []*core.PassDBMap,
) (*core.PassDBResult, error) {
	if v.err != nil {
		return nil, v.err
	}

	result := core.GetPassDBResultFromPool()
	result.UserFound = true
	result.Authenticated = v.authenticated
	result.AccountField = "uid"
	result.Account = auth.Request.Username
	result.Backend = definitions.BackendLDAP
	result.Attributes = map[string][]any{"uid": {auth.Request.Username}}

	return result, nil
}

// TestNativeSubjectSourceWithoutBackendResultAnswersTempFail proves that a backend temporary failure never turns a
// subject provider scheduled in a later checkpoint into an application error (HTTP 500), whatever its run_if state.
func TestNativeSubjectSourceWithoutBackendResultAnswersTempFail(t *testing.T) {
	core.InitPassDBResultPool()
	core.SetDefaultLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))

	tempFail := nativeAuthOutcomeVerifier{err: errors.ErrBackendTemporaryFailure}
	rejected := nativeAuthOutcomeVerifier{}

	testCases := []struct {
		name         string
		authState    string
		verifier     nativeAuthOutcomeVerifier
		wantDecision core.AuthDecision
		wantSubject  int32
	}{
		{name: "tempfail any", authState: "any", verifier: tempFail, wantDecision: core.AuthDecisionTempFail},
		{name: "tempfail default", verifier: tempFail, wantDecision: core.AuthDecisionTempFail},
		{
			name: "tempfail unauthenticated", authState: "unauthenticated", verifier: tempFail,
			wantDecision: core.AuthDecisionTempFail,
		},
		{
			name: "tempfail authenticated", authState: "authenticated", verifier: tempFail,
			wantDecision: core.AuthDecisionTempFail,
		},
		{
			name: "rejected any", authState: "any", verifier: rejected,
			wantDecision: core.AuthDecisionFail, wantSubject: 1,
		},
		{
			name: "rejected authenticated", authState: "authenticated", verifier: rejected,
			wantDecision: core.AuthDecisionFail,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			probe := &nativeAuthExecutionProbe{}
			fixture := fmt.Sprintf(nativeSubjectBackendFixture, nativeSubjectRunIf(testCase.authState))
			configured, state := nativeAuthGenerationCandidateFromFixture(t, fixture, probe)
			runtime := newNativeAuthGenerationRuntime(t, configured, state)
			application := newNativeAuthApplicationWithVerifier(t, configured, runtime.service, testCase.verifier)

			outcome, err := authenticateNativeSubjectRequest(t, application)
			if err != nil {
				t.Fatalf("Authenticate() error = %v, want %q outcome", err, testCase.wantDecision)
			}

			if outcome == nil || outcome.Decision != testCase.wantDecision {
				t.Fatalf("Authenticate() outcome = %#v, want %q", outcome, testCase.wantDecision)
			}

			if calls := probe.subjectCalls.Load(); calls != testCase.wantSubject {
				t.Fatalf("native subject calls = %d, want %d", calls, testCase.wantSubject)
			}
		})
	}
}

// authenticateNativeSubjectRequest runs one admitted production authentication request and returns its raw result.
func authenticateNativeSubjectRequest(
	t *testing.T,
	application core.AuthApplicationService,
) (*core.AuthOutcome, error) {
	t.Helper()

	requestContext, finalization := core.ContextWithPostActionExecutionGate(t.Context())
	defer finalization.Complete()

	return application.Authenticate(requestContext, core.AuthInput{
		Credentials: core.NewCredentials(
			core.WithUsername("native@example.test"),
			core.WithPassword(secret.FromBytes([]byte("native-auth-test-password"))),
		),
		Context: core.NewAuthContext(
			core.WithProtocol(definitions.ProtoIMAP),
			core.WithClientIP("192.0.2.35"),
		),
		CorrelationID: "native-subject-backend-" + t.Name(),
		EntryPoint:    core.AuthnEntryBackchannel,
		Service:       definitions.ServGRPC,
	})
}

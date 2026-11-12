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
	"strings"
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

// TestNativeBackendTempFailLogNamesBackendCause proves that the terminal tempfail line blames the failed backend and
// names its error. The subject provider is only skipped behind it, so the request must reach the backend tempfail
// rule instead of reporting the subject_analysis checkpoint as an indeterminate policy, which would send operators
// to the wrong component.
func TestNativeBackendTempFailLogNamesBackendCause(t *testing.T) {
	core.InitPassDBResultPool()

	probe := &nativeAuthExecutionProbe{}
	fixture := fmt.Sprintf(nativeSubjectBackendFixture, nativeSubjectRunIf("any"))
	configured, state := nativeAuthGenerationCandidateFromFixture(t, fixture, probe)
	runtime := newNativeAuthGenerationRuntime(t, configured, state)
	backendErr := errors.ErrBackendTemporaryFailure.WithDetail("user lookup failed: connection refused")
	logger, logs := newNativeCapturingLogger()
	application := newNativeAuthApplicationWithLogger(
		t, configured, runtime.service, nativeAuthOutcomeVerifier{err: backendErr}, logger,
	)

	recorder := serveNativeSubjectJSON(t, application, configured, logger)

	assertNativeSubjectJSONTempFail(t, recorder)

	line := nativeTempFailSummaryLine(t, logs.String())
	wantFields := []string{
		"level=WARN",
		"tempfail_reason=backend_tempfail",
		"checkpoint=auth_decision",
		"policy_rule=standard_backend_tempfail",
		"skipped_providers=native_subject:backend_unavailable",
		`tempfail_error="backend_temporary_failure: user lookup failed: connection refused"`,
	}

	for _, field := range wantFields {
		if !strings.Contains(line, field) {
			t.Fatalf("tempfail summary line misses %q:\n%s", field, line)
		}
	}
}

// nativeTempFailSummaryLine returns the single terminal tempfail summary line of one request log.
func nativeTempFailSummaryLine(t *testing.T, logs string) string {
	t.Helper()

	var lines []string

	for line := range strings.SplitSeq(logs, "\n") {
		if strings.Contains(line, `msg="`+definitions.TempFailDefault+`"`) {
			lines = append(lines, line)
		}
	}

	if len(lines) != 1 {
		t.Fatalf("tempfail summary lines = %d, want 1:\n%s", len(lines), logs)
	}

	return lines[0]
}

// TestNativeSubjectSourceWithoutCredentialAnswersFail proves that a request the host rejects before any backend runs
// (an empty password) ends as a regular login failure whatever the subject provider's run_if state is. The skipped
// subject provider must not turn the rejection into a temporary failure.
func TestNativeSubjectSourceWithoutCredentialAnswersFail(t *testing.T) {
	core.InitPassDBResultPool()
	core.SetDefaultLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))

	for _, authState := range []string{"any", "", "unauthenticated", "authenticated"} {
		t.Run("auth_state "+authState, func(t *testing.T) {
			probe := &nativeAuthExecutionProbe{}
			fixture := fmt.Sprintf(nativeSubjectBackendFixture, nativeSubjectRunIf(authState))
			configured, state := nativeAuthGenerationCandidateFromFixture(t, fixture, probe)
			runtime := newNativeAuthGenerationRuntime(t, configured, state)
			application := newNativeAuthApplicationWithVerifier(
				t, configured, runtime.service, nativeAuthOutcomeVerifier{authenticated: true},
			)

			outcome, err := authenticateNativeSubjectCredentials(
				t, application, core.NewCredentials(core.WithUsername(nativeSubjectTestUsername)),
			)
			if err != nil || outcome == nil || outcome.Decision != core.AuthDecisionFail {
				t.Fatalf("Authenticate() = %#v / %v, want a login failure", outcome, err)
			}

			if calls := probe.subjectCalls.Load(); calls != 0 {
				t.Fatalf("native subject calls = %d, want 0", calls)
			}
		})
	}
}

// nativeSubjectTestUsername is the login name of every native subject test request.
const nativeSubjectTestUsername = "native@example.test"

// authenticateNativeSubjectRequest runs one admitted production authentication request and returns its raw result.
func authenticateNativeSubjectRequest(
	t *testing.T,
	application core.AuthApplicationService,
) (*core.AuthOutcome, error) {
	t.Helper()

	return authenticateNativeSubjectCredentials(t, application, core.NewCredentials(
		core.WithUsername(nativeSubjectTestUsername),
		core.WithPassword(secret.FromBytes([]byte("native-auth-test-password"))),
	))
}

// authenticateNativeSubjectCredentials runs one admitted production authentication request with explicit credentials.
func authenticateNativeSubjectCredentials(
	t *testing.T,
	application core.AuthApplicationService,
	credentials core.Credentials,
) (*core.AuthOutcome, error) {
	t.Helper()

	requestContext, finalization := core.ContextWithPostActionExecutionGate(t.Context())
	defer finalization.Complete()

	return application.Authenticate(requestContext, core.AuthInput{
		Credentials: credentials,
		Context: core.NewAuthContext(
			core.WithProtocol(definitions.ProtoIMAP),
			core.WithClientIP("192.0.2.35"),
		),
		CorrelationID: "native-subject-backend-" + t.Name(),
		EntryPoint:    core.AuthnEntryBackchannel,
		Service:       definitions.ServGRPC,
	})
}

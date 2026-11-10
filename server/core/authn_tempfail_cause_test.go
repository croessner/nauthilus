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
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/report"
	"github.com/gin-gonic/gin"
)

// authnTempFailCauseCase describes one terminal temporary failure and the cause its log line must name.
type authnTempFailCauseCase struct {
	prepare    func(*testing.T, *authnFSMGuardHarness)
	name       string
	checkpoint policy.Stage
	effect     decision.Effect
	code       decision.StatusCode
	wantFields []string
}

// TestAuthnUnselectedTempFailLogsCause pins that a temporary failure decided without a selected policy rule still
// writes the terminal tempfail log line, with the client-visible text and the cause, so operators can tell why a
// request was answered "Temporary server problem, try again later".
func TestAuthnUnselectedTempFailLogsCause(t *testing.T) {
	authenticated := authnFSMGuardVerifier{authenticated: true, userFound: true}

	tests := []authnTempFailCauseCase{
		{
			name: "provider outage before the backend", checkpoint: policy.StagePreAuth,
			effect: decision.EffectIndeterminate, code: decision.StatusCodeProviderUnavailable,
			wantFields: []string{
				"tempfail_reason=policy_indeterminate", "checkpoint=pre_auth", "status_code=provider_unavailable",
			},
		},
		{
			name: "evaluation failure after a failed check", prepare: runAuthnFSMGuardBackendAndSubject,
			checkpoint: policy.StageAuthDecision, effect: decision.EffectIndeterminate,
			code: decision.StatusCodeEvaluationFailed,
			wantFields: []string{
				"tempfail_reason=policy_indeterminate", "checkpoint=auth_decision", "status_code=evaluation_failed",
			},
		},
		{
			name: "ok without host evidence", prepare: injectAuthnFSMGuardUnbackedOK,
			checkpoint: policy.StageSubjectAnalysis, effect: decision.EffectNotApplicable,
			code:       decision.StatusCodeNotApplicable,
			wantFields: []string{"tempfail_reason=auth_fsm_guard", "checkpoint=subject_analysis"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newAuthnFSMGuardHarness(t, policy.OperationAuthenticate, authenticated, testLuaSubject{})
			if test.prepare != nil {
				test.prepare(t, harness)
			}

			result, err := harness.execution.finalize(
				string(test.checkpoint),
				mustAuthnDecisionResponseWithCode(t, test.effect, test.code),
				harness.execution.currentResult(),
			)
			if err != nil {
				t.Fatalf("finalize() error = %v", err)
			}

			if result.currentDecision() != AuthDecisionTempFail {
				t.Fatalf("decision = %s, want tempfail", result.currentDecision())
			}

			assertAuthnTempFailLogLine(t, harness, test.wantFields)
		})
	}
}

// assertAuthnTempFailLogLine checks that exactly one tempfail summary line names the session, text, and cause.
func assertAuthnTempFailLogLine(t *testing.T, harness *authnFSMGuardHarness, wantFields []string) {
	t.Helper()

	var lines []string

	for line := range strings.SplitSeq(harness.logs.String(), "\n") {
		if strings.Contains(line, `msg="`+definitions.TempFailDefault+`"`) {
			lines = append(lines, line)
		}
	}

	if len(lines) != 1 {
		t.Fatalf("tempfail summary lines = %d, want 1:\n%s", len(lines), harness.logs.String())
	}

	want := append([]string{
		definitions.LogKeyStatus + "=tempfail",
		"session=" + harness.execution.auth.Runtime.GUID,
	}, wantFields...)

	for _, field := range want {
		if !strings.Contains(lines[0], field) {
			t.Fatalf("tempfail line misses %q:\n%s", field, lines[0])
		}
	}
}

// TestAuthnSelectedTempFailLogsRuleAndOutcome pins that a temporary failure selected by a policy rule names the rule
// and its outcome marker in the terminal tempfail log line.
func TestAuthnSelectedTempFailLogsRuleAndOutcome(t *testing.T) {
	authenticated := authnFSMGuardVerifier{authenticated: true, userFound: true}
	harness := newAuthnFSMGuardHarness(t, policy.OperationAuthenticate, authenticated, testLuaSubject{})
	runAuthnFSMGuardBackendAndSubject(t, harness)

	checkpoint := string(policy.StageAuthDecision)
	harness.execution.CaptureAuthnDecision(context.Background(), decision.Target{}, checkpoint, &report.FinalDecision{
		PolicyName: "standard_backend_tempfail", Stage: policy.StageAuthDecision, Effect: policy.DecisionTempFail,
		OutcomeMarker: "auth.outcome.backend_tempfail", FSMEventMarker: policy.FSMEventMarkerAuthTempFail,
		ResponseMarker: policy.ResponseMarkerTempFail,
	})

	result, err := harness.execution.finalize(
		checkpoint,
		mustAuthnDecisionResponse(t, decision.EffectIndeterminate),
		harness.execution.currentResult(),
	)
	if err != nil {
		t.Fatalf("finalize() error = %v", err)
	}

	if result.currentDecision() != AuthDecisionTempFail {
		t.Fatalf("decision = %s, want tempfail", result.currentDecision())
	}

	assertAuthnTempFailLogLine(t, harness, []string{
		"tempfail_reason=policy_indeterminate", "checkpoint=auth_decision",
		"policy_rule=standard_backend_tempfail", "outcome_marker=auth.outcome.backend_tempfail",
	})
}

// TestAuthnUnselectedTempFailKeepsOperatorTempFailMessage pins that the configured auth.response.tempfail_message
// replaces the built-in text on the unselected tempfail path both for the client and in the status_message of the
// log line, which also names the cause.
func TestAuthnUnselectedTempFailKeepsOperatorTempFailMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authenticated := authnFSMGuardVerifier{authenticated: true, userFound: true}
	harness := newAuthnFSMGuardHarness(t, policy.OperationAuthenticate, authenticated, testLuaSubject{})
	harness.cfg.GetServer().AuthResponse = config.AuthResponseSection{TempFailMessage: authResponseTestTempFail}

	result, err := harness.execution.finalize(
		string(policy.StagePreAuth),
		mustAuthnDecisionResponseWithCode(t, decision.EffectIndeterminate, decision.StatusCodeProviderUnavailable),
		harness.execution.currentResult(),
	)
	if err != nil {
		t.Fatalf("finalize() error = %v", err)
	}

	ctx, recorder := newHTTPAuthResponseTestContext(http.MethodGet, "/api/v1/auth/nginx")
	NewHTTPAuthResponseRenderer(httpAuthResponseTestDeps()).RenderAuth(ctx, AuthInput{Mode: AuthModeAuthenticate, Service: definitions.ServNginx},
		result.auth)

	if got := recorder.Header().Get("Auth-Status"); got != authResponseTestTempFail {
		t.Fatalf("Auth-Status = %q, want operator tempfail text %q", got, authResponseTestTempFail)
	}

	assertAuthnTempFailLogLine(t, harness, []string{
		"tempfail_reason=policy_indeterminate", `status_message="` + authResponseTestTempFail + `"`,
	})
}

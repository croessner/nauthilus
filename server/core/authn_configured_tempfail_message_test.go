// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package core

import (
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/model/authdto"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyfsm "github.com/croessner/nauthilus/v4/server/policy/fsm"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/go-redis/redismock/v9"
)

const configuredTempFailMessage = "Maintenance in progress, please try again later"

// TestAuthnCandidateConfiguredTempFailKeepsLiteralResponseMessage reproduces a configured tempfail rule whose
// literal response_message was replaced by the generic temporary-failure text.
func TestAuthnCandidateConfiguredTempFailKeepsLiteralResponseMessage(t *testing.T) {
	for _, checkpoint := range []policy.Stage{policy.StagePreAuth, policy.StageAuthDecision} {
		t.Run(string(checkpoint), func(t *testing.T) {
			outcome := runAuthnCandidateConfiguredTempFail(t, checkpoint)

			if outcome.Decision != AuthDecisionTempFail {
				t.Fatalf("configured decision = %q, want tempfail", outcome.Decision)
			}

			if outcome.StatusMessage != configuredTempFailMessage {
				t.Fatalf("configured tempfail message = %q, want %q", outcome.StatusMessage, configuredTempFailMessage)
			}

			if outcome.HTTPStatus != http.StatusInternalServerError {
				t.Fatalf("configured tempfail status = %d, want %d", outcome.HTTPStatus, http.StatusInternalServerError)
			}
		})
	}
}

// runAuthnCandidateConfiguredTempFail authenticates through a catalog whose configured checkpoint answers tempfail.
func runAuthnCandidateConfiguredTempFail(t *testing.T, checkpoint policy.Stage) *AuthOutcome {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t)
	username := "candidate-tempfail@example.test"
	manager := accountcache.NewManager(cfg)
	manager.Set(cfg, username, definitions.ProtoIMAP, "", username)

	db, _ := redismock.NewClientMock()
	current := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: manager,
		BackendAuthenticationCache: NewPositiveBackendAuthenticationCache(time.Now),
	})
	acceptor := &authnCandidateAcceptAll{}
	catalog := compileAuthnCandidateConfiguredCatalogWithRule(
		t, acceptor, policy.OperationAuthenticate, checkpoint, newAuthnCandidateConfiguredTempFailRule(t, checkpoint),
	)
	runtime := newAuthnCandidateDecisionServiceFromCatalog(t, cfg, acceptor, catalog)

	adapter, err := NewAuthnCandidateApplicationService(current, runtime, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	installAuthnCandidateServices(
		t,
		backendAuthenticationContractVerifier{calls: &atomic.Int32{}},
		backendAuthenticationContractSubject{calls: &atomic.Int32{}},
	)
	bindRegisteredAuthnApplicationHostServicesForTest(current)

	input := NewAuthInputFromStructuredRequest(
		definitions.ServJSON,
		AuthModeAuthenticate,
		authdto.Request{
			Username: username, Password: "candidate-secret", Protocol: definitions.ProtoIMAP,
			ClientIP: "203.0.113.79", Method: "plain",
		},
	)

	return authenticateAuthnCandidate(t, "configured tempfail", adapter, input)
}

// newAuthnCandidateConfiguredTempFailRule builds the rule a configured `decision: tempfail` with a literal
// response_message normalizes to.
func newAuthnCandidateConfiguredTempFailRule(t *testing.T, checkpoint policy.Stage) registry.PolicyRule {
	t.Helper()

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Kind: registry.ExpressionKindAlways})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	message, err := registry.NewPolicyResponseMessage(registry.PolicyResponseMessageInput{
		From: policy.ResponseSourceLiteral, Text: configuredTempFailMessage,
	})
	if err != nil {
		t.Fatalf("NewPolicyResponseMessage() error = %v", err)
	}

	rule, err := registry.NewAuthnPolicyRule(registry.PolicyRuleInput{
		Name:       "configured_tempfail_" + string(checkpoint),
		Checkpoint: string(checkpoint), Actions: []string{string(policy.OperationAuthenticate)},
		Expression: expression, Decision: decision.EffectIndeterminate, Reason: "maintenance",
		FSMEventMarker:  policyfsm.DefaultRuleMarker(checkpoint, policy.DecisionTempFail),
		ResponseMessage: message,
	})
	if err != nil {
		t.Fatalf("NewAuthnPolicyRule() error = %v", err)
	}

	return rule
}

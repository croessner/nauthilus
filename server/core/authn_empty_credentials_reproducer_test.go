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
	"io"
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	policyfsm "github.com/croessner/nauthilus/v4/server/policy/fsm"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/go-redis/redismock/v9"
)

// authnEmptyCredentialCase describes one empty-credential authenticate request through the builtin authn catalog.
type authnEmptyCredentialCase struct {
	prepare func(*AuthInput)
	name    string
}

// TestAuthnEmptyCredentialsSettleAsInvalidLogin pins that an empty username or password value is no input error but
// an ordinary failed login: the builtin auth_failure rule denies it with the regular invalid-login message.
func TestAuthnEmptyCredentialsSettleAsInvalidLogin(t *testing.T) {
	clearUsername := func(input *AuthInput) { input.Credentials.Username = "" }
	clearPassword := func(input *AuthInput) { input.Credentials.Password = secret.Value{} }

	cases := []authnEmptyCredentialCase{
		{name: "authenticate empty username", prepare: clearUsername},
		{name: "authenticate empty password", prepare: clearPassword},
		{name: "authenticate empty username and password", prepare: func(input *AuthInput) {
			clearUsername(input)
			clearPassword(input)
		}},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			runAuthnEmptyCredentialCase(t, test)
		})
	}
}

// runAuthnEmptyCredentialCase executes one case against the registered application service and builtin catalog.
func runAuthnEmptyCredentialCase(t *testing.T, test authnEmptyCredentialCase) {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t)
	db, mock := redismock.NewClientMock()

	var captured *authnCandidateExecution

	base := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db),
	})
	host := &authnCandidateInjectedHost{
		base:      base,
		configure: func(execution *authnCandidateExecution) { captured = execution },
	}

	adapter, err := NewAuthnCandidateApplicationService(
		host, newAuthnCandidateDecisionService(t, cfg, &authnCandidateAcceptAll{}), mustAuthnCandidateAuthentication(t),
	)
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	installAuthnCandidateServices(t, failingPasswordVerifier{}, testLuaSubject{})
	bindRegisteredAuthnApplicationHostServicesForTest(base)

	input := authnApplicationTestInput(AuthModeAuthenticate)
	test.prepare(&input)

	outcome := runAuthnEmptyCredentialOperation(t, adapter, input)
	assertAuthnEmptyCredentialOutcome(t, test, outcome, captured)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected Redis operation: %v", err)
	}
}

// runAuthnEmptyCredentialOperation authenticates the input and fails the test on any application error.
func runAuthnEmptyCredentialOperation(t *testing.T, adapter AuthApplicationService, input AuthInput) *AuthOutcome {
	t.Helper()

	ctx, gate := authnCandidateTestContext(context.Background(), input)
	defer gate.Complete()

	outcome, err := adapter.Authenticate(ctx, input)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	return outcome
}

// assertAuthnEmptyCredentialOutcome checks the client-visible outcome and the selected builtin rule.
func assertAuthnEmptyCredentialOutcome(
	t *testing.T,
	test authnEmptyCredentialCase,
	outcome *AuthOutcome,
	captured *authnCandidateExecution,
) {
	t.Helper()

	if outcome == nil || captured == nil {
		t.Fatalf("outcome = %#v, execution captured = %v", outcome, captured != nil)
	}

	if outcome.Decision != AuthDecisionFail || outcome.StatusMessage != definitions.PasswordFail ||
		outcome.TerminalState != policyfsm.StateAuthFail {
		t.Fatalf("%s outcome decision/status/terminal = %s/%q/%s, want fail/%q/%s", test.name, outcome.Decision,
			outcome.StatusMessage, outcome.TerminalState, definitions.PasswordFail, policyfsm.StateAuthFail)
	}

	selected := captured.selectedDecision(string(policy.StageAuthDecision))
	if selected == nil || selected.Effect != policy.DecisionDeny || selected.OutcomeMarker != policy.OutcomeMarkerAuthFailure ||
		selected.ResponseMarker != policy.ResponseMarkerFail {
		t.Fatalf("%s selected decision = %#v, want the ordinary auth_failure deny", test.name, selected)
	}
}

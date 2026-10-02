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

package core

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyfsm "github.com/croessner/nauthilus/v4/server/policy/fsm"
	"github.com/croessner/nauthilus/v4/server/secret"
)

// authnFSMGuardUnselectedCase binds host evidence and one unselected checkpoint response to the enforced FSM path.
type authnFSMGuardUnselectedCase struct {
	prepare       func(*testing.T, *authnFSMGuardHarness)
	verifier      PasswordVerifier
	name          string
	operation     policy.Operation
	checkpoint    policy.Stage
	effect        decision.Effect
	wantDecision  AuthDecision
	wantTerminal  string
	wantPath      []string
	wantViolation bool
}

// authnFSMGuardUnselectedCases lists finalizations without a captured selection on every decision.
func authnFSMGuardUnselectedCases() []authnFSMGuardUnselectedCase {
	authenticated := authnFSMGuardVerifier{authenticated: true, userFound: true}
	authenticate := policy.OperationAuthenticate

	return []authnFSMGuardUnselectedCase{
		{
			name: "ok without host evidence fails closed", operation: authenticate, verifier: authenticated,
			prepare: injectAuthnFSMGuardUnbackedOK, checkpoint: policy.StageSubjectAnalysis,
			effect: decision.EffectNotApplicable, wantDecision: AuthDecisionTempFail,
			wantTerminal: policyfsm.StateAuthTempFail, wantViolation: true,
			wantPath: authnFSMGuardHostPath(authenticate, policy.FSMEventMarkerAuthTempFail),
		},
		{
			name: "ok with a verified credential answers ok", operation: authenticate, verifier: authenticated,
			prepare: runAuthnFSMGuardBackendAndSubject, checkpoint: policy.StageSubjectAnalysis,
			effect: decision.EffectNotApplicable, wantDecision: AuthDecisionOK, wantTerminal: policyfsm.StateAuthOK,
			wantPath: authnFSMGuardHostPath(authenticate, policy.FSMEventMarkerAuthPermit),
		},
		{
			name: "no-match deny records auth_deny", operation: authenticate, verifier: authenticated,
			prepare: runAuthnFSMGuardBackendAndSubject, checkpoint: policy.StageAuthDecision,
			effect: decision.EffectDeny, wantDecision: AuthDecisionFail, wantTerminal: policyfsm.StateAuthFail,
			wantPath: authnFSMGuardHostPath(authenticate, policy.FSMEventMarkerAuthDeny),
		},
		{
			name: "pre_auth runtime failure records pre_auth_tempfail", operation: authenticate,
			verifier: authenticated, checkpoint: policy.StagePreAuth, effect: decision.EffectIndeterminate,
			wantDecision: AuthDecisionTempFail, wantTerminal: policyfsm.StateAuthTempFail,
			wantPath: []string{policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthTempFail},
		},
		{
			name: "runtime failure after a failed check records auth_tempfail", operation: authenticate,
			verifier: authnFSMGuardVerifier{userFound: true}, prepare: runAuthnFSMGuardBackendAndSubject,
			checkpoint: policy.StageAuthDecision, effect: decision.EffectIndeterminate,
			wantDecision: AuthDecisionTempFail, wantTerminal: policyfsm.StateAuthTempFail,
			wantPath: authnFSMGuardHostPath(authenticate, policy.FSMEventMarkerAuthTempFail),
		},
		{
			name: "list_accounts ok after the account provider answers ok", operation: policy.OperationListAccounts,
			verifier: authenticated, prepare: runAuthnFSMGuardAccountProvider, checkpoint: policy.StageAuthDecision,
			effect: decision.EffectNotApplicable, wantDecision: AuthDecisionOK, wantTerminal: policyfsm.StateAuthOK,
			wantPath: authnFSMGuardHostPath(policy.OperationListAccounts, policy.FSMEventMarkerAuthPermit),
		},
	}
}

// injectAuthnFSMGuardUnbackedOK stages an ok host result that no backend verification produced.
func injectAuthnFSMGuardUnbackedOK(_ *testing.T, h *authnFSMGuardHarness) {
	h.execution.authResult = definitions.AuthResultOK
}

// TestAuthnFSMGuardDrivesUnselectedFinalization proves a checkpoint without a captured selection still drives the
// host auth FSM, so response, outcome terminal state, and recorded FSM telemetry agree on every decision.
func TestAuthnFSMGuardDrivesUnselectedFinalization(t *testing.T) {
	for _, test := range authnFSMGuardUnselectedCases() {
		t.Run(test.name, func(t *testing.T) {
			harness := newAuthnFSMGuardHarness(t, test.operation, test.verifier, testLuaSubject{})
			if test.prepare != nil {
				test.prepare(t, harness)
			}

			checkpoint := string(test.checkpoint)
			before := authnFSMGuardViolations(t, test.operation, checkpoint)

			result, err := harness.execution.finalize(
				checkpoint,
				mustAuthnDecisionResponse(t, test.effect),
				harness.execution.currentResult(),
			)
			if err != nil {
				t.Fatalf("finalize() error = %v", err)
			}

			assertAuthnFSMGuardTelemetry(t, harness, result, test.wantDecision, test.wantTerminal, test.wantPath)

			want := 0.0
			if test.wantViolation {
				want = 1
			}

			if got := authnFSMGuardViolations(t, test.operation, checkpoint) - before; got != want {
				t.Fatalf("guard violations counted = %v, want %v", got, want)
			}
		})
	}
}

// clearAuthnFSMGuardUsername removes the username before the backend checkpoint runs.
func clearAuthnFSMGuardUsername(t *testing.T, h *authnFSMGuardHarness) {
	t.Helper()

	h.execution.auth.Request.Username = ""
	h.runBackend(t)
}

// clearAuthnFSMGuardPassword removes the password before the backend checkpoint runs.
func clearAuthnFSMGuardPassword(t *testing.T, h *authnFSMGuardHarness) {
	t.Helper()

	h.execution.auth.Request.Password = secret.Value{}
	h.runBackend(t)
}

// authnFSMGuardHostEventCases lists empty credentials and contradicting markers, where the host event decides the
// terminal FSM event whenever it reaches the terminal state of the enforced decision.
func authnFSMGuardHostEventCases() []authnFSMGuardCase {
	authenticate := policy.OperationAuthenticate
	verifier := authnFSMGuardVerifier{authenticated: true, userFound: true}

	return []authnFSMGuardCase{
		{
			name: "permit with an empty password is guarded", operation: authenticate, verifier: verifier,
			prepare: clearAuthnFSMGuardPassword, wantDecision: AuthDecisionTempFail, wantViolation: true,
			wantTerminal: policyfsm.StateAuthTempFail,
			wantPath:     authnFSMGuardHostPath(authenticate, policy.FSMEventMarkerAuthTempFail),
		},
		{
			name: "permit with an empty username is guarded with the host event", operation: authenticate,
			verifier: verifier, prepare: clearAuthnFSMGuardUsername, wantDecision: AuthDecisionTempFail,
			wantViolation: true, wantTerminal: policyfsm.StateAuthTempFail,
			wantPath: authnFSMGuardHostPath(authenticate, policy.FSMEventMarkerAuthEmptyUser),
		},
		{
			name: "deny with an empty password records auth_empty_pass", operation: authenticate, verifier: verifier,
			prepare: clearAuthnFSMGuardPassword, selected: policy.DecisionDeny, marker: policy.FSMEventMarkerAuthDeny,
			wantDecision: AuthDecisionFail, wantTerminal: policyfsm.StateAuthFail,
			wantPath: authnFSMGuardHostPath(authenticate, policy.FSMEventMarkerAuthEmptyPass),
		},
		{
			name: "tempfail with an empty username records auth_empty_user", operation: authenticate,
			verifier: verifier, prepare: clearAuthnFSMGuardUsername, selected: policy.DecisionTempFail,
			marker: policy.FSMEventMarkerAuthTempFail, wantDecision: AuthDecisionTempFail,
			wantTerminal: policyfsm.StateAuthTempFail,
			wantPath:     authnFSMGuardHostPath(authenticate, policy.FSMEventMarkerAuthEmptyUser),
		},
		{
			name: "tempfail with an empty password keeps a tempfail event", operation: authenticate,
			verifier: verifier, prepare: clearAuthnFSMGuardPassword, selected: policy.DecisionTempFail,
			marker: policy.FSMEventMarkerAuthTempFail, wantDecision: AuthDecisionTempFail,
			wantTerminal: policyfsm.StateAuthTempFail,
			wantPath:     authnFSMGuardHostPath(authenticate, policy.FSMEventMarkerAuthTempFail),
		},
		{
			name: "deny after a checked password overrides an empty password marker", operation: authenticate,
			verifier: authnFSMGuardVerifier{userFound: true}, prepare: runAuthnFSMGuardBackendAndSubject,
			selected: policy.DecisionDeny, marker: policy.FSMEventMarkerAuthEmptyPass,
			wantDecision: AuthDecisionFail, wantTerminal: policyfsm.StateAuthFail,
			wantPath: authnFSMGuardHostPath(authenticate, policy.FSMEventMarkerAuthDeny),
		},
	}
}

// TestAuthnFSMGuardUsesHostEventWhenConsistent keeps the per-event FSM distinction of empty credentials and of
// checked credentials, while the terminal state always follows the enforced decision.
func TestAuthnFSMGuardUsesHostEventWhenConsistent(t *testing.T) {
	for _, test := range authnFSMGuardHostEventCases() {
		t.Run(test.name, func(t *testing.T) {
			runAuthnFSMGuardCase(t, test)
		})
	}
}

// TestAuthnSettleCredentialKeepsFirstVerdict proves a second, different backend verdict can neither replace the
// frozen evidence nor the current result.
func TestAuthnSettleCredentialKeepsFirstVerdict(t *testing.T) {
	harness := newAuthnFSMGuardHarness(t, policy.OperationAuthenticate, authnFSMGuardVerifier{}, testLuaSubject{})

	harness.execution.settleCredential(definitions.AuthResultFail, true)
	harness.execution.settleCredential(definitions.AuthResultOK, true)

	if harness.execution.authResult != definitions.AuthResultFail {
		t.Fatalf("current result = %v, want the frozen failure", harness.execution.authResult)
	}

	target, _ := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if harness.execution.AuthnPermitBacked(context.Background(), target, string(policy.StageAuthDecision)) {
		t.Fatal("a second verdict raised the frozen credential")
	}

	logs := harness.logs.String()
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "frozen backend verdict") {
		t.Fatalf("second verdict was not logged as a warning: %s", logs)
	}
}

// TestAuthnFSMGuardVetoesListingAfterAccountDatabaseError proves a partial account listing cannot be permitted.
func TestAuthnFSMGuardVetoesListingAfterAccountDatabaseError(t *testing.T) {
	harness := newAuthnFSMGuardHarness(t, policy.OperationListAccounts, authnFSMGuardVerifier{}, testLuaSubject{})
	harness.cfg.Server.Backends = []*config.Backend{
		mustNamedPluginAccountDBBackend(t, "healthy.accounts"),
		mustNamedPluginAccountDBBackend(t, "failing.accounts"),
	}
	harness.execution.auth.deps.PluginBackendFactory = func(name string, _ AuthDeps) BackendManager {
		if name == "failing.accounts" {
			return &accountDBBackendManager{err: errors.New("account database unavailable")}
		}

		return &accountDBBackendManager{accounts: AccountList{"alice@example.test"}}
	}

	harness.execution.prepareAccountProvider()

	if len(harness.execution.accounts) != 1 {
		t.Fatalf("partial account listing = %v, want the healthy account only", harness.execution.accounts)
	}

	before := authnFSMGuardViolations(t, policy.OperationListAccounts, string(policy.StageAuthDecision))
	result := harness.finalize(t, policy.StageAuthDecision, policy.DecisionPermit, policy.FSMEventMarkerAuthPermit)

	assertAuthnFSMGuardTelemetry(t, harness, result, AuthDecisionTempFail, policyfsm.StateAuthTempFail,
		authnFSMGuardHostPath(policy.OperationListAccounts, policy.FSMEventMarkerAuthTempFail))

	if got := authnFSMGuardViolations(t, policy.OperationListAccounts, string(policy.StageAuthDecision)) - before; got != 1 {
		t.Fatalf("guard violations counted = %v, want 1", got)
	}
}

// failingAuthnFSMGuardCache rejects every positive password cache write.
type failingAuthnFSMGuardCache struct {
	authnFSMGuardRecordingCache
}

// OnSuccess records and rejects one positive cache write.
func (c *failingAuthnFSMGuardCache) OnSuccess(auth *AuthState, account string) error {
	_ = c.authnFSMGuardRecordingCache.OnSuccess(auth, account)

	return errors.New("positive cache unavailable")
}

// TestAuthnFSMGuardLowersCredentialAfterCacheWriteFailure proves a host-owned failure after verification lowers the
// verified credential, so a later permit is vetoed and guarded.
func TestAuthnFSMGuardLowersCredentialAfterCacheWriteFailure(t *testing.T) {
	cache := &failingAuthnFSMGuardCache{}
	harness := newAuthnFSMGuardHarness(t, policy.OperationAuthenticate,
		authnFSMGuardVerifier{authenticated: true, userFound: true}, testLuaSubject{})
	harness.execution.auth.deps.HostServices.cache = cache

	harness.runBackendPlan(t, backendExecutionPlan{
		positions:                map[definitions.Backend]int{definitions.BackendCache: 0, definitions.BackendLDAP: 1},
		hasPositivePasswordCache: true,
	})
	harness.execution.auth.Runtime.UsedPassDBBackend = definitions.BackendLDAP
	harness.completeSubject()

	if cache.successes.Load() != 1 {
		t.Fatalf("positive cache writes = %d, want 1 attempted write", cache.successes.Load())
	}

	target, _ := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if harness.execution.AuthnPermitBacked(context.Background(), target, string(policy.StageAuthDecision)) {
		t.Fatal("a failed cache write left the credential verified")
	}

	result := harness.finalize(t, policy.StageAuthDecision, policy.DecisionPermit, policy.FSMEventMarkerAuthPermit)
	assertAuthnFSMGuardTelemetry(t, harness, result, AuthDecisionTempFail, policyfsm.StateAuthTempFail,
		authnFSMGuardHostPath(policy.OperationAuthenticate, policy.FSMEventMarkerAuthTempFail))
}

// TestAuthnSubjectCannotRaiseUserFound proves Lua and native subjects cannot report an identity the backend did not
// find, while a found identity stays found.
func TestAuthnSubjectCannotRaiseUserFound(t *testing.T) {
	tests := []struct {
		verifier PasswordVerifier
		raise    func(*authnFSMGuardHarness, *testing.T)
		name     string
		want     bool
	}{
		{name: "Lua subject on a missing identity", verifier: authnFSMGuardVerifier{},
			raise: (*authnFSMGuardHarness).raiseLuaSubjectAuthenticated},
		{name: "native subject on a missing identity", verifier: authnFSMGuardVerifier{},
			raise: (*authnFSMGuardHarness).patchNativeSubjectAuthenticated},
		{name: "native subject on a found identity", verifier: authnFSMGuardVerifier{authenticated: true, userFound: true},
			raise: (*authnFSMGuardHarness).patchNativeSubjectAuthenticated, want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newAuthnFSMGuardHarness(t, policy.OperationLookupIdentity, test.verifier, authnFSMGuardFlippingSubject{})
			harness.runBackend(t)
			test.raise(harness, t)

			if harness.execution.auth.Runtime.UserFound != test.want ||
				harness.execution.backendResult.UserFound != test.want {
				t.Fatalf("user found request=%t backend=%t, want %t", harness.execution.auth.Runtime.UserFound,
					harness.execution.backendResult.UserFound, test.want)
			}

			if test.want != (harness.execution.authResult == definitions.AuthResultOK) {
				t.Fatalf("lookup result = %v, want found=%t", harness.execution.authResult, test.want)
			}
		})
	}
}

// TestAuthnHostEvidenceAccessIsSynchronized lets the Decision Service read the evidence while the host writes it;
// the race detector proves both sides share one lock.
func TestAuthnHostEvidenceAccessIsSynchronized(t *testing.T) {
	harness := newAuthnFSMGuardHarness(t, policy.OperationAuthenticate,
		authnFSMGuardVerifier{authenticated: true, userFound: true}, testLuaSubject{})
	target, _ := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	done := make(chan struct{})

	var readers sync.WaitGroup

	readers.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
				harness.execution.AuthnPermitBacked(context.Background(), target, string(policy.StageAuthDecision))
			}
		}
	})

	harness.runBackend(t)
	harness.completeSubject()
	close(done)
	readers.Wait()

	if !harness.execution.AuthnPermitBacked(context.Background(), target, string(policy.StageAuthDecision)) {
		t.Fatal("verified credential does not back a permit")
	}
}

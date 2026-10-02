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
	"log/slog"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/catalogcompile"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
	"github.com/croessner/nauthilus/v4/server/rediscli"

	"github.com/go-redis/redismock/v9"
)

const (
	authnGuardE2ESyncEffect   = "authn/guard_e2e_sync"
	authnGuardE2ESyncProvider = "authn/guard_e2e_sync_owner"
	authnGuardE2EPostEffect   = "authn/guard_e2e_post"
	authnGuardE2EPostProvider = "authn/guard_e2e_post_owner"
)

// authnGuardE2ESyncOwner counts synchronous obligation executions.
type authnGuardE2ESyncOwner struct {
	calls atomic.Int32
}

// IdempotencyKey forbids replay, like the standard authn effect owners.
func (*authnGuardE2ESyncOwner) IdempotencyKey(string) string { return "" }

// Execute records one obligation execution.
func (o *authnGuardE2ESyncOwner) Execute(context.Context, policyruntime.EffectExecution) effectsupervisor.Result {
	o.calls.Add(1)

	return effectsupervisor.Succeeded()
}

// authnGuardE2EPostOwner counts post-action preparations.
type authnGuardE2EPostOwner struct {
	prepared atomic.Int32
}

// IdempotencyKey forbids replay, like the standard authn effect owners.
func (*authnGuardE2EPostOwner) IdempotencyKey(string) string { return "" }

// Prepare records one post-action preparation and returns inert executable work.
func (o *authnGuardE2EPostOwner) Prepare(context.Context, policyruntime.EffectExecution) (effectsupervisor.Work, error) {
	o.prepared.Add(1)

	return authnGuardE2EWork{}, nil
}

// authnGuardE2EWork is inert supervised post-action work.
type authnGuardE2EWork struct{}

// Validate accepts the inert work.
func (authnGuardE2EWork) Validate() error { return nil }

// Execute completes the inert work.
func (authnGuardE2EWork) Execute(context.Context) effectsupervisor.Result {
	return effectsupervisor.Succeeded()
}

// Cleanup releases nothing.
func (authnGuardE2EWork) Cleanup() {}

// authnGuardE2EFixture owns one real Decision Service with a configured permit carrying two host effects.
type authnGuardE2EFixture struct {
	adapter  AuthApplicationService
	sync     *authnGuardE2ESyncOwner
	post     *authnGuardE2EPostOwner
	acceptor *authnCandidateCountingAcceptor
}

// newAuthnGuardE2EFixture compiles the configured permit, binds its owners, and wires a real candidate host.
func newAuthnGuardE2EFixture(t *testing.T, verifier PasswordVerifier) authnGuardE2EFixture {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t)
	db, _ := redismock.NewClientMock()
	host := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(&authnFSMGuardLogBuffer{}, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
		HostServices: newTestAuthnHostServices(t, verifier, testLuaSubject{}),
	})

	supervisor, err := effectsupervisor.New(
		effectsupervisor.Config{Capacity: 4, Workers: 1},
		effectsupervisor.ProviderBinding{Name: authnGuardE2EPostProvider, Provider: effectsupervisor.NewExecutableProvider()},
	)
	if err != nil {
		t.Fatalf("effectsupervisor.New() error = %v", err)
	}

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		if shutdownErr := supervisor.Shutdown(shutdownCtx); shutdownErr != nil {
			t.Errorf("post-action supervisor shutdown: %v", shutdownErr)
		}
	})

	fixture := authnGuardE2EFixture{
		sync: &authnGuardE2ESyncOwner{}, post: &authnGuardE2EPostOwner{},
		acceptor: &authnCandidateCountingAcceptor{delegate: supervisor},
	}
	catalog := compileAuthnGuardE2ECatalog(t, fixture.acceptor)
	runtime := newAuthnCandidateDecisionServiceWithBindings(t, cfg, fixture.acceptor, catalog,
		&authnCandidatePolicyModel{Generation: 701, Mode: "enforce"},
		authnCandidateExtraBindings{
			syncEffects: map[string]policyruntime.SyncEffectProvider{authnGuardE2ESyncProvider: fixture.sync},
			postActions: map[string]policyruntime.PostActionProvider{authnGuardE2EPostProvider: fixture.post},
		})

	adapter, err := NewAuthnCandidateApplicationService(host, runtime, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	fixture.adapter = adapter

	return fixture
}

// compileAuthnGuardE2ECatalog binds an always-matching auth_decision permit with a sync obligation and a post-action.
func compileAuthnGuardE2ECatalog(t *testing.T, acceptor effectsupervisor.Acceptor) *policyruntime.TargetCatalog {
	t.Helper()

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	setID, contribution := newAuthnCandidateConfiguredContributionWithEffects(t, newAuthnGuardE2EPermitRule(t),
		[]registry.ProviderDefinition{
			mustAuthnGuardE2EProvider(t, target, authnGuardE2ESyncProvider, registry.ExecutionHostSync, nil),
			mustAuthnGuardE2EProvider(t, target, authnGuardE2EPostProvider, registry.ExecutionHostPostAction, acceptor),
		},
		[]registry.EffectDefinition{
			mustAuthnGuardE2EEffect(t, target, authnGuardE2ESyncEffect, authnGuardE2ESyncProvider, registry.ExecutionHostSync),
			mustAuthnGuardE2EEffect(t, target, authnGuardE2EPostEffect, authnGuardE2EPostProvider, registry.ExecutionHostPostAction),
		})

	catalog, err := catalogcompile.NewTargetCatalogCompiler(
		registry.NewBuiltinTargetContributor(acceptor),
		authnCandidateStaticContributor{contribution: contribution},
	).Compile(context.Background(), []registry.TargetActivation{
		newAuthnCandidateConfiguredActivationFor(t, target, setID, policy.StageAuthDecision),
	})
	if err != nil {
		t.Fatalf("configured authn catalog Compile() error = %v", err)
	}

	return catalog
}

// newAuthnGuardE2EPermitRule constructs one unconditional permit carrying both host effects.
func newAuthnGuardE2EPermitRule(t *testing.T) registry.PolicyRule {
	t.Helper()

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Kind: registry.ExpressionKindAlways})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	uses := make([]registry.EffectUse, 0, 2)

	for _, id := range []string{authnGuardE2ESyncEffect, authnGuardE2EPostEffect} {
		use, useErr := registry.NewEffectUse(id, nil)
		if useErr != nil {
			t.Fatalf("NewEffectUse(%s) error = %v", id, useErr)
		}

		uses = append(uses, use)
	}

	rule, err := registry.NewAuthnPolicyRule(registry.PolicyRuleInput{
		Name: "configured_unconditional_permit", Checkpoint: string(policy.StageAuthDecision),
		Actions: []string{string(policy.OperationAuthenticate)}, Expression: expression,
		Decision: decision.EffectPermit, FSMEventMarker: policy.FSMEventMarkerAuthPermit,
		ResponseMarker: policy.ResponseMarkerOK, Effects: uses,
	})
	if err != nil {
		t.Fatalf("NewAuthnPolicyRule() error = %v", err)
	}

	return rule
}

// mustAuthnGuardE2EProvider declares one host-owned effect provider.
func mustAuthnGuardE2EProvider(
	t *testing.T,
	target decision.Target,
	id string,
	execution registry.ExecutionClass,
	acceptor effectsupervisor.Acceptor,
) registry.ProviderDefinition {
	t.Helper()

	provider, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID: id, Targets: []decision.Target{target}, Executions: []registry.ExecutionClass{execution},
		PostActionAcceptance: acceptor,
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition(%s) error = %v", id, err)
	}

	return provider
}

// mustAuthnGuardE2EEffect declares one host-owned obligation.
func mustAuthnGuardE2EEffect(
	t *testing.T,
	target decision.Target,
	id string,
	provider string,
	execution registry.ExecutionClass,
) registry.EffectDefinition {
	t.Helper()

	effect, err := registry.NewEffectDefinition(registry.EffectDefinitionInput{
		ID: id, Provider: provider, Kind: registry.EffectKindObligation, Execution: execution,
		Targets: []decision.Target{target},
	})
	if err != nil {
		t.Fatalf("NewEffectDefinition(%s) error = %v", id, err)
	}

	return effect
}

// TestAuthnUnbackedPermitEndToEndDispatchesNothing drives the real candidate host and Decision Service: a configured
// permit without host evidence answers tempfail, dispatches neither obligation nor post-action, and counts one
// violation, while the same permit after a verified credential answers ok and dispatches both.
func TestAuthnUnbackedPermitEndToEndDispatchesNothing(t *testing.T) {
	tests := []struct {
		verifier       PasswordVerifier
		name           string
		wantDecision   AuthDecision
		wantTerminal   string
		wantEffects    int32
		wantViolations float64
	}{
		{
			name: "failed password", verifier: authnFSMGuardVerifier{userFound: true},
			wantDecision: AuthDecisionTempFail, wantTerminal: string(authFSMStateAuthTempFail), wantViolations: 1,
		},
		{
			name: "verified password", verifier: authnFSMGuardVerifier{authenticated: true, userFound: true},
			wantDecision: AuthDecisionOK, wantTerminal: string(authFSMStateAuthOK), wantEffects: 1,
		},
	}

	checkpoint := string(policy.StageAuthDecision)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuthnGuardE2EFixture(t, test.verifier)
			before := authnFSMGuardViolations(t, policy.OperationAuthenticate, checkpoint)

			outcome := authenticateAuthnCandidate(t, test.name, fixture.adapter, authnApplicationTestInput(AuthModeAuthenticate))

			if outcome.Decision != test.wantDecision || outcome.TerminalState != test.wantTerminal {
				t.Fatalf("outcome = %q/%q, want %q/%q", outcome.Decision, outcome.TerminalState,
					test.wantDecision, test.wantTerminal)
			}

			if len(outcome.FSMEventPath) == 0 || !slices.Contains([]string{
				policy.FSMEventMarkerAuthPermit, policy.FSMEventMarkerAuthTempFail,
			}, outcome.FSMEventPath[len(outcome.FSMEventPath)-1]) {
				t.Fatalf("FSM path = %v, want a host-driven terminal event", outcome.FSMEventPath)
			}

			if fixture.sync.calls.Load() != test.wantEffects || fixture.post.prepared.Load() != test.wantEffects ||
				fixture.acceptor.calls.Load() != test.wantEffects {
				t.Fatalf("dispatched sync/prepared/accepted = %d/%d/%d, want %d each", fixture.sync.calls.Load(),
					fixture.post.prepared.Load(), fixture.acceptor.calls.Load(), test.wantEffects)
			}

			if got := authnFSMGuardViolations(t, policy.OperationAuthenticate, checkpoint) - before; got != test.wantViolations {
				t.Fatalf("guard violations counted = %v, want %v", got, test.wantViolations)
			}
		})
	}
}

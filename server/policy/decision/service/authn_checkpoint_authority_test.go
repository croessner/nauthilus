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

package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/compiler"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	authnObservedPolicySet = "authn/observed"
	authnObservedEffect    = "authn/observed_mutation"
	authnObservedProvider  = "authn/observed_mutation_owner"
)

type authnOperationPlanCase struct {
	action        string
	want          []string
	wantProviders [][]string
}

func TestAuthnStandardAuthCheckpointFallbackIsNeutralThenDefaultDeny(t *testing.T) {
	evaluator, _ := mustBuiltinAuthnCheckpointRuntime(t)
	generation := mustRuntimeGeneration(
		t,
		11,
		&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)},
		&recordingAdmissionAuthority{},
		evaluator,
	)
	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	err := service.WithSession(context.Background(), mustAuthorityInvocation(t, true), func(session DecisionSession) error {
		wantPlan := []string{string(policy.StagePreAuth), string(policy.StageAuthDecision)}
		if got := checkpointPlanNames(session.Checkpoints()); !reflect.DeepEqual(got, wantPlan) {
			t.Fatalf("session checkpoints = %v, want %v", got, wantPlan)
		}

		preAuth := evaluateAuthnCheckpoint(t, session, string(policy.StagePreAuth))
		if preAuth.Effect() != decision.EffectNotApplicable || preAuth.Policy().PolicySet() != registry.BuiltinStandardAuthPolicySet {
			t.Fatalf("pre_auth standard fallback = %q/%q, want not_applicable/%q", preAuth.Effect(), preAuth.Policy().PolicySet(), registry.BuiltinStandardAuthPolicySet)
		}

		final := evaluateAuthnCheckpoint(t, session, string(policy.StageAuthDecision))
		if final.Effect() != decision.EffectDeny || final.Policy().PolicySet() != registry.BuiltinStandardAuthPolicySet {
			t.Fatalf("final standard fallback = %q/%q, want deny/%q", final.Effect(), final.Policy().PolicySet(), registry.BuiltinStandardAuthPolicySet)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("DecisionService.WithSession() error = %v", err)
	}
}

func TestAuthnCheckpointSessionUsesExactOperationPlans(t *testing.T) {
	tests := []authnOperationPlanCase{
		{
			action: string(policy.OperationAuthenticate),
			want:   []string{"pre_auth", "auth_decision"},
			wantProviders: [][]string{
				{policy.AuthnProviderBruteForce},
				{
					policy.AuthnProviderEnvironment,
					policy.AuthnProviderTLSEncryption,
					policy.AuthnProviderRelayDomains,
					policy.AuthnProviderRBL,
					policy.AuthnProviderBackend,
					policy.AuthnProviderSubject,
				},
			},
		},
		{
			action: string(policy.OperationLookupIdentity),
			want:   []string{"pre_auth", "auth_decision"},
			wantProviders: [][]string{
				{
					policy.AuthnProviderEnvironment,
					policy.AuthnProviderTLSEncryption,
					policy.AuthnProviderRBL,
				},
				{policy.AuthnProviderBackend, policy.AuthnProviderSubject},
			},
		},
		{
			action:        string(policy.OperationListAccounts),
			want:          []string{"auth_decision"},
			wantProviders: [][]string{{policy.AuthnProviderAccount}},
		},
	}

	service := mustAuthnOperationPlanService(t, tests)

	for _, test := range tests {
		t.Run(test.action, func(t *testing.T) {
			err := service.WithSession(
				context.Background(),
				mustAuthorityTargetInvocation(t, policy.AuthnNamespace, test.action),
				func(session DecisionSession) error {
					plans := session.Checkpoints()
					if got := checkpointPlanNames(plans); !reflect.DeepEqual(got, test.want) {
						t.Fatalf("checkpoints = %v, want %v", got, test.want)
					}

					if got := checkpointProviderPlans(plans); !reflect.DeepEqual(got, test.wantProviders) {
						t.Fatalf("checkpoint providers = %v, want %v", got, test.wantProviders)
					}

					return nil
				},
			)
			if err != nil {
				t.Fatalf("DecisionService.WithSession() error = %v", err)
			}
		})
	}
}

func TestAuthnCheckpointSessionRejectsOutOfOrderEvaluation(t *testing.T) {
	evaluator, _ := mustBuiltinAuthnCheckpointRuntime(t)
	generation := mustRuntimeGeneration(
		t,
		23,
		&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)},
		&recordingAdmissionAuthority{},
		evaluator,
	)
	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	err := service.WithSession(context.Background(), mustAuthorityInvocation(t, true), func(session DecisionSession) error {
		detached := session.Checkpoints()
		providers := detached[0].ProviderIDs()
		providers[0] = "authn/tampered"
		detached[0] = newCheckpointPlan("auth_decision", []string{"authn/tampered"})

		if got := session.Checkpoints()[0].Name(); got != "pre_auth" {
			t.Fatalf("mutated session checkpoint = %q, want pre_auth", got)
		}

		if got := session.Checkpoints()[0].ProviderIDs()[0]; got != policy.AuthnProviderBruteForce {
			t.Fatalf("mutated session provider = %q, want %q", got, policy.AuthnProviderBruteForce)
		}

		facts, factErr := decision.NewFactSet(nil)
		if factErr != nil {
			return factErr
		}

		checkpoint, checkpointErr := decision.NewCheckpoint("auth_decision", facts)
		if checkpointErr != nil {
			return checkpointErr
		}

		if _, evaluationErr := session.Evaluate(context.Background(), checkpoint); !errors.Is(evaluationErr, ErrDecisionEvaluation) {
			t.Fatalf("out-of-order checkpoint error = %v, want ErrDecisionEvaluation", evaluationErr)
		}

		evaluateAuthnCheckpoint(t, session, "pre_auth")
		evaluateAuthnCheckpoint(t, session, "auth_decision")

		return nil
	})
	if err != nil {
		t.Fatalf("DecisionService.WithSession() error = %v", err)
	}
}

// checkpointPlanNames projects only checkpoint identities for order assertions.
func checkpointPlanNames(plans []CheckpointPlan) []string {
	result := make([]string, 0, len(plans))
	for _, plan := range plans {
		result = append(result, plan.Name())
	}

	return result
}

// checkpointProviderPlans projects detached provider orders for schedule assertions.
func checkpointProviderPlans(plans []CheckpointPlan) [][]string {
	result := make([][]string, 0, len(plans))
	for _, plan := range plans {
		result = append(result, plan.ProviderIDs())
	}

	return result
}

func TestAuthnObserveCheckpointRecordsComparisonWithoutEffects(t *testing.T) {
	catalog, target, effectID, configuredSet := mustAuthnObserveCheckpointCatalog(t)
	mutator := &recordingSyncEffectProvider{result: effectsupervisor.Succeeded()}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog,
		syncEffects: map[string]syncEffectBinding{
			effectID: {provider: mutator},
		},
		ids:               &sequenceIDGenerator{},
		evaluationTimeout: time.Second,
	})

	outcome := evaluateAuthnRuntimeCheckpoint(t, evaluator, target, string(policy.StagePreAuth))
	if outcome.response.Effect() != decision.EffectNotApplicable || outcome.response.Policy().PolicySet() != registry.BuiltinStandardAuthPolicySet {
		t.Fatalf("observe production result = %q/%q, want standard_auth neutral", outcome.response.Effect(), outcome.response.Policy().PolicySet())
	}

	report := outcome.report.runtime
	if report.comparisonPolicySet != configuredSet || report.comparisonRule != "observed_deny" || report.comparisonEffect != decision.EffectDeny {
		t.Fatalf(
			"observe comparison = %q/%q/%q, want %q/observed_deny/deny",
			report.comparisonPolicySet,
			report.comparisonRule,
			report.comparisonEffect,
			configuredSet,
		)
	}

	if mutator.callCount() != 0 || len(report.effects) != 0 {
		t.Fatalf("observe mutations = provider:%d report:%v, want none", mutator.callCount(), report.effects)
	}
}

// evaluateAuthnCheckpoint runs one empty-fact checkpoint through an admitted session.
func evaluateAuthnCheckpoint(t *testing.T, session DecisionSession, name string) decision.DecisionResponse {
	t.Helper()

	facts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	checkpoint, err := decision.NewCheckpoint(name, facts)
	if err != nil {
		t.Fatalf("NewCheckpoint(%q) error = %v", name, err)
	}

	response, err := session.Evaluate(context.Background(), checkpoint)
	if err != nil {
		t.Fatalf("DecisionSession.Evaluate(%q) error = %v", name, err)
	}

	return response
}

// evaluateAuthnRuntimeCheckpoint executes one internal authn checkpoint for report evidence.
func evaluateAuthnRuntimeCheckpoint(
	t *testing.T,
	evaluator checkpointEvaluator,
	target decision.Target,
	checkpointName string,
) runtimeEvaluation {
	t.Helper()

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion,
		Target:  target,
	}, mustAuthorityCaller(t, true))
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	facts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	checkpoint, err := decision.NewCheckpoint(checkpointName, facts)
	if err != nil {
		t.Fatalf("NewCheckpoint(%q) error = %v", checkpointName, err)
	}

	outcome, err := evaluator.Evaluate(context.Background(), checkpointEvaluation{
		request:      request,
		checkpoint:   checkpoint,
		finalization: decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
		supervisor:   &recordingEffectAcceptor{},
		generation:   17,
	})
	if err != nil {
		t.Fatalf("checkpoint evaluator error = %v", err)
	}

	return outcome
}

// mustAuthnOperationPlanService compiles every requested builtin operation into one runtime.
func mustAuthnOperationPlanService(
	t *testing.T,
	tests []authnOperationPlanCase,
) *DecisionService {
	t.Helper()

	activations := make([]registry.TargetActivation, 0, len(tests))
	for _, test := range tests {
		activation, err := registry.NewTargetActivation(
			"policy.targets.authn."+test.action,
			policy.AuthnNamespace,
			test.action,
			"authn/"+test.action+"/v1",
		)
		if err != nil {
			t.Fatalf("NewTargetActivation(%q) error = %v", test.action, err)
		}

		activation, err = activation.WithPolicy(registry.BuiltinStandardAuthPolicySet, "")
		if err != nil {
			t.Fatalf("TargetActivation.WithPolicy(%q) error = %v", test.action, err)
		}

		activations = append(activations, activation)
	}

	catalog, err := compiler.NewTargetCatalogCompiler(
		registry.NewBuiltinTargetContributor(&recordingEffectAcceptor{}),
	).Compile(context.Background(), activations)
	if err != nil {
		t.Fatalf("TargetCatalogCompiler.Compile() error = %v", err)
	}

	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
	})
	generation := mustRuntimeGeneration(
		t,
		19,
		&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)},
		&recordingAdmissionAuthority{},
		evaluator,
	)

	return mustDecisionService(t, &replaceableGenerationSource{generation: generation})
}

// mustAuthnObserveCheckpointCatalog builds one observed pre-auth rule with a host mutation.
func mustAuthnObserveCheckpointCatalog(
	t *testing.T,
) (*policyruntime.TargetCatalog, decision.Target, string, string) {
	t.Helper()

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	contribution := mustAuthnObserveContribution(t, target)
	activation := mustAuthnObserveActivation(t, target)

	catalog, err := compiler.NewTargetCatalogCompiler(
		registry.NewBuiltinTargetContributor(&recordingEffectAcceptor{}),
		staticAuthnCheckpointContributor{contribution: contribution},
	).Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("TargetCatalogCompiler.Compile() error = %v", err)
	}

	return catalog, target, authnObservedEffect, authnObservedPolicySet
}

// mustAuthnObserveContribution composes the configured set and its host-owned effect.
func mustAuthnObserveContribution(t *testing.T, target decision.Target) registry.DefinitionContribution {
	t.Helper()

	provider, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID: authnObservedProvider, Targets: []decision.Target{target},
		Executions: []registry.ExecutionClass{registry.ExecutionHostSync},
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	effect, err := registry.NewEffectDefinition(registry.EffectDefinitionInput{
		ID: authnObservedEffect, Provider: authnObservedProvider, Targets: []decision.Target{target},
		Kind: registry.EffectKindObligation, Execution: registry.ExecutionHostSync,
	})
	if err != nil {
		t.Fatalf("NewEffectDefinition() error = %v", err)
	}

	ownership, err := registry.NewNamespaceOwnership("test.authn.observe", []string{policy.AuthnNamespace})
	if err != nil {
		t.Fatalf("NewNamespaceOwnership() error = %v", err)
	}

	contribution, err := registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
		Ownership: ownership, PolicySets: []registry.PolicySetDefinition{mustAuthnObservedPolicySet(t)},
		Providers: []registry.ProviderDefinition{provider}, Effects: []registry.EffectDefinition{effect},
	})
	if err != nil {
		t.Fatalf("NewCompleteDefinitionContribution() error = %v", err)
	}

	return contribution
}

// mustAuthnObservedPolicySet constructs the comparison-only deny selection.
func mustAuthnObservedPolicySet(t *testing.T) registry.PolicySetDefinition {
	t.Helper()

	use, err := registry.NewEffectUse(authnObservedEffect, nil)
	if err != nil {
		t.Fatalf("NewEffectUse() error = %v", err)
	}

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Kind: registry.ExpressionKindAlways})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name: "observed_deny", Checkpoint: string(policy.StagePreAuth), Expression: expression,
		Decision: decision.EffectDeny, Effects: []registry.EffectUse{use},
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	setID, err := registry.ParsePolicySetID("test.observe", authnObservedPolicySet)
	if err != nil {
		t.Fatalf("ParsePolicySetID() error = %v", err)
	}

	set, err := registry.NewPolicySetDefinition(registry.PolicySetDefinitionInput{
		ID: setID, Rules: []registry.PolicyRule{rule},
	})
	if err != nil {
		t.Fatalf("NewPolicySetDefinition() error = %v", err)
	}

	return set
}

// mustAuthnObserveActivation binds the configured set while retaining standard authority.
func mustAuthnObserveActivation(t *testing.T, target decision.Target) registry.TargetActivation {
	t.Helper()

	binding, err := registry.NewPolicySetImport(
		"policy.targets.authn.authenticate.pre_auth", authnObservedPolicySet, target,
		string(policy.StagePreAuth), registry.ExportContract{},
	)
	if err != nil {
		t.Fatalf("NewPolicySetImport() error = %v", err)
	}

	activation, err := registry.NewTargetActivation(
		"policy.targets.authn.authenticate", policy.AuthnNamespace,
		string(policy.OperationAuthenticate), "authn/authenticate/v1",
	)
	if err != nil {
		t.Fatalf("NewTargetActivation() error = %v", err)
	}

	activation, err = activation.WithPolicy(registry.BuiltinStandardAuthPolicySet, "")
	if err != nil {
		t.Fatalf("TargetActivation.WithPolicy() error = %v", err)
	}

	activation, err = activation.WithPolicySetBindings([]registry.PolicySetImport{binding})
	if err != nil {
		t.Fatalf("TargetActivation.WithPolicySetBindings() error = %v", err)
	}

	activation, err = activation.WithAuthorityMode(registry.AuthorityModeObserve)
	if err != nil {
		t.Fatalf("TargetActivation.WithAuthorityMode() error = %v", err)
	}

	return activation
}

type staticAuthnCheckpointContributor struct {
	contribution registry.DefinitionContribution
}

// Contribute returns one immutable test-owned authn extension batch.
func (c staticAuthnCheckpointContributor) Contribute(context.Context) (registry.DefinitionContribution, error) {
	return c.contribution, nil
}

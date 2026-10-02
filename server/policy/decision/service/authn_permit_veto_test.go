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
	"reflect"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/catalogcompile"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// authnPermitVetoCase binds one selected rule decision and host-evidence verdict to the effects that must run.
type authnPermitVetoCase struct {
	name           string
	ruleEffect     decision.Effect
	wantEffects    []string
	permitUnbacked bool
}

// authnPermitVetoCases lists permits with and without host evidence and tightening decisions.
func authnPermitVetoCases() []authnPermitVetoCase {
	dispatched := []string{
		"sync:" + authnPermitVetoSyncProvider + ":1",
		"prepare:" + authnPermitVetoPostProvider + ":2",
		"accept:" + authnPermitVetoPostProvider + ":2",
	}

	return []authnPermitVetoCase{
		{name: "backed permit dispatches its obligations", ruleEffect: decision.EffectPermit, wantEffects: dispatched},
		{name: "unbacked permit dispatches no obligation", ruleEffect: decision.EffectPermit, permitUnbacked: true},
		{
			name: "deny dispatches its obligations without permit evidence", ruleEffect: decision.EffectDeny,
			permitUnbacked: true, wantEffects: dispatched,
		},
		{
			name: "tempfail dispatches its obligations without permit evidence", ruleEffect: decision.EffectIndeterminate,
			permitUnbacked: true, wantEffects: dispatched,
		},
	}
}

// TestAuthnPermitWithoutHostEvidenceDispatchesNoEffects proves the Decision Service withholds every synchronous
// obligation and post-action of a permit the request-local host evidence does not back, before any of them runs.
func TestAuthnPermitWithoutHostEvidenceDispatchesNoEffects(t *testing.T) {
	for _, test := range authnPermitVetoCases() {
		t.Run(test.name, func(t *testing.T) {
			log := &authnEffectOrderLog{}
			evaluator, target := mustAuthnPermitVetoRuntime(t, log, test.ruleEffect)
			source := newSuppliedAuthnDecisionSource(t, nil, true)
			source.permitUnbacked = test.permitUnbacked

			outcome := evaluateAuthnSourceNamedCheckpoint(
				t,
				evaluator,
				target,
				source,
				&orderedAcceptingAuthnAcceptor{log: log},
				string(policy.StageAuthDecision),
			)

			if outcome.response.Effect() != test.ruleEffect {
				t.Fatalf("response effect = %q, want %q", outcome.response.Effect(), test.ruleEffect)
			}

			if got := log.entries(); !reflect.DeepEqual(got, test.wantEffects) {
				t.Fatalf("dispatched effects = %v, want %v", got, test.wantEffects)
			}

			captured := source.capturedDecision()
			if captured == nil {
				t.Fatal("selection was not captured")
			}

			if test.wantEffects == nil && (len(captured.Obligations) > 0 || len(captured.Advice) > 0) {
				t.Fatalf("captured unbacked permit keeps effects %v/%v", captured.Obligations, captured.Advice)
			}
		})
	}
}

const (
	authnPermitVetoPolicySet    = "authn/permit_veto"
	authnPermitVetoSyncEffect   = "authn/permit_veto_sync"
	authnPermitVetoSyncProvider = "authn/permit_veto_sync_owner"
	authnPermitVetoPostEffect   = "authn/permit_veto_post"
	authnPermitVetoPostProvider = "authn/permit_veto_post_owner"
)

// mustAuthnPermitVetoRuntime compiles one enforced authn rule with a synchronous obligation and a post-action.
func mustAuthnPermitVetoRuntime(
	t *testing.T,
	log *authnEffectOrderLog,
	ruleEffect decision.Effect,
) (checkpointEvaluator, decision.Target) {
	t.Helper()

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	catalog, err := catalogcompile.NewTargetCatalogCompiler(
		registry.NewBuiltinTargetContributor(&recordingEffectAcceptor{}),
		staticAuthnCheckpointContributor{contribution: mustAuthnPermitVetoContribution(t, target, ruleEffect)},
	).Compile(context.Background(), []registry.TargetActivation{mustAuthnPermitVetoActivation(t, target)})
	if err != nil {
		t.Fatalf("TargetCatalogCompiler.Compile() error = %v", err)
	}

	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
		syncEffects: map[string]syncEffectBinding{
			authnPermitVetoSyncProvider: {provider: &orderedAuthnSyncEffectProvider{log: log}},
		},
		postActions: map[string]postActionBinding{
			authnPermitVetoPostProvider: {provider: &orderedAuthnPostActionProvider{log: log}},
		},
	})

	return evaluator, target
}

// mustAuthnPermitVetoContribution composes the configured rule and its two host-owned effects.
func mustAuthnPermitVetoContribution(
	t *testing.T,
	target decision.Target,
	ruleEffect decision.Effect,
) registry.DefinitionContribution {
	t.Helper()

	ownership, err := registry.NewNamespaceOwnership("test.authn.permit_veto", []string{policy.AuthnNamespace})
	if err != nil {
		t.Fatalf("NewNamespaceOwnership() error = %v", err)
	}

	contribution, err := registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
		Ownership:  ownership,
		PolicySets: []registry.PolicySetDefinition{mustAuthnPermitVetoPolicySet(t, ruleEffect)},
		Providers: []registry.ProviderDefinition{
			decisionRuntimeHostProvider(t, target, authnPermitVetoSyncProvider, registry.ExecutionHostSync, nil),
			decisionRuntimeHostProvider(
				t, target, authnPermitVetoPostProvider, registry.ExecutionHostPostAction, &recordingEffectAcceptor{},
			),
		},
		Effects: []registry.EffectDefinition{
			decisionRuntimeEffect(t, target, authnPermitVetoSyncEffect, authnPermitVetoSyncProvider,
				registry.EffectKindObligation, registry.ExecutionHostSync),
			decisionRuntimeEffect(t, target, authnPermitVetoPostEffect, authnPermitVetoPostProvider,
				registry.EffectKindObligation, registry.ExecutionHostPostAction),
		},
	})
	if err != nil {
		t.Fatalf("NewCompleteDefinitionContribution() error = %v", err)
	}

	return contribution
}

// mustAuthnPermitVetoPolicySet constructs one always-matching auth_decision rule carrying both obligations.
func mustAuthnPermitVetoPolicySet(t *testing.T, ruleEffect decision.Effect) registry.PolicySetDefinition {
	t.Helper()

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Kind: registry.ExpressionKindAlways})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	rule, err := registry.NewAuthnPolicyRule(registry.PolicyRuleInput{
		Name: "configured_outcome", Checkpoint: string(policy.StageAuthDecision), Expression: expression,
		Decision: ruleEffect, Effects: []registry.EffectUse{
			decisionRuntimeEffectUse(t, authnPermitVetoSyncEffect),
			decisionRuntimeEffectUse(t, authnPermitVetoPostEffect),
		},
	})
	if err != nil {
		t.Fatalf("NewAuthnPolicyRule() error = %v", err)
	}

	setID, err := registry.ParsePolicySetID("test.permit_veto", authnPermitVetoPolicySet)
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

// mustAuthnPermitVetoActivation binds the configured set at auth_decision with enforced authority.
func mustAuthnPermitVetoActivation(t *testing.T, target decision.Target) registry.TargetActivation {
	t.Helper()

	binding, err := registry.NewPolicySetImport(
		"policy.targets.authn.authenticate.auth_decision", authnPermitVetoPolicySet, target,
		string(policy.StageAuthDecision), registry.ExportContract{},
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

	return activation
}

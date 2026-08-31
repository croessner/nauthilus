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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/lualib/policyprovider"
	"github.com/croessner/nauthilus/v4/server/policy/catalogcompile"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

const (
	decisionRuntimeLuaFailureProviderID = "mail/lua.scheduler.failed"
	decisionRuntimeLuaFailureFactID     = "lua.scheduler.failed"
)

func TestDecisionRuntimeProjectsRulesAndExplicitNoMatch(t *testing.T) {
	tests := []struct {
		name       string
		ruleEffect decision.Effect
		noMatch    registry.NoMatchBehavior
		wantEffect decision.Effect
		wantCode   decision.StatusCode
	}{
		{name: "permit", ruleEffect: decision.EffectPermit, noMatch: registry.NoMatchDeny, wantEffect: decision.EffectPermit, wantCode: decision.StatusCodePermit},
		{name: "deny", ruleEffect: decision.EffectDeny, noMatch: registry.NoMatchNotApplicable, wantEffect: decision.EffectDeny, wantCode: decision.StatusCodePolicyDenied},
		{name: "not applicable", noMatch: registry.NoMatchNotApplicable, wantEffect: decision.EffectNotApplicable, wantCode: decision.StatusCodeNoApplicableRule},
		{name: "no match deny", noMatch: registry.NoMatchDeny, wantEffect: decision.EffectDeny, wantCode: decision.StatusCodeNoMatchDeny},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog, target := decisionRuntimeCatalog(t, test.ruleEffect, test.noMatch, nil, nil, nil)
			evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
				catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
			})
			response := evaluateRuntimeCheckpoint(t, evaluator, target, decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit))

			if response.Effect() != test.wantEffect || response.Status().Code() != test.wantCode {
				t.Fatalf("effect/status = %q/%q, want %q/%q", response.Effect(), response.Status().Code(), test.wantEffect, test.wantCode)
			}
		})
	}
}

func TestDecisionRuntimeUsesCompiledRecurringTimeWindowSemantics(t *testing.T) {
	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindAttribute, FactID: "input.time", FactKind: decision.ValueKindTimestamp,
		Operator: registry.ExpressionOperatorWithinTimeWindow, Reference: "@time_window.business_hours",
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	catalog, target := decisionRuntimeCatalogWithRuleExpression(
		t,
		expression,
		[]registry.FactSchema{decisionRuntimeTimestampFactSchema(t, "input.time", decision.FactSourceCaller)},
	)
	window := policyruntime.CompiledTimeWindow{
		LocationName: "Europe/Berlin",
		Days:         []time.Weekday{time.Monday},
		Intervals:    []policyruntime.CompiledTimeInterval{{StartMinute: 9 * 60, EndMinute: 17 * 60}},
	}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
		timeWindows: map[string]policyruntime.CompiledTimeWindow{
			policyruntime.ConditionMaterialKey(target.Namespace(), "@time_window.business_hours"): window,
		},
	})

	tests := []struct {
		name       string
		instant    time.Time
		wantEffect decision.Effect
	}{
		{name: "monday in local interval", instant: time.Date(2026, time.August, 10, 8, 30, 0, 0, time.UTC), wantEffect: decision.EffectPermit},
		{name: "sunday outside weekday", instant: time.Date(2026, time.August, 9, 8, 30, 0, 0, time.UTC), wantEffect: decision.EffectDeny},
		{name: "dst local interval", instant: time.Date(2026, time.March, 30, 8, 30, 0, 0, time.UTC), wantEffect: decision.EffectPermit},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := evaluateRuntimeCheckpointWithInput(t, evaluator, target, map[string]decision.Value{
				"time": runtimeTimestampValue(t, test.instant),
			})
			if response.Effect() != test.wantEffect {
				t.Fatalf("time-window effect = %q, want %q", response.Effect(), test.wantEffect)
			}
		})
	}
}

func TestDecisionServiceUsesConcreteRuntimeForGenericAndAuthnCheckpoints(t *testing.T) {
	genericCatalog, _ := decisionRuntimeCatalog(t, decision.EffectPermit, registry.NoMatchDeny, nil, nil, nil)
	genericIDs := &sequenceIDGenerator{}
	genericRuntime := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: genericCatalog, ids: genericIDs, evaluationTimeout: time.Second,
	})
	genericGeneration := mustRuntimeGeneration(
		t,
		1,
		&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)},
		&recordingAdmissionAuthority{},
		genericRuntime,
	)
	genericService := mustDecisionService(t, &replaceableGenerationSource{generation: genericGeneration})

	if _, err := genericService.Evaluate(context.Background(), mustAuthorityTargetInvocation(t, "mail", "submit")); err != nil {
		t.Fatalf("generic DecisionService.Evaluate() error = %v", err)
	}

	authnRuntime, authnIDs := mustBuiltinAuthnCheckpointRuntime(t)
	authnGeneration := mustRuntimeGeneration(
		t,
		2,
		&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)},
		&recordingAdmissionAuthority{},
		authnRuntime,
	)
	authnService := mustDecisionService(t, &replaceableGenerationSource{generation: authnGeneration})

	err := authnService.WithSession(context.Background(), mustAuthorityInvocation(t, true), func(session DecisionSession) error {
		evaluateSessionCheckpoints(t, session, []string{"pre_auth", "auth_decision"})

		return nil
	})
	if err != nil {
		t.Fatalf("DecisionService.WithSession() error = %v", err)
	}

	if genericIDs.callCount() != 1 || authnIDs.callCount() != 2 {
		t.Fatalf("concrete runtime checkpoint calls = generic:%d authn:%d, want 1/2", genericIDs.callCount(), authnIDs.callCount())
	}
}

func TestDecisionRuntimeBuildsProvenanceAndFailsClosedOnCollision(t *testing.T) {
	provider := &recordingFactProvider{facts: []providedFact{{id: "plugin.reputation.score", category: decision.FactCategoryEnvironment, value: runtimeStringValue(t, "high")}}}
	descriptor := decisionRuntimeProvider(t, "mail/reputation", "plugin.reputation.score", registry.ProviderFailureIndeterminate, nil)
	catalog, target := decisionRuntimeCatalog(t, decision.EffectPermit, registry.NoMatchDeny, []registry.FactSchema{
		decisionRuntimeFactSchema(t, "subject.account", decision.FactSourceCaller, false),
		decisionRuntimeFactSchema(t, "plugin.reputation.score", decision.FactSourcePlugin, false),
	}, []registry.ProviderDefinition{descriptor}, nil)
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog,
		factProviders: map[string]factProviderBinding{
			"mail/reputation": {provider: provider, source: decision.FactSourcePlugin, authority: "reputation", component: "mail/reputation"},
		},
		ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
	})

	response := evaluateRuntimeCheckpointWithSubject(t, evaluator, target, map[string]decision.Value{"account": runtimeStringValue(t, "alice")})
	if response.Effect() != decision.EffectPermit {
		t.Fatalf("effect = %q, want permit", response.Effect())
	}

	facts := provider.recordedFacts()

	callerFact, ok := facts.Get("subject.account")
	if !ok || callerFact.Provenance().Source() != decision.FactSourceCaller {
		t.Fatalf("caller fact provenance = %#v", callerFact.Provenance())
	}

	provider.facts = append(provider.facts, providedFact{id: "subject.account", category: decision.FactCategorySubject, value: runtimeStringValue(t, "overwrite")})
	response = evaluateRuntimeCheckpointWithSubject(t, evaluator, target, map[string]decision.Value{"account": runtimeStringValue(t, "alice")})

	if response.Effect() != decision.EffectIndeterminate {
		t.Fatalf("collision effect = %q, want indeterminate", response.Effect())
	}
}

func TestDecisionRuntimeRejectsProviderSchemaViolationBeforeFactInsertion(t *testing.T) {
	provider := &recordingFactProvider{facts: []providedFact{{
		id:       "plugin.reputation.score",
		category: decision.FactCategoryEnvironment,
		value:    runtimeBooleanValue(t, true),
	}}}
	descriptor := decisionRuntimeProvider(
		t,
		"mail/reputation",
		"plugin.reputation.score",
		registry.ProviderFailureContinue,
		nil,
	)
	catalog, target := decisionRuntimeCatalog(
		t,
		decision.EffectPermit,
		registry.NoMatchDeny,
		[]registry.FactSchema{
			decisionRuntimeFactSchema(t, "plugin.reputation.score", decision.FactSourcePlugin, false),
		},
		[]registry.ProviderDefinition{descriptor},
		nil,
	)
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog,
		factProviders: map[string]factProviderBinding{
			"mail/reputation": decisionRuntimeFactBinding(provider, "reputation"),
		},
		ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
	})

	outcome := evaluateRuntimeOutcome(t, evaluator, target, &recordingEffectAcceptor{})
	if outcome.response.Effect() != decision.EffectIndeterminate {
		t.Fatalf("effect = %q, want indeterminate", outcome.response.Effect())
	}

	if len(outcome.report.runtime.providers) != 1 ||
		outcome.report.runtime.providers[0].state != providerStateFailed {
		t.Fatalf("provider records = %#v, want one failed schema validation", outcome.report.runtime.providers)
	}

	if _, exists := outcome.report.runtime.facts.Get("plugin.reputation.score"); exists {
		t.Fatal("schema-invalid provider fact reached the evaluation fact set")
	}
}

func TestDecisionRuntimeRejectsAdmittedFactOverwrite(t *testing.T) {
	value := runtimeStringValue(t, "forged-principal")
	provenance, _ := decision.NewProvenance(decision.FactSourceNauthilus, "nauthilus", "test")

	forged, err := decision.NewFact("caller.principal", decision.FactCategoryEnvironment, value, provenance)
	if err != nil {
		t.Fatalf("NewFact() error = %v", err)
	}

	admittedFact := mustRuntimeTrustedFact(
		t,
		"caller.principal",
		decision.FactSourceNauthilus,
		runtimeStringValue(t, "trusted-client"),
	)
	admitted, _ := decision.NewFactSet([]decision.Fact{admittedFact})
	checkpointFacts, _ := decision.NewFactSet([]decision.Fact{forged})

	if _, err = mergeAdmittedFacts(admitted, checkpointFacts); err == nil {
		t.Fatal("mergeAdmittedFacts() overwrite error = nil")
	}
}

func TestDecisionRuntimePreservesAdmittedAuthenticationFacts(t *testing.T) {
	admitted, err := decision.NewFactSet([]decision.Fact{
		mustRuntimeTrustedFact(
			t,
			"caller.scopes",
			decision.FactSourceNauthilus,
			runtimeStringListValue(t, []string{"scope:a", "scope:z"}),
		),
		mustRuntimeTrustedFact(
			t,
			"caller.authentication_kind",
			decision.FactSourceNauthilus,
			runtimeStringValue(t, "bearer"),
		),
		mustRuntimeTrustedFact(
			t,
			"transport.source_ip",
			decision.FactSourceTransport,
			runtimeStringValue(t, "192.0.2.10"),
		),
	})
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	empty, _ := decision.NewFactSet(nil)

	admitted, err = mergeAdmittedFacts(admitted, empty)
	if err != nil {
		t.Fatalf("mergeAdmittedFacts() error = %v", err)
	}

	assertTrustedRuntimeFact(t, admitted, "caller.scopes", decision.FactSourceNauthilus)
	assertTrustedRuntimeFact(t, admitted, "caller.authentication_kind", decision.FactSourceNauthilus)
	assertTrustedRuntimeFact(t, admitted, "transport.source_ip", decision.FactSourceTransport)
}

func TestDecisionRuntimeRejectsInvalidAdmittedFactsBeforeProviderInvocation(t *testing.T) {
	provider := &countingFactProvider{facts: []providedFact{{
		id: "plugin.optional.value", category: decision.FactCategoryEnvironment, value: runtimeStringValue(t, "unused"),
	}}}
	descriptor := decisionRuntimeProvider(t, "mail/provider", "plugin.optional.value", registry.ProviderFailureIndeterminate, nil)

	tests := []struct {
		name       string
		attributes map[string]decision.Value
		required   bool
	}{
		{name: "wrong kind", attributes: map[string]decision.Value{"account": runtimeBooleanValue(t, true)}},
		{name: "required fact has no producer", required: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider.reset()

			catalog, target := decisionRuntimeCatalog(t, decision.EffectPermit, registry.NoMatchDeny, []registry.FactSchema{
				decisionRuntimeFactSchema(t, "subject.account", decision.FactSourceCaller, test.required),
				decisionRuntimeFactSchema(t, "plugin.optional.value", decision.FactSourcePlugin, false),
			}, []registry.ProviderDefinition{descriptor}, nil)
			evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
				catalog: catalog,
				factProviders: map[string]factProviderBinding{
					"mail/provider": decisionRuntimeFactBinding(provider, "provider"),
				},
				ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
			})

			response := evaluateRuntimeCheckpointWithSubject(t, evaluator, target, test.attributes)
			if response.Effect() != decision.EffectIndeterminate || provider.callCount() != 0 {
				t.Fatalf("invalid admitted facts effect/provider calls = %q/%d, want indeterminate/0", response.Effect(), provider.callCount())
			}
		})
	}
}

func TestDecisionRuntimeProviderFailureAndDependencySemantics(t *testing.T) {
	tests := []struct {
		name            string
		failure         registry.ProviderFailureBehavior
		wantEffect      decision.Effect
		wantDependent   int
		wantIndependent int
	}{
		{name: "continue skips dependent", failure: registry.ProviderFailureContinue, wantEffect: decision.EffectPermit, wantIndependent: 1},
		{name: "indeterminate cancels later levels", failure: registry.ProviderFailureIndeterminate, wantEffect: decision.EffectIndeterminate, wantIndependent: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			independentStarted := make(chan struct{})
			failed := &blockingFactProvider{waitFor: independentStarted, err: errors.New("provider failed")}
			independent := &blockingFactProvider{
				started: independentStarted,
				facts: []providedFact{{
					id: "plugin.independent.value", category: decision.FactCategoryEnvironment, value: runtimeStringValue(t, "ok"),
				}},
			}
			dependent := &countingFactProvider{facts: []providedFact{{id: "plugin.dependent.value", category: decision.FactCategoryEnvironment, value: runtimeStringValue(t, "late")}}}
			providers := []registry.ProviderDefinition{
				decisionRuntimeProvider(t, "mail/failed", "plugin.failed.value", test.failure, nil),
				decisionRuntimeProvider(t, "mail/independent", "plugin.independent.value", registry.ProviderFailureIndeterminate, nil),
				decisionRuntimeProvider(t, "mail/dependent", "plugin.dependent.value", registry.ProviderFailureIndeterminate, []string{"mail/failed"}),
			}
			facts := []registry.FactSchema{
				decisionRuntimeFactSchema(t, "plugin.failed.value", decision.FactSourcePlugin, false),
				decisionRuntimeFactSchema(t, "plugin.independent.value", decision.FactSourcePlugin, false),
				decisionRuntimeFactSchema(t, "plugin.dependent.value", decision.FactSourcePlugin, false),
			}
			catalog, target := decisionRuntimeCatalog(t, decision.EffectPermit, registry.NoMatchDeny, facts, providers, nil)
			evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
				catalog: catalog,
				factProviders: map[string]factProviderBinding{
					"mail/failed":      decisionRuntimeFactBinding(failed, "failed"),
					"mail/independent": decisionRuntimeFactBinding(independent, "independent"),
					"mail/dependent":   decisionRuntimeFactBinding(dependent, "dependent"),
				},
				ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
			})

			response := evaluateRuntimeCheckpoint(t, evaluator, target, decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit))
			if response.Effect() != test.wantEffect {
				t.Fatalf("effect = %q, want %q", response.Effect(), test.wantEffect)
			}

			if dependent.callCount() != test.wantDependent || independent.callCount() != test.wantIndependent {
				t.Fatalf("dependent/independent calls = %d/%d, want %d/%d", dependent.callCount(), independent.callCount(), test.wantDependent, test.wantIndependent)
			}
		})
	}
}

func TestDecisionRuntimeLuaProviderUsesSharedFailureAndDependencySemantics(t *testing.T) {
	tests := []struct {
		name       string
		failure    registry.ProviderFailureBehavior
		wantEffect decision.Effect
	}{
		{name: "continue skips dependent", failure: registry.ProviderFailureContinue, wantEffect: decision.EffectPermit},
		{name: "indeterminate stops evaluation", failure: registry.ProviderFailureIndeterminate, wantEffect: decision.EffectIndeterminate},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			luaDefinition, luaBinding := decisionRuntimeLuaFailureBinding(t, test.failure)
			dependent := &countingFactProvider{facts: []providedFact{{
				id: "plugin.dependent.value", category: decision.FactCategoryEnvironment,
				value: runtimeStringValue(t, "late"),
			}}}
			providers := []registry.ProviderDefinition{
				luaDefinition,
				decisionRuntimeProvider(
					t,
					"mail/dependent",
					"plugin.dependent.value",
					registry.ProviderFailureIndeterminate,
					[]string{decisionRuntimeLuaFailureProviderID},
				),
			}
			facts := []registry.FactSchema{
				decisionRuntimeFactSchema(t, decisionRuntimeLuaFailureFactID, decision.FactSourceLua, false),
				decisionRuntimeFactSchema(t, "plugin.dependent.value", decision.FactSourcePlugin, false),
			}
			catalog, target := decisionRuntimeCatalog(t, decision.EffectPermit, registry.NoMatchDeny, facts, providers, nil)
			evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
				catalog: catalog,
				factProviders: map[string]factProviderBinding{
					decisionRuntimeLuaFailureProviderID: luaBinding,
					"mail/dependent":                    decisionRuntimeFactBinding(dependent, "dependent"),
				},
				ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
			})

			response := evaluateRuntimeCheckpoint(
				t,
				evaluator,
				target,
				decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
			)
			if response.Effect() != test.wantEffect {
				t.Fatalf("effect = %q, want %q", response.Effect(), test.wantEffect)
			}

			if dependent.callCount() != 0 {
				t.Fatalf("dependent calls = %d, want 0", dependent.callCount())
			}
		})
	}
}

func TestDecisionRuntimeProviderContractViolationOverridesContinue(t *testing.T) {
	provider := &blockingFactProvider{err: fmt.Errorf(
		"%w: undeclared Lua result",
		policyruntime.ErrProviderContractViolation,
	)}
	descriptor := decisionRuntimeProvider(
		t,
		"mail/lua-risk",
		"plugin.failed.value",
		registry.ProviderFailureContinue,
		nil,
	)
	catalog, target := decisionRuntimeCatalog(
		t,
		decision.EffectPermit,
		registry.NoMatchDeny,
		[]registry.FactSchema{
			decisionRuntimeFactSchema(t, "plugin.failed.value", decision.FactSourcePlugin, false),
		},
		[]registry.ProviderDefinition{descriptor},
		nil,
	)
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog,
		factProviders: map[string]factProviderBinding{
			"mail/lua-risk": decisionRuntimeFactBinding(provider, "failed"),
		},
		ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
	})

	response := evaluateRuntimeCheckpoint(
		t,
		evaluator,
		target,
		decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
	)
	if response.Effect() != decision.EffectIndeterminate {
		t.Fatalf("effect = %q, want indeterminate", response.Effect())
	}
}

func TestDecisionRuntimeCancellationDiscardsConcurrentFactsAndLaterWork(t *testing.T) {
	failureStarted := make(chan struct{})
	siblingCanceled := make(chan struct{})
	failed := &blockingFactProvider{started: failureStarted, err: errors.New("provider failed")}
	sibling := &blockingFactProvider{
		waitFor:  failureStarted,
		facts:    []providedFact{{id: "plugin.sibling.value", category: decision.FactCategoryEnvironment, value: runtimeStringValue(t, "discarded")}},
		canceled: siblingCanceled,
	}
	later := &countingFactProvider{facts: []providedFact{{id: "plugin.later.value", category: decision.FactCategoryEnvironment, value: runtimeStringValue(t, "late")}}}
	providers := []registry.ProviderDefinition{
		decisionRuntimeProvider(t, "mail/failed", "plugin.failed.value", registry.ProviderFailureIndeterminate, nil),
		decisionRuntimeProvider(t, "mail/sibling", "plugin.sibling.value", registry.ProviderFailureIndeterminate, nil),
		decisionRuntimeProvider(t, "mail/later", "plugin.later.value", registry.ProviderFailureIndeterminate, []string{"mail/sibling"}),
	}
	facts := []registry.FactSchema{
		decisionRuntimeFactSchema(t, "plugin.failed.value", decision.FactSourcePlugin, false),
		decisionRuntimeFactSchema(t, "plugin.sibling.value", decision.FactSourcePlugin, false),
		decisionRuntimeFactSchema(t, "plugin.later.value", decision.FactSourcePlugin, false),
	}
	catalog, target := decisionRuntimeCatalog(t, decision.EffectPermit, registry.NoMatchDeny, facts, providers, nil)
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog,
		factProviders: map[string]factProviderBinding{
			"mail/failed":  decisionRuntimeFactBinding(failed, "failed"),
			"mail/sibling": decisionRuntimeFactBinding(sibling, "sibling"),
			"mail/later":   decisionRuntimeFactBinding(later, "later"),
		},
		ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
	})

	outcome := evaluateRuntimeOutcome(t, evaluator, target, &recordingEffectAcceptor{})
	if outcome.response.Effect() != decision.EffectIndeterminate {
		t.Fatalf("effect = %q, want indeterminate", outcome.response.Effect())
	}

	select {
	case <-siblingCanceled:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("concurrent sibling did not observe level cancellation")
	}

	if later.callCount() != 0 {
		t.Fatalf("later provider calls = %d, want 0", later.callCount())
	}

	if _, ok := outcome.report.runtime.facts.Get("plugin.sibling.value"); ok {
		t.Fatal("canceled-level sibling fact was retained")
	}
}

func TestDecisionRuntimeEvaluationTimeoutCancelsProvider(t *testing.T) {
	canceled := make(chan struct{})
	provider := &blockingFactProvider{canceled: canceled}
	descriptor := decisionRuntimeProvider(t, "mail/slow", "plugin.slow.value", registry.ProviderFailureIndeterminate, nil)
	catalog, target := decisionRuntimeCatalog(t, decision.EffectPermit, registry.NoMatchDeny, []registry.FactSchema{
		decisionRuntimeFactSchema(t, "plugin.slow.value", decision.FactSourcePlugin, false),
	}, []registry.ProviderDefinition{descriptor}, nil)
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog,
		factProviders: map[string]factProviderBinding{
			"mail/slow": decisionRuntimeFactBinding(provider, "slow"),
		},
		ids: &sequenceIDGenerator{}, evaluationTimeout: 10 * time.Millisecond,
	})

	outcome := evaluateRuntimeOutcome(t, evaluator, target, &recordingEffectAcceptor{})
	if outcome.response.Effect() != decision.EffectIndeterminate {
		t.Fatalf("timed-out provider effect = %q, want indeterminate", outcome.response.Effect())
	}

	select {
	case <-canceled:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("provider did not observe evaluation timeout cancellation")
	}
}

func TestDecisionRuntimeDeadlineBoundsUncooperativeProvider(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	provider := &capturingFactProvider{
		provider: &uncooperativeFactProvider{started: started, release: release},
	}
	descriptor := decisionRuntimeProvider(t, "mail/stuck", "plugin.stuck.value", registry.ProviderFailureIndeterminate, nil)
	catalog, target := decisionRuntimeCatalog(t, decision.EffectPermit, registry.NoMatchDeny, []registry.FactSchema{
		decisionRuntimeFactSchema(t, "plugin.stuck.value", decision.FactSourcePlugin, false),
	}, []registry.ProviderDefinition{descriptor}, nil)
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog,
		factProviders: map[string]factProviderBinding{
			"mail/stuck": decisionRuntimeFactBinding(provider, "stuck"),
		},
		ids: &sequenceIDGenerator{}, evaluationTimeout: 10 * time.Millisecond,
	})

	result := make(chan runtimeEvaluation, 1)
	go func() {
		result <- evaluateRuntimeOutcome(t, evaluator, target, &recordingEffectAcceptor{})
	}()

	<-started

	select {
	case outcome := <-result:
		close(release)

		if outcome.response.Effect() != decision.EffectIndeterminate {
			t.Fatalf("uncooperative provider effect = %q, want indeterminate", outcome.response.Effect())
		}
	case <-time.After(100 * time.Millisecond):
		close(release)
		<-result

		t.Fatal("evaluation exceeded its deadline while provider ignored cancellation")
	}

	if got := provider.captures.Load(); got != 1 {
		t.Fatalf("provider call captures = %d, want 1", got)
	}
}

func TestDecisionRuntimeRequiredFactDiagnosticsAndFreshInvocation(t *testing.T) {
	catalog, target := decisionRuntimeCatalog(t, decision.EffectPermit, registry.NoMatchDeny, []registry.FactSchema{
		decisionRuntimeFactSchema(t, "subject.account", decision.FactSourceCaller, true),
	}, nil, nil)
	ids := &sequenceIDGenerator{}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{catalog: catalog, ids: ids, evaluationTimeout: time.Second})

	missing := evaluateRuntimeCheckpointOptions(t, evaluator, target, nil, true)
	if missing.Effect() != decision.EffectIndeterminate || missing.Diagnostics() == nil {
		t.Fatalf("missing required fact response = %q diagnostics=%v", missing.Effect(), missing.Diagnostics())
	}

	first := evaluateRuntimeCheckpointOptions(t, evaluator, target, map[string]decision.Value{"account": runtimeStringValue(t, "alice")}, true)
	second := evaluateRuntimeCheckpointOptions(t, evaluator, target, map[string]decision.Value{"account": runtimeStringValue(t, "alice")}, false)

	if first.DecisionID().String() == second.DecisionID().String() {
		t.Fatalf("fresh invocations reused Decision ID %q", first.DecisionID().String())
	}

	if first.Diagnostics() == nil || second.Diagnostics() != nil {
		t.Fatalf("diagnostics opt-in projection = first:%v second:%v", first.Diagnostics(), second.Diagnostics())
	}
}

func TestDecisionRuntimeDiagnosticsSanitizerIsBoundedAndDeterministic(t *testing.T) {
	forward := make(map[string]decision.Value)
	reverse := make(map[string]decision.Value)

	for index := 0; index < 100; index++ {
		key := fmt.Sprintf("provider.alias_%03d", index)
		forward[key] = runtimeStringValue(t, fmt.Sprintf("state-%080d", index))
	}

	for index := 99; index >= 0; index-- {
		key := fmt.Sprintf("provider.alias_%03d", index)
		reverse[key] = forward[key]
	}

	first := boundDiagnosticEntries(forward)
	second := boundDiagnosticEntries(reverse)

	if len(first) > maximumDiagnosticEntries || diagnosticProjectionSize(first) > maximumDiagnosticBytes {
		t.Fatalf("bounded diagnostics entries/bytes = %d/%d", len(first), diagnosticProjectionSize(first))
	}

	if got, want := sortedDiagnosticKeys(first), sortedDiagnosticKeys(second); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("deterministic keys = %v, want %v", got, want)
	}

	escaped := map[string]decision.Value{"provider.quoted\"alias": runtimeStringValue(t, "line\nvalue\\suffix")}

	encoded, err := json.Marshal(diagnosticJSONMap(escaped))
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if got, want := diagnosticProjectionSize(escaped), len(encoded); got != want {
		t.Fatalf("diagnostic JSON size = %d, want serialized size %d", got, want)
	}
}

func TestDecisionRuntimeEffectOwnershipFailureAndAmbiguity(t *testing.T) {
	target, _ := decision.NewTarget("mail", "submit")
	returnOnly := decisionRuntimeEffect(t, target, "mail/return", "", registry.EffectKindObligation, registry.ExecutionReturnOnly)
	syncEffect := decisionRuntimeEffect(t, target, "mail/sync", "mail/sync_provider", registry.EffectKindObligation, registry.ExecutionHostSync)
	postEffect := decisionRuntimeEffect(t, target, "mail/post", "mail/post_provider", registry.EffectKindObligation, registry.ExecutionHostPostAction)
	adviceEffect := decisionRuntimeEffect(t, target, "mail/advice", "", registry.EffectKindAdvice, registry.ExecutionReturnOnly)
	providers := []registry.ProviderDefinition{
		decisionRuntimeHostProvider(t, target, "mail/sync_provider", registry.ExecutionHostSync, nil),
		decisionRuntimeHostProvider(t, target, "mail/post_provider", registry.ExecutionHostPostAction, &recordingEffectAcceptor{}),
	}
	obligations := []registry.EffectUse{
		decisionRuntimeEffectUse(t, "mail/return"),
		decisionRuntimeEffectUse(t, "mail/sync"),
		decisionRuntimeEffectUse(t, "mail/post"),
	}
	advice := []registry.EffectUse{decisionRuntimeEffectUse(t, "mail/advice")}
	catalog, target := decisionRuntimeCatalogWithSelections(
		t,
		decision.EffectPermit,
		registry.NoMatchDeny,
		nil,
		providers,
		[]registry.EffectDefinition{returnOnly, syncEffect, postEffect, adviceEffect},
		obligations,
		advice,
	)
	syncProvider := &recordingSyncEffectProvider{result: effectsupervisor.Succeeded()}
	work := &recordingPostActionWork{result: effectsupervisor.Failed("late_failure")}
	postProvider := &recordingPostActionProvider{work: work}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
		syncEffects: map[string]syncEffectBinding{"mail/sync_provider": {provider: syncProvider}},
		postActions: map[string]postActionBinding{"mail/post_provider": {provider: postProvider}},
	})
	acceptor := &failingEffectAcceptor{err: errors.New("saturated")}
	outcome := evaluateRuntimeOutcome(t, evaluator, target, acceptor)

	if outcome.response.Effect() != decision.EffectIndeterminate || syncProvider.callCount() != 1 || acceptor.callCount() != 1 {
		t.Fatalf("acceptance failure effect/sync/accept = %q/%d/%d", outcome.response.Effect(), syncProvider.callCount(), acceptor.callCount())
	}

	if outcome.response.Status().Code() != decision.StatusCodeEffectAcceptanceRejected {
		t.Fatalf("acceptance failure status = %q, want %q", outcome.response.Status().Code(), decision.StatusCodeEffectAcceptanceRejected)
	}

	if work.cleanupCount() != 1 {
		t.Fatalf("rejected post-action cleanup count = %d, want 1", work.cleanupCount())
	}

	if got, want := effectReportStates(outcome.report.runtime.effects), []effectsupervisor.State{
		effectsupervisor.StateAttempted,
		effectsupervisor.StateSucceeded,
		effectsupervisor.StateAttempted,
		effectsupervisor.StateFailed,
	}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("partial effect report = %#v", outcome.report.runtime.effects)
	}

	assertDecisionRuntimeOutcomeUnknown(t, providers[0], syncEffect)
}

func TestDecisionRuntimeRecordsUnstartedEffectsAfterSynchronousFailure(t *testing.T) {
	target, _ := decision.NewTarget("mail", "submit")
	provider := decisionRuntimeHostProvider(t, target, "mail/sync_provider", registry.ExecutionHostSync, nil)
	effects := make([]registry.EffectDefinition, 0, 3)
	uses := make([]registry.EffectUse, 0, 3)

	for index := 1; index <= 3; index++ {
		id := fmt.Sprintf("mail/sync_%d", index)
		effects = append(effects, decisionRuntimeEffect(
			t,
			target,
			id,
			"mail/sync_provider",
			registry.EffectKindObligation,
			registry.ExecutionHostSync,
		))
		uses = append(uses, decisionRuntimeEffectUse(t, id))
	}

	catalog, target := decisionRuntimeCatalogWithSelections(
		t,
		decision.EffectPermit,
		registry.NoMatchDeny,
		nil,
		[]registry.ProviderDefinition{provider},
		effects,
		uses,
		nil,
	)
	syncProvider := &recordingSyncEffectProvider{result: effectsupervisor.Failed("known_failure")}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
		syncEffects: map[string]syncEffectBinding{"mail/sync_provider": {provider: syncProvider}},
	})

	outcome := evaluateRuntimeOutcome(t, evaluator, target, &recordingEffectAcceptor{})
	want := []effectsupervisor.State{
		effectsupervisor.StateAttempted,
		effectsupervisor.StateFailed,
		effectsupervisor.StateNotStarted,
		effectsupervisor.StateNotStarted,
	}

	if got := effectReportStates(outcome.report.runtime.effects); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("effect lifecycle states = %v, want %v", got, want)
	}

	if syncProvider.callCount() != 1 {
		t.Fatalf("synchronous effect calls = %d, want 1", syncProvider.callCount())
	}
}

func TestDecisionRuntimeTimeoutFailsClosedAfterSynchronousEffect(t *testing.T) {
	target, _ := decision.NewTarget("mail", "submit")
	syncEffect := decisionRuntimeEffect(t, target, "mail/sync", "mail/sync_provider", registry.EffectKindObligation, registry.ExecutionHostSync)
	provider := decisionRuntimeHostProvider(t, target, "mail/sync_provider", registry.ExecutionHostSync, nil)
	catalog, target := decisionRuntimeCatalogWithSelections(
		t,
		decision.EffectPermit,
		registry.NoMatchDeny,
		nil,
		[]registry.ProviderDefinition{provider},
		[]registry.EffectDefinition{syncEffect},
		[]registry.EffectUse{decisionRuntimeEffectUse(t, "mail/sync")},
		nil,
	)
	syncProvider := &cancelAwareSyncEffectProvider{done: make(chan struct{})}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: 10 * time.Millisecond,
		syncEffects: map[string]syncEffectBinding{"mail/sync_provider": {provider: syncProvider}},
	})

	outcome := evaluateRuntimeOutcome(t, evaluator, target, &recordingEffectAcceptor{})

	select {
	case <-syncProvider.done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("synchronous provider did not observe evaluation cancellation")
	}

	if outcome.response.Effect() != decision.EffectIndeterminate || syncProvider.callCount() != 1 {
		t.Fatalf("timed-out sync effect/calls = %q/%d, want indeterminate/1", outcome.response.Effect(), syncProvider.callCount())
	}
}

func TestDecisionRuntimeDeadlineBoundsUncooperativeSynchronousEffect(t *testing.T) {
	target, _ := decision.NewTarget("mail", "submit")
	syncEffect := decisionRuntimeEffect(t, target, "mail/sync", "mail/sync_provider", registry.EffectKindObligation, registry.ExecutionHostSync)
	provider := decisionRuntimeHostProvider(t, target, "mail/sync_provider", registry.ExecutionHostSync, nil)
	catalog, target := decisionRuntimeCatalogWithSelections(
		t,
		decision.EffectPermit,
		registry.NoMatchDeny,
		nil,
		[]registry.ProviderDefinition{provider},
		[]registry.EffectDefinition{syncEffect},
		[]registry.EffectUse{decisionRuntimeEffectUse(t, "mail/sync")},
		nil,
	)
	started := make(chan struct{})
	release := make(chan struct{})
	syncProvider := &capturingSyncEffectProvider{
		provider: &uncooperativeSyncEffectProvider{started: started, release: release},
	}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: 10 * time.Millisecond,
		syncEffects: map[string]syncEffectBinding{"mail/sync_provider": {provider: syncProvider}},
	})

	result := make(chan runtimeEvaluation, 1)
	go func() {
		result <- evaluateRuntimeOutcome(t, evaluator, target, &recordingEffectAcceptor{})
	}()

	<-started

	select {
	case outcome := <-result:
		close(release)

		if outcome.response.Effect() != decision.EffectIndeterminate {
			t.Fatalf("uncooperative sync effect = %q, want indeterminate", outcome.response.Effect())
		}
	case <-time.After(100 * time.Millisecond):
		close(release)
		<-result

		t.Fatal("evaluation exceeded its deadline while synchronous effect ignored cancellation")
	}

	if got := syncProvider.captures.Load(); got != 1 {
		t.Fatalf("synchronous effect call captures = %d, want 1", got)
	}
}

// assertDecisionRuntimeOutcomeUnknown proves synchronous ambiguity is non-retryable and attempted once.
func assertDecisionRuntimeOutcomeUnknown(
	t *testing.T,
	provider registry.ProviderDefinition,
	syncEffect registry.EffectDefinition,
) {
	t.Helper()

	unknown := &recordingSyncEffectProvider{result: effectsupervisor.OutcomeUnknown("dispatch_ambiguous")}
	unknownCatalog, unknownTarget := decisionRuntimeCatalogWithSelections(
		t,
		decision.EffectPermit,
		registry.NoMatchDeny,
		nil,
		[]registry.ProviderDefinition{provider},
		[]registry.EffectDefinition{syncEffect},
		[]registry.EffectUse{decisionRuntimeEffectUse(t, "mail/sync")},
		nil,
	)
	unknownEvaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: unknownCatalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
		syncEffects: map[string]syncEffectBinding{"mail/sync_provider": {provider: unknown}},
	})
	unknownResponse := evaluateRuntimeOutcome(t, unknownEvaluator, unknownTarget, &recordingEffectAcceptor{}).response

	if unknownResponse.Status().Code() != decision.StatusCodeEffectOutcomeUnknown || unknownResponse.Status().Retryable() || unknown.callCount() != 1 {
		t.Fatalf("outcome_unknown status/retry/calls = %q/%v/%d", unknownResponse.Status().Code(), unknownResponse.Status().Retryable(), unknown.callCount())
	}
}

func TestDecisionRuntimeAcceptedLateFailureDoesNotMutateAndCleansUp(t *testing.T) {
	target, _ := decision.NewTarget("mail", "submit")
	postEffect := decisionRuntimeEffect(t, target, "mail/post", "mail/post_provider", registry.EffectKindObligation, registry.ExecutionHostPostAction)
	provider := decisionRuntimeHostProvider(t, target, "mail/post_provider", registry.ExecutionHostPostAction, &recordingEffectAcceptor{})
	catalog, target := decisionRuntimeCatalogWithSelections(
		t,
		decision.EffectPermit,
		registry.NoMatchDeny,
		nil,
		[]registry.ProviderDefinition{provider},
		[]registry.EffectDefinition{postEffect},
		[]registry.EffectUse{decisionRuntimeEffectUse(t, "mail/post")},
		nil,
	)
	work := &recordingPostActionWork{result: effectsupervisor.Failed("late_failure")}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
		postActions: map[string]postActionBinding{"mail/post_provider": {provider: &recordingPostActionProvider{work: work}}},
	})

	supervisor, err := effectsupervisor.New(
		effectsupervisor.Config{Capacity: 1, Workers: 1},
		effectsupervisor.ProviderBinding{Name: "mail/post_provider", Provider: effectsupervisor.NewExecutableProvider()},
	)
	if err != nil {
		t.Fatalf("effectsupervisor.New() error = %v", err)
	}

	finalization := decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit)
	outcome := evaluateRuntimeOutcomeWithFinalization(t, evaluator, target, supervisor, finalization)

	if outcome.response.Effect() != decision.EffectPermit || len(outcome.response.Obligations()) != 0 {
		t.Fatalf("accepted response = %q obligations=%d", outcome.response.Effect(), len(outcome.response.Obligations()))
	}

	finalization.Complete()

	waitContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err = supervisor.WaitIdle(waitContext); err != nil {
		t.Fatalf("WaitIdle() error = %v", err)
	}

	if work.executeCount() != 1 || work.cleanupCount() != 1 || outcome.response.Effect() != decision.EffectPermit {
		t.Fatalf("late failure execution/cleanup/response = %d/%d/%q", work.executeCount(), work.cleanupCount(), outcome.response.Effect())
	}

	if err = supervisor.Shutdown(waitContext); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

func TestDecisionRuntimeReleasesPreparedWorkWhenSupervisorPlanValidationFails(t *testing.T) {
	target, _ := decision.NewTarget("mail", "submit")
	postEffect := decisionRuntimeEffect(t, target, "mail/post", "mail/post_provider", registry.EffectKindObligation, registry.ExecutionHostPostAction)
	provider := decisionRuntimeHostProvider(t, target, "mail/post_provider", registry.ExecutionHostPostAction, &recordingEffectAcceptor{})
	catalog, target := decisionRuntimeCatalogWithSelections(
		t,
		decision.EffectPermit,
		registry.NoMatchDeny,
		nil,
		[]registry.ProviderDefinition{provider},
		[]registry.EffectDefinition{postEffect},
		[]registry.EffectUse{decisionRuntimeEffectUse(t, "mail/post")},
		nil,
	)
	work := &recordingPostActionWork{}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second, postActionBudget: time.Nanosecond,
		postActions: map[string]postActionBinding{"mail/post_provider": {provider: &recordingPostActionProvider{work: work}}},
	})

	outcome := evaluateRuntimeOutcome(t, evaluator, target, &recordingEffectAcceptor{})
	if outcome.response.Effect() != decision.EffectIndeterminate || work.cleanupCount() != 1 {
		t.Fatalf("invalid plan effect/cleanup = %q/%d, want indeterminate/1", outcome.response.Effect(), work.cleanupCount())
	}
}

func TestDecisionRuntimeRejectsTypedNilPostActionWorkWithoutPanic(t *testing.T) {
	target, _ := decision.NewTarget("mail", "submit")
	postEffect := decisionRuntimeEffect(t, target, "mail/post", "mail/post_provider", registry.EffectKindObligation, registry.ExecutionHostPostAction)
	provider := decisionRuntimeHostProvider(t, target, "mail/post_provider", registry.ExecutionHostPostAction, &recordingEffectAcceptor{})
	catalog, target := decisionRuntimeCatalogWithSelections(
		t,
		decision.EffectPermit,
		registry.NoMatchDeny,
		nil,
		[]registry.ProviderDefinition{provider},
		[]registry.EffectDefinition{postEffect},
		[]registry.EffectUse{decisionRuntimeEffectUse(t, "mail/post")},
		nil,
	)

	var work *panickingTypedNilWork

	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
		postActions: map[string]postActionBinding{"mail/post_provider": {provider: &recordingPostActionProvider{work: work}}},
	})

	outcome := evaluateRuntimeOutcome(t, evaluator, target, &recordingEffectAcceptor{})
	if outcome.response.Effect() != decision.EffectIndeterminate {
		t.Fatalf("typed-nil work effect = %q, want indeterminate", outcome.response.Effect())
	}
}

func TestDecisionRuntimeBoundsBlockingAndPanickingPostActionPreparation(t *testing.T) {
	target, _ := decision.NewTarget("mail", "submit")
	postEffect := decisionRuntimeEffect(t, target, "mail/post", "mail/post_provider", registry.EffectKindObligation, registry.ExecutionHostPostAction)
	provider := decisionRuntimeHostProvider(t, target, "mail/post_provider", registry.ExecutionHostPostAction, &recordingEffectAcceptor{})
	catalog, target := decisionRuntimeCatalogWithSelections(
		t,
		decision.EffectPermit,
		registry.NoMatchDeny,
		nil,
		[]registry.ProviderDefinition{provider},
		[]registry.EffectDefinition{postEffect},
		[]registry.EffectUse{decisionRuntimeEffectUse(t, "mail/post")},
		nil,
	)
	release := make(chan struct{})
	capturedBlocking := &capturingPostActionProvider{
		provider: &blockingPostActionProvider{release: release},
	}

	tests := []struct {
		name     string
		provider postActionProvider
		release  chan struct{}
	}{
		{name: "blocking", provider: capturedBlocking, release: release},
		{name: "panic", provider: panickingPostActionProvider{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
				catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: 10 * time.Millisecond,
				postActions: map[string]postActionBinding{"mail/post_provider": {provider: test.provider}},
			})
			result := make(chan runtimeEvaluation, 1)

			go func() {
				result <- evaluateRuntimeOutcome(t, evaluator, target, &recordingEffectAcceptor{})
			}()

			select {
			case outcome := <-result:
				if test.release != nil {
					close(test.release)
				}

				if outcome.response.Effect() != decision.EffectIndeterminate {
					t.Fatalf("preparation effect = %q, want indeterminate", outcome.response.Effect())
				}
			case <-time.After(100 * time.Millisecond):
				if test.release != nil {
					close(test.release)
				}

				t.Fatal("post-action preparation exceeded the evaluation deadline")
			}
		})
	}

	if got := capturedBlocking.captures.Load(); got != 1 {
		t.Fatalf("post-action preparation captures = %d, want 1", got)
	}
}

func TestDecisionRuntimePreservesAcceptedPostActionAfterLaterPreparationFailure(t *testing.T) {
	target, _ := decision.NewTarget("mail", "submit")
	provider := decisionRuntimeHostProvider(t, target, "mail/post_provider", registry.ExecutionHostPostAction, &recordingEffectAcceptor{})
	effects := []registry.EffectDefinition{
		decisionRuntimeEffect(t, target, "mail/post_1", "mail/post_provider", registry.EffectKindObligation, registry.ExecutionHostPostAction),
		decisionRuntimeEffect(t, target, "mail/post_2", "mail/post_provider", registry.EffectKindObligation, registry.ExecutionHostPostAction),
	}
	uses := []registry.EffectUse{
		decisionRuntimeEffectUse(t, "mail/post_1"),
		decisionRuntimeEffectUse(t, "mail/post_2"),
	}
	catalog, target := decisionRuntimeCatalogWithSelections(
		t, decision.EffectPermit, registry.NoMatchDeny, nil, []registry.ProviderDefinition{provider}, effects, uses, nil,
	)
	work := &recordingPostActionWork{result: effectsupervisor.Succeeded()}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
		postActions: map[string]postActionBinding{
			"mail/post_provider": {provider: &laterFailingPostActionProvider{work: work}},
		},
	})

	outcome := evaluateRuntimeOutcome(t, evaluator, target, &recordingEffectAcceptor{})
	if outcome.response.Effect() != decision.EffectIndeterminate {
		t.Fatalf("later preparation failure effect = %q, want indeterminate", outcome.response.Effect())
	}

	if work.cleanupCount() != 0 {
		t.Fatalf("accepted earlier work cleanup count = %d, want 0", work.cleanupCount())
	}
}

func TestDecisionRuntimeContainsFactProviderPanic(t *testing.T) {
	descriptor := decisionRuntimeProvider(t, "mail/panic", "plugin.panic.value", registry.ProviderFailureIndeterminate, nil)
	catalog, target := decisionRuntimeCatalog(t, decision.EffectPermit, registry.NoMatchDeny, []registry.FactSchema{
		decisionRuntimeFactSchema(t, "plugin.panic.value", decision.FactSourcePlugin, false),
	}, []registry.ProviderDefinition{descriptor}, nil)
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
		factProviders: map[string]factProviderBinding{
			"mail/panic": decisionRuntimeFactBinding(panickingFactProvider{}, "panic"),
		},
	})

	response := evaluateRuntimeCheckpoint(
		t,
		evaluator,
		target,
		decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
	)
	if response.Effect() != decision.EffectIndeterminate {
		t.Fatalf("panicking provider effect = %q, want indeterminate", response.Effect())
	}
}

type sequenceIDGenerator struct {
	mu   sync.Mutex
	next int
}

// callCount returns the number of fresh decision identities issued by the runtime.
func (g *sequenceIDGenerator) callCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.next
}

// Next returns a distinct deterministic test correlation identity.
func (g *sequenceIDGenerator) Next(prefix string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.next++

	return prefix + "-test-" + string(rune('0'+g.next)), nil
}

type recordingFactProvider struct {
	mu    sync.Mutex
	input decision.FactSet
	facts []providedFact
	err   error
}

type countingFactProvider struct {
	mu    sync.Mutex
	facts []providedFact
	err   error
	calls int
}

type recordingSyncEffectProvider struct {
	mu     sync.Mutex
	result effectsupervisor.Result
	calls  int
}

type cancelAwareSyncEffectProvider struct {
	mu    sync.Mutex
	done  chan struct{}
	calls int
}

type uncooperativeSyncEffectProvider struct {
	started chan<- struct{}
	release <-chan struct{}
}

type capturingSyncEffectProvider struct {
	provider syncEffectProvider
	captures atomic.Int64
}

// Execute rejects synchronous work that bypasses pre-goroutine call capture.
func (*capturingSyncEffectProvider) Execute(context.Context, effectExecution) effectsupervisor.Result {
	return effectsupervisor.Failed("sync_effect_call_not_captured")
}

// captureSyncEffectCall records and returns one detached call owner.
func (p *capturingSyncEffectProvider) captureSyncEffectCall() (syncEffectProvider, error) {
	p.captures.Add(1)

	return p.provider, nil
}

// Execute deliberately ignores cancellation until the test releases it.
func (p *uncooperativeSyncEffectProvider) Execute(_ context.Context, _ effectExecution) effectsupervisor.Result {
	close(p.started)
	<-p.release

	return effectsupervisor.Succeeded()
}

// Execute waits for evaluation cancellation and simulates a late success report.
func (p *cancelAwareSyncEffectProvider) Execute(ctx context.Context, _ effectExecution) effectsupervisor.Result {
	<-ctx.Done()

	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls++
	close(p.done)

	return effectsupervisor.Succeeded()
}

// callCount returns the synchronized timeout-path attempt count.
func (p *cancelAwareSyncEffectProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.calls
}

// Execute records one synchronous effect attempt and returns its bounded outcome.
func (p *recordingSyncEffectProvider) Execute(_ context.Context, _ effectExecution) effectsupervisor.Result {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls++

	return p.result
}

// callCount returns the synchronized synchronous attempt count.
func (p *recordingSyncEffectProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.calls
}

type recordingPostActionProvider struct {
	work effectsupervisor.Work
}

type blockingPostActionProvider struct {
	release <-chan struct{}
}

type capturingPostActionProvider struct {
	provider postActionProvider
	captures atomic.Int64
}

// Prepare rejects post-action work that bypasses pre-goroutine call capture.
func (*capturingPostActionProvider) Prepare(
	context.Context,
	effectExecution,
) (effectsupervisor.Work, error) {
	return nil, errors.New("post-action call was not captured")
}

// capturePostActionCall records and returns one detached preparation owner.
func (p *capturingPostActionProvider) capturePostActionCall() (postActionProvider, error) {
	p.captures.Add(1)

	return p.provider, nil
}

type panickingPostActionProvider struct{}

type laterFailingPostActionProvider struct {
	work  effectsupervisor.Work
	calls int
}

type panickingFactProvider struct{}

// Prepare returns one explicitly owned executable work item.
func (p *recordingPostActionProvider) Prepare(_ context.Context, _ effectExecution) (effectsupervisor.Work, error) {
	return p.work, nil
}

// Prepare deliberately ignores cancellation until the test releases it.
func (p *blockingPostActionProvider) Prepare(_ context.Context, _ effectExecution) (effectsupervisor.Work, error) {
	<-p.release

	return &recordingPostActionWork{}, nil
}

// Prepare panics to prove the application boundary contains provider faults.
func (panickingPostActionProvider) Prepare(context.Context, effectExecution) (effectsupervisor.Work, error) {
	panic("post-action prepare panic")
}

// Prepare returns one accepted work item before a later ordinal fails preparation.
func (p *laterFailingPostActionProvider) Prepare(context.Context, effectExecution) (effectsupervisor.Work, error) {
	p.calls++

	if p.calls == 1 {
		return p.work, nil
	}

	return nil, errors.New("later preparation failed")
}

// Collect panics to prove fact-provider faults fail closed.
func (panickingFactProvider) Collect(context.Context, factProviderInput) ([]providedFact, error) {
	panic("fact provider panic")
}

type recordingPostActionWork struct {
	mu       sync.Mutex
	result   effectsupervisor.Result
	executes int
	cleanups int
}

type panickingTypedNilWork struct{}

// Validate panics if a typed-nil work item crosses the preparation boundary.
func (w *panickingTypedNilWork) Validate() error {
	_ = *w

	return nil
}

// Execute panics if a typed-nil work item reaches execution.
func (w *panickingTypedNilWork) Execute(context.Context) effectsupervisor.Result {
	_ = *w

	return effectsupervisor.Succeeded()
}

// Cleanup panics if cleanup dereferences a typed-nil work item.
func (w *panickingTypedNilWork) Cleanup() {
	_ = *w
}

// Validate accepts the bounded test work item.
func (w *recordingPostActionWork) Validate() error {
	return nil
}

type blockingFactProvider struct {
	mu       sync.Mutex
	waitFor  <-chan struct{}
	started  chan<- struct{}
	canceled chan<- struct{}
	facts    []providedFact
	err      error
	calls    int
}

type uncooperativeFactProvider struct {
	started chan<- struct{}
	release <-chan struct{}
}

type capturingFactProvider struct {
	provider factProvider
	captures atomic.Int64
}

// Collect rejects execution that bypasses pre-goroutine call capture.
func (*capturingFactProvider) Collect(context.Context, factProviderInput) ([]providedFact, error) {
	return nil, errors.New("fact provider call was not captured")
}

// captureFactProviderCall records and returns one detached call owner.
func (p *capturingFactProvider) captureFactProviderCall() (factProvider, error) {
	p.captures.Add(1)

	return p.provider, nil
}

// Collect deliberately ignores cancellation until the test releases it.
func (p *uncooperativeFactProvider) Collect(_ context.Context, _ factProviderInput) ([]providedFact, error) {
	close(p.started)
	<-p.release

	return nil, nil
}

// Collect coordinates deterministic concurrent cancellation evidence.
func (p *blockingFactProvider) Collect(ctx context.Context, _ factProviderInput) ([]providedFact, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()

	if p.waitFor != nil {
		<-p.waitFor
	}

	if p.started != nil {
		close(p.started)
	}

	if p.canceled != nil {
		<-ctx.Done()
		close(p.canceled)

		return append([]providedFact(nil), p.facts...), ctx.Err()
	}

	return append([]providedFact(nil), p.facts...), p.err
}

// callCount returns the synchronized provider invocation count.
func (p *blockingFactProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.calls
}

// Execute records one post-finalization attempt.
func (w *recordingPostActionWork) Execute(_ context.Context) effectsupervisor.Result {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.executes++

	return w.result
}

// Cleanup records idempotent ownership release.
func (w *recordingPostActionWork) Cleanup() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cleanups == 0 {
		w.cleanups++
	}
}

// executeCount returns the synchronized execution count.
func (w *recordingPostActionWork) executeCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.executes
}

// cleanupCount returns the synchronized cleanup count.
func (w *recordingPostActionWork) cleanupCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.cleanups
}

type failingEffectAcceptor struct {
	mu    sync.Mutex
	err   error
	calls int
}

// Accept records one rejected ownership-transfer attempt.
func (a *failingEffectAcceptor) Accept(_ context.Context, _ effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.calls++

	return effectsupervisor.Receipt{}, a.err
}

// callCount returns the synchronized acceptance attempt count.
func (a *failingEffectAcceptor) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.calls
}

// Collect records one at-most-once provider attempt.
func (p *countingFactProvider) Collect(_ context.Context, _ factProviderInput) ([]providedFact, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls++

	return append([]providedFact(nil), p.facts...), p.err
}

// callCount returns the synchronized attempt count.
func (p *countingFactProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.calls
}

// reset clears synchronized provider invocation evidence between table cases.
func (p *countingFactProvider) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls = 0
}

// Collect records the immutable input and returns configured provider output.
func (p *recordingFactProvider) Collect(_ context.Context, input factProviderInput) ([]providedFact, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.input = input.facts

	return append([]providedFact(nil), p.facts...), p.err
}

// recordedFacts returns the most recent immutable provider input.
func (p *recordingFactProvider) recordedFacts() decision.FactSet {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.input
}

// mustCheckpointRuntime constructs one private concrete checkpoint evaluator.
func mustCheckpointRuntime(t *testing.T, config checkpointRuntimeConfig) checkpointEvaluator {
	t.Helper()

	evaluator, err := newCheckpointRuntime(config)
	if err != nil {
		t.Fatalf("newCheckpointRuntime() error = %v", err)
	}

	return evaluator
}

// mustBuiltinAuthnCheckpointRuntime compiles the builtin authn plan for shared-runtime evidence.
func mustBuiltinAuthnCheckpointRuntime(t *testing.T) (checkpointEvaluator, *sequenceIDGenerator) {
	t.Helper()

	activation, err := registry.NewTargetActivation(
		"policy.targets.authn.authenticate",
		"authn",
		"authenticate",
		"authn/authenticate/v1",
	)
	if err != nil {
		t.Fatalf("NewTargetActivation() error = %v", err)
	}

	activation, err = activation.WithPolicy(registry.BuiltinStandardAuthPolicySet, "")
	if err != nil {
		t.Fatalf("TargetActivation.WithPolicy() error = %v", err)
	}

	catalog, err := catalogcompile.NewTargetCatalogCompiler(
		registry.NewBuiltinTargetContributor(&recordingEffectAcceptor{}),
	).Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("TargetCatalogCompiler.Compile() error = %v", err)
	}

	ids := &sequenceIDGenerator{}

	return mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: ids, evaluationTimeout: time.Second,
	}), ids
}

// evaluateRuntimeCheckpoint executes one admitted final checkpoint with an empty request body.
func evaluateRuntimeCheckpoint(
	t *testing.T,
	evaluator checkpointEvaluator,
	target decision.Target,
	finalization decision.EvaluationFinalization,
) decision.DecisionResponse {
	t.Helper()

	return evaluateRuntimeCheckpointInput(t, evaluator, target, nil, finalization)
}

// evaluateRuntimeCheckpointWithSubject executes one admitted final checkpoint with caller facts.
func evaluateRuntimeCheckpointWithSubject(
	t *testing.T,
	evaluator checkpointEvaluator,
	target decision.Target,
	attributes map[string]decision.Value,
) decision.DecisionResponse {
	t.Helper()

	return evaluateRuntimeCheckpointInput(
		t,
		evaluator,
		target,
		attributes,
		decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
	)
}

// evaluateRuntimeCheckpointWithInput executes one checkpoint with additional caller input facts.
func evaluateRuntimeCheckpointWithInput(
	t *testing.T,
	evaluator checkpointEvaluator,
	target decision.Target,
	attributes map[string]decision.Value,
) decision.DecisionResponse {
	t.Helper()

	caller := mustAuthorityCaller(t, false)

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion, RequestID: "request-input", Target: target, Attributes: attributes,
	}, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	empty, _ := decision.NewFactSet(nil)
	admitted := runtimeCallerFactSet(t, "input", decision.FactCategoryEnvironment, attributes)
	checkpoint, _ := decision.NewCheckpoint(decision.CheckpointFinalDecision, empty)

	outcome, err := evaluator.Evaluate(context.Background(), checkpointEvaluation{
		request: request, checkpoint: checkpoint, facts: admitted, supervisor: &recordingEffectAcceptor{}, generation: 1,
		finalization: decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	return outcome.response
}

// evaluateRuntimeCheckpointOptions executes one request with explicit diagnostics intent.
func evaluateRuntimeCheckpointOptions(
	t *testing.T,
	evaluator checkpointEvaluator,
	target decision.Target,
	attributes map[string]decision.Value,
	includeDiagnostics bool,
) decision.DecisionResponse {
	t.Helper()

	caller := mustAuthorityCaller(t, false)
	entity, _ := decision.NewEntity(decision.EntityInput{Attributes: attributes})

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion, RequestID: "request-options", Target: target, Subject: entity,
		Options: decision.EvaluationOptions{IncludeDiagnostics: includeDiagnostics},
	}, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	empty, _ := decision.NewFactSet(nil)
	admitted := runtimeCallerFactSet(t, "subject", decision.FactCategorySubject, attributes)
	checkpoint, _ := decision.NewCheckpoint(decision.CheckpointFinalDecision, empty)

	outcome, err := evaluator.Evaluate(context.Background(), checkpointEvaluation{
		request: request, checkpoint: checkpoint, facts: admitted, supervisor: &recordingEffectAcceptor{}, generation: 1,
		finalization: decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	return outcome.response
}

// evaluateRuntimeCheckpointInput constructs the private admitted runtime boundary.
func evaluateRuntimeCheckpointInput(
	t *testing.T,
	evaluator checkpointEvaluator,
	target decision.Target,
	attributes map[string]decision.Value,
	finalization decision.EvaluationFinalization,
) decision.DecisionResponse {
	t.Helper()

	caller := mustAuthorityCaller(t, false)

	entity, err := decision.NewEntity(decision.EntityInput{Attributes: attributes})
	if err != nil {
		t.Fatalf("NewEntity() error = %v", err)
	}

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion, RequestID: "request-runtime", Target: target, Subject: entity,
	}, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	empty, _ := decision.NewFactSet(nil)
	admitted := runtimeCallerFactSet(t, "subject", decision.FactCategorySubject, attributes)
	checkpoint, _ := decision.NewCheckpoint(decision.CheckpointFinalDecision, empty)

	outcome, err := evaluator.Evaluate(context.Background(), checkpointEvaluation{
		request: request, checkpoint: checkpoint, facts: admitted,
		supervisor: &recordingEffectAcceptor{}, generation: 1, finalization: finalization,
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	return outcome.response
}

// evaluateRuntimeOutcome returns internal report evidence for one admitted test invocation.
func evaluateRuntimeOutcome(
	t *testing.T,
	evaluator checkpointEvaluator,
	target decision.Target,
	supervisor effectsupervisor.Acceptor,
) runtimeEvaluation {
	t.Helper()

	return evaluateRuntimeOutcomeWithFinalization(
		t,
		evaluator,
		target,
		supervisor,
		decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
	)
}

// evaluateRuntimeOutcomeWithFinalization preserves the host gate for late-execution tests.
func evaluateRuntimeOutcomeWithFinalization(
	t *testing.T,
	evaluator checkpointEvaluator,
	target decision.Target,
	supervisor effectsupervisor.Acceptor,
	finalization decision.EvaluationFinalization,
) runtimeEvaluation {
	t.Helper()

	caller := mustAuthorityCaller(t, false)

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion, RequestID: "request-effects", Target: target,
	}, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	empty, _ := decision.NewFactSet(nil)
	checkpoint, _ := decision.NewCheckpoint(decision.CheckpointFinalDecision, empty)

	outcome, err := evaluator.Evaluate(context.Background(), checkpointEvaluation{
		request: request, checkpoint: checkpoint, supervisor: supervisor, generation: 1, finalization: finalization,
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	return outcome
}

// decisionRuntimeCatalog constructs one exact generic runtime fixture.
func decisionRuntimeCatalog(
	t *testing.T,
	ruleEffect decision.Effect,
	noMatch registry.NoMatchBehavior,
	facts []registry.FactSchema,
	providers []registry.ProviderDefinition,
	effects []registry.EffectDefinition,
) (*policyruntime.TargetCatalog, decision.Target) {
	return decisionRuntimeCatalogWithSelections(t, ruleEffect, noMatch, facts, providers, effects, nil, nil)
}

// decisionRuntimeCatalogWithSelections constructs a generic runtime fixture with typed effects.
func decisionRuntimeCatalogWithSelections(
	t *testing.T,
	ruleEffect decision.Effect,
	noMatch registry.NoMatchBehavior,
	facts []registry.FactSchema,
	providers []registry.ProviderDefinition,
	effects []registry.EffectDefinition,
	obligations []registry.EffectUse,
	advice []registry.EffectUse,
) (*policyruntime.TargetCatalog, decision.Target) {
	return decisionRuntimeCatalogFixture(t, ruleEffect, noMatch, facts, providers, effects, obligations, advice, nil)
}

// decisionRuntimeCatalogWithRuleExpression constructs one generic rule with an explicit condition.
func decisionRuntimeCatalogWithRuleExpression(
	t *testing.T,
	expression registry.PolicyExpression,
	facts []registry.FactSchema,
) (*policyruntime.TargetCatalog, decision.Target) {
	return decisionRuntimeCatalogFixture(
		t, decision.EffectPermit, registry.NoMatchDeny, facts, nil, nil, nil, nil, &expression,
	)
}

// decisionRuntimeCatalogFixture constructs one generic runtime catalog with optional explicit rule condition.
func decisionRuntimeCatalogFixture(
	t *testing.T,
	ruleEffect decision.Effect,
	noMatch registry.NoMatchBehavior,
	facts []registry.FactSchema,
	providers []registry.ProviderDefinition,
	effects []registry.EffectDefinition,
	obligations []registry.EffectUse,
	advice []registry.EffectUse,
	expression *registry.PolicyExpression,
) (*policyruntime.TargetCatalog, decision.Target) {
	t.Helper()

	target, _ := decision.NewTarget("mail", "submit")
	identity, _ := registry.NewSchemaIdentity("mail", "submit", "v1")

	schema, err := registry.NewSchemaDefinition(identity, facts)
	if err != nil {
		t.Fatalf("NewSchemaDefinition() error = %v", err)
	}

	providerIDs := scheduledProviderIDs(providers)

	checkpoint, err := registry.NewCheckpointDefinition(decision.CheckpointFinalDecision, nil, providerIDs)
	if err != nil {
		t.Fatalf("NewCheckpointDefinition() error = %v", err)
	}

	plan, err := registry.NewDomainPlanDefinition(target, []registry.CheckpointDefinition{checkpoint})
	if err != nil {
		t.Fatalf("NewDomainPlanDefinition() error = %v", err)
	}

	record := policyruntime.TargetCatalogRecord{
		Target: target, Schema: schema, SourcePlan: plan, Providers: providers, Effects: effects,
		Checkpoints: []policyruntime.CheckpointRecord{{
			Name:              decision.CheckpointFinalDecision,
			ProviderIDs:       providerIDs,
			ProviderInstances: checkpoint.ProviderInstances(),
		}},
		NoMatch: noMatch, AuthorityMode: registry.AuthorityModeEnforce,
	}
	sets := make([]registry.PolicySetDefinition, 0, 1)

	if ruleEffect.Valid() {
		condition := decisionRuntimeCondition(expression)
		set := bindDecisionRuntimeRule(t, target, providerIDs, ruleEffect, obligations, advice, condition, &record)
		sets = append(sets, set)
	}

	catalog, err := policyruntime.NewTargetCatalog([]policyruntime.TargetCatalogRecord{record}, sets)
	if err != nil {
		t.Fatalf("NewTargetCatalog() error = %v", err)
	}

	return catalog, target
}

// scheduledProviderIDs returns generic provider IDs in fixture order.
func scheduledProviderIDs(providers []registry.ProviderDefinition) []string {
	result := make([]string, 0, len(providers))

	for _, provider := range providers {
		if provider.Scheduled() {
			result = append(result, provider.ID())
		}
	}

	return result
}

// decisionRuntimeCondition resolves the fixture's explicit or always condition.
func decisionRuntimeCondition(expression *registry.PolicyExpression) registry.PolicyExpression {
	if expression != nil {
		return *expression
	}

	condition, _ := registry.NewPolicyExpression(registry.PolicyExpressionInput{Kind: registry.ExpressionKindAlways})

	return condition
}

// bindDecisionRuntimeRule attaches one source-authenticated default rule to a record.
func bindDecisionRuntimeRule(
	t *testing.T,
	target decision.Target,
	providerIDs []string,
	ruleEffect decision.Effect,
	obligations []registry.EffectUse,
	advice []registry.EffectUse,
	expression registry.PolicyExpression,
	record *policyruntime.TargetCatalogRecord,
) registry.PolicySetDefinition {
	t.Helper()

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name: "selected", Checkpoint: decision.CheckpointFinalDecision, Expression: expression, Decision: ruleEffect,
		Effects: obligations, Advice: advice,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	setID, _ := registry.NewPolicySetID("mail", "default")

	set, err := registry.NewPolicySetDefinition(registry.PolicySetDefinitionInput{ID: setID, Rules: []registry.PolicyRule{rule}, DiagnosticID: "policy"})
	if err != nil {
		t.Fatalf("NewPolicySetDefinition() error = %v", err)
	}

	binding, err := registry.NewPolicySetImport("runtime.policy", setID.String(), target, decision.CheckpointFinalDecision, registry.ExportContract{})
	if err != nil {
		t.Fatalf("NewPolicySetImport() error = %v", err)
	}

	checkpoint, _ := registry.NewCheckpointDefinition(decision.CheckpointFinalDecision, []registry.PolicySetImport{binding}, providerIDs)
	plan, _ := registry.NewDomainPlanDefinition(target, []registry.CheckpointDefinition{checkpoint})
	record.SourcePlan = plan
	record.DefaultPolicySet = setID
	record.Checkpoints[0].PolicySetBindings = []registry.PolicySetImport{binding}
	record.Checkpoints[0].PolicySetIDs = []registry.PolicySetID{setID}
	record.Checkpoints[0].Rules = []policyruntime.CompiledRuleRecord{policyruntime.ProjectPolicyRule(target, setID, decision.CheckpointFinalDecision, rule)}

	return set
}

// decisionRuntimeFactSchema constructs one exact bounded string fact.
func decisionRuntimeFactSchema(t *testing.T, id string, source decision.FactSource, required bool) registry.FactSchema {
	t.Helper()

	category := decision.FactCategoryEnvironment
	if len(id) >= len("subject.") && id[:len("subject.")] == "subject." {
		category = decision.FactCategorySubject
	} else if len(id) >= len("resource.") && id[:len("resource.")] == "resource." {
		category = decision.FactCategoryResource
	}

	fact, err := registry.NewFactSchema(registry.FactSchemaInput{
		ID: id, AllowedSources: []decision.FactSource{source}, Category: category,
		Kind: decision.ValueKindString, MaxLength: 64, Required: required,
	})
	if err != nil {
		t.Fatalf("NewFactSchema(%s) error = %v", id, err)
	}

	return fact
}

// decisionRuntimeTimestampFactSchema constructs one exact timestamp fact declaration.
func decisionRuntimeTimestampFactSchema(t *testing.T, id string, source decision.FactSource) registry.FactSchema {
	t.Helper()

	fact, err := registry.NewFactSchema(registry.FactSchemaInput{
		ID: id, AllowedSources: []decision.FactSource{source}, Category: decision.FactCategoryEnvironment,
		Kind: decision.ValueKindTimestamp,
	})
	if err != nil {
		t.Fatalf("NewFactSchema(%s) error = %v", id, err)
	}

	return fact
}

// decisionRuntimeStringListFactSchema constructs one bounded trusted string-list declaration.
func decisionRuntimeStringListFactSchema(t *testing.T, id string, source decision.FactSource) registry.FactSchema {
	t.Helper()

	fact, err := registry.NewFactSchema(registry.FactSchemaInput{
		ID: id, AllowedSources: []decision.FactSource{source}, Category: decision.FactCategoryEnvironment,
		Kind: decision.ValueKindStrings, MaxLength: 64, MaxItems: 16,
	})
	if err != nil {
		t.Fatalf("NewFactSchema(%s) error = %v", id, err)
	}

	return fact
}

// decisionRuntimeFactBinding assigns host-owned provider provenance.
func decisionRuntimeFactBinding(provider factProvider, authority string) factProviderBinding {
	return factProviderBinding{
		provider: provider, source: decision.FactSourcePlugin, authority: authority, component: "mail/" + authority,
	}
}

// decisionRuntimeLuaFailureBinding prepares one real restricted Lua callback for scheduler tests.
func decisionRuntimeLuaFailureBinding(
	t *testing.T,
	failure registry.ProviderFailureBehavior,
) (registry.ProviderDefinition, factProviderBinding) {
	t.Helper()

	path := filepath.Join(
		"..", "..", "..", "..", "testdata", "lua", "policyprovider", "scheduler_failure.lua",
	)

	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scheduler failure fixture: %v", err)
	}

	script, err := policyprovider.CompileScript(path, source)
	if err != nil {
		t.Fatalf("CompileScript() error = %v", err)
	}

	collector, err := policyprovider.NewLuaFactCollector(t.Context(), script, policyprovider.FactProviderDescriptor{
		Namespace: "mail", Name: "failed", Timeout: time.Second,
		Targets: []policyprovider.TargetSelector{{Namespace: "mail", Action: "submit"}},
		Outputs: []policyprovider.FactOutputDescriptor{{
			Name: "failed", Category: decision.FactCategoryEnvironment,
			Kind: decision.ValueKindString, MaxLength: 64,
		}},
	})
	if err != nil {
		t.Fatalf("NewLuaFactCollector() error = %v", err)
	}

	ownership, err := registry.NewNamespaceOwnership("lua.scheduler", []string{"mail"})
	if err != nil {
		t.Fatalf("NewNamespaceOwnership() error = %v", err)
	}

	prepared, err := policyprovider.PrepareGeneration(t.Context(), policyprovider.GenerationInput{
		PostActionAcceptance: &recordingEffectAcceptor{},
		Ownership:            ownership,
		Authority:            "scheduler",
		FactProviders: []policyprovider.FactProviderRegistration{{
			Collector: collector, Failure: failure,
		}},
	})
	if err != nil {
		t.Fatalf("PrepareGeneration() error = %v", err)
	}

	preparation, err := prepared.ExtensionPreparation(nil)
	if err != nil {
		t.Fatalf("ExtensionPreparation() error = %v", err)
	}

	definitions := preparation.Definitions[0].Providers()

	binding, exists := preparation.Bindings.FactProviders()[decisionRuntimeLuaFailureProviderID]
	if len(definitions) != 1 || !exists {
		t.Fatalf("Lua definitions/binding = %d/%t, want 1/true", len(definitions), exists)
	}

	return definitions[0], factProviderBinding{
		provider:  capturedFactProvider{provider: binding.Provider},
		source:    binding.Source,
		authority: binding.Authority,
		component: binding.Component,
	}
}

// decisionRuntimeHostProvider constructs one target-owned effect provider descriptor.
func decisionRuntimeHostProvider(
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

// decisionRuntimeEffect constructs one typed exact effect descriptor.
func decisionRuntimeEffect(
	t *testing.T,
	target decision.Target,
	id string,
	provider string,
	kind registry.EffectKind,
	execution registry.ExecutionClass,
) registry.EffectDefinition {
	t.Helper()

	effect, err := registry.NewEffectDefinition(registry.EffectDefinitionInput{
		ID: id, Provider: provider, Kind: kind, Execution: execution, Targets: []decision.Target{target},
	})
	if err != nil {
		t.Fatalf("NewEffectDefinition(%s) error = %v", id, err)
	}

	return effect
}

// decisionRuntimeEffectUse constructs one empty typed effect selection.
func decisionRuntimeEffectUse(t *testing.T, id string) registry.EffectUse {
	t.Helper()

	use, err := registry.NewEffectUse(id, nil)
	if err != nil {
		t.Fatalf("NewEffectUse(%s) error = %v", id, err)
	}

	return use
}

// decisionRuntimeProvider constructs one scheduled generic provider descriptor.
func decisionRuntimeProvider(
	t *testing.T,
	id string,
	fact string,
	failure registry.ProviderFailureBehavior,
	requires []string,
) registry.ProviderDefinition {
	t.Helper()

	target, _ := decision.NewTarget("mail", "submit")

	provider, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID: id, Targets: []decision.Target{target}, Executions: []registry.ExecutionClass{registry.ExecutionHostSync},
		ProducedFacts: []string{fact}, Failure: failure, Requires: requires, Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition(%s) error = %v", id, err)
	}

	return provider
}

// runtimeStringValue constructs one strict test string.
func runtimeStringValue(t *testing.T, value string) decision.Value {
	t.Helper()

	result, err := decision.NewValue(decision.ValueInput{String: &value})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	return result
}

// runtimeStringListValue constructs one strict test string list.
func runtimeStringListValue(t *testing.T, values []string) decision.Value {
	t.Helper()

	result, err := decision.NewValue(decision.ValueInput{Strings: values})
	if err != nil {
		t.Fatalf("NewValue(strings) error = %v", err)
	}

	return result
}

// mustRuntimeTrustedFact constructs one authenticator-owned admitted test fact.
func mustRuntimeTrustedFact(
	t *testing.T,
	id string,
	source decision.FactSource,
	value decision.Value,
) decision.Fact {
	t.Helper()

	provenance, err := decision.NewProvenance(source, "trusted-client", "authenticator")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	fact, err := decision.NewFact(id, decision.FactCategoryEnvironment, value, provenance)
	if err != nil {
		t.Fatalf("NewFact(%s) error = %v", id, err)
	}

	return fact
}

// runtimeCallerFactSet constructs the already-admitted caller facts for private evaluator tests.
func runtimeCallerFactSet(
	t *testing.T,
	prefix string,
	category decision.FactCategory,
	attributes map[string]decision.Value,
) decision.FactSet {
	t.Helper()

	provenance, err := decision.NewProvenance(decision.FactSourceCaller, "test-authority", "request")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	facts := make([]decision.Fact, 0, len(keys))
	for _, key := range keys {
		fact, factErr := decision.NewFact(prefix+"."+key, category, attributes[key], provenance)
		if factErr != nil {
			t.Fatalf("NewFact(%s.%s) error = %v", prefix, key, factErr)
		}

		facts = append(facts, fact)
	}

	result, err := decision.NewFactSet(facts)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	return result
}

// runtimeBooleanValue constructs one strict test boolean.
func runtimeBooleanValue(t *testing.T, value bool) decision.Value {
	t.Helper()

	result, err := decision.NewValue(decision.ValueInput{Boolean: &value})
	if err != nil {
		t.Fatalf("NewValue(boolean) error = %v", err)
	}

	return result
}

// runtimeTimestampValue constructs one strict UTC timestamp.
func runtimeTimestampValue(t *testing.T, value time.Time) decision.Value {
	t.Helper()

	value = value.UTC()

	result, err := decision.NewValue(decision.ValueInput{Timestamp: &value})
	if err != nil {
		t.Fatalf("NewValue(timestamp) error = %v", err)
	}

	return result
}

// diagnosticJSONMap projects strict scalar values for serializer-size evidence.
func diagnosticJSONMap(values map[string]decision.Value) map[string]any {
	result := make(map[string]any, len(values))

	for key, value := range values {
		if text, ok := value.StringValue(); ok {
			result[key] = text

			continue
		}

		if number, ok := value.Integer(); ok {
			result[key] = number
		}
	}

	return result
}

// effectReportStates returns lifecycle states in their recorded order.
func effectReportStates(records []effectRecord) []effectsupervisor.State {
	states := make([]effectsupervisor.State, 0, len(records))

	for _, record := range records {
		states = append(states, record.state)
	}

	return states
}

// sortedDiagnosticKeys returns stable selected-key evidence across insertion orders.
func sortedDiagnosticKeys(values map[string]decision.Value) []string {
	keys := make([]string, 0, len(values))

	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

// assertTrustedRuntimeFact verifies exact host-assigned fact provenance.
func assertTrustedRuntimeFact(t *testing.T, facts decision.FactSet, id string, source decision.FactSource) {
	t.Helper()

	fact, ok := facts.Get(id)
	if !ok || fact.Provenance().Source() != source || fact.Provenance().Authority() != "trusted-client" {
		t.Fatalf("trusted fact %s = %#v", id, fact)
	}
}

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
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/catalogcompile"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	"github.com/croessner/nauthilus/v4/server/policy/report"
)

func TestAuthnStandardAuthBruteForceExecutesOnlyBucketUpdate(t *testing.T) {
	log := &authnEffectOrderLog{}
	source := &recordingAuthnDecisionSource{standard: standardAuthBruteForceReport()}
	evaluator, target := mustAuthnEffectRuntime(t, log)
	acceptor := &recordingEffectAcceptor{}

	outcome := evaluateAuthnSourceCheckpoint(t, evaluator, target, source, acceptor)

	if outcome.response.Effect() != decision.EffectDeny {
		t.Fatalf("brute-force effect = %q, want deny", outcome.response.Effect())
	}

	wantOrder := []string{fmt.Sprintf("sync:%s:1", policy.AuthnProviderBruteForce)}
	if got := log.entries(); !reflect.DeepEqual(got, wantOrder) {
		t.Fatalf("effect order = %v, want %v", got, wantOrder)
	}

	wantStates := []effectsupervisor.State{
		effectsupervisor.StateAttempted,
		effectsupervisor.StateSucceeded,
	}
	if got := effectReportStates(outcome.report.runtime.effects); !reflect.DeepEqual(got, wantStates) {
		t.Fatalf("partial effect states = %v, want %v", got, wantStates)
	}

	captured := source.capturedDecision()
	if captured == nil || captured.PolicyName != "standard_brute_force_deny" {
		t.Fatalf("captured authn selection = %#v, want standard brute-force decision", captured)
	}

	wantObligations := []string{policy.EffectBruteForceUpdate}
	if got := authnEffectRequestIDs(captured.Obligations); !reflect.DeepEqual(got, wantObligations) {
		t.Fatalf("captured authn obligation IDs = %v, want %v", got, wantObligations)
	}

}

func TestBuiltinStandardAuthCatalogPreservesSemanticPrecedence(t *testing.T) {
	attributes := authnCatalogExtensionAttributes()
	evaluator, target := mustAuthnEffectRuntimeWithPolicyAttributes(t, &authnEffectOrderLog{}, attributes)

	tests := []struct {
		name     string
		facts    []authnCatalogBooleanFact
		wantRule string
	}{
		{
			name: "Lua environment rejection precedes backend success",
			facts: []authnCatalogBooleanFact{
				authnNauthilusBooleanFact(policy.AuthnLuaEnvironmentFactID("precedence", "triggered"), decision.FactCategoryEnvironment, true),
				authnBackendBooleanFact(policy.AuthnFactAuthenticated, true),
			},
			wantRule: "standard_lua_environment_precedence_trigger",
		},
		{
			name: "Lua subject rejection precedes backend success",
			facts: []authnCatalogBooleanFact{
				authnNauthilusBooleanFact(policy.AuthnLuaSubjectFactID("precedence", "rejected"), decision.FactCategorySubject, true),
				authnBackendBooleanFact(policy.AuthnFactAuthenticated, true),
			},
			wantRule: "standard_lua_subject_precedence_reject",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := newSuppliedAuthnDecisionSource(t, test.facts, false)
			outcome := evaluateAuthnSourceNamedCheckpoint(
				t,
				evaluator,
				target,
				source,
				&recordingEffectAcceptor{},
				string(policy.StageAuthDecision),
			)

			if outcome.response.Effect() != decision.EffectDeny {
				t.Fatalf("collision effect = %q, want deny", outcome.response.Effect())
			}

			if selected := source.capturedDecision(); selected == nil || selected.PolicyName != test.wantRule {
				t.Fatalf("collision selection = %#v, want %s", selected, test.wantRule)
			}
		})
	}
}

func TestBuiltinStandardAuthTerminalPreAuthEffectsPreservePostAction(t *testing.T) {
	for _, test := range authnTerminalPreAuthEffectCases() {
		t.Run(test.name, func(t *testing.T) {
			log := &authnEffectOrderLog{}
			evaluator, target := mustAuthnEffectRuntimeWithPolicyAttributes(
				t,
				log,
				authnCatalogExtensionAttributes(),
			)
			source := newSuppliedAuthnDecisionSource(t, test.facts, true)
			outcome := evaluateAuthnSourceNamedCheckpoint(
				t,
				evaluator,
				target,
				source,
				&orderedAcceptingAuthnAcceptor{log: log},
				string(policy.StageAuthDecision),
			)

			if outcome.response.Effect() != test.wantEffect {
				t.Fatalf("terminal effect = %q, want %q", outcome.response.Effect(), test.wantEffect)
			}

			if got := log.entries(); !reflect.DeepEqual(got, test.wantOrder) {
				t.Fatalf("terminal effect order = %v, want %v", got, test.wantOrder)
			}

			if selected := source.capturedDecision(); selected == nil || selected.PolicyName != test.wantRule {
				t.Fatalf("terminal selection = %#v, want %s", selected, test.wantRule)
			}
		})
	}
}

func TestBuiltinStandardAuthNativeEnvironmentErrorMapsTempFail(t *testing.T) {
	evaluator, target := mustAuthnEffectRuntimeWithPolicyAttributes(
		t,
		&authnEffectOrderLog{},
		authnCatalogExtensionAttributes(),
	)
	source := newSuppliedAuthnDecisionSource(t, []authnCatalogBooleanFact{
		authnNauthilusBooleanFact(authnPluginEnvironmentFactID("error"), decision.FactCategoryEnvironment, true),
	}, true)
	outcome := evaluateAuthnSourceNamedCheckpoint(
		t,
		evaluator,
		target,
		source,
		&recordingEffectAcceptor{},
		string(policy.StageAuthDecision),
	)

	if outcome.response.Effect() != decision.EffectIndeterminate {
		t.Fatalf("native environment error effect = %q, want indeterminate", outcome.response.Effect())
	}

	selected := source.capturedDecision()
	if selected == nil || selected.FSMEventMarker != policy.FSMEventMarkerPreAuthTempFail ||
		selected.ResponseMarker != policy.ResponseMarkerTempFail {
		t.Fatalf("native environment error selection = %#v, want pre-auth tempfail", selected)
	}
}

// authnEffectRequestIDs projects retained selection identities for report comparisons.
func authnEffectRequestIDs(requests []report.EffectRequest) []string {
	result := make([]string, 0, len(requests))
	for _, request := range requests {
		result = append(result, request.ID)
	}

	return result
}

func TestAuthnStandardAuthRuntimeFailureCausesRemainDistinct(t *testing.T) {
	for _, test := range authnRuntimeFailureCases() {
		t.Run(test.name, func(t *testing.T) {
			assertAuthnRuntimeFailureCause(t, test)
		})
	}
}

type authnRuntimeFailureMode string

const (
	authnRuntimeSyncFailure    authnRuntimeFailureMode = "sync_failure"
	authnRuntimeOutcomeUnknown authnRuntimeFailureMode = "outcome_unknown"
	authnRuntimeCancellation   authnRuntimeFailureMode = "cancellation"
)

type authnRuntimeFailureCase struct {
	name          string
	mode          authnRuntimeFailureMode
	wantCode      decision.StatusCode
	wantCancelled bool
}

// authnRuntimeFailureCases lists every non-acceptance indeterminate standard-auth cause.
func authnRuntimeFailureCases() []authnRuntimeFailureCase {
	return []authnRuntimeFailureCase{
		{name: "synchronous failure", mode: authnRuntimeSyncFailure, wantCode: decision.StatusCodeEvaluationFailed},
		{name: "outcome unknown", mode: authnRuntimeOutcomeUnknown, wantCode: decision.StatusCodeEffectOutcomeUnknown},
		{name: "request cancellation", mode: authnRuntimeCancellation, wantCode: decision.StatusCodeEffectOutcomeUnknown, wantCancelled: true},
	}
}

// assertAuthnRuntimeFailureCause proves one cause remains distinct from acceptance rejection.
func assertAuthnRuntimeFailureCause(t *testing.T, test authnRuntimeFailureCase) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	syncOverrides, postOverrides := authnRuntimeFailureBindings(test.mode, cancel)
	evaluator, target := mustAuthnEffectRuntimeWithOverrides(
		t,
		&authnEffectOrderLog{},
		syncOverrides,
		postOverrides,
	)
	outcome := evaluateAuthnSourceCheckpointWithContext(
		ctx,
		t,
		evaluator,
		target,
		&recordingAuthnDecisionSource{standard: standardAuthBruteForceReport()},
		&recordingEffectAcceptor{},
	)

	if outcome.response.Effect() != decision.EffectIndeterminate ||
		outcome.response.Status().Code() != test.wantCode {
		t.Fatalf(
			"runtime effect/status = %q/%q, want indeterminate/%q",
			outcome.response.Effect(),
			outcome.response.Status().Code(),
			test.wantCode,
		)
	}

	if outcome.response.Status().Code() == decision.StatusCodeEffectAcceptanceRejected {
		t.Fatal("non-acceptance runtime failure was classified as acceptance rejection")
	}

	if test.wantCancelled && ctx.Err() != context.Canceled {
		t.Fatalf("evaluation context error = %v, want canceled", ctx.Err())
	}
}

// authnRuntimeFailureBindings replaces the exact owner that produces one failure cause.
func authnRuntimeFailureBindings(
	mode authnRuntimeFailureMode,
	cancel context.CancelFunc,
) (map[string]syncEffectBinding, map[string]postActionBinding) {
	switch mode {
	case authnRuntimeSyncFailure:
		return map[string]syncEffectBinding{
			policy.AuthnProviderBruteForce: {provider: &recordingSyncEffectProvider{
				result: effectsupervisor.Failed("known_failure"),
			}},
		}, nil
	case authnRuntimeOutcomeUnknown:
		return map[string]syncEffectBinding{
			policy.AuthnProviderBruteForce: {provider: &recordingSyncEffectProvider{
				result: effectsupervisor.OutcomeUnknown("dispatch_ambiguous"),
			}},
		}, nil
	case authnRuntimeCancellation:
		return map[string]syncEffectBinding{
			policy.AuthnProviderBruteForce: {provider: cancelingAuthnSyncEffectProvider{cancel: cancel}},
		}, nil
	default:
		return nil, nil
	}
}

func TestAuthnConfiguredResponseProjectionPreservesSanitizationAndLocalization(t *testing.T) {
	facts := mustAuthnPresentationFacts(t, map[string]string{
		"lua.presentation.message":  "blocked\r\nreason",
		"lua.presentation.language": " de-DE ",
	})
	attributeMessage := mustAuthnResponseMessage(t, registry.PolicyResponseMessageInput{
		From: policy.ResponseSourceAttributeDetail, FactID: "lua.presentation.message",
		Detail: "status_message", Fallback: "fallback", MaxLength: 7,
	})

	selected := authnRuleResponseMessage(attributeMessage, policy.ResponseMarkerFail, facts)
	if selected == nil || selected.Message != "blocked" || !selected.Truncated || selected.FallbackUsed {
		t.Fatalf("attribute response selection = %#v, want sanitized and truncated fact value", selected)
	}

	i18nMessage := mustAuthnResponseMessage(t, registry.PolicyResponseMessageInput{
		From: policy.ResponseSourceI18N, I18NKey: "auth.policy.denied", Fallback: "access denied",
	})
	i18nSelection := authnRuleResponseMessage(i18nMessage, policy.ResponseMarkerFail, facts)
	language := mustAuthnResponseLanguage(t, registry.PolicyResponseLanguageInput{
		From: policy.ResponseSourceAttribute, FactID: "lua.presentation.language", Fallback: "en",
	})

	selectedLanguage := authnRuleResponseLanguage(language, i18nSelection, facts)
	if selectedLanguage == nil || selectedLanguage.Language != "de-DE" || selectedLanguage.FallbackUsed {
		t.Fatalf("response language selection = %#v, want normalized de-DE fact value", selectedLanguage)
	}

	literalMessage := mustAuthnResponseMessage(t, registry.PolicyResponseMessageInput{
		From: policy.ResponseSourceLiteral, Text: "literal denial",
	})
	if got := authnRuleResponseLanguage(language, authnRuleResponseMessage(literalMessage, policy.ResponseMarkerFail, facts), facts); got != nil {
		t.Fatalf("non-localized response language = %#v, want nil", got)
	}
}

func TestSharedRuntimePreservesLuaNativeFactAuthorityAndEffectOrder(t *testing.T) {
	fixture := newAuthnLuaNativeParityFixture(t)

	response := evaluateRuntimeCheckpoint(
		t,
		fixture.evaluator,
		fixture.target,
		decision.NewEvaluationFinalization(effectsupervisor.BoundaryGRPCUnaryReturn),
	)
	if response.Effect() != decision.EffectPermit {
		t.Fatalf("shared runtime effect = %q, want permit", response.Effect())
	}

	collected := fixture.auditFacts.recordedFacts()
	assertAuthnProviderFactAuthority(t, collected, "lua.policy.verdict", decision.FactSourceLua, "policy")
	assertAuthnProviderFactAuthority(t, collected, "plugin.policy.verdict", decision.FactSourcePlugin, "policy")

	wantOrder := []string{"sync:lua/effects:1", "sync:plugin/effects:2"}
	if got := fixture.log.entries(); !reflect.DeepEqual(got, wantOrder) {
		t.Fatalf("Lua/native effect order = %v, want %v", got, wantOrder)
	}
}

type authnLuaNativeParityFixture struct {
	evaluator  checkpointEvaluator
	target     decision.Target
	auditFacts *recordingFactProvider
	log        *authnEffectOrderLog
}

type authnLuaNativeFactFixture struct {
	bindings  map[string]factProviderBinding
	providers []registry.ProviderDefinition
	schemas   []registry.FactSchema
	audit     *recordingFactProvider
}

type authnLuaNativeEffectFixture struct {
	providers []registry.ProviderDefinition
	effects   []registry.EffectDefinition
	uses      []registry.EffectUse
}

// newAuthnLuaNativeParityFixture assembles one concrete shared runtime with both extension kinds.
func newAuthnLuaNativeParityFixture(t *testing.T) authnLuaNativeParityFixture {
	t.Helper()

	target, err := decision.NewTarget("mail", "submit")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	facts := newAuthnLuaNativeFactFixture(t)
	effects := newAuthnLuaNativeEffectFixture(t, target)
	providers := append(facts.providers, effects.providers...)
	catalog, target := decisionRuntimeCatalogWithSelections(
		t,
		decision.EffectPermit,
		registry.NoMatchDeny,
		facts.schemas,
		providers,
		effects.effects,
		effects.uses,
		nil,
	)
	log := &authnEffectOrderLog{}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog:       catalog,
		factProviders: facts.bindings,
		syncEffects: map[string]syncEffectBinding{
			"lua/effects":    {provider: &orderedAuthnSyncEffectProvider{log: log}},
			"plugin/effects": {provider: &orderedAuthnSyncEffectProvider{log: log}},
		},
		ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
	})

	return authnLuaNativeParityFixture{
		evaluator:  evaluator,
		target:     target,
		auditFacts: facts.audit,
		log:        log,
	}
}

// newAuthnLuaNativeFactFixture declares exact provenance for Lua, native, and host facts.
func newAuthnLuaNativeFactFixture(t *testing.T) authnLuaNativeFactFixture {
	t.Helper()

	luaFacts := &recordingFactProvider{facts: []providedFact{{
		id: "lua.policy.verdict", category: decision.FactCategoryEnvironment,
		value: runtimeStringValue(t, "allow"),
	}}}
	nativeFacts := &recordingFactProvider{facts: []providedFact{{
		id: "plugin.policy.verdict", category: decision.FactCategoryEnvironment,
		value: runtimeStringValue(t, "allow"),
	}}}
	auditFacts := &recordingFactProvider{facts: []providedFact{{
		id: "nauthilus.audit.seen", category: decision.FactCategoryEnvironment,
		value: runtimeStringValue(t, "yes"),
	}}}

	return authnLuaNativeFactFixture{
		bindings: map[string]factProviderBinding{
			"lua/policy":    {provider: luaFacts, source: decision.FactSourceLua, authority: "policy", component: "lua/policy"},
			"plugin/policy": {provider: nativeFacts, source: decision.FactSourcePlugin, authority: "policy", component: "plugin/policy"},
			"mail/audit":    {provider: auditFacts, source: decision.FactSourceNauthilus, authority: "nauthilus", component: "mail/audit"},
		},
		providers: []registry.ProviderDefinition{
			decisionRuntimeProvider(t, "lua/policy", "lua.policy.verdict", registry.ProviderFailureIndeterminate, nil),
			decisionRuntimeProvider(t, "plugin/policy", "plugin.policy.verdict", registry.ProviderFailureIndeterminate, []string{"lua/policy"}),
			decisionRuntimeProvider(t, "mail/audit", "nauthilus.audit.seen", registry.ProviderFailureIndeterminate, []string{"plugin/policy"}),
		},
		schemas: []registry.FactSchema{
			decisionRuntimeFactSchema(t, "lua.policy.verdict", decision.FactSourceLua, false),
			decisionRuntimeFactSchema(t, "plugin.policy.verdict", decision.FactSourcePlugin, false),
			decisionRuntimeFactSchema(t, "nauthilus.audit.seen", decision.FactSourceNauthilus, false),
		},
		audit: auditFacts,
	}
}

// newAuthnLuaNativeEffectFixture declares ordered synchronous providers and uses.
func newAuthnLuaNativeEffectFixture(
	t *testing.T,
	target decision.Target,
) authnLuaNativeEffectFixture {
	t.Helper()

	luaEffect := decisionRuntimeEffect(
		t, target, "mail/lua_effect", "lua/effects", registry.EffectKindObligation, registry.ExecutionHostSync,
	)
	nativeEffect := decisionRuntimeEffect(
		t, target, "mail/native_effect", "plugin/effects", registry.EffectKindObligation, registry.ExecutionHostSync,
	)

	luaUse, err := registry.NewEffectUse(luaEffect.ID(), nil)
	if err != nil {
		t.Fatalf("NewEffectUse(lua) error = %v", err)
	}

	nativeUse, err := registry.NewEffectUse(nativeEffect.ID(), nil)
	if err != nil {
		t.Fatalf("NewEffectUse(native) error = %v", err)
	}

	return authnLuaNativeEffectFixture{
		providers: []registry.ProviderDefinition{
			decisionRuntimeHostProvider(t, target, "lua/effects", registry.ExecutionHostSync, nil),
			decisionRuntimeHostProvider(t, target, "plugin/effects", registry.ExecutionHostSync, nil),
		},
		effects: []registry.EffectDefinition{luaEffect, nativeEffect},
		uses:    []registry.EffectUse{luaUse, nativeUse},
	}
}

// assertAuthnProviderFactAuthority verifies one exact immutable provider owner.
func assertAuthnProviderFactAuthority(
	t *testing.T,
	facts decision.FactSet,
	id string,
	source decision.FactSource,
	authority string,
) {
	t.Helper()

	fact, ok := facts.Get(id)
	if !ok || fact.Provenance().Source() != source || fact.Provenance().Authority() != authority {
		t.Fatalf("fact %q provenance = %#v, want %s/%s", id, fact.Provenance(), source, authority)
	}
}

// mustAuthnPresentationFacts constructs strict provider-owned response facts.
func mustAuthnPresentationFacts(t *testing.T, values map[string]string) decision.FactSet {
	t.Helper()

	provenance, err := decision.NewProvenance(decision.FactSourceLua, "presentation", "response")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	facts := make([]decision.Fact, 0, len(values))
	for id, raw := range values {
		value, valueErr := decision.NewValue(decision.ValueInput{String: &raw})
		if valueErr != nil {
			t.Fatalf("NewValue(%q) error = %v", id, valueErr)
		}

		fact, factErr := decision.NewFact(id, decision.FactCategoryEnvironment, value, provenance)
		if factErr != nil {
			t.Fatalf("NewFact(%q) error = %v", id, factErr)
		}

		facts = append(facts, fact)
	}

	result, err := decision.NewFactSet(facts)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	return result
}

// mustAuthnResponseMessage constructs one validated configured response-message source.
func mustAuthnResponseMessage(t *testing.T, input registry.PolicyResponseMessageInput) registry.PolicyResponseMessage {
	t.Helper()

	message, err := registry.NewPolicyResponseMessage(input)
	if err != nil {
		t.Fatalf("NewPolicyResponseMessage() error = %v", err)
	}

	return message
}

// mustAuthnResponseLanguage constructs one validated configured response-language source.
func mustAuthnResponseLanguage(t *testing.T, input registry.PolicyResponseLanguageInput) registry.PolicyResponseLanguage {
	t.Helper()

	language, err := registry.NewPolicyResponseLanguage(input)
	if err != nil {
		t.Fatalf("NewPolicyResponseLanguage() error = %v", err)
	}

	return language
}

// standardAuthBruteForceReport returns facts that select the established three-effect deny.
func standardAuthBruteForceReport() *report.DecisionReport {
	policyReport := report.NewDecisionReport()
	policyReport.Operation = policy.OperationAuthenticate
	policyReport.Attributes[policy.AttributeBruteForceError] = report.AttributeValue{
		ID: policy.AttributeBruteForceError, Stage: policy.StagePreAuth,
		Operation: policy.OperationAuthenticate, Value: false,
	}
	policyReport.Attributes[policy.AttributeBruteForceTriggered] = report.AttributeValue{
		ID: policy.AttributeBruteForceTriggered, Stage: policy.StagePreAuth,
		Operation: policy.OperationAuthenticate, Value: true,
	}
	policyReport.Checks["brute_force"] = report.CheckResult{
		Name: "brute_force", Stage: policy.StagePreAuth,
		Operation: policy.OperationAuthenticate, Status: policy.CheckStatusOK,
	}

	return policyReport
}

type authnTerminalPreAuthEffectCase struct {
	name       string
	wantRule   string
	facts      []authnCatalogBooleanFact
	wantOrder  []string
	wantEffect decision.Effect
}

// authnTerminalPreAuthEffectCases proves default terminal rules do not inject Lua actions.
func authnTerminalPreAuthEffectCases() []authnTerminalPreAuthEffectCase {
	authenticated := authnBackendBooleanFact(policy.AuthnFactAuthenticated, true)
	learningOnly := []string{fmt.Sprintf("sync:%s:1", policy.AuthnProviderBruteForce)}

	return []authnTerminalPreAuthEffectCase{
		{
			name: "TLS tempfail", wantRule: "standard_tls_enforcement",
			facts: []authnCatalogBooleanFact{
				authnNauthilusBooleanFact(policy.AuthnFactTLSSecure, decision.FactCategoryEnvironment, false),
				authenticated,
			},
			wantEffect: decision.EffectIndeterminate,
			wantOrder:  nil,
		},
		{
			name: "relay deny", wantRule: "standard_relay_domain_reject",
			facts: []authnCatalogBooleanFact{
				authnNauthilusBooleanFact(policy.AuthnFactRelayDomainPresent, decision.FactCategoryEnvironment, true),
				authnNauthilusBooleanFact(policy.AuthnFactRelayDomainKnown, decision.FactCategoryEnvironment, false),
				authenticated,
			},
			wantEffect: decision.EffectDeny, wantOrder: learningOnly,
		},
		{
			name: "RBL deny", wantRule: "standard_rbl_reject",
			facts: []authnCatalogBooleanFact{
				authnNauthilusBooleanFact(policy.AuthnFactRBLThresholdReached, decision.FactCategoryEnvironment, true),
				authenticated,
			},
			wantEffect: decision.EffectDeny, wantOrder: learningOnly,
		},
		{
			name: "Lua environment deny", wantRule: "standard_lua_environment_precedence_trigger",
			facts: []authnCatalogBooleanFact{
				authnNauthilusBooleanFact(policy.AuthnLuaEnvironmentFactID("precedence", "triggered"), decision.FactCategoryEnvironment, true),
				authenticated,
			},
			wantEffect: decision.EffectDeny, wantOrder: learningOnly,
		},
		{
			name: "native environment deny", wantRule: "standard_plugin_environment_candidate_verdict_trigger",
			facts: []authnCatalogBooleanFact{
				authnNauthilusBooleanFact(authnPluginEnvironmentFactID("triggered"), decision.FactCategoryEnvironment, true),
				authenticated,
			},
			wantEffect: decision.EffectDeny,
			wantOrder:  nil,
		},
	}
}

// authnCatalogExtensionAttributes declares generated host facts used by catalog precedence tests.
func authnCatalogExtensionAttributes() map[string]registry.AttributeDefinition {
	result := make(map[string]registry.AttributeDefinition)

	for _, input := range []struct {
		id       string
		check    string
		category registry.AttributeCategory
		detail   bool
	}{
		{id: "auth.lua.environment.precedence.triggered", check: "lua_environment_precedence", category: registry.AttributeCategoryEnvironment, detail: true},
		{id: "auth.lua.environment.precedence.abort", check: "lua_environment_precedence", category: registry.AttributeCategoryEnvironment},
		{id: "auth.lua.environment.precedence.error", check: "lua_environment_precedence", category: registry.AttributeCategoryEnvironment},
		{id: "auth.lua.subject.precedence.rejected", check: "lua_subject_precedence", category: registry.AttributeCategorySubject, detail: true},
		{id: "auth.lua.subject.precedence.error", check: "lua_subject_precedence", category: registry.AttributeCategorySubject},
		{id: policy.PluginEnvironmentAttributeID("candidate", "verdict", "triggered"), check: "plugin_environment_candidate", category: registry.AttributeCategoryEnvironment, detail: true},
		{id: policy.PluginEnvironmentAttributeID("candidate", "verdict", "abort"), check: "plugin_environment_candidate", category: registry.AttributeCategoryEnvironment},
		{id: policy.PluginEnvironmentAttributeID("candidate", "verdict", "error"), check: "plugin_environment_candidate", category: registry.AttributeCategoryEnvironment},
	} {
		definition := registry.AttributeDefinition{
			ID: input.id, Stage: policy.StagePreAuth,
			Operations:    []policy.Operation{policy.OperationAuthenticate},
			ProducerCheck: input.check, Category: input.category,
			Type: registry.AttributeTypeBool, Source: registry.SourceBuiltin,
		}
		if input.category == registry.AttributeCategorySubject {
			definition.Stage = policy.StageSubjectAnalysis
		}

		if input.detail {
			definition.Details = map[string]registry.DetailDefinition{
				"status_message": {
					Type: registry.AttributeTypeString, Sensitivity: registry.DetailSensitivityPublic,
					Purpose: registry.DetailPurposeResponseMessage, MaxLength: 256,
				},
			}
		}

		result[input.id] = definition
	}

	return result
}

// authnPluginEnvironmentFactID returns one host-owned native environment fact.
func authnPluginEnvironmentFactID(suffix string) string {
	return "nauthilus." + policy.PluginEnvironmentAttributeID("candidate", "verdict", suffix)
}

// mustAuthnEffectRuntime compiles the builtin authn target with concrete effect owners.
func mustAuthnEffectRuntime(
	t *testing.T,
	log *authnEffectOrderLog,
) (checkpointEvaluator, decision.Target) {
	return mustAuthnEffectRuntimeWithOverrides(t, log, nil, nil)
}

// mustAuthnEffectRuntimeWithOverrides replaces exact effect owners for failure-cause fixtures.
func mustAuthnEffectRuntimeWithOverrides(
	t *testing.T,
	log *authnEffectOrderLog,
	syncOverrides map[string]syncEffectBinding,
	postOverrides map[string]postActionBinding,
) (checkpointEvaluator, decision.Target) {
	return mustAuthnEffectRuntimeWithPolicy(
		t,
		log,
		nil,
		syncOverrides,
		postOverrides,
	)
}

// mustAuthnEffectRuntimeWithPolicyAttributes compiles generated extension facts with standard effects.
func mustAuthnEffectRuntimeWithPolicyAttributes(
	t *testing.T,
	log *authnEffectOrderLog,
	attributes map[string]registry.AttributeDefinition,
) (checkpointEvaluator, decision.Target) {
	return mustAuthnEffectRuntimeWithPolicy(t, log, attributes, nil, nil)
}

// mustAuthnEffectRuntimeWithPolicy compiles one captured authn vocabulary and exact effect bindings.
func mustAuthnEffectRuntimeWithPolicy(
	t *testing.T,
	log *authnEffectOrderLog,
	attributes map[string]registry.AttributeDefinition,
	syncOverrides map[string]syncEffectBinding,
	postOverrides map[string]postActionBinding,
) (checkpointEvaluator, decision.Target) {
	t.Helper()

	activation, err := registry.NewTargetActivation(
		"policy.targets.authn.authenticate",
		policy.AuthnNamespace,
		string(policy.OperationAuthenticate),
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
		registry.NewBuiltinTargetContributorWithAuthnPolicy(attributes, &recordingEffectAcceptor{}),
	).Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("TargetCatalogCompiler.Compile() error = %v", err)
	}

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	syncEffects := map[string]syncEffectBinding{
		policy.AuthnProviderBruteForce: {provider: &orderedAuthnSyncEffectProvider{log: log}},
		"authn/lua_action":             {provider: &orderedAuthnSyncEffectProvider{log: log}},
	}
	for providerID, binding := range syncOverrides {
		syncEffects[providerID] = binding
	}

	postActions := map[string]postActionBinding{
		"authn/post_action": {provider: &orderedAuthnPostActionProvider{log: log}},
	}
	for providerID, binding := range postOverrides {
		postActions[providerID] = binding
	}

	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog:           catalog,
		ids:               &sequenceIDGenerator{},
		evaluationTimeout: time.Second,
		syncEffects:       syncEffects,
		postActions:       postActions,
	})

	return evaluator, target
}

// evaluateAuthnSourceCheckpoint runs the builtin pre-auth checkpoint with one request-local source.
func evaluateAuthnSourceCheckpoint(
	t *testing.T,
	evaluator checkpointEvaluator,
	target decision.Target,
	source AuthnDecisionSource,
	acceptor effectsupervisor.Acceptor,
) runtimeEvaluation {
	return evaluateAuthnSourceCheckpointWithContext(
		context.Background(),
		t,
		evaluator,
		target,
		source,
		acceptor,
	)
}

// evaluateAuthnSourceCheckpointWithContext runs the builtin checkpoint with an exact request context.
func evaluateAuthnSourceCheckpointWithContext(
	ctx context.Context,
	t *testing.T,
	evaluator checkpointEvaluator,
	target decision.Target,
	source AuthnDecisionSource,
	acceptor effectsupervisor.Acceptor,
) runtimeEvaluation {
	return evaluateAuthnSourceNamedCheckpointWithContext(
		ctx,
		t,
		evaluator,
		target,
		source,
		acceptor,
		string(policy.StagePreAuth),
	)
}

// evaluateAuthnSourceNamedCheckpoint runs one catalog-owned checkpoint with request-local facts.
func evaluateAuthnSourceNamedCheckpoint(
	t *testing.T,
	evaluator checkpointEvaluator,
	target decision.Target,
	source AuthnDecisionSource,
	acceptor effectsupervisor.Acceptor,
	checkpointName string,
) runtimeEvaluation {
	return evaluateAuthnSourceNamedCheckpointWithContext(
		context.Background(),
		t,
		evaluator,
		target,
		source,
		acceptor,
		checkpointName,
	)
}

// evaluateAuthnSourceNamedCheckpointWithContext retains the supplied request and checkpoint boundaries.
func evaluateAuthnSourceNamedCheckpointWithContext(
	ctx context.Context,
	t *testing.T,
	evaluator checkpointEvaluator,
	target decision.Target,
	source AuthnDecisionSource,
	acceptor effectsupervisor.Acceptor,
	checkpointName string,
) runtimeEvaluation {
	t.Helper()

	caller := mustAuthorityCaller(t, false)

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion,
		Target:  target,
	}, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	facts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	checkpoint, err := decision.NewCheckpoint(checkpointName, facts)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}

	ctx = ContextWithAuthnDecisionSource(ctx, source)
	hostStates, hostReasons := completedHostProviderReceipts(t, evaluator, target, checkpointName)

	outcome, err := evaluator.Evaluate(ctx, checkpointEvaluation{
		request:      request,
		checkpoint:   checkpoint,
		hostStates:   hostStates,
		hostReasons:  hostReasons,
		supervisor:   acceptor,
		generation:   31,
		finalization: decision.NewEvaluationFinalization(effectsupervisor.BoundaryGRPCUnaryReturn),
	})
	if err != nil {
		t.Fatalf("checkpoint evaluator error = %v", err)
	}

	return outcome
}

type authnCatalogBooleanFact struct {
	id        string
	authority string
	component string
	category  decision.FactCategory
	source    decision.FactSource
	value     bool
}

// authnNauthilusBooleanFact declares one host-owned catalog observation.
func authnNauthilusBooleanFact(
	id string,
	category decision.FactCategory,
	value bool,
) authnCatalogBooleanFact {
	return authnCatalogBooleanFact{
		id: id, authority: "nauthilus", component: "authn-catalog-test",
		category: category, source: decision.FactSourceNauthilus, value: value,
	}
}

// authnBackendBooleanFact declares one backend-owned catalog observation.
func authnBackendBooleanFact(id string, value bool) authnCatalogBooleanFact {
	return authnCatalogBooleanFact{
		id: id, authority: "backend", component: "authn-catalog-test",
		category: decision.FactCategorySubject, source: decision.FactSourceBackend, value: value,
	}
}

type suppliedAuthnDecisionSource struct {
	facts          decision.FactSet
	captured       *report.FinalDecision
	effectsEnabled bool
	mu             sync.Mutex
}

// newSuppliedAuthnDecisionSource constructs one strict request-local catalog fact source.
func newSuppliedAuthnDecisionSource(
	t *testing.T,
	inputs []authnCatalogBooleanFact,
	effectsEnabled bool,
) *suppliedAuthnDecisionSource {
	t.Helper()

	facts := make([]decision.Fact, 0, len(inputs))
	for _, input := range inputs {
		provenance, err := decision.NewProvenance(input.source, input.authority, input.component)
		if err != nil {
			t.Fatalf("NewProvenance(%s) error = %v", input.id, err)
		}

		value := runtimeBooleanValue(t, input.value)

		fact, err := decision.NewFact(input.id, input.category, value, provenance)
		if err != nil {
			t.Fatalf("NewFact(%s) error = %v", input.id, err)
		}

		facts = append(facts, fact)
	}

	set, err := decision.NewFactSet(facts)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	return &suppliedAuthnDecisionSource{facts: set, effectsEnabled: effectsEnabled}
}

// StandardAuthFacts returns the immutable supplied catalog observations.
func (s *suppliedAuthnDecisionSource) StandardAuthFacts(
	context.Context,
	decision.Target,
	string,
) (decision.FactSet, error) {
	return decision.NewFactSet(s.facts.Facts())
}

// StandardAuthEffectsEnabled exposes the exact request-local observe gate.
func (s *suppliedAuthnDecisionSource) StandardAuthEffectsEnabled(
	context.Context,
	decision.Target,
	string,
) bool {
	return s.effectsEnabled
}

// CaptureAuthnDecision records the most recent terminal catalog selection.
func (s *suppliedAuthnDecisionSource) CaptureAuthnDecision(
	_ context.Context,
	_ decision.Target,
	_ string,
	final *report.FinalDecision,
) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.captured = report.CloneFinalDecision(final)
}

// capturedDecision returns the detached most recent catalog selection.
func (s *suppliedAuthnDecisionSource) capturedDecision() *report.FinalDecision {
	s.mu.Lock()
	defer s.mu.Unlock()

	return report.CloneFinalDecision(s.captured)
}

type recordingAuthnDecisionSource struct {
	standard *report.DecisionReport
	captured *report.FinalDecision
	mu       sync.Mutex
}

// StandardAuthFacts returns frozen request-local facts in the catalog vocabulary.
func (s *recordingAuthnDecisionSource) StandardAuthFacts(
	context.Context,
	decision.Target,
	string,
) (decision.FactSet, error) {
	if s.standard == nil {
		return decision.NewFactSet(nil)
	}

	provenance, err := decision.NewProvenance(decision.FactSourceNauthilus, "nauthilus", "brute_force")
	if err != nil {
		return decision.FactSet{}, err
	}

	facts := make([]decision.Fact, 0, 2)

	for _, identity := range []struct {
		attribute string
		fact      string
	}{
		{attribute: policy.AttributeBruteForceError, fact: policy.AuthnFactBruteForceError},
		{attribute: policy.AttributeBruteForceTriggered, fact: policy.AuthnFactBruteForceTriggered},
	} {
		attribute, exists := s.standard.Attributes[identity.attribute]
		if !exists {
			continue
		}

		value, ok := attribute.Value.(bool)
		if !ok {
			return decision.FactSet{}, fmt.Errorf("attribute %s is not boolean", identity.attribute)
		}

		strict, valueErr := decision.NewValue(decision.ValueInput{Boolean: &value})
		if valueErr != nil {
			return decision.FactSet{}, valueErr
		}

		fact, factErr := decision.NewFact(
			identity.fact,
			decision.FactCategoryEnvironment,
			strict,
			provenance,
		)
		if factErr != nil {
			return decision.FactSet{}, factErr
		}

		facts = append(facts, fact)
	}

	return decision.NewFactSet(facts)
}

// StandardAuthEffectsEnabled keeps the focused standard effect fixture enabled.
func (*recordingAuthnDecisionSource) StandardAuthEffectsEnabled(
	context.Context,
	decision.Target,
	string,
) bool {
	return true
}

// CaptureAuthnDecision records the selection before host-effect execution begins.
func (s *recordingAuthnDecisionSource) CaptureAuthnDecision(
	_ context.Context,
	_ decision.Target,
	_ string,
	final *report.FinalDecision,
) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.captured = final
}

// capturedDecision returns the most recent selected authn result.
func (s *recordingAuthnDecisionSource) capturedDecision() *report.FinalDecision {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.captured
}

type authnEffectOrderLog struct {
	values []string
	mu     sync.Mutex
}

// append records one synchronized effect lifecycle boundary.
func (l *authnEffectOrderLog) append(value string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.values = append(l.values, value)
}

// entries returns a detached effect-order snapshot.
func (l *authnEffectOrderLog) entries() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.values...)
}

type orderedAuthnSyncEffectProvider struct {
	log *authnEffectOrderLog
}

// Execute records one successful synchronous effect owner invocation.
func (p *orderedAuthnSyncEffectProvider) Execute(_ context.Context, execution effectExecution) effectsupervisor.Result {
	p.log.append(fmt.Sprintf("sync:%s:%d", execution.provider, execution.ordinal))

	return effectsupervisor.Succeeded()
}

type orderedAuthnPostActionProvider struct {
	log *authnEffectOrderLog
}

// Prepare records immutable post-action capture before supervisor acceptance.
func (p *orderedAuthnPostActionProvider) Prepare(
	_ context.Context,
	execution effectExecution,
) (effectsupervisor.Work, error) {
	p.log.append(fmt.Sprintf("prepare:%s:%d", execution.provider, execution.ordinal))

	return &recordingPostActionWork{result: effectsupervisor.Failed(definitions.TempFailDefault)}, nil
}

type authnEffectState struct {
	value    string
	captured string
	mu       sync.Mutex
}

// update records state produced by an earlier synchronous effect.
func (s *authnEffectState) update(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.value = value
}

// capture snapshots the state visible when post-action preparation begins.
func (s *authnEffectState) capture() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.captured = s.value
}

// capturedValue returns the immutable value retained by preparation.
func (s *authnEffectState) capturedValue() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.captured
}

type statefulAuthnSyncEffectProvider struct {
	state *authnEffectState
}

// Execute mutates request state at the selected synchronous ordinal.
func (p statefulAuthnSyncEffectProvider) Execute(
	context.Context,
	effectExecution,
) effectsupervisor.Result {
	p.state.update("account-after-sync")

	return effectsupervisor.Succeeded()
}

type statefulAuthnPostActionProvider struct {
	state *authnEffectState
}

// Prepare captures request state only when its effect ordinal is reached.
func (p statefulAuthnPostActionProvider) Prepare(
	context.Context,
	effectExecution,
) (effectsupervisor.Work, error) {
	p.state.capture()

	return &recordingPostActionWork{result: effectsupervisor.Succeeded()}, nil
}

type orderedFailingAuthnAcceptor struct {
	log *authnEffectOrderLog
	err error
}

type orderedAcceptingAuthnAcceptor struct {
	log *authnEffectOrderLog
}

// Accept records one successful immutable plan transfer.
func (a *orderedAcceptingAuthnAcceptor) Accept(
	_ context.Context,
	plan effectsupervisor.Plan,
) (effectsupervisor.Receipt, error) {
	a.log.append(fmt.Sprintf("accept:%s:%d", plan.Provider(), plan.EffectOrdinal()))

	return effectsupervisor.Receipt{}, nil
}

type failingAuthnPostActionProvider struct{}

// Prepare returns one deterministic standard-auth preparation failure.
func (failingAuthnPostActionProvider) Prepare(
	context.Context,
	effectExecution,
) (effectsupervisor.Work, error) {
	return nil, errors.New("post-action preparation failed")
}

type cancelingAuthnSyncEffectProvider struct {
	cancel context.CancelFunc
}

// Execute cancels the admitted request after one successful synchronous attempt.
func (p cancelingAuthnSyncEffectProvider) Execute(
	context.Context,
	effectExecution,
) effectsupervisor.Result {
	p.cancel()

	return effectsupervisor.Succeeded()
}

type cancelingAuthnSupervisorAcceptor struct {
	supervisor *effectsupervisor.Supervisor
	cancel     context.CancelFunc
}

// Accept cancels the request immediately before the real supervisor transfer.
func (a cancelingAuthnSupervisorAcceptor) Accept(
	ctx context.Context,
	plan effectsupervisor.Plan,
) (effectsupervisor.Receipt, error) {
	a.cancel()

	return a.supervisor.Accept(ctx, plan)
}

type authnSupervisorProvider struct{}

// Capture returns the already immutable test work when acceptance remains live.
func (authnSupervisorProvider) Capture(
	ctx context.Context,
	work effectsupervisor.Work,
) (effectsupervisor.Work, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return work, nil
}

// Execute is unreachable because the acceptance fixture cancels before transfer.
func (authnSupervisorProvider) Execute(
	context.Context,
	effectsupervisor.Work,
) effectsupervisor.Result {
	return effectsupervisor.Failed("unexpected_execution")
}

// Release has no external resource in the acceptance-cancellation fixture.
func (authnSupervisorProvider) Release(effectsupervisor.Work) {}

// Accept records the mandatory transfer attempt and rejects it.
func (a *orderedFailingAuthnAcceptor) Accept(
	_ context.Context,
	plan effectsupervisor.Plan,
) (effectsupervisor.Receipt, error) {
	a.log.append(fmt.Sprintf("accept:%s:%d", plan.Provider(), plan.EffectOrdinal()))

	return effectsupervisor.Receipt{}, a.err
}

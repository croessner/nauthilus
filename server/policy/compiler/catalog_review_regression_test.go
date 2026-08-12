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

package compiler

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/evaluation"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

func TestBuiltinStandardAuthEffectsResolveEstablishedSelectionsAndTypedParameters(t *testing.T) {
	compiler, activation := builtinAuthnCatalog(t, "")

	catalog, err := compiler.Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	target, ok := catalog.Lookup(mustCatalogTarget(t, "authn", "authenticate"))
	if !ok {
		t.Fatal("builtin authn target missing")
	}

	standardReport := report.NewDecisionReport()
	standardReport.Operation = policy.OperationAuthenticate
	standardReport.Checks["brute_force"] = report.CheckResult{
		Name:      "brute_force",
		Type:      policy.CheckTypeBruteForce,
		Operation: policy.OperationAuthenticate,
		Stage:     policy.StagePreAuth,
		Status:    policy.CheckStatusOK,
	}
	standardReport.Attributes[policy.AttributeBruteForceTriggered] = report.AttributeValue{
		ID:        policy.AttributeBruteForceTriggered,
		Stage:     policy.StagePreAuth,
		Operation: policy.OperationAuthenticate,
		Value:     true,
	}

	result := evaluation.EvaluateStandardAuth(standardReport)
	if result.Final == nil || len(result.Final.Obligations) != 3 {
		t.Fatalf("standard_auth obligations = %+v, want established brute-force selection", result.Final)
	}

	assertStandardAuthEffectSelections(t, target, result.Final.Obligations)
	assertStandardAuthProviderOrder(t, target)
}

func TestBuiltinStandardAuthEffectsUseExactEstablishedTargetAllowlists(t *testing.T) {
	contribution, err := registry.NewBuiltinTargetContributor(catalogAcceptanceCapability{}).Contribute(context.Background())
	if err != nil {
		t.Fatalf("Contribute() error = %v", err)
	}

	want := map[string][]string{
		policy.ObligationBruteForceUpdate:     {"authn/authenticate", "authn/lookup_identity"},
		policy.ObligationLuaActionDispatch:    {"authn/authenticate", "authn/lookup_identity"},
		policy.ObligationLuaPostActionEnqueue: {"authn/authenticate"},
	}

	for _, effect := range contribution.Effects() {
		targets := make([]string, 0, len(effect.Targets()))
		for _, target := range effect.Targets() {
			targets = append(targets, target.String())
		}

		if !reflect.DeepEqual(targets, want[effect.SelectionID()]) {
			t.Fatalf("effect %s targets = %v, want %v", effect.SelectionID(), targets, want[effect.SelectionID()])
		}
	}
}

func TestBuiltinStandardAuthEffectsUseExactEstablishedOwnersAndClasses(t *testing.T) {
	contribution, err := registry.NewBuiltinTargetContributor(catalogAcceptanceCapability{}).Contribute(context.Background())
	if err != nil {
		t.Fatalf("Contribute() error = %v", err)
	}

	want := map[string]struct {
		provider  string
		execution registry.ExecutionClass
	}{
		policy.ObligationBruteForceUpdate: {
			provider: "authn/brute_force", execution: registry.ExecutionHostSync,
		},
		policy.ObligationLuaActionDispatch: {
			provider: "authn/lua_action", execution: registry.ExecutionHostSync,
		},
		policy.ObligationLuaPostActionEnqueue: {
			provider: "authn/post_action", execution: registry.ExecutionHostPostAction,
		},
	}

	for _, effect := range contribution.Effects() {
		expected, exists := want[effect.SelectionID()]
		if !exists {
			t.Fatalf("unexpected builtin effect selection %q", effect.SelectionID())
		}

		if effect.Provider() != expected.provider || effect.Execution() != expected.execution {
			t.Fatalf(
				"effect %s owner/class = %s/%s, want %s/%s",
				effect.SelectionID(),
				effect.Provider(),
				effect.Execution(),
				expected.provider,
				expected.execution,
			)
		}
	}
}

func TestBuiltinAuthnProvidersUseExactEstablishedTargetAllowlists(t *testing.T) {
	contribution, err := registry.NewBuiltinTargetContributor(catalogAcceptanceCapability{}).Contribute(context.Background())
	if err != nil {
		t.Fatalf("Contribute() error = %v", err)
	}

	authAndLookup := []string{"authn/authenticate", "authn/lookup_identity"}
	want := map[string][]string{
		"authn/brute_force":      authAndLookup,
		"authn/lua_action":       authAndLookup,
		"authn/post_action":      {"authn/authenticate"},
		"authn/environment":      authAndLookup,
		"authn/tls_encryption":   authAndLookup,
		"authn/relay_domains":    {"authn/authenticate"},
		"authn/rbl":              authAndLookup,
		"authn/auth_backend":     authAndLookup,
		"authn/subject":          authAndLookup,
		"authn/account_provider": {"authn/list_accounts"},
	}

	for _, provider := range contribution.Providers() {
		targets := make([]string, 0, len(provider.Targets()))
		for _, target := range provider.Targets() {
			targets = append(targets, target.String())
		}

		if !reflect.DeepEqual(targets, want[provider.ID()]) {
			t.Fatalf("provider %s targets = %v, want %v", provider.ID(), targets, want[provider.ID()])
		}
	}
}

func TestBuiltinAuthnPlansPreserveExactCheckpointProviderSchedules(t *testing.T) {
	tests := []struct {
		action      string
		checkpoints map[string][]string
	}{
		{
			action: "authenticate",
			checkpoints: map[string][]string{
				"pre_auth":      {"authn/brute_force"},
				"auth_decision": {"authn/environment", "authn/tls_encryption", "authn/relay_domains", "authn/rbl", "authn/auth_backend", "authn/subject"},
			},
		},
		{
			action: "lookup_identity",
			checkpoints: map[string][]string{
				"pre_auth":      {"authn/environment", "authn/tls_encryption", "authn/rbl"},
				"auth_decision": {"authn/auth_backend", "authn/subject"},
			},
		},
		{
			action: "list_accounts",
			checkpoints: map[string][]string{
				"auth_decision": {"authn/account_provider"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.action, func(t *testing.T) {
			compiler := NewTargetCatalogCompiler(registry.NewBuiltinTargetContributor(catalogAcceptanceCapability{}))
			activation := mustCompilerActivation(
				t,
				"policy.targets.authn."+test.action,
				"authn",
				test.action,
				"authn/"+test.action+"/v1",
			)

			catalog, err := compiler.Compile(context.Background(), []registry.TargetActivation{activation})
			if err != nil {
				t.Fatalf("Compile() error = %v", err)
			}

			target, exists := catalog.Lookup(mustCatalogTarget(t, "authn", test.action))
			if !exists {
				t.Fatal("compiled authn target missing")
			}

			if len(target.DomainPlan().Checkpoints()) != len(test.checkpoints) {
				t.Fatalf("checkpoint count = %d, want %d", len(target.DomainPlan().Checkpoints()), len(test.checkpoints))
			}

			for checkpointName, providers := range test.checkpoints {
				checkpoint, checkpointExists := target.DomainPlan().Checkpoint(checkpointName)
				if !checkpointExists || !reflect.DeepEqual(checkpoint.ProviderIDs(), providers) {
					t.Fatalf("checkpoint %s providers = %v, want %v", checkpointName, checkpoint.ProviderIDs(), providers)
				}
			}
		})
	}
}

func TestBuiltinAuthnCatalogAllowsAdditionalConfiguredEffectsAndProviders(t *testing.T) {
	target := mustCatalogTarget(t, "authn", "authenticate")
	provider := mustCatalogProvider(t, registry.ProviderDefinitionInput{
		ID:         "authn/custom_provider",
		Targets:    []decision.Target{target},
		Executions: []registry.ExecutionClass{registry.ExecutionHostSync},
	})
	effect := mustCatalogEffect(t, registry.EffectDefinitionInput{
		ID:        "authn/custom_effect",
		Provider:  provider.ID(),
		Targets:   []decision.Target{target},
		Kind:      registry.EffectKindObligation,
		Execution: registry.ExecutionHostSync,
	})

	ownership, err := registry.NewNamespaceOwnership("test.authn.extension", []string{"authn"})
	if err != nil {
		t.Fatalf("NewNamespaceOwnership() error = %v", err)
	}

	contribution, err := registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
		Ownership: ownership,
		Providers: []registry.ProviderDefinition{provider},
		Effects:   []registry.EffectDefinition{effect},
	})
	if err != nil {
		t.Fatalf("NewCompleteDefinitionContribution() error = %v", err)
	}

	_, activation := builtinAuthnCatalog(t, "")
	compiler := NewTargetCatalogCompiler(
		registry.NewBuiltinTargetContributor(catalogAcceptanceCapability{}),
		testCatalogContributor{contribution: contribution},
	)

	catalog, err := compiler.Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	compiled, exists := catalog.Lookup(target)
	if !exists {
		t.Fatal("compiled authn target missing")
	}

	if _, exists = compiled.LookupProvider(provider.ID()); !exists {
		t.Fatal("configured authn provider missing")
	}

	if _, exists = compiled.LookupEffect(effect.ID()); !exists {
		t.Fatal("configured authn effect missing")
	}
}

// assertStandardAuthEffectSelections resolves real evaluator output through the catalog.
func assertStandardAuthEffectSelections(
	t *testing.T,
	target policyruntime.CompiledTarget,
	selections []report.EffectRequest,
) {
	t.Helper()

	for _, selection := range selections {
		effect, exists := target.LookupEffectSelection(selection.ID)
		if !exists {
			t.Fatalf("standard_auth selection %q is not registered", selection.ID)
		}

		if !effect.IsBuiltin() {
			t.Fatalf("standard_auth selection %q has a configurable execution class", selection.ID)
		}

		use, useErr := registry.NewEffectUse(effect.ID(), catalogEffectParameters(t, selection.Args))
		if useErr != nil {
			t.Fatalf("NewEffectUse(%q) error = %v", selection.ID, useErr)
		}

		if useErr = effect.ValidateUse(use); useErr != nil {
			t.Fatalf("ValidateUse(%q) error = %v", selection.ID, useErr)
		}

		provider, exists := target.LookupProvider(effect.Provider())
		if !exists || !provider.IsBuiltin() {
			t.Fatalf("standard_auth selection %q has no immutable builtin provider", selection.ID)
		}
	}
}

// assertStandardAuthProviderOrder verifies the hard cut and remaining host work order.
func assertStandardAuthProviderOrder(t *testing.T, target policyruntime.CompiledTarget) {
	t.Helper()

	preAuth, exists := target.DomainPlan().Checkpoint("pre_auth")
	if !exists || !reflect.DeepEqual(preAuth.ProviderIDs(), []string{"authn/brute_force"}) {
		t.Fatalf("pre_auth providers = %v, want brute-force hard-cut owner", preAuth.ProviderIDs())
	}

	authDecision, exists := target.DomainPlan().Checkpoint("auth_decision")

	wantProviders := []string{
		"authn/environment",
		"authn/tls_encryption",
		"authn/relay_domains",
		"authn/rbl",
		"authn/auth_backend",
		"authn/subject",
	}
	if !exists || !reflect.DeepEqual(authDecision.ProviderIDs(), wantProviders) {
		t.Fatalf("auth_decision providers = %v, want %v", authDecision.ProviderIDs(), wantProviders)
	}
}

// catalogEffectParameters converts established string/bool obligation arguments to strict values.
func catalogEffectParameters(t *testing.T, values map[string]any) map[string]decision.Value {
	t.Helper()

	result := make(map[string]decision.Value, len(values))
	for name, value := range values {
		var input decision.ValueInput

		switch typed := value.(type) {
		case string:
			input.String = &typed
		case bool:
			input.Boolean = &typed
		default:
			t.Fatalf("unsupported established effect parameter %s type %T", name, value)
		}

		strict, err := decision.NewValue(input)
		if err != nil {
			t.Fatalf("NewValue(%s) error = %v", name, err)
		}

		result[name] = strict
	}

	return result
}

func TestCatalogInstantiatesExecutableExpressionsIntoTargetLocalRules(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)
	expression := mustCatalogExpression(t, "input.domain", registry.ExpressionOperatorEqual, mustCatalogStringValue(t, "example.org"))
	fixture.sharedSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
		ID:             mustCatalogSetID(t, testSharedSetID),
		Visibility:     registry.PolicySetVisibilityExported,
		ExportContract: &fixture.contract,
		Rules: []registry.PolicyRule{mustCatalogExpressionRule(
			t,
			"shared_deny",
			decisionPoint,
			expression,
			decision.EffectDeny,
		)},
	})

	catalog := fixture.compile(t)

	target, ok := catalog.Lookup(fixture.target)
	if !ok {
		t.Fatal("compiled target missing")
	}

	set, ok := target.LookupPolicySet(mustCatalogSetID(t, testSharedSetID))
	if !ok {
		t.Fatal("target-local compiled policy set missing")
	}

	rules := set.Rules()
	if len(rules) != 1 || rules[0].Target().String() != fixture.target.String() || rules[0].Checkpoint() != decisionPoint {
		t.Fatalf("compiled rules = %+v, want one exactly instantiated rule", rules)
	}

	if rules[0].Expression().Operator() != registry.ExpressionOperatorEqual || rules[0].Expression().FactID() != "input.domain" {
		t.Fatalf("compiled expression = %+v, want executable fact equality", rules[0].Expression())
	}
}

//nolint:funlen // One table intentionally covers the complete closed operator vocabulary.
func TestPolicyExpressionRetainsCompleteConditionTreeVocabulary(t *testing.T) {
	stringValue := mustCatalogStringValue(t, "example.org")
	booleanValue := mustCatalogBooleanValue(t, true)
	integerValue := mustCatalogIntegerValue(t, 10)
	timestampValue := mustCatalogTimestampValue(t)

	tests := []registry.PolicyExpressionInput{
		{FactID: "input.string", FactKind: decision.ValueKindString, Operator: registry.ExpressionOperatorIs, Values: []decision.Value{stringValue}},
		{FactID: "input.string", FactKind: decision.ValueKindString, Operator: registry.ExpressionOperatorEQ, Values: []decision.Value{stringValue}},
		{FactID: "input.string", FactKind: decision.ValueKindString, Operator: registry.ExpressionOperatorNotEqual, Values: []decision.Value{stringValue}},
		{FactID: "input.string", FactKind: decision.ValueKindString, Operator: registry.ExpressionOperatorIn, Reference: "@string.allowed"},
		{FactID: "input.string", FactKind: decision.ValueKindString, Operator: registry.ExpressionOperatorNotIn, Values: []decision.Value{stringValue}},
		{FactID: "input.string", FactKind: decision.ValueKindString, Operator: registry.ExpressionOperatorMatches, Values: []decision.Value{mustCatalogStringValue(t, `^example\\.org$`)}},
		{FactID: "input.string", FactKind: decision.ValueKindString, Operator: registry.ExpressionOperatorExists, Values: []decision.Value{booleanValue}},
		{FactID: "input.list", FactKind: decision.ValueKindStrings, Operator: registry.ExpressionOperatorContains, Values: []decision.Value{stringValue}},
		{FactID: "input.list", FactKind: decision.ValueKindStrings, Operator: registry.ExpressionOperatorContainsAny, Values: []decision.Value{stringValue}},
		{FactID: "input.list", FactKind: decision.ValueKindStrings, Operator: registry.ExpressionOperatorContainsAll, Values: []decision.Value{stringValue}},
		{FactID: "input.list", FactKind: decision.ValueKindStrings, Operator: registry.ExpressionOperatorContainsNone, Values: []decision.Value{stringValue}},
		{FactID: "input.number", FactKind: decision.ValueKindInteger, Operator: registry.ExpressionOperatorGT, Values: []decision.Value{integerValue}},
		{FactID: "input.number", FactKind: decision.ValueKindInteger, Operator: registry.ExpressionOperatorGTE, Values: []decision.Value{integerValue}},
		{FactID: "input.number", FactKind: decision.ValueKindInteger, Operator: registry.ExpressionOperatorLT, Values: []decision.Value{integerValue}},
		{FactID: "input.number", FactKind: decision.ValueKindInteger, Operator: registry.ExpressionOperatorLTE, Values: []decision.Value{integerValue}},
		{FactID: "input.ip", FactKind: decision.ValueKindString, Operator: registry.ExpressionOperatorCIDRContains, Reference: "@network.trusted"},
		{FactID: "input.time", FactKind: decision.ValueKindTimestamp, Operator: registry.ExpressionOperatorWithinTimeWindow, Reference: "@time_window.business_hours"},
		{FactID: "input.time", FactKind: decision.ValueKindTimestamp, Operator: registry.ExpressionOperatorEqual, Values: []decision.Value{timestampValue}},
	}

	children := make([]registry.PolicyExpression, 0, len(tests))
	for index, input := range tests {
		expression, err := registry.NewPolicyExpression(input)
		if err != nil {
			t.Fatalf("NewPolicyExpression(operator %s index %d) error = %v", input.Operator, index, err)
		}

		children = append(children, expression)
	}

	anyNode, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindAny, Children: children[:2],
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression(any) error = %v", err)
	}

	not, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindNot, Children: []registry.PolicyExpression{anyNode},
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression(not) error = %v", err)
	}

	root, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindAll, Children: append(children[2:], not),
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression(all) error = %v", err)
	}

	if root.Kind() != registry.ExpressionKindAll || len(root.Children()) != len(children)-1 {
		t.Fatalf("complete expression tree = %+v, want ordered all/any/not tree", root)
	}

	contracts := root.FactContracts()
	if len(contracts) != 5 {
		t.Fatalf("tree fact contracts = %v, want five deduplicated typed facts", contracts)
	}
}

func TestPolicyExpressionRejectsOversizedInlineOperands(t *testing.T) {
	oversized := mustCatalogStringValue(t, strings.Repeat("x", 64*1024+1))

	_, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		FactID: "input.string", FactKind: decision.ValueKindString,
		Operator: registry.ExpressionOperatorMatches, Values: []decision.Value{oversized},
	})
	if !errors.Is(err, registry.ErrInvalidPolicyExpression) {
		t.Fatalf("NewPolicyExpression(oversized regex) error = %v, want bounded rejection", err)
	}
}

func TestPolicyExpressionRejectsCrossFamilyConditionSetReferences(t *testing.T) {
	tests := []registry.PolicyExpressionInput{
		{FactID: "input.value", FactKind: decision.ValueKindString, Operator: registry.ExpressionOperatorIn, Reference: "@network.allowed"},
		{FactID: "input.value", FactKind: decision.ValueKindString, Operator: registry.ExpressionOperatorCIDRContains, Reference: "@time_window.office"},
		{FactID: "input.time", FactKind: decision.ValueKindTimestamp, Operator: registry.ExpressionOperatorWithinTimeWindow, Reference: "@string.office"},
	}

	for _, input := range tests {
		if _, err := registry.NewPolicyExpression(input); !errors.Is(err, registry.ErrInvalidPolicyExpression) {
			t.Fatalf("NewPolicyExpression(%s, %s) error = %v, want family rejection", input.Operator, input.Reference, err)
		}
	}
}

func TestCatalogRejectsCompositeExpressionFactOutsideExactSchema(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)
	unknown := mustCatalogFactContract(t, "input.unknown", decision.ValueKindString)

	root, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindAll,
		Children: []registry.PolicyExpression{
			mustCatalogFactExpression(t, fixture.factContract),
			mustCatalogFactExpression(t, unknown),
		},
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression(all) error = %v", err)
	}

	contract := mustCatalogCheckpointContract(
		t,
		[]string{decisionPoint},
		[]registry.FactContract{fixture.factContract, unknown},
		[]decision.Effect{decision.EffectDeny},
		[]string{testEffectID},
	)
	fixture.contract = contract
	fixture.sharedSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
		ID: mustCatalogSetID(t, testSharedSetID), Visibility: registry.PolicySetVisibilityExported,
		ExportContract: &contract,
		Rules:          []registry.PolicyRule{mustCatalogExpressionRule(t, "composite", decisionPoint, root, decision.EffectDeny)},
	})
	fixture.rootSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
		ID:      testRootSetIDValue(t),
		Imports: []registry.PolicySetImport{mustCatalogImport(t, testSharedSetID, fixture.target, decisionPoint, contract)},
	})

	if _, err = fixture.tryCompile(); !errors.Is(err, ErrPolicyRuleFactMismatch) {
		t.Fatalf("Compile(composite unknown fact) error = %v, want all-leaf schema rejection", err)
	}
}

func TestCatalogRetainsCompleteRuleDecisionMetadata(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)

	message, err := registry.NewPolicyResponseMessage(registry.PolicyResponseMessageInput{
		From: "i18n", I18NKey: "auth.policy.company.account_blocked", Fallback: "Account blocked",
	})
	if err != nil {
		t.Fatalf("NewPolicyResponseMessage() error = %v", err)
	}

	language, err := registry.NewPolicyResponseLanguage(registry.PolicyResponseLanguageInput{From: "literal", Language: "de-DE"})
	if err != nil {
		t.Fatalf("NewPolicyResponseLanguage() error = %v", err)
	}

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name: "metadata", Checkpoint: decisionPoint,
		Expression: mustCatalogFactExpression(t, fixture.factContract), Effects: []registry.EffectUse{mustCatalogEffectUse(t, testEffectID)},
		Decision: decision.EffectDeny, Reason: "blocked", OutcomeMarker: "deny", FSMEventMarker: "auth_deny",
		ResponseMarker: "fail", ResponseMessage: message, ResponseLanguage: language,
		SkipRemainingCheckpointProviders: true,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	fixture.sharedSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
		ID: mustCatalogSetID(t, testSharedSetID), Visibility: registry.PolicySetVisibilityExported,
		ExportContract: &fixture.contract, Rules: []registry.PolicyRule{rule},
	})
	catalog := fixture.compile(t)
	target, _ := catalog.Lookup(fixture.target)
	set, _ := target.LookupPolicySet(mustCatalogSetID(t, testSharedSetID))
	compiled := set.Rules()[0]

	if compiled.Reason() != "blocked" || compiled.OutcomeMarker() != "deny" ||
		compiled.FSMEventMarker() != "auth_deny" || compiled.ResponseMarker() != "fail" ||
		compiled.ResponseMessage().I18NKey() != "auth.policy.company.account_blocked" ||
		compiled.ResponseLanguage().Language() != "de-DE" || !compiled.SkipRemainingCheckpointProviders() {
		t.Fatalf("compiled rule metadata = %+v, want complete retained decision semantics", compiled)
	}
}

func TestCatalogCompilesReusableSetAcrossCompatibleCheckpoints(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)
	checkpoints := []string{"preflight", decisionPoint}
	contract := mustCatalogCheckpointContract(
		t,
		checkpoints,
		[]registry.FactContract{fixture.factContract},
		[]decision.Effect{decision.EffectDeny},
		[]string{testEffectID},
	)
	fixture.contract = contract
	fixture.sharedSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
		ID:             mustCatalogSetID(t, testSharedSetID),
		Visibility:     registry.PolicySetVisibilityExported,
		ExportContract: &contract,
		Rules: []registry.PolicyRule{
			mustCatalogRuleAtCheckpoint(t, "preflight_deny", "preflight", fixture.factContract),
			mustCatalogRuleAtCheckpoint(t, "final_deny", decisionPoint, fixture.factContract),
		},
	})
	fixture.rootSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
		ID: testRootSetIDValue(t),
		Imports: []registry.PolicySetImport{
			mustCatalogImport(t, testSharedSetID, fixture.target, "preflight", contract),
			mustCatalogImport(t, testSharedSetID, fixture.target, decisionPoint, contract),
		},
	})
	fixture.plan = mustCatalogPlan(t, fixture.target, []registry.CheckpointDefinition{
		mustCatalogCheckpoint(t, "preflight", []registry.PolicySetImport{
			mustCatalogImport(t, testRootSetID, fixture.target, "preflight", registry.ExportContract{}),
		}, nil),
		mustCatalogCheckpoint(t, decisionPoint, []registry.PolicySetImport{
			mustCatalogImport(t, testRootSetID, fixture.target, decisionPoint, registry.ExportContract{}),
		}, nil),
	})

	catalog := fixture.compile(t)
	target, _ := catalog.Lookup(fixture.target)

	for _, checkpointName := range checkpoints {
		checkpoint, ok := target.DomainPlan().Checkpoint(checkpointName)
		if !ok || !checkpoint.ContainsPolicySet(testSharedSetID) {
			t.Fatalf("checkpoint %q did not instantiate reusable set", checkpointName)
		}
	}
}

func TestCatalogValidatesInactiveImportedCapabilityAgainstExactTargetSchema(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)
	requiredFact := mustCatalogFactContract(t, "input.required", decision.ValueKindString)
	contract := mustCatalogCheckpointContract(
		t,
		[]string{decisionPoint},
		[]registry.FactContract{requiredFact},
		[]decision.Effect{decision.EffectDeny},
		nil,
	)

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name:       "verify_only",
		Checkpoint: decisionPoint,
		Actions:    []string{"verify"},
		Expression: mustCatalogFactExpression(t, requiredFact),
		Decision:   decision.EffectDeny,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	fixture.sharedSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
		ID:             mustCatalogSetID(t, testSharedSetID),
		Visibility:     registry.PolicySetVisibilityExported,
		ExportContract: &contract,
		Rules:          []registry.PolicyRule{rule},
	})
	fixture.rootSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
		ID:      testRootSetIDValue(t),
		Imports: []registry.PolicySetImport{mustCatalogImport(t, testSharedSetID, fixture.target, decisionPoint, contract)},
	})

	if _, err = fixture.tryCompile(); !errors.Is(err, ErrPolicyRuleFactMismatch) {
		t.Fatalf("Compile() inactive import capability error = %v, want exact target-schema rejection", err)
	}
}

//nolint:funlen // Enforce and observe projections are asserted together as one authority contract.
func TestAuthnConfiguredCheckpointDoesNotEvictStandardFallback(t *testing.T) {
	configuredID := mustCatalogSetID(t, "authn/configured")
	configured := mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
		ID: configuredID,
		Rules: []registry.PolicyRule{mustCatalogExpressionDecisionRule(
			t,
			"configured_deny",
			"pre_auth",
			mustCatalogExpression(t, "", registry.ExpressionOperatorAlways),
			decision.EffectDeny,
		)},
	})
	compiler, activation, target := configuredAuthnCatalog(t, configured)

	catalog, err := compiler.Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	compiled, _ := catalog.Lookup(target)

	preAuth, _ := compiled.DomainPlan().Checkpoint("pre_auth")
	if got := preAuth.PolicySetIDs(); !reflect.DeepEqual(got, []string{configuredID.String(), registry.BuiltinStandardAuthPolicySet}) {
		t.Fatalf("pre_auth set authority = %v, want configured then standard fallback", got)
	}

	if got := preAuth.ProductionPolicySetIDs(); !reflect.DeepEqual(got, []string{configuredID.String()}) {
		t.Fatalf("enforce pre_auth production authority = %v, want configured set", got)
	}

	authDecision, _ := compiled.DomainPlan().Checkpoint("auth_decision")
	if got := authDecision.PolicySetIDs(); !reflect.DeepEqual(got, []string{registry.BuiltinStandardAuthPolicySet}) {
		t.Fatalf("auth_decision set authority = %v, want untouched standard fallback", got)
	}

	if got := authDecision.ProductionPolicySetIDs(); !reflect.DeepEqual(got, []string{registry.BuiltinStandardAuthPolicySet}) {
		t.Fatalf("enforce auth_decision production authority = %v, want standard fallback", got)
	}

	observeActivation, err := activation.WithAuthorityMode(registry.AuthorityModeObserve)
	if err != nil {
		t.Fatalf("TargetActivation.WithAuthorityMode(observe) error = %v", err)
	}

	observeCatalog, err := compiler.Compile(context.Background(), []registry.TargetActivation{observeActivation})
	if err != nil {
		t.Fatalf("Compile(observe) error = %v", err)
	}

	observeTarget, _ := observeCatalog.Lookup(target)
	if observeTarget.AuthorityMode() != registry.AuthorityModeObserve {
		t.Fatalf("observe target authority = %s, want observe", observeTarget.AuthorityMode())
	}

	observePreAuth, _ := observeTarget.DomainPlan().Checkpoint("pre_auth")
	if got := observePreAuth.ProductionPolicySetIDs(); !reflect.DeepEqual(got, []string{registry.BuiltinStandardAuthPolicySet}) {
		t.Fatalf("observe pre_auth production authority = %v, want standard_auth", got)
	}

	if got := observePreAuth.ComparisonPolicySetIDs(); !reflect.DeepEqual(got, []string{configuredID.String()}) {
		t.Fatalf("observe pre_auth comparison authority = %v, want configured set", got)
	}
}

func TestAuthnEnforceIgnoresConfiguredSetWithoutApplicableCheckpointRules(t *testing.T) {
	configured := mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
		ID: mustCatalogSetID(t, "authn/configured"),
		Rules: []registry.PolicyRule{mustCatalogActionRestrictedRule(
			t,
			"verify_only",
			"pre_auth",
			"lookup_identity",
		)},
	})
	compiler, activation, target := configuredAuthnCatalog(t, configured)

	catalog, err := compiler.Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	compiled, _ := catalog.Lookup(target)
	preAuth, _ := compiled.DomainPlan().Checkpoint("pre_auth")

	if got := preAuth.ProductionPolicySetIDs(); !reflect.DeepEqual(got, []string{registry.BuiltinStandardAuthPolicySet}) {
		t.Fatalf("inactive configured authority = %v, want standard_auth production fallback", got)
	}
}

// configuredAuthnCatalog adds one configured set and exact pre-auth binding to builtin authn.
func configuredAuthnCatalog(
	t *testing.T,
	configured registry.PolicySetDefinition,
) (*TargetCatalogCompiler, registry.TargetActivation, decision.Target) {
	t.Helper()

	target := mustCatalogTarget(t, "authn", "authenticate")

	ownership, err := registry.NewNamespaceOwnership("test.authn.configured", []string{"authn"})
	if err != nil {
		t.Fatalf("NewNamespaceOwnership() error = %v", err)
	}

	contribution, err := registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
		Ownership: ownership, PolicySets: []registry.PolicySetDefinition{configured},
	})
	if err != nil {
		t.Fatalf("NewCompleteDefinitionContribution() error = %v", err)
	}

	binding := mustCatalogImport(t, configured.ID().String(), target, "pre_auth", registry.ExportContract{})
	compiler, activation := builtinAuthnCatalog(t, "")

	activation, err = activation.WithPolicySetBindings([]registry.PolicySetImport{binding})
	if err != nil {
		t.Fatalf("TargetActivation.WithPolicySetBindings() error = %v", err)
	}

	compiler.contributors = append(compiler.contributors, testCatalogContributor{contribution: contribution})

	return compiler, activation, target
}

// mustCatalogActionRestrictedRule constructs one inactive-action authority fixture.
func mustCatalogActionRestrictedRule(
	t *testing.T,
	name string,
	checkpoint string,
	action string,
) registry.PolicyRule {
	t.Helper()

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name: name, Checkpoint: checkpoint, Actions: []string{action},
		Expression: mustCatalogExpression(t, "", registry.ExpressionOperatorAlways),
		Decision:   decision.EffectDeny,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	return rule
}

// mustCatalogExpressionDecisionRule constructs one executable decision without selected effects.
func mustCatalogExpressionDecisionRule(
	t *testing.T,
	name string,
	checkpoint string,
	expression registry.PolicyExpression,
	result decision.Effect,
) registry.PolicyRule {
	t.Helper()

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name:       name,
		Checkpoint: checkpoint,
		Expression: expression,
		Decision:   result,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	return rule
}

func TestPlanBindingsRejectTargetAndCheckpointMismatch(t *testing.T) {
	target := mustCatalogTarget(t, "dkim2", "sign")
	other := mustCatalogTarget(t, "dkim2", "verify")
	setID := testRootSetIDValue(t)

	wrongCheckpoint := mustCatalogImport(t, setID.String(), target, "preflight", registry.ExportContract{})
	if _, err := registry.NewCheckpointDefinition(decisionPoint, []registry.PolicySetImport{wrongCheckpoint}, nil); !errors.Is(err, registry.ErrInvalidCheckpoint) {
		t.Fatalf("NewCheckpointDefinition() error = %v, want exact checkpoint rejection", err)
	}

	wrongTarget := mustCatalogImport(t, setID.String(), other, decisionPoint, registry.ExportContract{})

	checkpoint := mustCatalogCheckpoint(t, decisionPoint, []registry.PolicySetImport{wrongTarget}, nil)
	if _, err := registry.NewDomainPlanDefinition(target, []registry.CheckpointDefinition{checkpoint}); !errors.Is(err, registry.ErrInvalidDomainPlan) {
		t.Fatalf("NewDomainPlanDefinition() error = %v, want exact target rejection", err)
	}
}

func TestCompilerRejectsSameNamespaceStandardAuthImport(t *testing.T) {
	contribution, err := registry.NewBuiltinTargetContributor(catalogAcceptanceCapability{}).Contribute(context.Background())
	if err != nil {
		t.Fatalf("Contribute() error = %v", err)
	}

	target := mustCatalogTarget(t, "authn", "authenticate")
	imported := mustCatalogImport(t, registry.BuiltinStandardAuthPolicySet, target, "pre_auth", registry.ExportContract{})
	sets := make(map[string]registry.PolicySetDefinition)

	for _, set := range contribution.PolicySets() {
		sets[set.ID().String()] = set
	}

	if err = validatePolicySetImport("authn", imported, sets, false); !errors.Is(err, ErrStandardAuthCrossNamespaceImport) {
		t.Fatalf("validatePolicySetImport(authn standard_auth) error = %v, want non-importable rejection", err)
	}
}

func TestCompilerRejectsForgedBuiltinPathForConfiguredStandardAuthRoot(t *testing.T) {
	compiler, activation := builtinAuthnCatalog(t, "")
	target := mustCatalogTarget(t, "authn", "authenticate")

	binding, err := registry.NewPolicySetImport(
		"builtin.authn.forged.pre_auth",
		registry.BuiltinStandardAuthPolicySet,
		target,
		"pre_auth",
		registry.ExportContract{},
	)
	if err != nil {
		t.Fatalf("NewPolicySetImport() error = %v", err)
	}

	activation, err = activation.WithPolicySetBindings([]registry.PolicySetImport{binding})
	if err != nil {
		t.Fatalf("TargetActivation.WithPolicySetBindings() error = %v", err)
	}

	_, err = compiler.Compile(context.Background(), []registry.TargetActivation{activation})
	if !errors.Is(err, ErrStandardAuthCrossNamespaceImport) {
		t.Fatalf("Compile() error = %v, want forged builtin-root rejection", err)
	}
}

func TestPolicyRulesRejectReservedRuntimeDecisions(t *testing.T) {
	for _, result := range []decision.Effect{decision.EffectNotApplicable, decision.EffectIndeterminate} {
		_, err := registry.NewPolicyRule(registry.PolicyRuleInput{
			Name:       "reserved_result",
			Checkpoint: decisionPoint,
			Expression: mustCatalogExpression(t, "", registry.ExpressionOperatorAlways),
			Decision:   result,
		})
		if !errors.Is(err, registry.ErrInvalidPolicySetDefinition) {
			t.Fatalf("NewPolicyRule(%q) error = %v, want reserved-result rejection", result, err)
		}
	}
}

func TestCatalogRejectsTypedNilPostActionCapability(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)

	var capability *catalogPointerAcceptanceCapability

	fixture.providers = []registry.ProviderDefinition{mustCatalogProvider(t, registry.ProviderDefinitionInput{
		PostActionAcceptance: capability,
		ID:                   "common/post",
		Targets:              []decision.Target{fixture.target},
		Executions:           []registry.ExecutionClass{registry.ExecutionHostPostAction},
	})}
	fixture.effects = []registry.EffectDefinition{mustCatalogEffect(t, registry.EffectDefinitionInput{
		ID:        testEffectID,
		Kind:      registry.EffectKindObligation,
		Execution: registry.ExecutionHostPostAction,
		Targets:   []decision.Target{fixture.target},
		Provider:  "common/post",
	})}

	if _, err := fixture.tryCompile(); !errors.Is(err, ErrMissingPostActionAcceptanceCapability) {
		t.Fatalf("Compile() typed-nil capability error = %v, want missing capability", err)
	}
}

func TestEffectDescriptorsRejectUnboundedParameterCatalogs(t *testing.T) {
	parameters := make([]registry.ParameterSchema, 0, 65)

	for index := range 65 {
		parameter, err := registry.NewParameterSchema(registry.ParameterSchemaInput{
			Name: fmt.Sprintf("value_%d", index),
			Kind: decision.ValueKindBoolean,
		})
		if err != nil {
			t.Fatalf("NewParameterSchema(%d) error = %v", index, err)
		}

		parameters = append(parameters, parameter)
	}

	_, err := registry.NewEffectDefinition(registry.EffectDefinitionInput{
		ID:         "common/oversized",
		Kind:       registry.EffectKindObligation,
		Execution:  registry.ExecutionReturnOnly,
		Targets:    []decision.Target{mustCatalogTarget(t, "dkim2", "sign")},
		Parameters: parameters,
	})
	if !errors.Is(err, registry.ErrInvalidEffectDefinition) {
		t.Fatalf("NewEffectDefinition(65 parameters) error = %v, want bounded rejection", err)
	}
}

func TestEffectDescriptorsRejectAggregateParameterSizeOverflow(t *testing.T) {
	target := mustCatalogTarget(t, "dkim2", "sign")
	parameters := make([]registry.ParameterSchema, 0, 2)
	values := make(map[string]decision.Value, 2)

	for _, name := range []string{"first", "second"} {
		parameter, err := registry.NewParameterSchema(registry.ParameterSchemaInput{
			Name: name, Kind: decision.ValueKindString, MaxLength: 40 * 1024, Required: true,
		})
		if err != nil {
			t.Fatalf("NewParameterSchema(%s) error = %v", name, err)
		}

		parameters = append(parameters, parameter)
		values[name] = mustCatalogStringValue(t, strings.Repeat("x", 40*1024))
	}

	effect := mustCatalogEffect(t, registry.EffectDefinitionInput{
		ID:         "dkim2/large",
		Kind:       registry.EffectKindObligation,
		Execution:  registry.ExecutionReturnOnly,
		Targets:    []decision.Target{target},
		Parameters: parameters,
	})

	use, err := registry.NewEffectUse(effect.ID(), values)
	if err != nil {
		t.Fatalf("NewEffectUse() error = %v", err)
	}

	if err = effect.ValidateUse(use); err == nil {
		t.Fatal("ValidateUse() accepted aggregate parameters above the catalog byte bound")
	}
}

func TestParameterSchemasRejectUnboundedAllowedStringEnums(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		maximum int
	}{
		{
			name:    "member count",
			values:  makeCatalogEnumValues(65, 16),
			maximum: 16,
		},
		{
			name:    "aggregate bytes",
			values:  makeCatalogEnumValues(33, 2048),
			maximum: 2048,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := registry.NewParameterSchema(registry.ParameterSchemaInput{
				Name: "action", Kind: decision.ValueKindString, MaxLength: test.maximum,
				AllowedStrings: test.values,
			})
			if !errors.Is(err, registry.ErrInvalidEffectDefinition) {
				t.Fatalf("NewParameterSchema() error = %v, want bounded enum rejection", err)
			}
		})
	}
}

// makeCatalogEnumValues returns unique strings with one exact byte length.
func makeCatalogEnumValues(count int, length int) []string {
	values := make([]string, 0, count)

	for index := range count {
		prefix := fmt.Sprintf("%04d", index)
		values = append(values, prefix+strings.Repeat("x", length-len(prefix)))
	}

	return values
}

func TestEffectUseValidationSelectsDeterministicFirstUnknownParameter(t *testing.T) {
	effect := mustCatalogEffect(t, registry.EffectDefinitionInput{
		ID:        "dkim2/notice",
		Kind:      registry.EffectKindObligation,
		Execution: registry.ExecutionReturnOnly,
		Targets:   []decision.Target{mustCatalogTarget(t, "dkim2", "sign")},
	})

	use, err := registry.NewEffectUse(effect.ID(), map[string]decision.Value{
		"z_unknown": mustCatalogStringValue(t, "z"),
		"a_unknown": mustCatalogStringValue(t, "a"),
	})
	if err != nil {
		t.Fatalf("NewEffectUse() error = %v", err)
	}

	for range 100 {
		err = effect.ValidateUse(use)
		if err == nil || !strings.Contains(err.Error(), "a_unknown") {
			t.Fatalf("ValidateUse() error = %v, want deterministic a_unknown", err)
		}
	}
}

func TestEffectUseValidationRejectsOversizedArgumentMaps(t *testing.T) {
	effect := mustCatalogEffect(t, registry.EffectDefinitionInput{
		ID:        "dkim2/notice",
		Kind:      registry.EffectKindObligation,
		Execution: registry.ExecutionReturnOnly,
		Targets:   []decision.Target{mustCatalogTarget(t, "dkim2", "sign")},
	})
	values := make(map[string]decision.Value, 65)

	for index := range 65 {
		values[fmt.Sprintf("value_%d", index)] = mustCatalogStringValue(t, "value")
	}

	use, err := registry.NewEffectUse(effect.ID(), values)
	if err != nil {
		t.Fatalf("NewEffectUse() error = %v", err)
	}

	if err = effect.ValidateUse(use); err == nil {
		t.Fatal("ValidateUse() accepted more than 64 parameter values")
	}
}

func TestPolicySetRejectsUnconstructedRule(t *testing.T) {
	_, err := registry.NewPolicySetDefinition(registry.PolicySetDefinitionInput{
		ID:    mustCatalogSetID(t, "dkim2/invalid"),
		Rules: []registry.PolicyRule{{}},
	})
	if !errors.Is(err, registry.ErrInvalidPolicySetDefinition) {
		t.Fatalf("NewPolicySetDefinition(zero rule) error = %v, want constructor-bound rejection", err)
	}
}

func TestCatalogValidationSelectsDeterministicFirstInvalidDescriptor(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)
	fixture.effects = []registry.EffectDefinition{
		mustCatalogEffect(t, registry.EffectDefinitionInput{
			ID:        "common/z_invalid",
			Kind:      registry.EffectKindObligation,
			Execution: registry.ExecutionHostSync,
			Targets:   []decision.Target{fixture.target},
			Provider:  "common/z_missing",
		}),
		mustCatalogEffect(t, registry.EffectDefinitionInput{
			ID:        "common/a_invalid",
			Kind:      registry.EffectKindObligation,
			Execution: registry.ExecutionHostSync,
			Targets:   []decision.Target{fixture.target},
			Provider:  "common/a_missing",
		}),
	}

	for range 128 {
		_, err := fixture.tryCompile()
		if err == nil || !strings.Contains(err.Error(), "common/a_invalid") {
			t.Fatalf("Compile() deterministic error = %v, want lexically first invalid effect", err)
		}
	}
}

type catalogPointerAcceptanceCapability struct{}

// Accept implements the host-internal capability for typed-nil validation.
func (*catalogPointerAcceptanceCapability) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

// mustCatalogStringValue constructs one strict string for expression and effect tests.
func mustCatalogStringValue(t *testing.T, value string) decision.Value {
	t.Helper()

	strict, err := decision.NewValue(decision.ValueInput{String: &value})
	if err != nil {
		t.Fatalf("NewValue(%q) error = %v", value, err)
	}

	return strict
}

// mustCatalogBooleanValue constructs one strict boolean expression operand.
func mustCatalogBooleanValue(t *testing.T, value bool) decision.Value {
	t.Helper()

	strict, err := decision.NewValue(decision.ValueInput{Boolean: &value})
	if err != nil {
		t.Fatalf("NewValue(boolean) error = %v", err)
	}

	return strict
}

// mustCatalogIntegerValue constructs one strict integer expression operand.
func mustCatalogIntegerValue(t *testing.T, value int64) decision.Value {
	t.Helper()

	strict, err := decision.NewValue(decision.ValueInput{Integer: &value})
	if err != nil {
		t.Fatalf("NewValue(integer) error = %v", err)
	}

	return strict
}

// mustCatalogTimestampValue constructs one strict timestamp expression operand.
func mustCatalogTimestampValue(t *testing.T) decision.Value {
	t.Helper()

	value := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)

	strict, err := decision.NewValue(decision.ValueInput{Timestamp: &value})
	if err != nil {
		t.Fatalf("NewValue(timestamp) error = %v", err)
	}

	return strict
}

// mustCatalogExpression constructs one immutable executable source expression.
func mustCatalogExpression(
	t *testing.T,
	factID string,
	operator registry.ExpressionOperator,
	values ...decision.Value,
) registry.PolicyExpression {
	t.Helper()

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		FactID:   factID,
		Operator: operator,
		Values:   values,
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	return expression
}

// mustCatalogExpressionRule constructs one rule with an executable source expression.
func mustCatalogExpressionRule(
	t *testing.T,
	name string,
	checkpoint string,
	expression registry.PolicyExpression,
	result decision.Effect,
) registry.PolicyRule {
	t.Helper()

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name:       name,
		Checkpoint: checkpoint,
		Expression: expression,
		Effects:    []registry.EffectUse{mustCatalogEffectUse(t, testEffectID)},
		Decision:   result,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	return rule
}

// mustCatalogRuleAtCheckpoint reuses the focused fixture rule shape at one checkpoint.
func mustCatalogRuleAtCheckpoint(
	t *testing.T,
	name string,
	checkpoint string,
	fact registry.FactContract,
) registry.PolicyRule {
	t.Helper()

	return mustCatalogExpressionRule(
		t,
		name,
		checkpoint,
		mustCatalogExpression(t, fact.ID(), registry.ExpressionOperatorEqual, mustCatalogStringValue(t, "example.org")),
		decision.EffectDeny,
	)
}

// mustCatalogCheckpointContract constructs one exact multi-checkpoint capability.
func mustCatalogCheckpointContract(
	t *testing.T,
	checkpoints []string,
	facts []registry.FactContract,
	decisions []decision.Effect,
	effects []string,
) registry.ExportContract {
	t.Helper()

	contract, err := registry.NewExportContractForCheckpoints(checkpoints, facts, decisions, effects)
	if err != nil {
		t.Fatalf("NewExportContractForCheckpoints() error = %v", err)
	}

	return contract
}

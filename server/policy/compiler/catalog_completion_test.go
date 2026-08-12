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
	"reflect"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/evaluation"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	testSharedSetID = "common/shared"
	testRootSetID   = "dkim2/root"
	testEffectID    = "common/notice"
	decisionPoint   = "final_decision"
)

type catalogAcceptanceCapability struct{}

// Accept proves that the test binding implements the host-internal capability.
func (catalogAcceptanceCapability) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

func TestPolicySetIdentitiesAreQualifiedAndPrivateByDefault(t *testing.T) {
	identity, err := registry.NewPolicySetID("dkim2", "root")
	if err != nil {
		t.Fatalf("NewPolicySetID() error = %v", err)
	}

	set, err := registry.NewPolicySetDefinition(registry.PolicySetDefinitionInput{ID: identity})
	if err != nil {
		t.Fatalf("NewPolicySetDefinition() error = %v", err)
	}

	if identity.String() != testRootSetID {
		t.Fatalf("policy set identity = %q, want %q", identity.String(), testRootSetID)
	}

	if set.Visibility() != registry.PolicySetVisibilityPrivate {
		t.Fatalf("default visibility = %q, want private", set.Visibility())
	}

	for _, value := range []string{"common/*", "common", "common/", "standard_auth"} {
		if _, err := registry.ParsePolicySetID("policy.namespaces.common.sets", value); !errors.Is(err, registry.ErrInvalidPolicySetIdentity) {
			t.Fatalf("ParsePolicySetID(%q) error = %v, want exact qualified identity rejection", value, err)
		}
	}
}

func TestCatalogCompilesExactExportedImportAndOnlyReferencedSets(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)
	catalog := fixture.compile(t)

	compiled, ok := catalog.Lookup(fixture.target)
	if !ok {
		t.Fatal("compiled target missing")
	}

	checkpoint, ok := compiled.DomainPlan().Checkpoint(decisionPoint)
	if !ok {
		t.Fatal("decision checkpoint missing")
	}

	if got := checkpoint.PolicySetIDs(); !reflect.DeepEqual(got, []string{testRootSetID, testSharedSetID}) {
		t.Fatalf("checkpoint policy sets = %v, want exact root/import order", got)
	}

	if checkpoint.ContainsPolicySet("dkim2/unreferenced") {
		t.Fatal("unreferenced namespace set became executable")
	}

	if compiled.NoMatch() != registry.NoMatchDeny {
		t.Fatalf("NoMatch() = %q, want deny", compiled.NoMatch())
	}
}

func TestCatalogRejectsPrivateIncompleteAndIncompatibleCrossNamespaceImports(t *testing.T) {
	tests := append(policySetImportBasicCases(t), policySetImportCompatibilityCases(t)...)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCatalogCompletionFixture(t, test.visibility, false)
			if test.mutate != nil {
				test.mutate(fixture)
			}

			_, err := fixture.tryCompile()
			if !errors.Is(err, test.want) {
				t.Fatalf("Compile() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCatalogRejectsCyclicImplicitTargetAndCheckpointImports(t *testing.T) {
	tests := append(policySetBindingGraphCases(t), policyRuleBindingCases(t)...)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)
			test.mutate(fixture)

			_, err := fixture.tryCompile()
			if !errors.Is(err, test.want) {
				t.Fatalf("Compile() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCatalogValidatesEffectProvidersClassesAndParametersBeforeActivation(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)
	fixture.effects = []registry.EffectDefinition{mustCatalogEffect(t, registry.EffectDefinitionInput{
		ID:        testEffectID,
		Kind:      registry.EffectKindObligation,
		Execution: registry.ExecutionHostSync,
		Targets:   []decision.Target{fixture.target},
		Provider:  "common/missing",
	})}

	if _, err := fixture.tryCompile(); !errors.Is(err, ErrUnknownEffectProvider) {
		t.Fatalf("Compile() missing provider error = %v, want unknown provider", err)
	}

	invalidCombinations := []registry.EffectDefinitionInput{
		{
			ID:        "common/return_only_bound",
			Kind:      registry.EffectKindObligation,
			Execution: registry.ExecutionReturnOnly,
			Targets:   []decision.Target{fixture.target},
			Provider:  "common/sync",
		},
		{
			ID:        "common/host_unbound",
			Kind:      registry.EffectKindObligation,
			Execution: registry.ExecutionHostSync,
			Targets:   []decision.Target{fixture.target},
		},
		{
			ID:        "common/advice_host",
			Kind:      registry.EffectKindAdvice,
			Execution: registry.ExecutionHostSync,
			Targets:   []decision.Target{fixture.target},
			Provider:  "common/sync",
		},
		{
			ID:      "common/missing_execution",
			Kind:    registry.EffectKindObligation,
			Targets: []decision.Target{fixture.target},
		},
		{
			ID:        "common/invalid_execution",
			Kind:      registry.EffectKindObligation,
			Execution: registry.ExecutionClass("external_async"),
			Targets:   []decision.Target{fixture.target},
		},
	}

	for _, input := range invalidCombinations {
		if _, err := registry.NewEffectDefinition(input); !errors.Is(err, registry.ErrInvalidEffectDefinition) {
			t.Fatalf("NewEffectDefinition(%s) error = %v, want invalid combination", input.ID, err)
		}
	}
}

func TestCatalogRequiresPostActionAcceptanceCapability(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)
	fixture.providers = []registry.ProviderDefinition{mustCatalogProvider(t, registry.ProviderDefinitionInput{
		ID:         "common/post",
		Targets:    []decision.Target{fixture.target},
		Executions: []registry.ExecutionClass{registry.ExecutionHostPostAction},
	})}
	fixture.effects = []registry.EffectDefinition{mustCatalogEffect(t, registry.EffectDefinitionInput{
		ID:        testEffectID,
		Kind:      registry.EffectKindObligation,
		Execution: registry.ExecutionHostPostAction,
		Targets:   []decision.Target{fixture.target},
		Provider:  "common/post",
	})}

	if _, err := fixture.tryCompile(); !errors.Is(err, ErrMissingPostActionAcceptanceCapability) {
		t.Fatalf("Compile() error = %v, want missing acceptance capability", err)
	}

	fixture.providers = []registry.ProviderDefinition{mustCatalogProvider(t, registry.ProviderDefinitionInput{
		ID:                   "common/post",
		Targets:              []decision.Target{fixture.target},
		Executions:           []registry.ExecutionClass{registry.ExecutionHostPostAction},
		PostActionAcceptance: catalogAcceptanceCapability{},
	})}

	if _, err := fixture.tryCompile(); err != nil {
		t.Fatalf("Compile() with acceptance capability error = %v", err)
	}
}

func TestCatalogValidatesEffectTargetAndTypedParameterSchema(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)
	otherTarget := mustCatalogTarget(t, "dkim2", "verify")
	fixture.effects = []registry.EffectDefinition{mustCatalogEffect(t, registry.EffectDefinitionInput{
		ID:        testEffectID,
		Kind:      registry.EffectKindObligation,
		Execution: registry.ExecutionReturnOnly,
		Targets:   []decision.Target{otherTarget},
	})}

	if _, err := fixture.tryCompile(); !errors.Is(err, ErrPolicyEffectTargetMismatch) {
		t.Fatalf("Compile() effect target error = %v, want target mismatch", err)
	}

	parameter, err := registry.NewParameterSchema(registry.ParameterSchemaInput{
		Name:      "reason",
		Kind:      decision.ValueKindString,
		MaxLength: 64,
		Required:  true,
	})
	if err != nil {
		t.Fatalf("NewParameterSchema() error = %v", err)
	}

	fixture.effects = []registry.EffectDefinition{mustCatalogEffect(t, registry.EffectDefinitionInput{
		ID:         testEffectID,
		Kind:       registry.EffectKindObligation,
		Execution:  registry.ExecutionReturnOnly,
		Targets:    []decision.Target{fixture.target},
		Parameters: []registry.ParameterSchema{parameter},
	})}

	if _, err := fixture.tryCompile(); !errors.Is(err, ErrPolicyEffectParameterMismatch) {
		t.Fatalf("Compile() effect parameter error = %v, want typed parameter mismatch", err)
	}
}

func TestEffectDescriptorsExposeNoOptionalAcceptanceOrRetrySurface(t *testing.T) {
	forbidden := []string{"required", "besteffort", "best_effort", "retry", "idempot", "replay", "dedup"}
	types := []reflect.Type{
		reflect.TypeOf(registry.EffectDefinitionInput{}),
		reflect.TypeOf(registry.EffectDefinition{}),
		reflect.TypeOf(registry.ProviderDefinitionInput{}),
		reflect.TypeOf(registry.ProviderDefinition{}),
	}

	for _, descriptorType := range types {
		for index := range descriptorType.NumField() {
			name := strings.ToLower(descriptorType.Field(index).Name)
			for _, fragment := range forbidden {
				if strings.Contains(name, fragment) {
					t.Fatalf("%s exposes forbidden field %s", descriptorType, descriptorType.Field(index).Name)
				}
			}
		}
	}
}

func TestCatalogRejectsInvalidAndDuplicateTargetDiagnosticAliases(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)

	if _, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID:           "common/provider",
		Targets:      []decision.Target{fixture.target},
		Executions:   []registry.ExecutionClass{registry.ExecutionHostSync},
		DiagnosticID: "internal/path",
	}); !errors.Is(err, registry.ErrInvalidDiagnosticPublicID) {
		t.Fatalf("NewProviderDefinition(path alias) error = %v, want invalid diagnostic id", err)
	}

	if _, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID:           "common/provider",
		Targets:      []decision.Target{fixture.target},
		Executions:   []registry.ExecutionClass{registry.ExecutionHostSync},
		DiagnosticID: strings.Repeat("a", 65),
	}); !errors.Is(err, registry.ErrInvalidDiagnosticPublicID) {
		t.Fatalf("NewProviderDefinition(overlong alias) error = %v, want bounded diagnostic id", err)
	}

	fixture.sharedSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
		ID:             mustCatalogSetID(t, testSharedSetID),
		Visibility:     registry.PolicySetVisibilityExported,
		ExportContract: &fixture.contract,
		Rules:          fixture.sharedSet.Rules(),
		DiagnosticID:   "shared_component",
	})
	fixture.effects = []registry.EffectDefinition{mustCatalogEffect(t, registry.EffectDefinitionInput{
		ID:           testEffectID,
		Kind:         registry.EffectKindObligation,
		Execution:    registry.ExecutionReturnOnly,
		Targets:      []decision.Target{fixture.target},
		DiagnosticID: "shared_component",
	})}

	if _, err := fixture.tryCompile(); !errors.Is(err, ErrDuplicateDiagnosticPublicID) {
		t.Fatalf("Compile() duplicate alias error = %v, want duplicate diagnostic id", err)
	}
}

func TestCatalogRequiresExplicitGenericNoMatchAndRejectsAuthnNoMatch(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)
	fixture.activation = mustCatalogActivation(t, "policy.targets[0]", "dkim2", "sign", "dkim2/sign/v1", "", "")

	if _, err := fixture.tryCompile(); !errors.Is(err, ErrMissingNoMatchBehavior) {
		t.Fatalf("Compile() missing no_match error = %v, want missing behavior", err)
	}

	fixture.activation = mustCatalogActivation(t, "policy.targets[0]", "dkim2", "sign", "dkim2/sign/v1", "", "permit")
	if _, err := fixture.tryCompile(); !errors.Is(err, ErrInvalidNoMatchBehavior) {
		t.Fatalf("Compile() permit no_match error = %v, want invalid behavior", err)
	}

	compiler, activation := builtinAuthnCatalog(t, "deny")
	if _, err := compiler.Compile(context.Background(), []registry.TargetActivation{activation}); !errors.Is(err, ErrAuthnNoMatchBehavior) {
		t.Fatalf("Compile() authn no_match error = %v, want authn rejection", err)
	}
}

func TestCatalogAcceptsGenericNotApplicableNoMatch(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)
	fixture.activation = mustCatalogActivation(
		t,
		"policy.targets[0]",
		"dkim2",
		"sign",
		"dkim2/sign/v1",
		"",
		"not_applicable",
	)

	catalog := fixture.compile(t)
	compiled, exists := catalog.Lookup(fixture.target)

	if !exists || compiled.NoMatch() != registry.NoMatchNotApplicable {
		t.Fatalf("compiled no_match = %q, want not_applicable", compiled.NoMatch())
	}
}

func TestCatalogRequiresDefaultPolicySetToUseAnExactCheckpointBinding(t *testing.T) {
	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)
	fixture.activation = mustCatalogActivation(t, "policy.targets[0]", "dkim2", "sign", "dkim2/sign/v1", "dkim2/unreferenced", "deny")

	if _, err := fixture.tryCompile(); !errors.Is(err, ErrDefaultPolicySetUnbound) {
		t.Fatalf("Compile() unbound default error = %v, want exact checkpoint binding", err)
	}

	fixture.activation = mustCatalogActivation(t, "policy.targets[0]", "dkim2", "sign", "dkim2/sign/v1", testSharedSetID, "deny")
	if _, err := fixture.tryCompile(); !errors.Is(err, ErrDefaultPolicySetNamespaceMismatch) {
		t.Fatalf("Compile() cross-namespace default error = %v, want explicit import boundary", err)
	}
}

func TestStandardAuthIsAuthnOnlyPrivateAndFinalDefaultDeny(t *testing.T) {
	compiler, activation := builtinAuthnCatalog(t, "")

	catalog, err := compiler.Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	target := mustCatalogTarget(t, "authn", "authenticate")

	compiled, ok := catalog.Lookup(target)
	if !ok {
		t.Fatal("builtin authn target missing")
	}

	set, ok := catalog.LookupPolicySet(mustCatalogSetID(t, registry.BuiltinStandardAuthPolicySet))
	if !ok {
		t.Fatal("builtin standard_auth set missing")
	}

	assertBuiltinStandardAuthDescriptor(t, catalog, compiled, set)

	standardResult := evaluation.EvaluateStandardAuth(report.NewDecisionReport())
	assertExistingStandardAuthDefaultDeny(t, standardResult)
}

func TestStandardAuthCannotBeExportedCrossImportedOrAssignedOutsideAuthn(t *testing.T) {
	identity := mustCatalogSetID(t, registry.BuiltinStandardAuthPolicySet)
	if _, err := registry.NewPolicySetDefinition(registry.PolicySetDefinitionInput{
		ID:         identity,
		Visibility: registry.PolicySetVisibilityExported,
	}); !errors.Is(err, registry.ErrBuiltinPolicySetImmutable) {
		t.Fatalf("export standard_auth error = %v, want immutable builtin", err)
	}

	fixture := newCatalogCompletionFixture(t, registry.PolicySetVisibilityExported, false)

	fixture.activation = mustCatalogActivation(t, "policy.targets[0]", "dkim2", "sign", "dkim2/sign/v1", registry.BuiltinStandardAuthPolicySet, "deny")
	if _, err := fixture.tryCompile(); !errors.Is(err, ErrStandardAuthTargetMismatch) {
		t.Fatalf("Compile() standard_auth non-authn error = %v, want target mismatch", err)
	}

	fixture.activation = mustCatalogActivation(t, "policy.targets[0]", "dkim2", "sign", "dkim2/sign/v1", "", "deny")
	fixture.rootSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
		ID:      testRootSetIDValue(t),
		Imports: []registry.PolicySetImport{mustCatalogImport(t, registry.BuiltinStandardAuthPolicySet, fixture.target, decisionPoint, fixture.contract)},
	})
	fixture.contributors = append(fixture.contributors, registry.NewBuiltinTargetContributor(catalogAcceptanceCapability{}))

	if _, err := fixture.tryCompile(); !errors.Is(err, ErrStandardAuthCrossNamespaceImport) {
		t.Fatalf("Compile() standard_auth import error = %v, want cross-import rejection", err)
	}
}

type policySetImportCase struct {
	name       string
	visibility registry.PolicySetVisibility
	mutate     func(*catalogCompletionFixture)
	want       error
}

// policySetImportBasicCases returns privacy and completeness contract cases.
func policySetImportBasicCases(t *testing.T) []policySetImportCase {
	t.Helper()

	return []policySetImportCase{
		{
			name:       "private",
			visibility: registry.PolicySetVisibilityPrivate,
			want:       ErrPrivatePolicySetImport,
		},
		{
			name:       "incomplete contract",
			visibility: registry.PolicySetVisibilityExported,
			mutate: func(fixture *catalogCompletionFixture) {
				fixture.rootSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
					ID:      testRootSetIDValue(t),
					Imports: []registry.PolicySetImport{mustCatalogImport(t, testSharedSetID, fixture.target, decisionPoint, registry.ExportContract{})},
				})
			},
			want: ErrIncompletePolicySetImport,
		},
	}
}

// policySetImportCompatibilityCases returns fact, decision, and effect mismatch cases.
func policySetImportCompatibilityCases(t *testing.T) []policySetImportCase {
	t.Helper()

	return []policySetImportCase{
		policySetImportMismatchCase(t, "fact type mismatch", func(_ *catalogCompletionFixture) registry.ExportContract {
			wrongFact := mustCatalogFactContract(t, "input.domain", decision.ValueKindInteger)

			return mustCatalogContract(t, decisionPoint, []registry.FactContract{wrongFact}, []decision.Effect{decision.EffectDeny}, []string{testEffectID})
		}),
		policySetImportMismatchCase(t, "decision mismatch", func(fixture *catalogCompletionFixture) registry.ExportContract {
			return mustCatalogContract(t, decisionPoint, []registry.FactContract{fixture.factContract}, []decision.Effect{decision.EffectPermit}, []string{testEffectID})
		}),
		policySetImportMismatchCase(t, "effect mismatch", func(fixture *catalogCompletionFixture) registry.ExportContract {
			return mustCatalogContract(t, decisionPoint, []registry.FactContract{fixture.factContract}, []decision.Effect{decision.EffectDeny}, []string{"common/other"})
		}),
	}
}

// policySetImportMismatchCase constructs one exact cross-namespace mismatch case.
func policySetImportMismatchCase(
	t *testing.T,
	name string,
	contract func(*catalogCompletionFixture) registry.ExportContract,
) policySetImportCase {
	t.Helper()

	return policySetImportCase{
		name:       name,
		visibility: registry.PolicySetVisibilityExported,
		mutate: func(fixture *catalogCompletionFixture) {
			fixture.rootSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
				ID:      testRootSetIDValue(t),
				Imports: []registry.PolicySetImport{mustCatalogImport(t, testSharedSetID, fixture.target, decisionPoint, contract(fixture))},
			})
		},
		want: ErrIncompatiblePolicySetImport,
	}
}

type policySetBindingCase struct {
	name   string
	mutate func(*catalogCompletionFixture)
	want   error
}

// policySetBindingGraphCases returns cyclic and implicit cross-namespace cases.
func policySetBindingGraphCases(t *testing.T) []policySetBindingCase {
	t.Helper()

	return []policySetBindingCase{
		{name: "cycle", mutate: func(fixture *catalogCompletionFixture) {
			firstID := mustCatalogSetID(t, "dkim2/first")
			secondID := mustCatalogSetID(t, "dkim2/second")
			fixture.rootSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
				ID:      firstID,
				Imports: []registry.PolicySetImport{mustCatalogImport(t, secondID.String(), fixture.target, decisionPoint, registry.ExportContract{})},
			})
			fixture.extraSets = []registry.PolicySetDefinition{mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
				ID:      secondID,
				Imports: []registry.PolicySetImport{mustCatalogImport(t, firstID.String(), fixture.target, decisionPoint, registry.ExportContract{})},
			})}
			fixture.plan = mustCatalogPlan(t, fixture.target, []registry.CheckpointDefinition{
				mustCatalogCheckpoint(t, decisionPoint, []registry.PolicySetImport{mustCatalogImport(t, firstID.String(), fixture.target, decisionPoint, registry.ExportContract{})}, nil),
			})
		}, want: ErrPolicySetImportCycle},
		{name: "implicit cross namespace", mutate: func(fixture *catalogCompletionFixture) {
			fixture.plan = mustCatalogPlan(t, fixture.target, []registry.CheckpointDefinition{
				mustCatalogCheckpoint(t, decisionPoint, []registry.PolicySetImport{mustCatalogImport(t, testSharedSetID, fixture.target, decisionPoint, registry.ExportContract{})}, nil),
			})
		}, want: ErrIncompletePolicySetImport},
	}
}

// policyRuleBindingCases returns exact target, checkpoint, and fact cases.
func policyRuleBindingCases(t *testing.T) []policySetBindingCase {
	t.Helper()

	return []policySetBindingCase{
		{name: "expression fact mismatch", mutate: func(fixture *catalogCompletionFixture) {
			wrongFact := mustCatalogFactContract(t, "input.unknown", decision.ValueKindString)
			fixture.rootSet = mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
				ID: testRootSetIDValue(t), Rules: []registry.PolicyRule{mustCatalogRule(t, "unknown_fact", fixture.target, decisionPoint, wrongFact)},
			})
		}, want: ErrPolicyRuleFactMismatch},
	}
}

// assertBuiltinStandardAuthDescriptor verifies catalog isolation and fallback metadata.
func assertBuiltinStandardAuthDescriptor(
	t *testing.T,
	catalog *policyruntime.TargetCatalog,
	target policyruntime.CompiledTarget,
	set policyruntime.CompiledPolicySet,
) {
	t.Helper()

	if set.Visibility() != registry.PolicySetVisibilityPrivate || !set.IsBuiltinStandardAuth() || !set.HasFinalDefaultDeny() {
		t.Fatalf("standard_auth descriptor = visibility %q builtin %t final deny %t", set.Visibility(), set.IsBuiltinStandardAuth(), set.HasFinalDefaultDeny())
	}

	if target.DefaultPolicySet().String() != registry.BuiltinStandardAuthPolicySet || target.NoMatch() != registry.NoMatchUnset {
		t.Fatalf("authn defaults = set %q no_match %q", target.DefaultPolicySet().String(), target.NoMatch())
	}

	if catalog.AdmissionCount() != 0 {
		t.Fatalf("builtin activation granted %d client admissions", catalog.AdmissionCount())
	}
}

// assertExistingStandardAuthDefaultDeny verifies the established evaluator contract.
func assertExistingStandardAuthDefaultDeny(t *testing.T, result evaluation.Result) {
	t.Helper()

	if result.Final == nil || result.Final.PolicyName != "standard_default_deny" || result.Final.Effect != "deny" {
		t.Fatalf("existing standard_auth final result = %+v, want final default deny", result.Final)
	}
}

type catalogCompletionFixture struct {
	target       decision.Target
	factContract registry.FactContract
	contract     registry.ExportContract
	activation   registry.TargetActivation
	sharedSet    registry.PolicySetDefinition
	rootSet      registry.PolicySetDefinition
	extraSets    []registry.PolicySetDefinition
	plan         registry.DomainPlanDefinition
	providers    []registry.ProviderDefinition
	effects      []registry.EffectDefinition
	contributors []registry.Contributor
	baseTargets  []registry.TargetDefinition
	baseSchemas  []registry.SchemaDefinition
}

// newCatalogCompletionFixture constructs one complete generic target candidate.
func newCatalogCompletionFixture(t *testing.T, visibility registry.PolicySetVisibility, postAction bool) *catalogCompletionFixture {
	t.Helper()

	target := mustCatalogTarget(t, "dkim2", "sign")
	factContract := mustCatalogFactContract(t, "input.domain", decision.ValueKindString)
	contract := mustCatalogContract(t, decisionPoint, []registry.FactContract{factContract}, []decision.Effect{decision.EffectDeny}, []string{testEffectID})
	sharedRule := mustCatalogRule(t, "shared_deny", target, decisionPoint, factContract)

	sharedSetInput := registry.PolicySetDefinitionInput{
		ID:         mustCatalogSetID(t, testSharedSetID),
		Visibility: visibility,
		Rules:      []registry.PolicyRule{sharedRule},
	}
	if visibility == registry.PolicySetVisibilityExported {
		sharedSetInput.ExportContract = &contract
	}

	sharedSet := mustCatalogPolicySet(t, sharedSetInput)
	rootSet := mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{
		ID:      testRootSetIDValue(t),
		Imports: []registry.PolicySetImport{mustCatalogImport(t, testSharedSetID, target, decisionPoint, contract)},
	})
	unreferenced := mustCatalogPolicySet(t, registry.PolicySetDefinitionInput{ID: mustCatalogSetID(t, "dkim2/unreferenced")})
	plan := mustCatalogPlan(t, target, []registry.CheckpointDefinition{
		mustCatalogCheckpoint(t, decisionPoint, []registry.PolicySetImport{
			mustCatalogImport(t, testRootSetID, target, decisionPoint, registry.ExportContract{}),
		}, nil),
	})

	effect := mustCatalogEffect(t, registry.EffectDefinitionInput{
		ID:        testEffectID,
		Kind:      registry.EffectKindObligation,
		Execution: registry.ExecutionReturnOnly,
		Targets:   []decision.Target{target},
	})
	if postAction {
		effect = mustCatalogEffect(t, registry.EffectDefinitionInput{
			ID:        testEffectID,
			Kind:      registry.EffectKindObligation,
			Execution: registry.ExecutionHostPostAction,
			Targets:   []decision.Target{target},
			Provider:  "common/post",
		})
	}

	targetDefinition, schema := mustCatalogTargetAndSchema(t, target)
	activation := mustCatalogActivation(t, "policy.targets[0]", "dkim2", "sign", "dkim2/sign/v1", "", "deny")

	return &catalogCompletionFixture{
		target:       target,
		factContract: factContract,
		contract:     contract,
		activation:   activation,
		sharedSet:    sharedSet,
		rootSet:      rootSet,
		extraSets:    []registry.PolicySetDefinition{unreferenced},
		plan:         plan,
		effects:      []registry.EffectDefinition{effect},
		baseTargets:  []registry.TargetDefinition{targetDefinition},
		baseSchemas:  []registry.SchemaDefinition{schema},
	}
}

// tryCompile assembles and compiles the fixture without failing the caller test.
func (f *catalogCompletionFixture) tryCompile() (*policyruntime.TargetCatalog, error) {
	sets := append([]registry.PolicySetDefinition{f.sharedSet, f.rootSet}, f.extraSets...)

	ownership, err := registry.NewNamespaceOwnership("test.catalog", []string{"common", "dkim2"})
	if err != nil {
		return nil, err
	}

	contribution, err := registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
		Ownership:  ownership,
		Targets:    f.baseTargets,
		Schemas:    f.baseSchemas,
		PolicySets: sets,
		Plans:      []registry.DomainPlanDefinition{f.plan},
		Providers:  f.providers,
		Effects:    f.effects,
	})
	if err != nil {
		return nil, err
	}

	contributors := append([]registry.Contributor{testCatalogContributor{contribution: contribution}}, f.contributors...)

	return NewTargetCatalogCompiler(contributors...).Compile(context.Background(), []registry.TargetActivation{f.activation})
}

// compile assembles and compiles a fixture or fails the caller test.
func (f *catalogCompletionFixture) compile(t *testing.T) *policyruntime.TargetCatalog {
	t.Helper()

	catalog, err := f.tryCompile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	return catalog
}

// The remaining helpers keep constructor failures local to the focused fixture.
func mustCatalogTarget(t *testing.T, namespace string, action string) decision.Target {
	t.Helper()

	target, err := decision.NewTarget(namespace, action)
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return target
}

func mustCatalogSetID(t *testing.T, value string) registry.PolicySetID {
	t.Helper()

	id, err := registry.ParsePolicySetID("test.policy_set", value)
	if err != nil {
		t.Fatalf("ParsePolicySetID(%q) error = %v", value, err)
	}

	return id
}

func testRootSetIDValue(t *testing.T) registry.PolicySetID {
	return mustCatalogSetID(t, testRootSetID)
}

func mustCatalogFactContract(t *testing.T, id string, kind decision.ValueKind) registry.FactContract {
	t.Helper()

	contract, err := registry.NewFactContract(id, kind)
	if err != nil {
		t.Fatalf("NewFactContract() error = %v", err)
	}

	return contract
}

func mustCatalogContract(t *testing.T, checkpoint string, facts []registry.FactContract, decisions []decision.Effect, effects []string) registry.ExportContract {
	t.Helper()

	contract, err := registry.NewExportContract(checkpoint, facts, decisions, effects)
	if err != nil {
		t.Fatalf("NewExportContract() error = %v", err)
	}

	return contract
}

func mustCatalogRule(t *testing.T, name string, target decision.Target, checkpoint string, fact registry.FactContract) registry.PolicyRule {
	t.Helper()

	expression := mustCatalogFactExpression(t, fact)

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name:       name,
		Checkpoint: checkpoint,
		Actions:    []string{target.Action()},
		Expression: expression,
		Decision:   decision.EffectDeny,
		Effects:    []registry.EffectUse{mustCatalogEffectUse(t, testEffectID)},
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	return rule
}

// mustCatalogFactExpression constructs one typed equality expression for a fact contract.
func mustCatalogFactExpression(t *testing.T, fact registry.FactContract) registry.PolicyExpression {
	t.Helper()

	var input decision.ValueInput

	switch fact.Kind() {
	case decision.ValueKindString:
		value := "example.org"
		input.String = &value
	case decision.ValueKindInteger:
		value := int64(1)
		input.Integer = &value
	default:
		t.Fatalf("unsupported fixture fact kind %q", fact.Kind())
	}

	value, err := decision.NewValue(input)
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		FactID:   fact.ID(),
		Operator: registry.ExpressionOperatorEqual,
		Values:   []decision.Value{value},
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	return expression
}

func mustCatalogEffectUse(t *testing.T, id string) registry.EffectUse {
	t.Helper()

	use, err := registry.NewEffectUse(id, nil)
	if err != nil {
		t.Fatalf("NewEffectUse() error = %v", err)
	}

	return use
}

func mustCatalogPolicySet(t *testing.T, input registry.PolicySetDefinitionInput) registry.PolicySetDefinition {
	t.Helper()

	set, err := registry.NewPolicySetDefinition(input)
	if err != nil {
		t.Fatalf("NewPolicySetDefinition() error = %v", err)
	}

	return set
}

func mustCatalogImport(t *testing.T, setID string, target decision.Target, checkpoint string, contract registry.ExportContract) registry.PolicySetImport {
	t.Helper()

	imported, err := registry.NewPolicySetImport("test.import", setID, target, checkpoint, contract)
	if err != nil {
		t.Fatalf("NewPolicySetImport() error = %v", err)
	}

	return imported
}

func mustCatalogCheckpoint(t *testing.T, name string, sets []registry.PolicySetImport, providers []string) registry.CheckpointDefinition {
	t.Helper()

	checkpoint, err := registry.NewCheckpointDefinition(name, sets, providers)
	if err != nil {
		t.Fatalf("NewCheckpointDefinition() error = %v", err)
	}

	return checkpoint
}

func mustCatalogPlan(t *testing.T, target decision.Target, checkpoints []registry.CheckpointDefinition) registry.DomainPlanDefinition {
	t.Helper()

	plan, err := registry.NewDomainPlanDefinition(target, checkpoints)
	if err != nil {
		t.Fatalf("NewDomainPlanDefinition() error = %v", err)
	}

	return plan
}

func mustCatalogProvider(t *testing.T, input registry.ProviderDefinitionInput) registry.ProviderDefinition {
	t.Helper()

	provider, err := registry.NewProviderDefinition(input)
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	return provider
}

func mustCatalogEffect(t *testing.T, input registry.EffectDefinitionInput) registry.EffectDefinition {
	t.Helper()

	effect, err := registry.NewEffectDefinition(input)
	if err != nil {
		t.Fatalf("NewEffectDefinition() error = %v", err)
	}

	return effect
}

func mustCatalogTargetAndSchema(t *testing.T, target decision.Target) (registry.TargetDefinition, registry.SchemaDefinition) {
	t.Helper()

	fact, err := registry.NewFactSchema(registry.FactSchemaInput{
		ID:             "input.domain",
		AllowedSources: []decision.FactSource{decision.FactSourceCaller},
		Category:       decision.FactCategoryEnvironment,
		Kind:           decision.ValueKindString,
		MaxLength:      255,
	})
	if err != nil {
		t.Fatalf("NewFactSchema() error = %v", err)
	}

	identity, err := registry.NewSchemaIdentity(target.Namespace(), target.Action(), "v1")
	if err != nil {
		t.Fatalf("NewSchemaIdentity() error = %v", err)
	}

	schema, err := registry.NewSchemaDefinition(identity, []registry.FactSchema{fact})
	if err != nil {
		t.Fatalf("NewSchemaDefinition() error = %v", err)
	}

	targetDefinition, err := registry.NewTargetDefinition(target, []registry.SchemaIdentity{identity})
	if err != nil {
		t.Fatalf("NewTargetDefinition() error = %v", err)
	}

	return targetDefinition, schema
}

func mustCatalogActivation(t *testing.T, path string, namespace string, action string, schema string, defaultSet string, noMatch string) registry.TargetActivation {
	t.Helper()

	activation, err := registry.NewTargetActivation(path, namespace, action, schema)
	if err != nil {
		t.Fatalf("NewTargetActivation() error = %v", err)
	}

	activation, err = activation.WithPolicy(defaultSet, noMatch)
	if err != nil {
		t.Fatalf("TargetActivation.WithPolicy() error = %v", err)
	}

	return activation
}

func builtinAuthnCatalog(t *testing.T, noMatch string) (*TargetCatalogCompiler, registry.TargetActivation) {
	t.Helper()

	compiler := NewTargetCatalogCompiler(registry.NewBuiltinTargetContributor(catalogAcceptanceCapability{}))
	activation := mustCatalogActivation(
		t,
		"policy.targets.authn.authenticate",
		"authn",
		"authenticate",
		"authn/authenticate/v1",
		registry.BuiltinStandardAuthPolicySet,
		noMatch,
	)

	return compiler, activation
}

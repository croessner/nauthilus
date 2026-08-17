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

package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

type directRuntimeRecordCase struct {
	name   string
	record TargetCatalogRecord
	want   error
}

type runtimeNilAcceptance map[string]string

// Accept implements the internal capability for a typed-nil runtime boundary test.
func (runtimeNilAcceptance) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

func TestTargetCatalogRejectsIncompleteDirectRuntimeRecords(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)

	_, err := NewTargetCatalog([]TargetCatalogRecord{{
		Target:  target,
		Schema:  schema,
		NoMatch: registry.NoMatchDeny,
	}})
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(incomplete) error = %v, want fail-closed rejection", err)
	}
}

func TestTargetCatalogRejectsDuplicateCheckpointKeys(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	record := TargetCatalogRecord{
		Target:        target,
		Schema:        schema,
		AuthorityMode: registry.AuthorityModeEnforce,
		Checkpoints: []CheckpointRecord{
			{Name: "final_decision"},
			{Name: "final_decision"},
		},
		NoMatch: registry.NoMatchDeny,
	}

	_, err := NewTargetCatalog([]TargetCatalogRecord{record})
	if !errors.Is(err, ErrDuplicateCompiledCheckpoint) {
		t.Fatalf("NewTargetCatalog(duplicate checkpoint) error = %v, want collision rejection", err)
	}
}

func TestTargetCatalogRejectsDirectDescriptorCollisionsAndUnknownReferences(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	tests := completionDirectRuntimeRecordCases(t, target, schema)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewTargetCatalog([]TargetCatalogRecord{test.record})
			if !errors.Is(err, test.want) {
				t.Fatalf("NewTargetCatalog() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestTargetCatalogRejectsDirectRuleSchemaMismatch(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)

	setID, err := registry.NewPolicySetID("dkim2", "default")
	if err != nil {
		t.Fatalf("NewPolicySetID() error = %v", err)
	}

	value := "blocked"

	strict, err := decision.NewValue(decision.ValueInput{String: &value})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		FactID: "input.unknown", Operator: registry.ExpressionOperatorEqual, Values: []decision.Value{strict},
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	sourceRule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name: "deny_unknown", Checkpoint: "final_decision", Expression: expression, Decision: decision.EffectDeny,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	set, err := registry.NewPolicySetDefinition(registry.PolicySetDefinitionInput{ID: setID, Rules: []registry.PolicyRule{sourceRule}})
	if err != nil {
		t.Fatalf("NewPolicySetDefinition() error = %v", err)
	}

	record := TargetCatalogRecord{
		Target: target, Schema: schema,
		AuthorityMode: registry.AuthorityModeEnforce,
		Checkpoints: []CheckpointRecord{{
			Name: "final_decision", PolicySetIDs: []registry.PolicySetID{setID},
			Rules: []CompiledRuleRecord{{
				Target: target, PolicySetID: setID, Name: sourceRule.Name(), Checkpoint: sourceRule.Checkpoint(),
				Expression: sourceRule.Expression(), Decision: sourceRule.Decision(),
			}},
		}},
		DefaultPolicySet: setID,
		NoMatch:          registry.NoMatchDeny,
	}
	record.Checkpoints[0].PolicySetBindings = []registry.PolicySetImport{
		completionRuntimeImport(t, setID, target, "final_decision", registry.ExportContract{}),
	}
	record = completionRuntimeAuthorizeRecord(t, record)

	_, err = NewTargetCatalog([]TargetCatalogRecord{record}, []registry.PolicySetDefinition{set})
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(rule schema mismatch) error = %v, want fail-closed rejection", err)
	}
}

func TestTargetCatalogRejectsTypedNilDirectPostActionCapability(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)

	var capability runtimeNilAcceptance

	provider, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		PostActionAcceptance: capability,
		ID:                   "dkim2/post",
		Targets:              []decision.Target{target},
		Executions:           []registry.ExecutionClass{registry.ExecutionHostPostAction},
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	effect, err := registry.NewEffectDefinition(registry.EffectDefinitionInput{
		ID: "dkim2/post", Kind: registry.EffectKindObligation, Execution: registry.ExecutionHostPostAction,
		Targets: []decision.Target{target}, Provider: provider.ID(),
	})
	if err != nil {
		t.Fatalf("NewEffectDefinition() error = %v", err)
	}

	record := TargetCatalogRecord{
		Target: target, Schema: schema, Checkpoints: []CheckpointRecord{{Name: "final_decision"}},
		Providers: []registry.ProviderDefinition{provider}, Effects: []registry.EffectDefinition{effect},
		NoMatch: registry.NoMatchDeny, AuthorityMode: registry.AuthorityModeEnforce,
	}
	record = completionRuntimeAuthorizeRecord(t, record)

	_, err = NewTargetCatalog([]TargetCatalogRecord{record})
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(typed nil) error = %v, want missing capability rejection", err)
	}
}

func TestTargetCatalogRejectsDuplicateDirectDiagnosticAliases(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)

	setID, err := registry.NewPolicySetID("dkim2", "default")
	if err != nil {
		t.Fatalf("NewPolicySetID() error = %v", err)
	}

	set, err := registry.NewPolicySetDefinition(registry.PolicySetDefinitionInput{
		ID: setID, DiagnosticID: "shared_component",
	})
	if err != nil {
		t.Fatalf("NewPolicySetDefinition() error = %v", err)
	}

	provider, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID: "dkim2/provider", Targets: []decision.Target{target},
		Executions: []registry.ExecutionClass{registry.ExecutionHostSync}, DiagnosticID: "shared_component",
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	record := TargetCatalogRecord{
		Target: target, Schema: schema,
		AuthorityMode: registry.AuthorityModeEnforce,
		Checkpoints: []CheckpointRecord{{
			Name: "final_decision", PolicySetIDs: []registry.PolicySetID{setID}, ProviderIDs: []string{provider.ID()},
		}},
		Providers:        []registry.ProviderDefinition{provider},
		DefaultPolicySet: setID,
		NoMatch:          registry.NoMatchDeny,
	}
	record.Checkpoints[0].PolicySetBindings = []registry.PolicySetImport{
		completionRuntimeImport(t, setID, target, "final_decision", registry.ExportContract{}),
	}
	record = completionRuntimeAuthorizeRecord(t, record)

	_, err = NewTargetCatalog([]TargetCatalogRecord{record}, []registry.PolicySetDefinition{set})
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(duplicate diagnostic alias) error = %v, want fail-closed rejection", err)
	}
}

func TestTargetCatalogRejectsDirectForeignPrivatePolicySetBinding(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	privateID := completionRuntimeSetID(t, "common", "private")
	privateSet := completionRuntimePolicySet(t, registry.PolicySetDefinitionInput{ID: privateID})
	binding := completionRuntimeImport(t, privateID, target, "final_decision", registry.ExportContract{})

	record := TargetCatalogRecord{
		Target: target, Schema: schema, AuthorityMode: registry.AuthorityModeEnforce,
		Checkpoints: []CheckpointRecord{{
			Name: "final_decision", PolicySetBindings: []registry.PolicySetImport{binding},
			PolicySetIDs: []registry.PolicySetID{privateID},
		}},
		NoMatch: registry.NoMatchDeny,
	}
	record = completionRuntimeAuthorizeRecord(t, record)

	_, err := NewTargetCatalog([]TargetCatalogRecord{record}, []registry.PolicySetDefinition{privateSet})
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(foreign private set) error = %v, want authority rejection", err)
	}
}

func TestTargetCatalogRejectsDirectStandardAuthBindingOutsideAuthn(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)

	contribution, err := registry.NewBuiltinTargetContributor(runtimeNilAcceptance{"owner": "runtime"}).Contribute(context.Background())
	if err != nil {
		t.Fatalf("Contribute() error = %v", err)
	}

	standardID := completionRuntimeSetID(t, "authn", "standard_auth")
	binding := completionRuntimeImport(t, standardID, target, "final_decision", registry.ExportContract{})
	record := TargetCatalogRecord{
		Target: target, Schema: schema, AuthorityMode: registry.AuthorityModeEnforce,
		Checkpoints: []CheckpointRecord{{
			Name: "final_decision", PolicySetBindings: []registry.PolicySetImport{binding},
			PolicySetIDs: []registry.PolicySetID{standardID},
		}},
		NoMatch: registry.NoMatchDeny,
	}
	record = completionRuntimeAuthorizeRecord(t, record)

	_, err = NewTargetCatalog([]TargetCatalogRecord{record}, contribution.PolicySets())
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(non-authn standard_auth) error = %v, want isolation rejection", err)
	}
}

func TestTargetCatalogRejectsIncompleteOrDuplicateDirectRuleProjection(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	setID := completionRuntimeSetID(t, "dkim2", "configured")

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Operator: registry.ExpressionOperatorAlways})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	sourceRule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name: "deny", Checkpoint: "final_decision", Expression: expression, Decision: decision.EffectDeny,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	set := completionRuntimePolicySet(t, registry.PolicySetDefinitionInput{ID: setID, Rules: []registry.PolicyRule{sourceRule}})
	binding := completionRuntimeImport(t, setID, target, "final_decision", registry.ExportContract{})
	compiled := CompiledRuleRecord{
		Target: target, PolicySetID: setID, Name: sourceRule.Name(), Checkpoint: sourceRule.Checkpoint(),
		Expression: sourceRule.Expression(), Decision: sourceRule.Decision(),
	}
	base := TargetCatalogRecord{
		Target: target, Schema: schema, AuthorityMode: registry.AuthorityModeEnforce,
		Checkpoints: []CheckpointRecord{{
			Name: "final_decision", PolicySetBindings: []registry.PolicySetImport{binding},
			PolicySetIDs: []registry.PolicySetID{setID}, Rules: []CompiledRuleRecord{compiled},
		}},
		DefaultPolicySet: setID, NoMatch: registry.NoMatchDeny,
	}
	base = completionRuntimeAuthorizeRecord(t, base)

	tests := []struct {
		name  string
		rules []CompiledRuleRecord
	}{
		{name: "omitted", rules: nil},
		{name: "duplicated", rules: []CompiledRuleRecord{compiled, compiled}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := base
			record.Checkpoints = append([]CheckpointRecord(nil), base.Checkpoints...)
			record.Checkpoints[0].Rules = test.rules

			_, compileErr := NewTargetCatalog([]TargetCatalogRecord{record}, []registry.PolicySetDefinition{set})
			if !errors.Is(compileErr, ErrInvalidCompiledTarget) {
				t.Fatalf("NewTargetCatalog(%s rules) error = %v, want exact projection rejection", test.name, compileErr)
			}
		})
	}
}

func TestTargetCatalogRejectsPolicySetClosureMismatch(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	rootID := completionRuntimeSetID(t, "dkim2", "root")
	nestedID := completionRuntimeSetID(t, "dkim2", "nested")
	nestedBinding := completionRuntimeImport(t, nestedID, target, "final_decision", registry.ExportContract{})
	root := completionRuntimePolicySet(t, registry.PolicySetDefinitionInput{ID: rootID, Imports: []registry.PolicySetImport{nestedBinding}})
	nested := completionRuntimePolicySet(t, registry.PolicySetDefinitionInput{ID: nestedID})
	rootBinding := completionRuntimeImport(t, rootID, target, "final_decision", registry.ExportContract{})
	record := TargetCatalogRecord{
		Target: target, Schema: schema, AuthorityMode: registry.AuthorityModeEnforce,
		Checkpoints: []CheckpointRecord{{
			Name: "final_decision", PolicySetBindings: []registry.PolicySetImport{rootBinding},
			PolicySetIDs: []registry.PolicySetID{rootID},
		}},
		DefaultPolicySet: rootID, NoMatch: registry.NoMatchDeny,
	}
	record = completionRuntimeAuthorizeRecord(t, record)

	_, err := NewTargetCatalog(
		[]TargetCatalogRecord{record},
		[]registry.PolicySetDefinition{root, nested},
	)
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(incomplete closure) error = %v, want exact closure rejection", err)
	}
}

func TestTargetCatalogRejectsDirectIncompleteExportBinding(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	sharedID := completionRuntimeSetID(t, "common", "shared")

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Operator: registry.ExpressionOperatorAlways})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name: "deny", Checkpoint: "final_decision", Expression: expression, Decision: decision.EffectDeny,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	contract, err := registry.NewExportContractForCheckpoints(
		[]string{"final_decision"}, nil, []decision.Effect{decision.EffectDeny}, nil,
	)
	if err != nil {
		t.Fatalf("NewExportContractForCheckpoints() error = %v", err)
	}

	shared := completionRuntimePolicySet(t, registry.PolicySetDefinitionInput{
		ID: sharedID, Visibility: registry.PolicySetVisibilityExported, ExportContract: &contract,
		Rules: []registry.PolicyRule{rule},
	})
	binding := completionRuntimeImport(t, sharedID, target, "final_decision", registry.ExportContract{})
	record := completionRuntimeRuleRecord(t, target, schema, sharedID, binding, rule)

	_, err = NewTargetCatalog([]TargetCatalogRecord{record}, []registry.PolicySetDefinition{shared})
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(incomplete export binding) error = %v, want exact-contract rejection", err)
	}
}

func TestTargetCatalogRejectsDeclaredExportOutsideActualSourceCapability(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	sharedID := completionRuntimeSetID(t, "common", "shared")

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Operator: registry.ExpressionOperatorAlways})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name: "deny", Checkpoint: "final_decision", Expression: expression, Decision: decision.EffectDeny,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	wrongContract, err := registry.NewExportContractForCheckpoints(
		[]string{"other_checkpoint"}, nil, []decision.Effect{decision.EffectDeny}, nil,
	)
	if err != nil {
		t.Fatalf("NewExportContractForCheckpoints() error = %v", err)
	}

	shared := completionRuntimePolicySet(t, registry.PolicySetDefinitionInput{
		ID: sharedID, Visibility: registry.PolicySetVisibilityExported, ExportContract: &wrongContract,
		Rules: []registry.PolicyRule{rule},
	})

	_, err = NewTargetCatalog(nil, []registry.PolicySetDefinition{shared})
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(false export contract) error = %v, want actual-capability rejection", err)
	}

	_ = target
	_ = schema
}

func TestTargetCatalogRejectsDirectCyclicSourceImports(t *testing.T) {
	target, _ := completionRuntimeTargetAndSchema(t)
	leftID := completionRuntimeSetID(t, "dkim2", "left")
	rightID := completionRuntimeSetID(t, "dkim2", "right")
	leftImport := completionRuntimeImport(t, rightID, target, "final_decision", registry.ExportContract{})
	rightImport := completionRuntimeImport(t, leftID, target, "final_decision", registry.ExportContract{})
	left := completionRuntimePolicySet(t, registry.PolicySetDefinitionInput{ID: leftID, Imports: []registry.PolicySetImport{leftImport}})
	right := completionRuntimePolicySet(t, registry.PolicySetDefinitionInput{ID: rightID, Imports: []registry.PolicySetImport{rightImport}})

	_, err := NewTargetCatalog(nil, []registry.PolicySetDefinition{left, right})
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(cyclic source imports) error = %v, want cycle rejection", err)
	}
}

func TestTargetCatalogRejectsInactiveImportAtIncompatibleCheckpoint(t *testing.T) {
	target, _ := completionRuntimeTargetAndSchema(t)
	sharedID := completionRuntimeSetID(t, "common", "shared")
	rootID := completionRuntimeSetID(t, "dkim2", "root")

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Operator: registry.ExpressionOperatorAlways})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name: "deny", Checkpoint: "final_decision", Expression: expression, Decision: decision.EffectDeny,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	contract, err := registry.NewExportContractForCheckpoints(
		[]string{"final_decision"}, nil, []decision.Effect{decision.EffectDeny}, nil,
	)
	if err != nil {
		t.Fatalf("NewExportContractForCheckpoints() error = %v", err)
	}

	shared := completionRuntimePolicySet(t, registry.PolicySetDefinitionInput{
		ID: sharedID, Visibility: registry.PolicySetVisibilityExported,
		ExportContract: &contract, Rules: []registry.PolicyRule{rule},
	})
	wrongCheckpoint := completionRuntimeImport(t, sharedID, target, "preflight", contract)
	root := completionRuntimePolicySet(t, registry.PolicySetDefinitionInput{
		ID: rootID, Imports: []registry.PolicySetImport{wrongCheckpoint},
	})

	_, err = NewTargetCatalog(nil, []registry.PolicySetDefinition{root, shared})
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(incompatible inactive checkpoint) error = %v, want rejection", err)
	}
}

func TestTargetCatalogRejectsSameNamespaceStandardAuthImport(t *testing.T) {
	contribution, err := registry.NewBuiltinTargetContributor(runtimeNilAcceptance{"owner": "runtime"}).Contribute(context.Background())
	if err != nil {
		t.Fatalf("Contribute() error = %v", err)
	}

	target := completionContributionTarget(t, contribution, "authn/authenticate")
	standardID := completionRuntimeSetID(t, "authn", "standard_auth")
	configuredID := completionRuntimeSetID(t, "authn", "configured")
	imported := completionRuntimeImport(t, standardID, target, "pre_auth", registry.ExportContract{})
	configured := completionRuntimePolicySet(t, registry.PolicySetDefinitionInput{
		ID: configuredID, Imports: []registry.PolicySetImport{imported},
	})
	sets := append(contribution.PolicySets(), configured)

	_, err = NewTargetCatalog(nil, sets)
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(authn set imports standard_auth) error = %v, want non-importable rejection", err)
	}
}

func TestTargetCatalogRejectsForgedAuthnSourcePlan(t *testing.T) {
	contribution, err := registry.NewBuiltinTargetContributor(runtimeNilAcceptance{"owner": "runtime"}).Contribute(context.Background())
	if err != nil {
		t.Fatalf("Contribute() error = %v", err)
	}

	var (
		target decision.Target
		schema registry.SchemaDefinition
	)

	for _, candidate := range contribution.Targets() {
		if candidate.Target().String() == "authn/authenticate" {
			target = candidate.Target()
		}
	}

	for _, candidate := range contribution.Schemas() {
		if candidate.Identity().String() == "authn/authenticate/v1" {
			schema = candidate
		}
	}

	standardID := completionRuntimeSetID(t, "authn", "standard_auth")
	binding := completionRuntimeImport(t, standardID, target, "bogus", registry.ExportContract{})
	record := TargetCatalogRecord{
		Target: target, Schema: schema, AuthorityMode: registry.AuthorityModeEnforce,
		Checkpoints: []CheckpointRecord{{
			Name: "bogus", PolicySetBindings: []registry.PolicySetImport{binding}, PolicySetIDs: []registry.PolicySetID{standardID},
		}},
		DefaultPolicySet: standardID,
	}
	record = completionRuntimeAuthorizeRecord(t, record)

	_, err = NewTargetCatalog([]TargetCatalogRecord{record}, contribution.PolicySets())
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(forged authn plan) error = %v, want builtin-provenance rejection", err)
	}
}

func TestTargetCatalogRejectsIncompleteOrForgedBuiltinAuthDescriptors(t *testing.T) {
	record, policySets := completionBuiltinAuthRuntimeRecord(t)

	if _, err := NewTargetCatalog([]TargetCatalogRecord{record}, policySets); err != nil {
		t.Fatalf("NewTargetCatalog(authn baseline) error = %v", err)
	}

	t.Run("omitted effect", func(t *testing.T) {
		mutated := record
		mutated.Effects = append([]registry.EffectDefinition(nil), record.Effects[1:]...)

		_, err := NewTargetCatalog([]TargetCatalogRecord{mutated}, policySets)
		if !errors.Is(err, ErrInvalidCompiledTarget) {
			t.Fatalf("NewTargetCatalog(omitted builtin effect) error = %v, want fail-closed rejection", err)
		}
	})

	t.Run("forged effect", func(t *testing.T) {
		mutated := record
		mutated.Effects = append([]registry.EffectDefinition(nil), record.Effects...)
		original := mutated.Effects[0]

		forged, err := registry.NewEffectDefinition(registry.EffectDefinitionInput{
			ID: original.ID(), Provider: original.Provider(), Targets: original.Targets(),
			Parameters: original.Parameters(), Kind: original.Kind(), Execution: original.Execution(),
		})
		if err != nil {
			t.Fatalf("NewEffectDefinition(forged builtin) error = %v", err)
		}

		mutated.Effects[0] = forged

		_, err = NewTargetCatalog([]TargetCatalogRecord{mutated}, policySets)
		if !errors.Is(err, ErrInvalidCompiledTarget) {
			t.Fatalf("NewTargetCatalog(forged builtin effect) error = %v, want immutable rejection", err)
		}
	})

	t.Run("forged schema", func(t *testing.T) {
		mutated := record

		forged, err := registry.NewSchemaDefinition(record.Schema.Identity(), record.Schema.Facts())
		if err != nil {
			t.Fatalf("NewSchemaDefinition(forged builtin) error = %v", err)
		}

		mutated.Schema = forged

		_, err = NewTargetCatalog([]TargetCatalogRecord{mutated}, policySets)
		if !errors.Is(err, ErrInvalidCompiledTarget) {
			t.Fatalf("NewTargetCatalog(forged builtin schema) error = %v, want immutable rejection", err)
		}
	})
}

func TestTargetCatalogAllowsConfiguredAuthnDescriptorsAlongsideBuiltins(t *testing.T) {
	record, policySets := completionBuiltinAuthRuntimeRecord(t)

	provider, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID:         "authn/custom_provider",
		Targets:    []decision.Target{record.Target},
		Executions: []registry.ExecutionClass{registry.ExecutionHostSync},
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	effect, err := registry.NewEffectDefinition(registry.EffectDefinitionInput{
		ID:        "authn/custom_effect",
		Provider:  provider.ID(),
		Targets:   []decision.Target{record.Target},
		Kind:      registry.EffectKindObligation,
		Execution: registry.ExecutionHostSync,
	})
	if err != nil {
		t.Fatalf("NewEffectDefinition() error = %v", err)
	}

	record.Providers = append(record.Providers, provider)
	record.Effects = append(record.Effects, effect)

	catalog, err := NewTargetCatalog([]TargetCatalogRecord{record}, policySets)
	if err != nil {
		t.Fatalf("NewTargetCatalog() error = %v", err)
	}

	compiled, exists := catalog.Lookup(record.Target)
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

func TestTargetCatalogRejectsConfiguredReplacementForBuiltinPlanProvider(t *testing.T) {
	record, policySets := completionBuiltinAuthRuntimeRecordForAction(t, "authn/list_accounts", "authn/list_accounts/v1")

	replacement, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID:         record.Providers[0].ID(),
		Targets:    []decision.Target{record.Target},
		Executions: record.Providers[0].Executions(),
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	record.Providers[0] = replacement

	_, err = NewTargetCatalog([]TargetCatalogRecord{record}, policySets)
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog() error = %v, want immutable plan-provider rejection", err)
	}
}

func TestBuiltinEffectParametersRejectInvalidEstablishedValues(t *testing.T) {
	record, _ := completionBuiltinAuthRuntimeRecord(t)

	var (
		luaEffect        registry.EffectDefinition
		bruteForceEffect registry.EffectDefinition
	)

	for _, effect := range record.Effects {
		switch effect.SelectionID() {
		case "auth.obligation.lua_action.dispatch":
			luaEffect = effect
		case "auth.obligation.brute_force.update":
			bruteForceEffect = effect
		}
	}

	tests := []map[string]decision.Value{
		{
			"action":  completionRuntimeStringValue(t, "smtp"),
			"feature": completionRuntimeStringValue(t, "feature"),
		},
		{
			"action":  completionRuntimeStringValue(t, "lua"),
			"feature": completionRuntimeStringValue(t, ""),
		},
	}

	for index, parameters := range tests {
		use, err := registry.NewEffectUse(luaEffect.ID(), parameters)
		if err != nil {
			t.Fatalf("NewEffectUse(%d) error = %v", index, err)
		}

		if err = luaEffect.ValidateUse(use); err == nil {
			t.Fatalf("ValidateUse(%d) accepted invalid established Lua parameters", index)
		}
	}

	use, err := registry.NewEffectUse(bruteForceEffect.ID(), map[string]decision.Value{
		"feature": completionRuntimeStringValue(t, ""),
	})
	if err != nil {
		t.Fatalf("NewEffectUse(brute force) error = %v", err)
	}

	if err = bruteForceEffect.ValidateUse(use); err == nil {
		t.Fatal("ValidateUse() accepted an empty optional brute-force feature")
	}
}

func TestGenericDomainPlanRejectsAuthnCheckpoint(t *testing.T) {
	target, _ := completionRuntimeTargetAndSchema(t)

	checkpoint, err := registry.NewCheckpointDefinition("pre_auth", nil, nil)
	if err != nil {
		t.Fatalf("NewCheckpointDefinition() error = %v", err)
	}

	if _, err = registry.NewDomainPlanDefinition(target, []registry.CheckpointDefinition{checkpoint}); !errors.Is(err, registry.ErrInvalidCheckpoint) {
		t.Fatalf("NewDomainPlanDefinition(generic pre_auth) error = %v, want auth-checkpoint rejection", err)
	}
}

func TestTargetCatalogRejectsDirectUnscheduledRequiredProvider(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	setID := completionRuntimeSetID(t, "dkim2", "configured")

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Operator: registry.ExpressionOperatorAlways})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name: "deny", Checkpoint: "final_decision", RequiredProviders: []string{"dkim2/provider"},
		Expression: expression, Decision: decision.EffectDeny,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	set := completionRuntimePolicySet(t, registry.PolicySetDefinitionInput{ID: setID, Rules: []registry.PolicyRule{rule}})
	binding := completionRuntimeImport(t, setID, target, "final_decision", registry.ExportContract{})
	record := completionRuntimeRuleRecord(t, target, schema, setID, binding, rule)

	_, err = NewTargetCatalog([]TargetCatalogRecord{record}, []registry.PolicySetDefinition{set})
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(unscheduled required provider) error = %v, want checkpoint rejection", err)
	}
}

func TestTargetCatalogRejectsDirectResponseFactSchemaMismatch(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	setID := completionRuntimeSetID(t, "dkim2", "configured")

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Operator: registry.ExpressionOperatorAlways})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	message, err := registry.NewPolicyResponseMessage(registry.PolicyResponseMessageInput{
		From: "attribute_detail", FactID: "input.missing", Detail: "message", Fallback: "Denied", MaxLength: 128,
	})
	if err != nil {
		t.Fatalf("NewPolicyResponseMessage() error = %v", err)
	}

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name: "deny", Checkpoint: "final_decision", Expression: expression,
		Decision: decision.EffectDeny, ResponseMessage: message,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	set := completionRuntimePolicySet(t, registry.PolicySetDefinitionInput{ID: setID, Rules: []registry.PolicyRule{rule}})
	binding := completionRuntimeImport(t, setID, target, "final_decision", registry.ExportContract{})
	record := completionRuntimeRuleRecord(t, target, schema, setID, binding, rule)

	_, err = NewTargetCatalog([]TargetCatalogRecord{record}, []registry.PolicySetDefinition{set})
	if !errors.Is(err, ErrInvalidCompiledTarget) {
		t.Fatalf("NewTargetCatalog(response fact mismatch) error = %v, want schema rejection", err)
	}
}

func TestNewEffectUseSelectsDeterministicFirstInvalidParameter(t *testing.T) {
	parameters := map[string]decision.Value{
		"":                       {},
		strings.Repeat("z", 129): {},
	}

	for range 100 {
		_, err := registry.NewEffectUse("dkim2/notice", parameters)
		if err == nil || !strings.Contains(err.Error(), "map key") {
			t.Fatalf("NewEffectUse(two invalid parameters) error = %v, want deterministic empty-key failure", err)
		}
	}
}

// completionDirectRuntimeRecordCases constructs collision and unresolved-reference inputs.
func completionDirectRuntimeRecordCases(
	t *testing.T,
	target decision.Target,
	schema registry.SchemaDefinition,
) []directRuntimeRecordCase {
	t.Helper()

	provider, effect, unknownSet := completionRuntimeDescriptors(t, target)

	tests := []directRuntimeRecordCase{
		{
			name: "duplicate provider",
			record: TargetCatalogRecord{
				Target: target, Schema: schema, Checkpoints: []CheckpointRecord{{Name: "final_decision"}},
				Providers: []registry.ProviderDefinition{provider, provider}, NoMatch: registry.NoMatchDeny,
				AuthorityMode: registry.AuthorityModeEnforce,
			},
			want: ErrDuplicateCompiledProvider,
		},
		{
			name: "duplicate effect",
			record: TargetCatalogRecord{
				Target: target, Schema: schema, Checkpoints: []CheckpointRecord{{Name: "final_decision"}},
				Effects: []registry.EffectDefinition{effect, effect}, NoMatch: registry.NoMatchDeny,
				AuthorityMode: registry.AuthorityModeEnforce,
			},
			want: ErrDuplicateCompiledEffect,
		},
		{
			name: "unknown set",
			record: TargetCatalogRecord{
				Target: target, Schema: schema,
				Checkpoints: []CheckpointRecord{{
					Name: "final_decision",
					PolicySetBindings: []registry.PolicySetImport{
						completionRuntimeImport(t, unknownSet, target, "final_decision", registry.ExportContract{}),
					},
					PolicySetIDs: []registry.PolicySetID{unknownSet},
				}},
				NoMatch: registry.NoMatchDeny, AuthorityMode: registry.AuthorityModeEnforce,
			},
			want: ErrInvalidCompiledTarget,
		},
		{
			name: "unknown provider",
			record: TargetCatalogRecord{
				Target: target, Schema: schema,
				Checkpoints: []CheckpointRecord{{Name: "final_decision", ProviderIDs: []string{"dkim2/missing"}}},
				NoMatch:     registry.NoMatchDeny, AuthorityMode: registry.AuthorityModeEnforce,
			},
			want: ErrInvalidCompiledTarget,
		},
	}

	for index := range tests {
		tests[index].record = completionRuntimeAuthorizeRecord(t, tests[index].record)
	}

	return tests
}

// completionRuntimeDescriptors constructs exact provider, effect, and unresolved set fixtures.
func completionRuntimeDescriptors(
	t *testing.T,
	target decision.Target,
) (registry.ProviderDefinition, registry.EffectDefinition, registry.PolicySetID) {
	t.Helper()

	provider, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID:         "dkim2/sync",
		Targets:    []decision.Target{target},
		Executions: []registry.ExecutionClass{registry.ExecutionHostSync},
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	effect, err := registry.NewEffectDefinition(registry.EffectDefinitionInput{
		ID:        "dkim2/notice",
		Kind:      registry.EffectKindObligation,
		Execution: registry.ExecutionReturnOnly,
		Targets:   []decision.Target{target},
	})
	if err != nil {
		t.Fatalf("NewEffectDefinition() error = %v", err)
	}

	unknownSet, err := registry.NewPolicySetID("dkim2", "missing")
	if err != nil {
		t.Fatalf("NewPolicySetID() error = %v", err)
	}

	return provider, effect, unknownSet
}

// completionRuntimeTargetAndSchema constructs one direct runtime boundary fixture.
func completionRuntimeTargetAndSchema(t *testing.T) (decision.Target, registry.SchemaDefinition) {
	t.Helper()

	target, err := decision.NewTarget("dkim2", "sign")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	identity, err := registry.NewSchemaIdentity("dkim2", "sign", "v1")
	if err != nil {
		t.Fatalf("NewSchemaIdentity() error = %v", err)
	}

	schema, err := registry.NewSchemaDefinition(identity, nil)
	if err != nil {
		t.Fatalf("NewSchemaDefinition() error = %v", err)
	}

	return target, schema
}

// completionBuiltinAuthRuntimeRecord projects one authentic direct-runtime builtin auth candidate.
func completionBuiltinAuthRuntimeRecord(t *testing.T) (TargetCatalogRecord, []registry.PolicySetDefinition) {
	t.Helper()

	return completionBuiltinAuthRuntimeRecordForAction(t, "authn/authenticate", "authn/authenticate/v1")
}

// completionBuiltinAuthRuntimeRecordForAction projects one authentic builtin auth action candidate.
func completionBuiltinAuthRuntimeRecordForAction(
	t *testing.T,
	targetIdentity string,
	schemaIdentity string,
) (TargetCatalogRecord, []registry.PolicySetDefinition) {
	t.Helper()

	contribution, err := registry.NewBuiltinTargetContributor(runtimeNilAcceptance{"owner": "runtime"}).Contribute(context.Background())
	if err != nil {
		t.Fatalf("Contribute() error = %v", err)
	}

	target := completionContributionTarget(t, contribution, targetIdentity)
	schema := completionContributionSchema(t, contribution, schemaIdentity)
	plan := completionContributionPlan(t, contribution, target)
	policySets := contribution.PolicySets()
	standardID := completionRuntimeSetID(t, "authn", "standard_auth")
	checkpoints := make([]CheckpointRecord, 0)

	for _, checkpoint := range plan.Checkpoints() {
		checkpoints = append(checkpoints, CheckpointRecord{
			Name: checkpoint.Name(), PolicySetBindings: checkpoint.PolicySets(),
			PolicySetIDs: []registry.PolicySetID{standardID}, ProviderIDs: checkpoint.Providers(),
			Rules: completionRuntimeRulesForCheckpoint(t, target, checkpoint.Name(), standardID, policySets),
		})
	}

	providers := make([]registry.ProviderDefinition, 0)

	for _, provider := range contribution.Providers() {
		if provider.AllowsTarget(target) {
			providers = append(providers, provider)
		}
	}

	effects := make([]registry.EffectDefinition, 0)

	for _, effect := range contribution.Effects() {
		if effect.AllowsTarget(target) {
			effects = append(effects, effect)
		}
	}

	return TargetCatalogRecord{
		Target: target, Schema: schema, SourcePlan: plan, Checkpoints: checkpoints,
		Providers: providers, Effects: effects, DefaultPolicySet: standardID,
		AuthorityMode: registry.AuthorityModeEnforce,
	}, policySets
}

// completionRuntimeRulesForCheckpoint projects exact source-owned rules into one fixture checkpoint.
func completionRuntimeRulesForCheckpoint(
	t *testing.T,
	target decision.Target,
	checkpoint string,
	setID registry.PolicySetID,
	policySets []registry.PolicySetDefinition,
) []CompiledRuleRecord {
	t.Helper()

	for _, set := range policySets {
		if set.ID().String() != setID.String() {
			continue
		}

		result := make([]CompiledRuleRecord, 0)

		for _, rule := range set.Rules() {
			if rule.Checkpoint() != checkpoint || !rule.AllowsAction(target.Action()) {
				continue
			}

			result = append(result, ProjectPolicyRule(target, setID, checkpoint, rule))
		}

		return result
	}

	t.Fatalf("policy set %s missing", setID.String())

	return nil
}

// completionContributionTarget resolves one exact contributed target.
func completionContributionTarget(
	t *testing.T,
	contribution registry.DefinitionContribution,
	identity string,
) decision.Target {
	t.Helper()

	for _, candidate := range contribution.Targets() {
		if candidate.Target().String() == identity {
			return candidate.Target()
		}
	}

	t.Fatalf("contribution target %s missing", identity)

	return decision.Target{}
}

// completionContributionSchema resolves one exact contributed schema.
func completionContributionSchema(
	t *testing.T,
	contribution registry.DefinitionContribution,
	identity string,
) registry.SchemaDefinition {
	t.Helper()

	for _, candidate := range contribution.Schemas() {
		if candidate.Identity().String() == identity {
			return candidate
		}
	}

	t.Fatalf("contribution schema %s missing", identity)

	return registry.SchemaDefinition{}
}

// completionContributionPlan resolves the exact contributed source plan.
func completionContributionPlan(
	t *testing.T,
	contribution registry.DefinitionContribution,
	target decision.Target,
) registry.DomainPlanDefinition {
	t.Helper()

	for _, candidate := range contribution.Plans() {
		if candidate.Target().String() == target.String() {
			return candidate
		}
	}

	t.Fatalf("contribution plan %s missing", target.String())

	return registry.DomainPlanDefinition{}
}

// completionRuntimeStringValue constructs one strict string parameter.
func completionRuntimeStringValue(t *testing.T, value string) decision.Value {
	t.Helper()

	strict, err := decision.NewValue(decision.ValueInput{String: &value})
	if err != nil {
		t.Fatalf("NewValue(%q) error = %v", value, err)
	}

	return strict
}

// completionRuntimeSetID constructs one exact direct-runtime set identity.
func completionRuntimeSetID(t *testing.T, namespace string, name string) registry.PolicySetID {
	t.Helper()

	id, err := registry.NewPolicySetID(namespace, name)
	if err != nil {
		t.Fatalf("NewPolicySetID(%s/%s) error = %v", namespace, name, err)
	}

	return id
}

// completionRuntimePolicySet constructs one direct-runtime source definition.
func completionRuntimePolicySet(t *testing.T, input registry.PolicySetDefinitionInput) registry.PolicySetDefinition {
	t.Helper()

	set, err := registry.NewPolicySetDefinition(input)
	if err != nil {
		t.Fatalf("NewPolicySetDefinition(%s) error = %v", input.ID.String(), err)
	}

	return set
}

// completionRuntimeImport constructs one exact direct-runtime checkpoint binding.
func completionRuntimeImport(
	t *testing.T,
	set registry.PolicySetID,
	target decision.Target,
	checkpoint string,
	contract registry.ExportContract,
) registry.PolicySetImport {
	t.Helper()

	imported, err := registry.NewPolicySetImport(
		"runtime.checkpoints."+checkpoint+".policy_sets",
		set.String(),
		target,
		checkpoint,
		contract,
	)
	if err != nil {
		t.Fatalf("NewPolicySetImport(%s) error = %v", set.String(), err)
	}

	return imported
}

// completionRuntimeRuleRecord constructs one exact source-authenticated generic runtime record.
func completionRuntimeRuleRecord(
	t *testing.T,
	target decision.Target,
	schema registry.SchemaDefinition,
	setID registry.PolicySetID,
	binding registry.PolicySetImport,
	rule registry.PolicyRule,
) TargetCatalogRecord {
	t.Helper()

	record := TargetCatalogRecord{
		Target: target, Schema: schema, AuthorityMode: registry.AuthorityModeEnforce,
		Checkpoints: []CheckpointRecord{{
			Name: "final_decision", PolicySetBindings: []registry.PolicySetImport{binding},
			PolicySetIDs: []registry.PolicySetID{setID},
			Rules: []CompiledRuleRecord{{
				Target: target, PolicySetID: setID, Name: rule.Name(), Checkpoint: rule.Checkpoint(),
				RequiredProviders: rule.RequiredProviders(), Expression: rule.Expression(), Effects: rule.Effects(), Advice: rule.Advice(),
				Decision: rule.Decision(), Reason: rule.Reason(), OutcomeMarker: rule.OutcomeMarker(),
				FSMEventMarker: rule.FSMEventMarker(), ResponseMarker: rule.ResponseMarker(),
				ResponseMessage: rule.ResponseMessage(), ResponseLanguage: rule.ResponseLanguage(),
				SkipRemainingCheckpointProviders: rule.SkipRemainingCheckpointProviders(),
			}},
		}},
		DefaultPolicySet: setID, NoMatch: registry.NoMatchDeny,
	}

	return completionRuntimeAuthorizeRecord(t, record)
}

// completionRuntimeAuthorizeRecord binds direct checkpoint records to one constructor-validated source plan.
func completionRuntimeAuthorizeRecord(t *testing.T, record TargetCatalogRecord) TargetCatalogRecord {
	t.Helper()

	checkpoints := make([]registry.CheckpointDefinition, 0, len(record.Checkpoints))
	for _, checkpoint := range record.Checkpoints {
		source, err := registry.NewCheckpointDefinition(
			checkpoint.Name,
			checkpoint.PolicySetBindings,
			checkpoint.ProviderIDs,
		)
		if err != nil {
			t.Fatalf("NewCheckpointDefinition(%s) error = %v", checkpoint.Name, err)
		}

		checkpoints = append(checkpoints, source)
	}

	plan, err := registry.NewDomainPlanDefinition(record.Target, checkpoints)
	if err != nil {
		t.Fatalf("NewDomainPlanDefinition(%s) error = %v", record.Target.String(), err)
	}

	record.SourcePlan = plan

	return record
}

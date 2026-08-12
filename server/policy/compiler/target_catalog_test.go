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
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

type testCatalogContributor struct {
	contribution registry.DefinitionContribution
	err          error
}

// Contribute returns the test-owned immutable definition batch.
func (c testCatalogContributor) Contribute(context.Context) (registry.DefinitionContribution, error) {
	return c.contribution, c.err
}

func TestTargetCatalogRequiresExplicitActivationAndSeparateAdmission(t *testing.T) {
	contributor := registry.NewBuiltinTargetContributor(catalogAcceptanceCapability{})
	compiler := NewTargetCatalogCompiler(contributor)

	catalog, err := compiler.Compile(context.Background(), nil)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	authTarget := mustCompilerTarget(t, "authn", "authenticate")
	if _, ok := catalog.Lookup(authTarget); ok {
		t.Fatal("unactivated builtin target is exposed")
	}

	admission := mustCompilerAdmission(t, "clients[0].targets[0]", "authn", "authenticate", "authn/authenticate/v1")
	if err := ValidateAdmissionReferences(catalog, []registry.ClientAdmissionReference{admission}); !errors.Is(err, ErrUnknownActivatedTarget) {
		t.Fatalf("ValidateAdmissionReferences() error = %v, want unknown activated target", err)
	}

	activation := mustCompilerActivation(t, "policy.targets[0]", "authn", "authenticate", "authn/authenticate/v1")

	catalog, err = compiler.Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("Compile() with activation error = %v", err)
	}

	if _, ok := catalog.Lookup(authTarget); !ok {
		t.Fatal("explicitly activated builtin target is unavailable")
	}

	if err := ValidateAdmissionReferences(catalog, []registry.ClientAdmissionReference{admission}); err != nil {
		t.Fatalf("ValidateAdmissionReferences() error = %v", err)
	}
}

func TestTargetCatalogRejectsCollisionsWithoutPrecedence(t *testing.T) {
	first := mustCompilerContribution(t, "test.first", "dkim2", "sign", "v1", decision.ValueKindString)
	second := mustCompilerContribution(t, "test.second", "dkim2", "sign", "v1", decision.ValueKindInteger)
	activation := mustCompilerActivation(t, "policy.targets[0]", "dkim2", "sign", "dkim2/sign/v1")

	_, err := NewTargetCatalogCompiler(
		testCatalogContributor{contribution: first},
		testCatalogContributor{contribution: second},
	).Compile(context.Background(), []registry.TargetActivation{activation})
	if !errors.Is(err, ErrDefinitionCollision) {
		t.Fatalf("Compile() error = %v, want definition collision", err)
	}

	if !strings.Contains(err.Error(), "dkim2/sign") || !strings.Contains(err.Error(), "test.first") || !strings.Contains(err.Error(), "test.second") {
		t.Fatalf("Compile() error = %q, want identity and both owners", err)
	}
}

func TestTargetCatalogRejectsUnconstructedContribution(t *testing.T) {
	_, err := NewTargetCatalogCompiler(testCatalogContributor{}).Compile(context.Background(), nil)
	if !errors.Is(err, registry.ErrInvalidContribution) {
		t.Fatalf("Compile() error = %v, want invalid contribution", err)
	}
}

func TestTargetCatalogRejectsSchemaCollisionWithoutTargetCollision(t *testing.T) {
	firstSchema := mustCompilerSchema(t, "dkim2", "sign", "v1", decision.ValueKindString)
	secondSchema := mustCompilerSchema(t, "dkim2", "sign", "v1", decision.ValueKindInteger)
	first := mustCompilerDefinitionContribution(t, "test.first", "dkim2", nil, []registry.SchemaDefinition{firstSchema})
	second := mustCompilerDefinitionContribution(t, "test.second", "dkim2", nil, []registry.SchemaDefinition{secondSchema})

	_, err := NewTargetCatalogCompiler(
		testCatalogContributor{contribution: first},
		testCatalogContributor{contribution: second},
	).Compile(context.Background(), nil)
	if !errors.Is(err, ErrDefinitionCollision) {
		t.Fatalf("Compile() error = %v, want schema definition collision", err)
	}

	if !strings.Contains(err.Error(), "schema dkim2/sign/v1") {
		t.Fatalf("Compile() error = %q, want exact schema collision identity", err)
	}
}

func TestTargetCatalogRejectsTargetCollisionWithoutSchemaCollision(t *testing.T) {
	firstSchema, err := registry.NewSchemaIdentity("dkim2", "sign", "v1")
	if err != nil {
		t.Fatalf("registry.NewSchemaIdentity() error = %v", err)
	}

	secondSchema, err := registry.NewSchemaIdentity("dkim2", "sign", "v2")
	if err != nil {
		t.Fatalf("registry.NewSchemaIdentity() error = %v", err)
	}

	firstTarget := mustCompilerTargetDefinition(t, "dkim2", "sign", firstSchema)
	secondTarget := mustCompilerTargetDefinition(t, "dkim2", "sign", secondSchema)
	first := mustCompilerDefinitionContribution(t, "test.first", "dkim2", []registry.TargetDefinition{firstTarget}, nil)
	second := mustCompilerDefinitionContribution(t, "test.second", "dkim2", []registry.TargetDefinition{secondTarget}, nil)

	_, err = NewTargetCatalogCompiler(
		testCatalogContributor{contribution: first},
		testCatalogContributor{contribution: second},
	).Compile(context.Background(), nil)
	if !errors.Is(err, ErrDefinitionCollision) {
		t.Fatalf("Compile() error = %v, want target definition collision", err)
	}

	if !strings.Contains(err.Error(), "target dkim2/sign") {
		t.Fatalf("Compile() error = %q, want exact target collision identity", err)
	}
}

func TestTargetCatalogRejectsUnknownAndDuplicateActivations(t *testing.T) {
	contribution := mustCompilerContribution(t, "test.catalog", "dkim2", "sign", "v1", decision.ValueKindString)
	compiler := NewTargetCatalogCompiler(testCatalogContributor{contribution: contribution})

	tests := []struct {
		name        string
		activations []registry.TargetActivation
		wantError   error
	}{
		{
			name:        "unknown target",
			activations: []registry.TargetActivation{mustCompilerActivation(t, "policy.targets[0]", "mcp", "invoke", "mcp/invoke/v1")},
			wantError:   ErrUnknownTargetDefinition,
		},
		{
			name:        "unknown exact schema",
			activations: []registry.TargetActivation{mustCompilerActivation(t, "policy.targets[0]", "dkim2", "sign", "dkim2/sign/v2")},
			wantError:   ErrUnknownSchemaDefinition,
		},
		{
			name: "duplicate target activation",
			activations: []registry.TargetActivation{
				mustCompilerActivation(t, "policy.targets[0]", "dkim2", "sign", "dkim2/sign/v1"),
				mustCompilerActivation(t, "policy.targets[1]", "dkim2", "sign", "dkim2/sign/v1"),
			},
			wantError: ErrDuplicateTargetActivation,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := compiler.Compile(context.Background(), test.activations)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("Compile() error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestTargetCatalogValidatesFactsAgainstSelectedExactSchema(t *testing.T) {
	v1 := mustCompilerSchema(t, "dkim2", "sign", "v1", decision.ValueKindString)
	v2 := mustCompilerSchema(t, "dkim2", "sign", "v2", decision.ValueKindInteger)
	target := mustCompilerTargetDefinition(t, "dkim2", "sign", v1.Identity(), v2.Identity())
	contribution := mustCompilerCompleteDefinitionContribution(t, "test.catalog", "dkim2", target, []registry.SchemaDefinition{v1, v2})
	compiler := NewTargetCatalogCompiler(testCatalogContributor{contribution: contribution})

	activation := mustCompilerActivation(t, "policy.targets[0]", "dkim2", "sign", "dkim2/sign/v1")

	catalog, err := compiler.Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	facts := mustCompilerFactSet(t, decision.ValueInput{Integer: pointerTo(int64(7))})

	err = catalog.ValidateFacts(mustCompilerTarget(t, "dkim2", "sign"), facts)
	if !errors.Is(err, registry.ErrFactSchemaMismatch) {
		t.Fatalf("ValidateFacts() error = %v, want exact schema mismatch", err)
	}

	if !strings.Contains(err.Error(), "dkim2/sign/v1") {
		t.Fatalf("ValidateFacts() error = %q, want selected schema identity", err)
	}

	v2Activation := mustCompilerActivation(t, "policy.targets[0]", "dkim2", "sign", "dkim2/sign/v2")

	v2Catalog, err := compiler.Compile(context.Background(), []registry.TargetActivation{v2Activation})
	if err != nil {
		t.Fatalf("Compile() v2 error = %v", err)
	}

	if err := v2Catalog.ValidateFacts(mustCompilerTarget(t, "dkim2", "sign"), facts); err != nil {
		t.Fatalf("ValidateFacts() v2 error = %v", err)
	}
}

// mustCompilerContribution constructs one complete test-owned contribution.
func mustCompilerContribution(
	t *testing.T,
	owner string,
	namespace string,
	action string,
	version string,
	kind decision.ValueKind,
) registry.DefinitionContribution {
	t.Helper()

	schema := mustCompilerSchema(t, namespace, action, version, kind)
	target := mustCompilerTargetDefinition(t, namespace, action, schema.Identity())

	return mustCompilerCompleteDefinitionContribution(t, owner, namespace, target, []registry.SchemaDefinition{schema})
}

// mustCompilerCompleteDefinitionContribution adds the minimum exact generic plan.
func mustCompilerCompleteDefinitionContribution(
	t *testing.T,
	owner string,
	namespace string,
	target registry.TargetDefinition,
	schemas []registry.SchemaDefinition,
) registry.DefinitionContribution {
	t.Helper()

	setID, err := registry.NewPolicySetID(namespace, "root")
	if err != nil {
		t.Fatalf("registry.NewPolicySetID() error = %v", err)
	}

	set, err := registry.NewPolicySetDefinition(registry.PolicySetDefinitionInput{ID: setID})
	if err != nil {
		t.Fatalf("registry.NewPolicySetDefinition() error = %v", err)
	}

	binding, err := registry.NewPolicySetImport("test.plan", setID.String(), target.Target(), "final_decision", registry.ExportContract{})
	if err != nil {
		t.Fatalf("registry.NewPolicySetImport() error = %v", err)
	}

	checkpoint, err := registry.NewCheckpointDefinition("final_decision", []registry.PolicySetImport{binding}, nil)
	if err != nil {
		t.Fatalf("registry.NewCheckpointDefinition() error = %v", err)
	}

	plan, err := registry.NewDomainPlanDefinition(target.Target(), []registry.CheckpointDefinition{checkpoint})
	if err != nil {
		t.Fatalf("registry.NewDomainPlanDefinition() error = %v", err)
	}

	ownership, err := registry.NewNamespaceOwnership(owner, []string{namespace})
	if err != nil {
		t.Fatalf("registry.NewNamespaceOwnership() error = %v", err)
	}

	contribution, err := registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
		Ownership:  ownership,
		Targets:    []registry.TargetDefinition{target},
		Schemas:    schemas,
		PolicySets: []registry.PolicySetDefinition{set},
		Plans:      []registry.DomainPlanDefinition{plan},
	})
	if err != nil {
		t.Fatalf("registry.NewCompleteDefinitionContribution() error = %v", err)
	}

	return contribution
}

// mustCompilerDefinitionContribution owns the supplied definitions under one namespace.
func mustCompilerDefinitionContribution(
	t *testing.T,
	owner string,
	namespace string,
	targets []registry.TargetDefinition,
	schemas []registry.SchemaDefinition,
) registry.DefinitionContribution {
	t.Helper()

	ownership, err := registry.NewNamespaceOwnership(owner, []string{namespace})
	if err != nil {
		t.Fatalf("registry.NewNamespaceOwnership() error = %v", err)
	}

	contribution, err := registry.NewDefinitionContribution(ownership, targets, schemas)
	if err != nil {
		t.Fatalf("registry.NewDefinitionContribution() error = %v", err)
	}

	return contribution
}

// mustCompilerSchema constructs one exact schema with one required caller fact.
func mustCompilerSchema(
	t *testing.T,
	namespace string,
	action string,
	version string,
	kind decision.ValueKind,
) registry.SchemaDefinition {
	t.Helper()

	factInput := registry.FactSchemaInput{
		ID:             "input.value",
		Category:       decision.FactCategoryEnvironment,
		Kind:           kind,
		AllowedSources: []decision.FactSource{decision.FactSourceCaller},
		Required:       true,
	}

	if kind == decision.ValueKindString {
		factInput.MaxLength = 64
	}

	fact, err := registry.NewFactSchema(factInput)
	if err != nil {
		t.Fatalf("registry.NewFactSchema() error = %v", err)
	}

	identity, err := registry.NewSchemaIdentity(namespace, action, version)
	if err != nil {
		t.Fatalf("registry.NewSchemaIdentity() error = %v", err)
	}

	schema, err := registry.NewSchemaDefinition(identity, []registry.FactSchema{fact})
	if err != nil {
		t.Fatalf("registry.NewSchemaDefinition() error = %v", err)
	}

	return schema
}

// mustCompilerTargetDefinition constructs one target with exact supported schemas.
func mustCompilerTargetDefinition(
	t *testing.T,
	namespace string,
	action string,
	schemas ...registry.SchemaIdentity,
) registry.TargetDefinition {
	t.Helper()

	target := mustCompilerTarget(t, namespace, action)

	definition, err := registry.NewTargetDefinition(target, schemas)
	if err != nil {
		t.Fatalf("registry.NewTargetDefinition() error = %v", err)
	}

	return definition
}

// mustCompilerTarget constructs one exact policy target.
func mustCompilerTarget(t *testing.T, namespace string, action string) decision.Target {
	t.Helper()

	target, err := decision.NewTarget(namespace, action)
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	return target
}

// mustCompilerActivation constructs one exact operator activation.
func mustCompilerActivation(t *testing.T, path string, namespace string, action string, schema string) registry.TargetActivation {
	t.Helper()

	activation, err := registry.NewTargetActivation(path, namespace, action, schema)
	if err != nil {
		t.Fatalf("registry.NewTargetActivation() error = %v", err)
	}

	defaultSet := ""
	noMatch := "deny"

	if namespace == "authn" {
		defaultSet = registry.BuiltinStandardAuthPolicySet
		noMatch = ""
	}

	activation, err = activation.WithPolicy(defaultSet, noMatch)
	if err != nil {
		t.Fatalf("registry.TargetActivation.WithPolicy() error = %v", err)
	}

	return activation
}

// mustCompilerAdmission constructs one future client admission reference.
func mustCompilerAdmission(t *testing.T, path string, namespace string, action string, schema string) registry.ClientAdmissionReference {
	t.Helper()

	admission, err := registry.NewClientAdmissionReference(path, namespace, action, schema)
	if err != nil {
		t.Fatalf("registry.NewClientAdmissionReference() error = %v", err)
	}

	return admission
}

// mustCompilerFactSet constructs one caller-owned input fact set.
func mustCompilerFactSet(t *testing.T, input decision.ValueInput) decision.FactSet {
	t.Helper()

	value, err := decision.NewValue(input)
	if err != nil {
		t.Fatalf("decision.NewValue() error = %v", err)
	}

	provenance, err := decision.NewProvenance(decision.FactSourceCaller, "client", "request")
	if err != nil {
		t.Fatalf("decision.NewProvenance() error = %v", err)
	}

	fact, err := decision.NewFact("input.value", decision.FactCategoryEnvironment, value, provenance)
	if err != nil {
		t.Fatalf("decision.NewFact() error = %v", err)
	}

	facts, err := decision.NewFactSet([]decision.Fact{fact})
	if err != nil {
		t.Fatalf("decision.NewFactSet() error = %v", err)
	}

	return facts
}

// pointerTo returns a pointer to one test value.
func pointerTo[T any](value T) *T {
	return &value
}

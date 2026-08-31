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

package registry

import (
	"errors"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

func TestCatalogIdentitiesRejectInvalidOrImplicitValues(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		action    string
		schema    string
		wantError error
		wantPath  string
	}{
		{name: "uppercase namespace", namespace: "DKIM2", action: "sign", schema: "dkim2/sign/v1", wantError: ErrInvalidNamespace, wantPath: "policy.targets[0].namespace"},
		{name: "normalized action", namespace: "dkim2", action: "Sign", schema: "dkim2/sign/v1", wantError: ErrInvalidAction, wantPath: "policy.targets[0].action"},
		{name: "missing schema", namespace: "dkim2", action: "sign", wantError: ErrInvalidSchemaIdentity, wantPath: "policy.targets[0].schema"},
		{name: "missing version", namespace: "dkim2", action: "sign", schema: "dkim2/sign", wantError: ErrInvalidSchemaIdentity, wantPath: "policy.targets[0].schema"},
		{name: "implicit latest", namespace: "dkim2", action: "sign", schema: "dkim2/sign/latest", wantError: ErrInvalidSchemaVersion, wantPath: "policy.targets[0].schema"},
		{name: "version range", namespace: "dkim2", action: "sign", schema: "dkim2/sign/v1-v2", wantError: ErrInvalidSchemaVersion, wantPath: "policy.targets[0].schema"},
		{name: "surprising leading zero", namespace: "dkim2", action: "sign", schema: "dkim2/sign/v01", wantError: ErrInvalidSchemaVersion, wantPath: "policy.targets[0].schema"},
		{name: "foreign schema", namespace: "dkim2", action: "sign", schema: "mcp/sign/v1", wantError: ErrTargetSchemaMismatch, wantPath: "policy.targets[0].schema"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewTargetActivation("policy.targets[0]", test.namespace, test.action, test.schema)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("NewTargetActivation() error = %v, want %v", err, test.wantError)
			}

			if !strings.Contains(err.Error(), test.wantPath) {
				t.Fatalf("NewTargetActivation() error = %q, want path %q", err, test.wantPath)
			}
		})
	}
}

func TestContributionRejectsDuplicateOwnershipAndForeignDefinitions(t *testing.T) {
	if _, err := NewNamespaceOwnership("test.catalog", []string{"dkim2", "dkim2"}); !errors.Is(err, ErrDuplicateNamespace) {
		t.Fatalf("NewNamespaceOwnership() error = %v, want duplicate namespace", err)
	}

	ownership := mustOwnership(t, "test.catalog", "dkim2")
	target := mustTargetDefinition(t, "mcp", "invoke", "v1")
	schema := mustSchemaDefinition(t, "mcp", "invoke", "v1", nil)

	_, err := NewDefinitionContribution(ownership, []TargetDefinition{target}, []SchemaDefinition{schema})
	if !errors.Is(err, ErrNamespaceOwnership) {
		t.Fatalf("NewDefinitionContribution() error = %v, want namespace ownership error", err)
	}

	if !strings.Contains(err.Error(), "mcp/invoke") {
		t.Fatalf("NewDefinitionContribution() error = %q, want target identity", err)
	}
}

func TestTargetDefinitionRejectsDuplicateExactSchemaVersion(t *testing.T) {
	target, err := decision.NewTarget("dkim2", "sign")
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	schema, err := NewSchemaIdentity("dkim2", "sign", "v1")
	if err != nil {
		t.Fatalf("NewSchemaIdentity() error = %v", err)
	}

	_, err = NewTargetDefinition(target, []SchemaIdentity{schema, schema})
	if !errors.Is(err, ErrDuplicateDefinition) {
		t.Fatalf("NewTargetDefinition() error = %v, want duplicate schema version", err)
	}
}

func TestContributionAndGateModelsOwnTheirInputs(t *testing.T) {
	factSources := []decision.FactSource{decision.FactSourceCaller}
	fact := mustFactSchema(t, FactSchemaInput{
		ID:             "input.recipe",
		Category:       decision.FactCategoryEnvironment,
		Kind:           decision.ValueKindString,
		AllowedSources: factSources,
		Required:       true,
		MaxLength:      64,
	})

	schema := mustSchemaDefinition(t, "dkim2", "sign-message", "v1", []FactSchema{fact})
	target := mustTargetDefinition(t, "dkim2", "sign-message", "v1")

	contribution, err := NewDefinitionContribution(
		mustOwnership(t, "test.catalog", "dkim2"),
		[]TargetDefinition{target},
		[]SchemaDefinition{schema},
	)
	if err != nil {
		t.Fatalf("NewDefinitionContribution() error = %v", err)
	}

	factSources[0] = decision.FactSourceToken
	returnedSchemas := contribution.Schemas()
	returnedSchemas[0] = SchemaDefinition{}
	returnedTargets := contribution.Targets()
	returnedTargets[0] = TargetDefinition{}

	gotSources := contribution.Schemas()[0].Facts()[0].AllowedSources()
	if len(gotSources) != 1 || gotSources[0] != decision.FactSourceCaller {
		t.Fatalf("contribution sources = %v, want immutable caller source", gotSources)
	}

	activation := mustActivation(t, "policy.targets[0]", "dkim2", "sign-message", "dkim2/sign-message/v1")

	admission, err := NewClientAdmissionReference("clients[0].targets[0]", "dkim2", "sign-message", "dkim2/sign-message/v1")
	if err != nil {
		t.Fatalf("NewClientAdmissionReference() error = %v", err)
	}

	if activation.Schema().String() != admission.Schema().String() {
		t.Fatalf("activation schema = %q, admission schema = %q", activation.Schema(), admission.Schema())
	}

	if activation.Path() == admission.Path() {
		t.Fatal("activation and admission unexpectedly share an authority path")
	}
}

// mustOwnership constructs namespace ownership for one focused registry test.
func mustOwnership(t *testing.T, owner string, namespaces ...string) NamespaceOwnership {
	t.Helper()

	ownership, err := NewNamespaceOwnership(owner, namespaces)
	if err != nil {
		t.Fatalf("NewNamespaceOwnership() error = %v", err)
	}

	return ownership
}

// mustSchemaDefinition constructs one exact schema for a focused registry test.
func mustSchemaDefinition(
	t *testing.T,
	namespace string,
	name string,
	version string,
	facts []FactSchema,
) SchemaDefinition {
	t.Helper()

	identity, err := NewSchemaIdentity(namespace, name, version)
	if err != nil {
		t.Fatalf("NewSchemaIdentity() error = %v", err)
	}

	schema, err := NewSchemaDefinition(identity, facts)
	if err != nil {
		t.Fatalf("NewSchemaDefinition() error = %v", err)
	}

	return schema
}

// mustTargetDefinition constructs one target and its exact schema versions.
func mustTargetDefinition(t *testing.T, namespace string, action string, versions ...string) TargetDefinition {
	t.Helper()

	target, err := decision.NewTarget(namespace, action)
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	schemas := make([]SchemaIdentity, 0, len(versions))
	for _, version := range versions {
		schema, schemaErr := NewSchemaIdentity(namespace, action, version)
		if schemaErr != nil {
			t.Fatalf("NewSchemaIdentity() error = %v", schemaErr)
		}

		schemas = append(schemas, schema)
	}

	definition, err := NewTargetDefinition(target, schemas)
	if err != nil {
		t.Fatalf("NewTargetDefinition() error = %v", err)
	}

	return definition
}

// mustFactSchema constructs one immutable fact definition for a focused test.
func mustFactSchema(t *testing.T, input FactSchemaInput) FactSchema {
	t.Helper()

	fact, err := NewFactSchema(input)
	if err != nil {
		t.Fatalf("NewFactSchema() error = %v", err)
	}

	return fact
}

// mustActivation constructs one exact operator activation for a focused test.
func mustActivation(t *testing.T, path string, namespace string, action string, schema string) TargetActivation {
	t.Helper()

	activation, err := NewTargetActivation(path, namespace, action, schema)
	if err != nil {
		t.Fatalf("NewTargetActivation() error = %v", err)
	}

	return activation
}

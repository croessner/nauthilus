package registry

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

// TestNativeRecordOutputExtendsOnlyItsBoundAuthnSchema reproduces missing record metadata at the authn boundary.
func TestNativeRecordOutputExtendsOnlyItsBoundAuthnSchema(t *testing.T) {
	field := mustRecordFieldSchema(t, RecordFieldSchemaInput{
		Name: "state", Kind: decision.ValueKindString, MaxLength: 16,
		Required: true, ExpressionVisible: true,
	})

	records, err := NewRecordSchema(RecordSchemaInput{
		ID: "assessment", Version: "v1", Fields: []RecordFieldSchema{field},
		MaxRecords: 4, MaxFields: 1, MaxAggregateBytes: 256,
	})
	if err != nil {
		t.Fatal(err)
	}

	output := ProviderFactOutputInput{ID: "plugin.assessor.subjects", Category: decision.FactCategoryResource,
		Kind: decision.ValueKindRecords, RecordSchema: &records}
	extension := mustAuthnExtensionContribution(t, authnExtensionFixture{
		owner: "plugin.assessor", namespace: "authn", provider: "authn/plugin.assessor.collect",
		prefix: "plugin.assessor.", targets: []decision.Target{mustExtensionTarget(t, "authn", "authenticate")},
		outputs: []ProviderFactOutputInput{output},
	})

	extended, err := ExtendBuiltinAuthnSchemas(mustBuiltinAuthnContribution(t), extension)
	if err != nil {
		t.Fatal(err)
	}

	facts := indexAuthnFactSchemas(builtinAuthnSchemaForAction(t, extended.Schemas(), "authenticate").Facts())

	actual, ok := facts[output.ID].RecordSchema()
	if !ok || !actual.Equivalent(records) {
		t.Fatal("bound authn schema lost the exact record contract")
	}

	lookup := indexAuthnFactSchemas(builtinAuthnSchemaForAction(t, extended.Schemas(), "lookup_identity").Facts())
	if _, exists := lookup[output.ID]; exists {
		t.Fatal("record output leaked to an unbound target")
	}
}

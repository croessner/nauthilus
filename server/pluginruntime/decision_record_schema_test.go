package pluginruntime

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// TestNativeRecordBindingRejectsNestedMetadataDrift protects captured generations from changed field authority.
func TestNativeRecordBindingRejectsNestedMetadataDrift(t *testing.T) {
	declared := pluginapi.DecisionFactOutputDescriptor{
		Name: "items", Category: pluginapi.DecisionFactCategoryResource, Kind: pluginapi.DecisionValueKindRecords,
		RecordSchema: &pluginapi.DecisionRecordSchemaDescriptor{
			ID: "items", Version: "v1", MaxRecords: 2, MaxFields: 1, MaxAggregateBytes: 128,
			Fields: []pluginapi.DecisionRecordFieldDescriptor{{Name: "state", Kind: pluginapi.DecisionValueKindString,
				MaxLength: 16, Required: true, ProviderVisibility: []string{"authn/plugin.reader.collect"}}},
		},
	}

	records, err := pluginregistry.ProjectDecisionRecordSchema(declared.RecordSchema)
	if err != nil {
		t.Fatal(err)
	}

	configured, err := registry.NewProviderFactOutput(registry.ProviderFactOutputInput{
		ID: "plugin.source.items", Category: decision.FactCategoryResource, Kind: decision.ValueKindRecords, RecordSchema: records,
	})
	if err != nil || !nativeFactOutputMatches(configured, declared) {
		t.Fatal("matching record capability rejected", err)
	}

	for name, mutate := range map[string]func(*pluginapi.DecisionRecordSchemaDescriptor){
		"required":   func(s *pluginapi.DecisionRecordSchemaDescriptor) { s.Fields[0].Required = false },
		"visibility": func(s *pluginapi.DecisionRecordSchemaDescriptor) { s.Fields[0].ExpressionVisible = true },
		"reader":     func(s *pluginapi.DecisionRecordSchemaDescriptor) { s.Fields[0].ProviderVisibility = nil },
		"bound":      func(s *pluginapi.DecisionRecordSchemaDescriptor) { s.MaxRecords++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := declared
			changed.RecordSchema = declared.RecordSchema.Clone()
			mutate(changed.RecordSchema)

			if nativeFactOutputMatches(configured, changed) {
				t.Fatal("changed record contract matched frozen generation")
			}
		})
	}
}

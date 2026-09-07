package pluginregistry

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
)

// TestRegisteredRecordMetadataIsDeeplyOwned exercises input and readback mutation across real registration.
func TestRegisteredRecordMetadataIsDeeplyOwned(t *testing.T) {
	registry := NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})
	descriptor := validNativeFactProviderDescriptor()

	descriptor.Outputs = []pluginapi.DecisionFactOutputDescriptor{{
		Name: "items", Category: pluginapi.DecisionFactCategoryResource, Kind: pluginapi.DecisionValueKindRecords,
		RecordSchema: &pluginapi.DecisionRecordSchemaDescriptor{
			ID: "items", Version: "v1", MaxRecords: 2, MaxFields: 1, MaxAggregateBytes: 128,
			Fields: []pluginapi.DecisionRecordFieldDescriptor{{Name: "state", Kind: pluginapi.DecisionValueKindString,
				MaxLength: 16, ProviderVisibility: []string{"authn/plugin.reader.collect"}}},
		},
	}}
	if err := registrar.RegisterDecisionFactProvider(&fakeDecisionFactProvider{descriptor: descriptor}); err != nil {
		t.Fatal(err)
	}

	if err := registrar.Commit(); err != nil {
		t.Fatal(err)
	}

	for _, exposed := range []*pluginapi.DecisionRecordSchemaDescriptor{
		descriptor.Outputs[0].RecordSchema,
		registry.DecisionFactProviders()[0].DecisionFactProviderDescriptor.Outputs[0].RecordSchema,
	} {
		exposed.Fields[0].Name = "mutated"
		exposed.Fields[0].ProviderVisibility[0] = "authn/plugin.other.collect"
		exposed.MaxRecords = 200
	}

	owned := registry.DecisionFactProviders()[0].DecisionFactProviderDescriptor.Outputs[0].RecordSchema
	if owned.Fields[0].Name != "state" || owned.Fields[0].ProviderVisibility[0] != "authn/plugin.reader.collect" || owned.MaxRecords != 2 {
		t.Fatal("registration exposed mutable record capability metadata")
	}
}

package pluginregistry

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// ProjectDecisionRecordSchema owns native output metadata at the transport-neutral policy boundary.
func ProjectDecisionRecordSchema(input *pluginapi.DecisionRecordSchemaDescriptor) (*registry.RecordSchema, error) {
	if input == nil {
		return nil, nil
	}

	if err := pluginapi.ValidateDecisionRecordSchemaDescriptor(input); err != nil {
		return nil, err
	}

	fields := make([]registry.RecordFieldSchema, 0, len(input.Fields))
	for _, field := range input.Fields {
		owned, err := registry.NewRecordFieldSchema(registry.RecordFieldSchemaInput{
			Name: field.Name, Kind: decision.ValueKind(field.Kind),
			ProviderVisibility: field.ProviderVisibility, Required: field.Required,
			ExpressionVisible: field.ExpressionVisible,
			MaxLength:         field.MaxLength, MaxItems: field.MaxItems, MaxBytes: field.MaxBytes,
		})
		if err != nil {
			return nil, err
		}

		fields = append(fields, owned)
	}

	owned, err := registry.NewRecordSchema(registry.RecordSchemaInput{
		ID: input.ID, Version: input.Version, Fields: fields,
		MinRecords: input.MinRecords, MaxRecords: input.MaxRecords,
		MaxFields: input.MaxFields, MaxAggregateBytes: input.MaxAggregateBytes,
	})
	if err != nil {
		return nil, err
	}

	return &owned, nil
}

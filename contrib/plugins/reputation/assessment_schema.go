package main

import (
	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// assessmentOutputSchema declares the provider-owned tuple when no catalog-owned correlation fields are requested.
// Correlated outputs retain their target catalog schema, which owns the additional field bounds and visibility.
func assessmentOutputSchema(name string, binding targetBindingConfig) *pluginapi.DecisionRecordSchemaDescriptor {
	for _, subject := range binding.Subjects {
		if len(subject.CorrelationFields) != 0 {
			return nil
		}
	}

	fields := []pluginapi.DecisionRecordFieldDescriptor{
		{Name: fieldRole, Kind: pluginapi.DecisionValueKindString, MaxLength: 64, Required: true, ExpressionVisible: true},
		{Name: fieldKind, Kind: pluginapi.DecisionValueKindString, MaxLength: 32, Required: true, ExpressionVisible: true},
	}
	for _, field := range view.Fields() {
		fields = append(fields, pluginapi.DecisionRecordFieldDescriptor{
			Name: field.Name, Kind: field.Kind, MaxLength: field.MaxLength,
			Required: field.Required, ExpressionVisible: true,
		})
	}

	return &pluginapi.DecisionRecordSchemaDescriptor{
		ID: name, Version: "v1", Fields: fields, MaxRecords: maximumAssessmentSubjects,
		MaxFields: len(fields), MaxAggregateBytes: 128 * 1024,
	}
}

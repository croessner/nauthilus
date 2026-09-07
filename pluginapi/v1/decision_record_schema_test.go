package pluginapi

import "testing"

// TestRecordOutputMetadataRejectsMalformedContracts keeps optional metadata closed and non-recursive.
func TestRecordOutputMetadataRejectsMalformedContracts(t *testing.T) {
	base := &DecisionRecordSchemaDescriptor{
		ID: "items", Version: "v1", MaxRecords: 2, MaxFields: 1, MaxAggregateBytes: 128,
		Fields: []DecisionRecordFieldDescriptor{{Name: "state", Kind: DecisionValueKindString, MaxLength: 16,
			Required: true, ExpressionVisible: true, ProviderVisibility: []string{"authn/plugin.reader.collect"}}},
	}
	if err := ValidateDecisionRecordSchemaDescriptor(base); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*DecisionRecordSchemaDescriptor){
		"recursive":        func(s *DecisionRecordSchemaDescriptor) { s.Fields[0].Kind = DecisionValueKindRecords },
		"duplicate":        func(s *DecisionRecordSchemaDescriptor) { s.Fields = append(s.Fields, s.Fields[0]) },
		"unbounded":        func(s *DecisionRecordSchemaDescriptor) { s.MaxAggregateBytes = 0 },
		"missing fields":   func(s *DecisionRecordSchemaDescriptor) { s.Fields = nil },
		"negative minimum": func(s *DecisionRecordSchemaDescriptor) { s.MinRecords = -1 },
		"bad version":      func(s *DecisionRecordSchemaDescriptor) { s.Version = "v01" },
		"unknown kind":     func(s *DecisionRecordSchemaDescriptor) { s.Fields[0].Kind = "unknown" },
		"wildcard reader":  func(s *DecisionRecordSchemaDescriptor) { s.Fields[0].ProviderVisibility[0] = "*" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base.Clone()
			mutate(candidate)

			if ValidateDecisionRecordSchemaDescriptor(candidate) == nil {
				t.Fatal("malformed schema accepted")
			}
		})
	}

	if err := ValidateDecisionRecordSchemaDescriptor(base); err != nil {
		t.Fatal("cloned mutation changed original metadata", err)
	}

	descriptor := validDecisionFactProviderDescriptor(t)

	descriptor.Outputs[0].RecordSchema = base
	if ValidateDecisionFactProviderDescriptor(descriptor) == nil {
		t.Fatal("record metadata accepted for scalar output")
	}
}

package pluginapi

import "strconv"

// DecisionRecordFieldDescriptor declares one closed, non-recursive output field.
type DecisionRecordFieldDescriptor struct {
	Name               string
	ProviderVisibility []string
	Kind               DecisionValueKind
	MaxLength          int
	MaxItems           int
	MaxBytes           int
	Required           bool
	ExpressionVisible  bool
}

// DecisionRecordSchemaDescriptor supplies schema metadata for descriptor-owned target extensions.
// Generic targets may instead use their catalog-owned schema when output metadata is absent.
type DecisionRecordSchemaDescriptor struct {
	ID                string
	Version           string
	Fields            []DecisionRecordFieldDescriptor
	MinRecords        int
	MaxRecords        int
	MaxFields         int
	MaxAggregateBytes int
}

// Clone detaches all mutable field and visibility metadata.
func (s *DecisionRecordSchemaDescriptor) Clone() *DecisionRecordSchemaDescriptor {
	if s == nil {
		return nil
	}

	owned := *s

	owned.Fields = append([]DecisionRecordFieldDescriptor(nil), s.Fields...)
	for index := range owned.Fields {
		owned.Fields[index].ProviderVisibility = append([]string(nil), s.Fields[index].ProviderVisibility...)
	}

	return &owned
}

// ValidateDecisionRecordSchemaDescriptor validates closed metadata before native registration.
func ValidateDecisionRecordSchemaDescriptor(s *DecisionRecordSchemaDescriptor) error {
	if s == nil {
		return nil
	}

	if !validDecisionRecordSchemaIdentity(s) || !validDecisionRecordSchemaLimits(s) {
		return invalidDecisionContract("record schema", "must declare a closed versioned schema with positive limits")
	}

	seen := make(map[string]struct{}, len(s.Fields))
	required := 0

	for _, field := range s.Fields {
		if err := validateDecisionRecordFieldDescriptor(field); err != nil {
			return err
		}

		if _, duplicate := seen[field.Name]; duplicate {
			return invalidDecisionContract("record schema", "contains duplicate fields")
		}

		seen[field.Name] = struct{}{}
		if field.Required {
			required++
		}
	}

	if required > s.MaxFields {
		return invalidDecisionContract("record schema", "field limit excludes required fields")
	}

	return nil
}

// validDecisionRecordSchemaIdentity requires a local identifier and canonical uint32 schema version.
func validDecisionRecordSchemaIdentity(s *DecisionRecordSchemaDescriptor) bool {
	if !validDecisionRecordFieldName(s.ID) || len(s.Version) < 2 || s.Version[0] != 'v' ||
		s.Version[1] < '1' || s.Version[1] > '9' {
		return false
	}

	_, err := strconv.ParseUint(s.Version[1:], 10, 32)

	return err == nil
}

// validDecisionRecordSchemaLimits checks collection bounds independently from field declarations.
func validDecisionRecordSchemaLimits(s *DecisionRecordSchemaDescriptor) bool {
	return len(s.Fields) > 0 && len(s.Fields) <= maximumDecisionDefinitions &&
		s.MinRecords >= 0 && s.MaxRecords > 0 && s.MinRecords <= s.MaxRecords &&
		s.MaxFields > 0 && s.MaxFields <= len(s.Fields) && s.MaxAggregateBytes > 0
}

// validateDecisionRecordFieldDescriptor checks leaf kinds and exact provider visibility.
func validateDecisionRecordFieldDescriptor(field DecisionRecordFieldDescriptor) error {
	if !validDecisionRecordFieldName(field.Name) || !field.Kind.IsValid() || field.Kind == DecisionValueKindRecords ||
		!validDecisionValueBounds(field.Kind, field.MaxLength, field.MaxItems, field.MaxBytes) {
		return invalidDecisionContract("record field", "must declare a bounded non-recursive leaf")
	}

	seen := make(map[string]struct{}, len(field.ProviderVisibility))
	for _, provider := range field.ProviderVisibility {
		if ValidateDecisionProviderReference(provider) != nil {
			return invalidDecisionContract("record field", "invalid provider visibility")
		}

		if _, duplicate := seen[provider]; duplicate {
			return invalidDecisionContract("record field", "duplicate provider visibility")
		}

		seen[provider] = struct{}{}
	}

	return nil
}

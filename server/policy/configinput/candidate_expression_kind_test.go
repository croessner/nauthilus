// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// TestCandidateExpressionAcceptsCompatibleNumericKinds protects whole-number YAML thresholds.
func TestCandidateExpressionAcceptsCompatibleNumericKinds(t *testing.T) {
	expression := candidateAttributeExpression(t, decision.ValueKindInteger)
	schema := map[string]registry.FactSchema{
		"plugin.subject.geoip_reputation.preexisting_samples": candidateFactSchema(
			t,
			decision.ValueKindDouble,
		),
	}

	err := validateCandidateExpression("authn", expression, schema, nil, nil)
	if err != nil {
		t.Fatalf("validateCandidateExpression() error = %v, want compatible numeric kinds", err)
	}
}

// TestCandidateExpressionRejectsIncompatibleKinds preserves strict non-numeric typing.
func TestCandidateExpressionRejectsIncompatibleKinds(t *testing.T) {
	expression := candidateAttributeExpression(t, decision.ValueKindString)
	schema := map[string]registry.FactSchema{
		"plugin.subject.geoip_reputation.preexisting_samples": candidateFactSchema(
			t,
			decision.ValueKindDouble,
		),
	}

	err := validateCandidateExpression("authn", expression, schema, nil, nil)
	if err == nil {
		t.Fatal("validateCandidateExpression() error = nil, want incompatible kind rejection")
	}
}

// candidateAttributeExpression constructs one typed attribute predicate.
func candidateAttributeExpression(t *testing.T, kind decision.ValueKind) registry.PolicyExpression {
	t.Helper()

	valueInput := decision.ValueInput{}
	operator := registry.ExpressionOperatorEQ

	switch kind {
	case decision.ValueKindInteger:
		value := int64(10)
		valueInput.Integer = &value
		operator = registry.ExpressionOperatorGTE
	case decision.ValueKindString:
		value := "10"
		valueInput.String = &value
	default:
		t.Fatalf("unsupported test value kind %s", kind)
	}

	value, err := decision.NewValue(valueInput)
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind:     registry.ExpressionKindAttribute,
		FactID:   "plugin.subject.geoip_reputation.preexisting_samples",
		FactKind: kind,
		Operator: operator,
		Values:   []decision.Value{value},
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	return expression
}

// candidateFactSchema constructs one plugin-owned fact declaration.
func candidateFactSchema(t *testing.T, kind decision.ValueKind) registry.FactSchema {
	t.Helper()

	fact, err := registry.NewFactSchema(registry.FactSchemaInput{
		ID:             "plugin.subject.geoip_reputation.preexisting_samples",
		AllowedSources: []decision.FactSource{decision.FactSourcePlugin},
		Category:       decision.FactCategoryEnvironment,
		Kind:           kind,
	})
	if err != nil {
		t.Fatalf("NewFactSchema() error = %v", err)
	}

	return fact
}

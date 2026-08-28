// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

func TestRecordQuantifiersUseExplicitMissingEmptyAndMultipleRecordSemantics(t *testing.T) {
	runtime := &checkpointRuntime{}
	pass := mustServiceValue(t, "pass")

	for _, testCase := range []struct {
		name       string
		quantifier registry.RecordQuantifier
		facts      decision.FactSet
		want       bool
	}{
		{name: "missing any", quantifier: registry.RecordQuantifierAny, facts: decision.FactSet{}, want: false},
		{name: "missing all", quantifier: registry.RecordQuantifierAll, facts: decision.FactSet{}, want: false},
		{name: "missing none", quantifier: registry.RecordQuantifierNone, facts: decision.FactSet{}, want: false},
		{name: "empty any", quantifier: registry.RecordQuantifierAny, facts: serviceRecordFacts(t), want: false},
		{name: "empty all", quantifier: registry.RecordQuantifierAll, facts: serviceRecordFacts(t), want: true},
		{name: "empty none", quantifier: registry.RecordQuantifierNone, facts: serviceRecordFacts(t), want: true},
		{name: "multiple any", quantifier: registry.RecordQuantifierAny, facts: serviceRecordFacts(t, "fail", "pass"), want: true},
		{name: "multiple all", quantifier: registry.RecordQuantifierAll, facts: serviceRecordFacts(t, "pass", "pass"), want: true},
		{name: "multiple none", quantifier: registry.RecordQuantifierNone, facts: serviceRecordFacts(t, "fail", "other"), want: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
				Kind: registry.ExpressionKindRecordQuantifier, FactID: "resource.chain",
				FactKind: decision.ValueKindRecords, RecordField: "result", RecordFieldKind: decision.ValueKindString,
				Quantifier: testCase.quantifier, Operator: registry.ExpressionOperatorEQ, Values: []decision.Value{pass},
			})
			if err != nil {
				t.Fatalf("NewPolicyExpression() error = %v", err)
			}

			if got := runtime.expressionMatches("mail", expression, testCase.facts); got != testCase.want {
				t.Fatalf("expressionMatches() = %t, want %t", got, testCase.want)
			}
		})
	}
}

// serviceRecordFacts constructs one whole-fact-provenance record collection fixture.
func serviceRecordFacts(t *testing.T, results ...string) decision.FactSet {
	t.Helper()

	records := make([]decision.Record, 0, len(results))
	for _, result := range results {
		leaf := mustServiceValue(t, result)
		fieldValue, _ := decision.NewRecordFieldValueFromValue(leaf)
		field, _ := decision.NewRecordField("result", fieldValue)
		record, _ := decision.NewRecord([]decision.RecordField{field})
		records = append(records, record)
	}

	list, _ := decision.NewRecordList(records)
	value, _ := decision.NewValue(decision.ValueInput{Records: &list})
	provenance, _ := decision.NewProvenance(decision.FactSourceCaller, "client", "request")
	fact, _ := decision.NewFact("resource.chain", decision.FactCategoryResource, value, provenance)
	facts, _ := decision.NewFactSet([]decision.Fact{fact})

	return facts
}

// mustServiceValue constructs one strict test string.
func mustServiceValue(t *testing.T, text string) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &text})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	return value
}

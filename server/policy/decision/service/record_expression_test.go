// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// TestRecordFieldPresenceUsesLocalFieldExistence keeps presence independent from scalar kind.
func TestRecordFieldPresenceUsesLocalFieldExistence(t *testing.T) {
	for _, test := range []struct {
		field  string
		exists bool
		want   bool
	}{
		{"result", true, true},
		{"result", false, false},
		{"optional", false, true},
		{"optional", true, false},
	} {
		value, _ := decision.NewValue(decision.ValueInput{Boolean: &test.exists})

		leaf, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
			Kind: registry.ExpressionKindRecordField, RecordField: test.field, RecordFieldKind: decision.ValueKindString,
			Operator: registry.ExpressionOperatorExists, Values: []decision.Value{value},
		})
		if err != nil {
			t.Fatal(err)
		}

		expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
			Kind: registry.ExpressionKindRecordQuantifier, FactID: "resource.chain", Quantifier: registry.RecordQuantifierAny,
			Children: []registry.PolicyExpression{leaf},
		})
		if err != nil {
			t.Fatal(err)
		}

		runtime := &checkpointRuntime{}
		if got := runtime.expressionMatches("workflow", expression, serviceRecordFacts(t, "pass")); got != test.want {
			t.Fatalf("%s exists=%t matched=%t, want %t", test.field, test.exists, got, test.want)
		}
	}
}

// TestCompositeRecordPredicateKeepsEvidenceOnOneRecord rejects a join across separate records.
func TestCompositeRecordPredicateKeepsEvidenceOnOneRecord(t *testing.T) {
	children := make([]registry.PolicyExpression, 0, 2)

	for _, value := range []string{"pass", "fail"} {
		child, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
			Kind: registry.ExpressionKind("record_field"), RecordField: "result",
			RecordFieldKind: decision.ValueKindString, Operator: registry.ExpressionOperatorEQ,
			Values: []decision.Value{mustServiceValue(t, value)},
		})
		if err != nil {
			t.Fatal(err)
		}

		children = append(children, child)
	}

	for _, kind := range []registry.ExpressionKind{registry.ExpressionKindAll, registry.ExpressionKindAny} {
		where, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Kind: kind, Children: children})
		if err != nil {
			t.Fatal(err)
		}

		expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
			Kind: registry.ExpressionKindRecordQuantifier, FactID: "resource.chain",
			Quantifier: registry.RecordQuantifierAny, Children: []registry.PolicyExpression{where},
		})
		if err != nil {
			t.Fatal(err)
		}

		runtime := &checkpointRuntime{}

		got := runtime.expressionMatches("workflow", expression, serviceRecordFacts(t, "pass", "fail"))
		if got != (kind == registry.ExpressionKindAny) {
			t.Fatalf("%s matched=%t", kind, got)
		}
	}
}

// TestCompositeRecordDistinctFields evaluates conjunction and negation on one bound record.
func TestCompositeRecordDistinctFields(t *testing.T) {
	children := make([]registry.PolicyExpression, 0, 2)

	for _, field := range []string{"result", "review"} {
		child, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
			Kind: registry.ExpressionKindRecordField, RecordField: field, RecordFieldKind: decision.ValueKindString,
			Operator: registry.ExpressionOperatorEQ, Values: []decision.Value{mustServiceValue(t, "pass")},
		})
		if err != nil {
			t.Fatal(err)
		}

		children = append(children, child)
	}

	where, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Kind: registry.ExpressionKindAll, Children: children})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		pairs   [][2]string
		want    bool
		negated bool
	}{
		{"split evidence", [][2]string{{"pass", "fail"}, {"fail", "pass"}}, false, false},
		{"same record", [][2]string{{"fail", "fail"}, {"pass", "pass"}}, true, false},
		{"nested negation rejects", [][2]string{{"pass", "pass"}}, false, true},
		{"nested negation matches", [][2]string{{"pass", "fail"}}, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			predicate := where

			if test.negated {
				var err error

				predicate, err = registry.NewPolicyExpression(registry.PolicyExpressionInput{Kind: registry.ExpressionKindNot, Children: []registry.PolicyExpression{where}})
				if err != nil {
					t.Fatal(err)
				}
			}

			expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
				Kind: registry.ExpressionKindRecordQuantifier, FactID: "resource.chain", Quantifier: registry.RecordQuantifierAny,
				Children: []registry.PolicyExpression{predicate},
			})
			if err != nil {
				t.Fatal(err)
			}

			runtime := &checkpointRuntime{}
			if got := runtime.expressionMatches("workflow", expression, compositePairFacts(t, test.pairs)); got != test.want {
				t.Fatalf("matched = %t, want %t", got, test.want)
			}
		})
	}
}

// compositePairFacts constructs independently owned two-field records for correlation tests.
func compositePairFacts(t *testing.T, pairs [][2]string) decision.FactSet {
	t.Helper()

	records := make([]decision.Record, 0, len(pairs))
	for _, pair := range pairs {
		fields := make([]decision.RecordField, 0, 2)

		for index, name := range []string{"result", "review"} {
			value, _ := decision.NewRecordFieldValueFromValue(mustServiceValue(t, pair[index]))
			field, _ := decision.NewRecordField(name, value)
			fields = append(fields, field)
		}

		record, _ := decision.NewRecord(fields)
		records = append(records, record)
	}

	return serviceFactsFromRecords(records)
}

// TestRecordQuantifiersUseExplicitMissingEmptyAndMultipleRecordSemantics preserves collection truth tables.
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
			where, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
				Kind: registry.ExpressionKindRecordField, RecordField: "result", RecordFieldKind: decision.ValueKindString,
				Operator: registry.ExpressionOperatorEQ, Values: []decision.Value{pass},
			})
			if err != nil {
				t.Fatal(err)
			}

			expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
				Kind: registry.ExpressionKindRecordQuantifier, FactID: "resource.chain",
				Quantifier: testCase.quantifier, Children: []registry.PolicyExpression{where},
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

	return serviceFactsFromRecords(records)
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

// serviceFactsFromRecords wraps constructed records in one caller-owned fact.
func serviceFactsFromRecords(records []decision.Record) decision.FactSet {
	list, _ := decision.NewRecordList(records)
	value, _ := decision.NewValue(decision.ValueInput{Records: &list})
	provenance, _ := decision.NewProvenance(decision.FactSourceCaller, "client", "request")
	fact, _ := decision.NewFact("resource.chain", decision.FactCategoryResource, value, provenance)
	facts, _ := decision.NewFactSet([]decision.Fact{fact})

	return facts
}

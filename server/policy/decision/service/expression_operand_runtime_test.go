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
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

const (
	operandTestNamespace = "workflow"
	operandTestFactID    = "input.subject"
	operandTestReference = "@network.office"
)

// TestMatchesUsesCompiledPattern keeps regular-expression semantics for attribute and record-local predicates.
func TestMatchesUsesCompiledPattern(t *testing.T) {
	runtime := newOperandTestRuntime(t, nil)
	attribute := mustOperandExpression(t, registry.PolicyExpressionInput{
		FactID: operandTestFactID, Operator: registry.ExpressionOperatorMatches,
		Values: []decision.Value{mustOperandString(t, "^admin-[0-9]+$")},
	})

	for _, test := range []struct {
		name  string
		facts decision.FactSet
		want  bool
	}{
		{"match", mustOperandStringFacts(t, "admin-42"), true},
		{"anchored mismatch", mustOperandStringFacts(t, "xadmin-42"), false},
		{"empty text", mustOperandStringFacts(t, ""), false},
		{"integer fact", mustOperandIntegerFacts(t, 42), false},
		{"missing fact", decision.FactSet{}, false},
	} {
		if got := runtime.expressionMatches(operandTestNamespace, attribute, test.facts); got != test.want {
			t.Fatalf("%s: matches = %t, want %t", test.name, got, test.want)
		}
	}

	negated := mustOperandExpression(t, registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindNot, Children: []registry.PolicyExpression{attribute},
	})
	if runtime.expressionMatches(operandTestNamespace, negated, mustOperandStringFacts(t, "admin-42")) {
		t.Fatal("not(matches) through a detached child clone matched, want the shared compiled pattern")
	}

	record := mustOperandExpression(t, registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindRecordField, RecordField: "result", RecordFieldKind: decision.ValueKindString,
		Operator: registry.ExpressionOperatorMatches, Values: []decision.Value{mustOperandString(t, "^pa")},
	})
	quantifier := mustOperandExpression(t, registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindRecordQuantifier, FactID: "resource.chain",
		Quantifier: registry.RecordQuantifierAny, Children: []registry.PolicyExpression{record},
	})

	if !runtime.expressionMatches(operandTestNamespace, quantifier, serviceRecordFacts(t, "pass")) {
		t.Fatal("record-local matches = false, want compiled pattern match")
	}

	if runtime.expressionMatches(operandTestNamespace, quantifier, serviceRecordFacts(t, "fail")) {
		t.Fatal("record-local matches = true, want compiled pattern mismatch")
	}
}

// TestCIDRContainsUsesCompiledLiteralNetwork keeps literal prefix, exact-address, and netip family semantics.
func TestCIDRContainsUsesCompiledLiteralNetwork(t *testing.T) {
	runtime := newOperandTestRuntime(t, nil)

	for _, test := range []struct {
		name    string
		network string
		fact    string
		want    bool
	}{
		{"prefix contains", "10.0.0.0/8", "10.20.30.40", true},
		{"prefix excludes", "10.0.0.0/8", "11.0.0.1", false},
		{"non-canonical prefix", "10.1.2.3/8", "10.9.9.9", true},
		{"exact address", "192.0.2.7", "192.0.2.7", true},
		{"exact address mismatch", "192.0.2.7", "192.0.2.8", false},
		{"ipv6 prefix", "2001:db8::/32", "2001:db8::1", true},
		{"ipv4 fact against mapped prefix", "::ffff:10.0.0.0/104", "10.0.0.1", false},
		{"mapped fact against ipv4 prefix", "10.0.0.0/8", "::ffff:10.0.0.1", false},
		{"mapped exact address", "::ffff:10.0.0.1", "10.0.0.1", false},
		{"zoned exact address", "fe80::1%eth0", "fe80::1%eth0", true},
		{"zoned exact address mismatch", "fe80::1%eth0", "fe80::1", false},
		{"zoned fact against prefix", "fe80::/10", "fe80::1%eth0", false},
		{"invalid fact", "10.0.0.0/8", "not-an-address", false},
		{"prefix fact", "10.0.0.0/8", "10.0.0.0/24", false},
	} {
		expression := mustOperandExpression(t, registry.PolicyExpressionInput{
			FactID: operandTestFactID, Operator: registry.ExpressionOperatorCIDRContains,
			Values: []decision.Value{mustOperandString(t, test.network)},
		})

		if got := runtime.expressionMatches(operandTestNamespace, expression, mustOperandStringFacts(t, test.fact)); got != test.want {
			t.Fatalf("%s: cidr_contains(%s, %s) = %t, want %t", test.name, test.network, test.fact, got, test.want)
		}
	}

	expression := mustOperandExpression(t, registry.PolicyExpressionInput{
		FactID: operandTestFactID, Operator: registry.ExpressionOperatorCIDRContains,
		Values: []decision.Value{mustOperandString(t, "10.0.0.0/8")},
	})
	if runtime.expressionMatches(operandTestNamespace, expression, mustOperandIntegerFacts(t, 10)) {
		t.Fatal("cidr_contains matched an integer fact, want false")
	}
}

// TestCIDRContainsUsesCompiledReferencedNetworks skips invalid set members and keeps missing-set semantics.
func TestCIDRContainsUsesCompiledReferencedNetworks(t *testing.T) {
	key := policyruntime.ConditionMaterialKey(operandTestNamespace, operandTestReference)
	integer := int64(7)

	integerValue, err := decision.NewValue(decision.ValueInput{Integer: &integer})
	if err != nil {
		t.Fatalf("NewValue(integer) error = %v", err)
	}

	runtime := newOperandTestRuntime(t, map[string][]decision.Value{
		key: {
			mustOperandString(t, "not-a-network"),
			integerValue,
			mustOperandString(t, "10.0.0.0/8"),
			mustOperandString(t, "192.0.2.7"),
			mustOperandString(t, "fe80::1%eth0"),
		},
	})
	expression := mustOperandExpression(t, registry.PolicyExpressionInput{
		FactID: operandTestFactID, FactKind: decision.ValueKindString,
		Operator: registry.ExpressionOperatorCIDRContains, Reference: operandTestReference,
	})

	for _, test := range []struct {
		fact string
		want bool
	}{
		{"10.1.1.1", true},
		{"192.0.2.7", true},
		{"fe80::1%eth0", true},
		{"192.0.2.8", false},
		{"not-a-network", false},
		{"::ffff:10.1.1.1", false},
	} {
		if got := runtime.expressionMatches(operandTestNamespace, expression, mustOperandStringFacts(t, test.fact)); got != test.want {
			t.Fatalf("referenced cidr_contains(%s) = %t, want %t", test.fact, got, test.want)
		}

		if got := runtime.guardAttributeMatch(operandTestNamespace, expression, mustOperandStringFacts(t, test.fact)); got != booleanGuardMatch(test.want) {
			t.Fatalf("referenced guard cidr_contains(%s) = %v, want %t", test.fact, got, test.want)
		}
	}

	stringKey := policyruntime.ConditionMaterialKey(operandTestNamespace, "@string.addresses")
	stringRuntime := newOperandTestRuntime(t, map[string][]decision.Value{stringKey: {mustOperandString(t, "10.0.0.1")}})

	if operands := stringRuntime.conditionSets[stringKey]; len(operands.values) != 1 || operands.networks.Len() != 0 {
		t.Fatal("string condition set was precompiled as a network set")
	}

	missing := newOperandTestRuntime(t, nil)
	if missing.expressionMatches(operandTestNamespace, expression, mustOperandStringFacts(t, "10.1.1.1")) {
		t.Fatal("cidr_contains matched an unavailable condition set, want false")
	}

	if got := missing.guardAttributeMatch(operandTestNamespace, expression, mustOperandStringFacts(t, "10.1.1.1")); got != guardUnknown {
		t.Fatalf("guard over an unavailable condition set = %v, want unknown", got)
	}
}

// BenchmarkMatchesRuntime measures one literal regular-expression predicate evaluation.
func BenchmarkMatchesRuntime(b *testing.B) {
	expression := mustOperandExpression(b, registry.PolicyExpressionInput{
		FactID: operandTestFactID, Operator: registry.ExpressionOperatorMatches,
		Values: []decision.Value{mustOperandString(b, `^[a-z0-9._%+-]+@(example|test)\.(org|net)$`)},
	})

	benchmarkOperandExpression(b, newOperandTestRuntime(b, nil), expression, "someone@example.org", true)
}

// BenchmarkCIDRContainsLiteralRuntime measures one literal network predicate evaluation.
func BenchmarkCIDRContainsLiteralRuntime(b *testing.B) {
	expression := mustOperandExpression(b, registry.PolicyExpressionInput{
		FactID: operandTestFactID, Operator: registry.ExpressionOperatorCIDRContains,
		Values: []decision.Value{mustOperandString(b, "2001:db8::/32")},
	})

	benchmarkOperandExpression(b, newOperandTestRuntime(b, nil), expression, "2001:db8::1", true)
}

// BenchmarkCIDRContainsReferencedRuntime measures one full non-matching referenced network-set scan.
func BenchmarkCIDRContainsReferencedRuntime(b *testing.B) {
	networks := make([]decision.Value, 0, 12)
	for _, network := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "198.18.0.0/15", "192.0.2.0/24",
		"198.51.100.0/24", "2001:db8::/32", "fd00::/8", "fe80::/10", "192.0.2.10", "192.0.2.11",
	} {
		networks = append(networks, mustOperandString(b, network))
	}

	key := policyruntime.ConditionMaterialKey(operandTestNamespace, operandTestReference)
	expression := mustOperandExpression(b, registry.PolicyExpressionInput{
		FactID: operandTestFactID, FactKind: decision.ValueKindString,
		Operator: registry.ExpressionOperatorCIDRContains, Reference: operandTestReference,
	})

	benchmarkOperandExpression(b, newOperandTestRuntime(b, map[string][]decision.Value{key: networks}), expression, "203.0.113.9", false)
}

// benchmarkOperandExpression repeatedly evaluates one predicate against one string fact.
func benchmarkOperandExpression(
	b *testing.B,
	runtime *checkpointRuntime,
	expression registry.PolicyExpression,
	fact string,
	want bool,
) {
	b.Helper()

	facts := mustOperandStringFacts(b, fact)

	b.ReportAllocs()

	for b.Loop() {
		if got := runtime.expressionMatches(operandTestNamespace, expression, facts); got != want {
			b.Fatalf("%s(%s) = %t, want %t", expression.Operator(), fact, got, want)
		}
	}
}

// newOperandTestRuntime builds one evaluator over an empty catalog and the given condition material.
func newOperandTestRuntime(tb testing.TB, conditionSets map[string][]decision.Value) *checkpointRuntime {
	tb.Helper()

	catalog, err := policyruntime.NewTargetCatalog(nil)
	if err != nil {
		tb.Fatalf("NewTargetCatalog() error = %v", err)
	}

	runtime, err := newCheckpointRuntime(checkpointRuntimeConfig{catalog: catalog, conditionSets: conditionSets})
	if err != nil {
		tb.Fatalf("newCheckpointRuntime() error = %v", err)
	}

	return runtime
}

// mustOperandExpression constructs one validated condition-tree node.
func mustOperandExpression(tb testing.TB, input registry.PolicyExpressionInput) registry.PolicyExpression {
	tb.Helper()

	expression, err := registry.NewPolicyExpression(input)
	if err != nil {
		tb.Fatalf("NewPolicyExpression() error = %v", err)
	}

	return expression
}

// mustOperandString constructs one strict string value.
func mustOperandString(tb testing.TB, text string) decision.Value {
	tb.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &text})
	if err != nil {
		tb.Fatalf("NewValue(%q) error = %v", text, err)
	}

	return value
}

// mustOperandStringFacts binds one string value to the test subject fact.
func mustOperandStringFacts(tb testing.TB, text string) decision.FactSet {
	tb.Helper()

	return mustOperandFacts(tb, mustOperandString(tb, text))
}

// mustOperandIntegerFacts binds one integer value to the test subject fact.
func mustOperandIntegerFacts(tb testing.TB, number int64) decision.FactSet {
	tb.Helper()

	value, err := decision.NewValue(decision.ValueInput{Integer: &number})
	if err != nil {
		tb.Fatalf("NewValue(%d) error = %v", number, err)
	}

	return mustOperandFacts(tb, value)
}

// mustOperandFacts constructs one caller-owned fact set for the test subject fact.
func mustOperandFacts(tb testing.TB, value decision.Value) decision.FactSet {
	tb.Helper()

	provenance, err := decision.NewProvenance(decision.FactSourceCaller, "test-authority", "request")
	if err != nil {
		tb.Fatalf("NewProvenance() error = %v", err)
	}

	fact, err := decision.NewFact(operandTestFactID, decision.FactCategoryEnvironment, value, provenance)
	if err != nil {
		tb.Fatalf("NewFact() error = %v", err)
	}

	facts, err := decision.NewFactSet([]decision.Fact{fact})
	if err != nil {
		tb.Fatalf("NewFactSet() error = %v", err)
	}

	return facts
}

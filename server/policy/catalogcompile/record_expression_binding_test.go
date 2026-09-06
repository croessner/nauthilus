package catalogcompile

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// TestRecordFieldCannotEscapeQuantifier rejects unbound native expressions before execution.
func TestRecordFieldCannotEscapeQuantifier(t *testing.T) {
	text := "pass"
	value, _ := decision.NewValue(decision.ValueInput{String: &text})

	leaf, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindRecordField, RecordField: "result", RecordFieldKind: decision.ValueKindString,
		Operator: registry.ExpressionOperatorEQ, Values: []decision.Value{value},
	})
	if err != nil {
		t.Fatal(err)
	}

	not, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Kind: registry.ExpressionKindNot, Children: []registry.PolicyExpression{leaf}})
	if err != nil {
		t.Fatal(err)
	}

	for _, expression := range []registry.PolicyExpression{leaf, not} {
		if err := validateRecordExpressionFields(expression, nil); err == nil {
			t.Fatal("unbound record field was accepted")
		}
	}

	bound, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindRecordQuantifier, FactID: "resource.chain", Quantifier: registry.RecordQuantifierAny,
		Children: []registry.PolicyExpression{leaf},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := registry.NewSchedulerGuardDefinition(registry.SchedulerGuardDefinitionInput{
		Path: "workflow.guard", Name: "check", Expression: bound,
	}); err == nil {
		t.Fatal("scheduler guard accepted an unsupported record expression")
	}
}

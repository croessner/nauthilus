// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// normalizeExpression recursively maps the closed standalone condition vocabulary.
func normalizeExpression(path string, configured policyconfig.ConditionConfig) (registry.PolicyExpression, error) {
	switch {
	case configured.Records != nil:
		return normalizeRecordExpression(path+".records", *configured.Records)
	case configured.Not != nil:
		child, err := normalizeExpression(path+".not", *configured.Not)
		if err != nil {
			return registry.PolicyExpression{}, err
		}

		return newExpression(path, registry.PolicyExpressionInput{Kind: registry.ExpressionKindNot, Children: []registry.PolicyExpression{child}})
	case len(configured.All) > 0:
		return normalizeExpressionChildren(path+".all", registry.ExpressionKindAll, configured.All)
	case len(configured.Any) > 0:
		return normalizeExpressionChildren(path+".any", registry.ExpressionKindAny, configured.Any)
	case configured.Always != nil:
		return newExpression(path, registry.PolicyExpressionInput{Kind: registry.ExpressionKindAlways})
	default:
		return normalizeAttributeExpression(path, configured)
	}
}

// normalizeRecordExpression maps one flat record-local predicate without introducing a child expression.
func normalizeRecordExpression(
	path string,
	configured policyconfig.RecordConditionConfig,
) (registry.PolicyExpression, error) {
	where := configured.Where
	where.Attribute = "record.field"

	leaf, err := normalizeAttributeExpression(path+".where", where)
	if err != nil {
		return registry.PolicyExpression{}, err
	}

	return newExpression(path, registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindRecordQuantifier, FactID: configured.Attribute,
		FactKind: decision.ValueKindRecords, Operator: leaf.Operator(), Reference: leaf.Reference(), Values: leaf.Values(),
		RecordField: configured.Field, RecordFieldKind: leaf.FactKind(),
		Quantifier: registry.RecordQuantifier(configured.Quantifier),
	})
}

// normalizeExpressionChildren constructs one ordered all/any node.
func normalizeExpressionChildren(
	path string,
	kind registry.ExpressionKind,
	configured []policyconfig.ConditionConfig,
) (registry.PolicyExpression, error) {
	children := make([]registry.PolicyExpression, 0, len(configured))

	for index, childConfig := range configured {
		child, err := normalizeExpression(fmt.Sprintf("%s[%d]", path, index), childConfig)
		if err != nil {
			return registry.PolicyExpression{}, err
		}

		children = append(children, child)
	}

	return newExpression(path, registry.PolicyExpressionInput{Kind: kind, Children: children})
}

// normalizeAttributeExpression selects one exact operator and strict operand shape.
func normalizeAttributeExpression(
	path string,
	configured policyconfig.ConditionConfig,
) (registry.PolicyExpression, error) {
	input := registry.PolicyExpressionInput{Kind: registry.ExpressionKindAttribute, FactID: configured.Attribute}

	if expression, handled, err := normalizeReferencedAttribute(path, input, configured); handled {
		return expression, err
	}

	if expression, handled, err := normalizeScalarAttribute(path, input, configured); handled {
		return expression, err
	}

	if expression, handled, err := normalizeCollectionAttribute(path, input, configured); handled {
		return expression, err
	}

	if expression, handled, err := normalizeOrderedAttribute(path, input, configured); handled {
		return expression, err
	}

	return registry.PolicyExpression{}, atPath(path, fmt.Errorf("condition requires exactly one operator"))
}

// normalizeReferencedAttribute handles string, network, and time-window source operands.
func normalizeReferencedAttribute(
	path string,
	input registry.PolicyExpressionInput,
	configured policyconfig.ConditionConfig,
) (registry.PolicyExpression, bool, error) {
	switch {
	case configured.Matches != "":
		input.Operator = registry.ExpressionOperatorMatches
		input.FactKind = decision.ValueKindString
		input.Values = mustStringOperand(configured.Matches)
	case configured.CIDRContains != "":
		input.Operator = registry.ExpressionOperatorCIDRContains
		input.FactKind = decision.ValueKindString
		input.Reference, input.Values = referenceOrString(configured.CIDRContains, "@network.")
	case configured.WithinTimeWindow != "":
		input.Operator = registry.ExpressionOperatorWithinTimeWindow
		input.FactKind = decision.ValueKindTimestamp
		input.Reference = configured.WithinTimeWindow
	default:
		return registry.PolicyExpression{}, false, nil
	}

	expression, err := newExpression(path, input)

	return expression, true, err
}

// normalizeScalarAttribute handles equality, membership, and presence operands.
func normalizeScalarAttribute(
	path string,
	input registry.PolicyExpressionInput,
	configured policyconfig.ConditionConfig,
) (registry.PolicyExpression, bool, error) {
	switch {
	case configured.Is != nil:
		expression, err := normalizeInlineExpression(path+".is", input, registry.ExpressionOperatorIs, configured.Is)

		return expression, true, err
	case configured.Eq != nil:
		expression, err := normalizeInlineExpression(path+".eq", input, registry.ExpressionOperatorEQ, configured.Eq)

		return expression, true, err
	case configured.Ne != nil:
		expression, err := normalizeInlineExpression(path+".ne", input, registry.ExpressionOperatorNotEqual, configured.Ne)

		return expression, true, err
	case configured.In != nil:
		expression, err := normalizeMembershipExpression(path+".in", input, registry.ExpressionOperatorIn, configured.In)

		return expression, true, err
	case configured.NotIn != nil:
		expression, err := normalizeMembershipExpression(path+".not_in", input, registry.ExpressionOperatorNotIn, configured.NotIn)

		return expression, true, err
	case configured.Exists != nil:
		input.Operator = registry.ExpressionOperatorExists
		input.FactKind = decision.ValueKindString
		input.Values = mustBooleanOperand(*configured.Exists)
		expression, err := newExpression(path+".exists", input)

		return expression, true, err
	default:
		return registry.PolicyExpression{}, false, nil
	}
}

// normalizeCollectionAttribute handles string-list membership operators.
func normalizeCollectionAttribute(
	path string,
	input registry.PolicyExpressionInput,
	configured policyconfig.ConditionConfig,
) (registry.PolicyExpression, bool, error) {
	input.FactKind = decision.ValueKindStrings

	switch {
	case configured.Contains != nil:
		expression, err := normalizeInlineExpression(path+".contains", input, registry.ExpressionOperatorContains, configured.Contains)

		return expression, true, err
	case len(configured.ContainsAny) > 0:
		expression, err := normalizeInlineExpression(path+".contains_any", input, registry.ExpressionOperatorContainsAny, configured.ContainsAny)

		return expression, true, err
	case len(configured.ContainsAll) > 0:
		expression, err := normalizeInlineExpression(path+".contains_all", input, registry.ExpressionOperatorContainsAll, configured.ContainsAll)

		return expression, true, err
	case len(configured.ContainsNone) > 0:
		expression, err := normalizeInlineExpression(path+".contains_none", input, registry.ExpressionOperatorContainsNone, configured.ContainsNone)

		return expression, true, err
	default:
		return registry.PolicyExpression{}, false, nil
	}
}

// normalizeOrderedAttribute handles numeric or timestamp comparison operands.
func normalizeOrderedAttribute(
	path string,
	input registry.PolicyExpressionInput,
	configured policyconfig.ConditionConfig,
) (registry.PolicyExpression, bool, error) {
	switch {
	case configured.GT != nil:
		expression, err := normalizeInlineExpression(path+".gt", input, registry.ExpressionOperatorGT, configured.GT)

		return expression, true, err
	case configured.GTE != nil:
		expression, err := normalizeInlineExpression(path+".gte", input, registry.ExpressionOperatorGTE, configured.GTE)

		return expression, true, err
	case configured.LT != nil:
		expression, err := normalizeInlineExpression(path+".lt", input, registry.ExpressionOperatorLT, configured.LT)

		return expression, true, err
	case configured.LTE != nil:
		expression, err := normalizeInlineExpression(path+".lte", input, registry.ExpressionOperatorLTE, configured.LTE)

		return expression, true, err
	default:
		return registry.PolicyExpression{}, false, nil
	}
}

// normalizeInlineExpression converts one or more inline values and infers the fact kind when safe.
func normalizeInlineExpression(
	path string,
	input registry.PolicyExpressionInput,
	operator registry.ExpressionOperator,
	configured any,
) (registry.PolicyExpression, error) {
	values, err := normalizeOperandValues(configured)
	if err != nil {
		return registry.PolicyExpression{}, atPath(path, err)
	}

	input.Operator = operator
	input.Values = values

	if input.FactKind == "" && len(values) > 0 {
		input.FactKind = values[0].Kind()
	}

	return newExpression(path, input)
}

// normalizeMembershipExpression distinguishes exact string-set references from inline members.
func normalizeMembershipExpression(
	path string,
	input registry.PolicyExpressionInput,
	operator registry.ExpressionOperator,
	configured any,
) (registry.PolicyExpression, error) {
	if reference, ok := configured.(string); ok && strings.HasPrefix(reference, "@string.") {
		input.Operator = operator
		input.FactKind = decision.ValueKindString
		input.Reference = reference

		return newExpression(path, input)
	}

	return normalizeInlineExpression(path, input, operator, configured)
}

// normalizeOperandValues flattens a configured list into strict scalar operands.
func normalizeOperandValues(configured any) ([]decision.Value, error) {
	value := reflect.ValueOf(configured)
	if value.IsValid() && (value.Kind() == reflect.Slice || value.Kind() == reflect.Array) {
		values := make([]decision.Value, 0, value.Len())
		for index := 0; index < value.Len(); index++ {
			normalized, err := normalizeValue(value.Index(index).Interface())
			if err != nil {
				return nil, err
			}

			values = append(values, normalized)
		}

		return values, nil
	}

	normalized, err := normalizeValue(configured)
	if err != nil {
		return nil, err
	}

	return []decision.Value{normalized}, nil
}

// normalizeValue constructs one transport-neutral strict primitive or string-list value.
func normalizeValue(configured any) (decision.Value, error) {
	switch value := configured.(type) {
	case string:
		return decision.NewValue(decision.ValueInput{String: &value})
	case bool:
		return decision.NewValue(decision.ValueInput{Boolean: &value})
	case json.Number:
		return normalizeJSONNumber(value)
	case []string:
		return decision.NewValue(decision.ValueInput{Strings: value})
	case []any:
		return normalizeStringList(value)
	case []byte:
		return decision.NewValue(decision.ValueInput{Bytes: value})
	case time.Time:
		return decision.NewValue(decision.ValueInput{Timestamp: &value})
	default:
		return normalizeNumericValue(configured)
	}
}

// normalizeStringList constructs one strict ordered list from transport values.
func normalizeStringList(configured []any) (decision.Value, error) {
	values := make([]string, 0, len(configured))

	for _, member := range configured {
		text, ok := member.(string)
		if !ok {
			return decision.Value{}, fmt.Errorf("lists must contain only strings")
		}

		values = append(values, text)
	}

	return decision.NewValue(decision.ValueInput{Strings: values})
}

// normalizeNumericValue converts transport-specific integer and float representations.
func normalizeNumericValue(configured any) (decision.Value, error) {
	value := reflect.ValueOf(configured)
	if !value.IsValid() {
		return decision.Value{}, fmt.Errorf("unsupported policy value type %T", configured)
	}

	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		integer := value.Int()

		return decision.NewValue(decision.ValueInput{Integer: &integer})
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return normalizeUnsigned(configured)
	case reflect.Float32, reflect.Float64:
		return normalizeFloat(value.Float())
	default:
		return decision.Value{}, fmt.Errorf("unsupported policy value type %T", configured)
	}
}

// normalizeUnsigned range-checks an unsigned transport value before strict construction.
func normalizeUnsigned(configured any) (decision.Value, error) {
	value := reflect.ValueOf(configured).Uint()
	if value > math.MaxInt64 {
		return decision.Value{}, fmt.Errorf("integer exceeds signed 64-bit range")
	}

	integer := int64(value)

	return decision.NewValue(decision.ValueInput{Integer: &integer})
}

// normalizeFloat preserves an explicitly floating transport value as a double.
func normalizeFloat(value float64) (decision.Value, error) {
	return decision.NewValue(decision.ValueInput{Double: &value})
}

// normalizeJSONNumber preserves integer and floating JSON spelling as distinct kinds.
func normalizeJSONNumber(value json.Number) (decision.Value, error) {
	if integer, err := value.Int64(); err == nil {
		return decision.NewValue(decision.ValueInput{Integer: &integer})
	}

	double, err := value.Float64()
	if err != nil {
		return decision.Value{}, err
	}

	return normalizeFloat(double)
}

// newExpression wraps registry validation with its exact configuration-owned path.
func newExpression(path string, input registry.PolicyExpressionInput) (registry.PolicyExpression, error) {
	expression, err := registry.NewPolicyExpression(input)
	if err != nil {
		return registry.PolicyExpression{}, atPath(path, err)
	}

	return expression, nil
}

// referenceOrString maps an exact condition-set reference or one inline string operand.
func referenceOrString(value string, prefix string) (string, []decision.Value) {
	if strings.HasPrefix(value, prefix) {
		return value, nil
	}

	return "", mustStringOperand(value)
}

// mustStringOperand constructs the already validated UTF-8 string operand.
func mustStringOperand(value string) []decision.Value {
	result, _ := decision.NewValue(decision.ValueInput{String: &value})

	return []decision.Value{result}
}

// mustBooleanOperand constructs one primitive boolean operand.
func mustBooleanOperand(value bool) []decision.Value {
	result, _ := decision.NewValue(decision.ValueInput{Boolean: &value})

	return []decision.Value{result}
}

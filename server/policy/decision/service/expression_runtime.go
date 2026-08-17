// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package service

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

type selectedRule struct {
	rule      policyruntime.CompiledRule
	controls  []policyruntime.CompiledRule
	policySet string
	matched   bool
}

// selectRule evaluates production policy sets in compiled deterministic order.
func (r *checkpointRuntime) selectRule(
	target policyruntime.CompiledTarget,
	checkpoint policyruntime.CompiledCheckpoint,
	facts decision.FactSet,
	providers []providerRecord,
) selectedRule {
	selected := r.selectRuleFromPolicySets(
		target,
		checkpoint.Name(),
		checkpoint.ProductionPolicySetIDs(),
		facts,
		providers,
	)
	if selected.matched || target.Target().Namespace() != policy.AuthnNamespace ||
		!checkpoint.ContainsPolicySet(registry.BuiltinStandardAuthPolicySet) {
		return selected
	}

	return r.selectRuleFromPolicySets(
		target,
		checkpoint.Name(),
		[]string{registry.BuiltinStandardAuthPolicySet},
		facts,
		providers,
	)
}

// selectComparisonRule evaluates observe-only sets without selecting their effects.
func (r *checkpointRuntime) selectComparisonRule(
	target policyruntime.CompiledTarget,
	checkpoint policyruntime.CompiledCheckpoint,
	facts decision.FactSet,
	providers []providerRecord,
) selectedRule {
	return r.selectRuleFromPolicySets(
		target,
		checkpoint.Name(),
		checkpoint.ComparisonPolicySetIDs(),
		facts,
		providers,
	)
}

// selectRuleFromPolicySets applies one deterministic set order for production or comparison.
func (r *checkpointRuntime) selectRuleFromPolicySets(
	target policyruntime.CompiledTarget,
	checkpoint string,
	policySetIDs []string,
	facts decision.FactSet,
	providers []providerRecord,
) selectedRule {
	controls := make([]policyruntime.CompiledRule, 0)

	for _, policySetID := range policySetIDs {
		setID, err := registry.ParsePolicySetID("runtime.policy_set", policySetID)
		if err != nil {
			continue
		}

		set, ok := target.LookupPolicySet(setID)
		if !ok {
			continue
		}

		for _, rule := range set.Rules() {
			if rule.Checkpoint() != checkpoint || !requiredProvidersCompleted(rule, providers) {
				continue
			}

			if !r.expressionMatches(rule.Expression(), facts) {
				continue
			}

			if authnNonterminalCheckpointControl(target, checkpoint, set, rule) {
				controls = append(controls, rule)

				continue
			}

			return selectedRule{rule: rule, controls: controls, policySet: policySetID, matched: true}
		}
	}

	return selectedRule{controls: controls}
}

// authnNonterminalCheckpointControl keeps final-checkpoint host controls as evidence while selection continues.
func authnNonterminalCheckpointControl(
	target policyruntime.CompiledTarget,
	checkpoint string,
	set policyruntime.CompiledPolicySet,
	rule policyruntime.CompiledRule,
) bool {
	return target.Target().Namespace() == policy.AuthnNamespace &&
		checkpoint == string(policy.StageAuthDecision) &&
		set.IsBuiltinStandardAuth() &&
		rule.Decision() == decision.EffectNotApplicable &&
		rule.SkipRemainingCheckpointProviders()
}

// recordComparisonSelection stores observe evidence without preparing or executing effects.
func recordComparisonSelection(report *runtimeReport, selected selectedRule) {
	if report == nil || !selected.matched {
		return
	}

	report.comparisonPolicySet = selected.policySet
	report.comparisonRule = selected.rule.Name()
	report.comparisonEffect = selected.rule.Decision()
}

// requiredProvidersCompleted applies compiler-approved provider-dependent rule skipping.
func requiredProvidersCompleted(rule policyruntime.CompiledRule, providers []providerRecord) bool {
	for _, providerID := range rule.RequiredProviders() {
		if !selectedProviderCompleted(providers, providerID) {
			return false
		}
	}

	return true
}

// expressionMatches evaluates one immutable compiled condition tree.
func (r *checkpointRuntime) expressionMatches(expression registry.PolicyExpression, facts decision.FactSet) bool {
	switch expression.Kind() {
	case registry.ExpressionKindAlways:
		return true
	case registry.ExpressionKindAll:
		for _, child := range expression.Children() {
			if !r.expressionMatches(child, facts) {
				return false
			}
		}

		return true
	case registry.ExpressionKindAny:
		for _, child := range expression.Children() {
			if r.expressionMatches(child, facts) {
				return true
			}
		}

		return false
	case registry.ExpressionKindNot:
		children := expression.Children()

		return len(children) == 1 && !r.expressionMatches(children[0], facts)
	case registry.ExpressionKindAttribute:
		return r.attributeExpressionMatches(expression, facts)
	default:
		return false
	}
}

// attributeExpressionMatches evaluates one strict typed fact predicate.
func (r *checkpointRuntime) attributeExpressionMatches(
	expression registry.PolicyExpression,
	facts decision.FactSet,
) bool {
	fact, exists := facts.Get(expression.FactID())
	if expression.Operator() == registry.ExpressionOperatorExists {
		expected, _ := expression.Values()[0].Boolean()

		return exists == expected
	}

	if !exists || fact.Value().Kind() != expression.FactKind() {
		return false
	}

	if expression.Operator() == registry.ExpressionOperatorWithinTimeWindow {
		return r.runtimeWithinTimeWindow(fact.Value(), expression.Reference())
	}

	operands := expression.Values()
	if expression.Reference() != "" {
		operands = append([]decision.Value(nil), r.conditionSets[expression.Reference()]...)
	}

	return matchAttributeOperator(expression.Operator(), fact.Value(), operands)
}

// matchAttributeOperator applies the closed expression operator matrix.
func matchAttributeOperator(
	operator registry.ExpressionOperator,
	fact decision.Value,
	operands []decision.Value,
) bool {
	switch operator {
	case registry.ExpressionOperatorIs, registry.ExpressionOperatorEqual, registry.ExpressionOperatorEQ,
		registry.ExpressionOperatorNotEqual, registry.ExpressionOperatorIn, registry.ExpressionOperatorNotIn:
		return matchRuntimeSetOperator(operator, fact, operands)
	case registry.ExpressionOperatorMatches:
		return matchesRuntimePattern(fact, operands)
	case registry.ExpressionOperatorContains, registry.ExpressionOperatorContainsAny,
		registry.ExpressionOperatorContainsAll, registry.ExpressionOperatorContainsNone:
		return matchRuntimeContainsOperator(operator, fact, operands)
	case registry.ExpressionOperatorGT, registry.ExpressionOperatorGTE,
		registry.ExpressionOperatorLT, registry.ExpressionOperatorLTE:
		return orderedRuntimeValue(operator, fact, operands)
	case registry.ExpressionOperatorCIDRContains:
		return runtimeCIDRContains(fact, operands)
	default:
		return false
	}
}

// matchRuntimeSetOperator evaluates equality and exact membership operators.
func matchRuntimeSetOperator(
	operator registry.ExpressionOperator,
	fact decision.Value,
	operands []decision.Value,
) bool {
	matched := slices.ContainsFunc(operands, func(value decision.Value) bool {
		return equalRuntimeValue(fact, value)
	})

	switch operator {
	case registry.ExpressionOperatorIs, registry.ExpressionOperatorEqual, registry.ExpressionOperatorEQ:
		return len(operands) == 1 && matched
	case registry.ExpressionOperatorNotEqual:
		return len(operands) == 1 && !matched
	case registry.ExpressionOperatorIn:
		return matched
	default:
		return !matched
	}
}

// matchRuntimeContainsOperator maps exact containment operators to one list matcher.
func matchRuntimeContainsOperator(
	operator registry.ExpressionOperator,
	fact decision.Value,
	operands []decision.Value,
) bool {
	switch operator {
	case registry.ExpressionOperatorContains, registry.ExpressionOperatorContainsAny:
		return containsRuntimeStrings(fact, operands, "any")
	case registry.ExpressionOperatorContainsAll:
		return containsRuntimeStrings(fact, operands, "all")
	default:
		return containsRuntimeStrings(fact, operands, "none")
	}
}

// equalRuntimeValue compares exact constructed values by active member.
func equalRuntimeValue(left decision.Value, right decision.Value) bool {
	if left.Kind() != right.Kind() {
		return false
	}

	switch left.Kind() {
	case decision.ValueKindString:
		leftValue, _ := left.StringValue()
		rightValue, _ := right.StringValue()

		return leftValue == rightValue
	case decision.ValueKindBoolean:
		leftValue, _ := left.Boolean()
		rightValue, _ := right.Boolean()

		return leftValue == rightValue
	case decision.ValueKindInteger:
		leftValue, _ := left.Integer()
		rightValue, _ := right.Integer()

		return leftValue == rightValue
	case decision.ValueKindDouble:
		leftValue, _ := left.Double()
		rightValue, _ := right.Double()

		return leftValue == rightValue
	case decision.ValueKindStrings:
		leftValue, _ := left.Strings()
		rightValue, _ := right.Strings()

		return slices.Equal(leftValue, rightValue)
	case decision.ValueKindBytes:
		leftValue, _ := left.Bytes()
		rightValue, _ := right.Bytes()

		return slices.Equal(leftValue, rightValue)
	case decision.ValueKindTimestamp:
		leftValue, _ := left.Timestamp()
		rightValue, _ := right.Timestamp()

		return leftValue.Equal(rightValue)
	default:
		return false
	}
}

// matchesRuntimePattern evaluates one compiler-validated regular expression.
func matchesRuntimePattern(fact decision.Value, operands []decision.Value) bool {
	if len(operands) != 1 {
		return false
	}

	text, textOK := fact.StringValue()

	pattern, patternOK := operands[0].StringValue()
	if !textOK || !patternOK {
		return false
	}

	compiled, err := regexp.Compile(pattern)

	return err == nil && compiled.MatchString(text)
}

// containsRuntimeStrings evaluates exact string-list containment modes.
func containsRuntimeStrings(fact decision.Value, operands []decision.Value, mode string) bool {
	members, ok := fact.Strings()
	if !ok {
		return false
	}

	matches := 0

	for _, operand := range operands {
		value, stringOK := operand.StringValue()
		if stringOK && slices.Contains(members, value) {
			matches++
		}
	}

	switch mode {
	case "all":
		return matches == len(operands)
	case "none":
		return matches == 0
	default:
		return matches > 0
	}
}

// orderedRuntimeValue evaluates integer, double, and timestamp comparisons.
func orderedRuntimeValue(
	operator registry.ExpressionOperator,
	fact decision.Value,
	operands []decision.Value,
) bool {
	if len(operands) != 1 {
		return false
	}

	comparison, ok := compareRuntimeValue(fact, operands[0])
	if !ok {
		return false
	}

	switch operator {
	case registry.ExpressionOperatorGT:
		return comparison > 0
	case registry.ExpressionOperatorGTE:
		return comparison >= 0
	case registry.ExpressionOperatorLT:
		return comparison < 0
	case registry.ExpressionOperatorLTE:
		return comparison <= 0
	default:
		return false
	}
}

// compareRuntimeValue returns one strict ordered comparison.
func compareRuntimeValue(left decision.Value, right decision.Value) (int, bool) {
	if left.Kind() != right.Kind() {
		return 0, false
	}

	switch left.Kind() {
	case decision.ValueKindInteger:
		leftValue, _ := left.Integer()
		rightValue, _ := right.Integer()

		return compareOrdered(leftValue, rightValue), true
	case decision.ValueKindDouble:
		leftValue, _ := left.Double()
		rightValue, _ := right.Double()

		return compareOrdered(leftValue, rightValue), true
	case decision.ValueKindTimestamp:
		leftValue, _ := left.Timestamp()
		rightValue, _ := right.Timestamp()

		return compareOrdered(leftValue.UnixNano(), rightValue.UnixNano()), true
	default:
		return 0, false
	}
}

// compareOrdered normalizes one ordered primitive comparison.
func compareOrdered[T ~int64 | ~float64](left T, right T) int {
	if left < right {
		return -1
	}

	if left > right {
		return 1
	}

	return 0
}

// runtimeCIDRContains evaluates an address fact against exact address or prefix operands.
func runtimeCIDRContains(fact decision.Value, operands []decision.Value) bool {
	text, ok := fact.StringValue()
	if !ok {
		return false
	}

	address, err := netip.ParseAddr(text)
	if err != nil {
		return false
	}

	for _, operand := range operands {
		network, stringOK := operand.StringValue()
		if !stringOK {
			continue
		}

		if prefix, prefixErr := netip.ParsePrefix(network); prefixErr == nil && prefix.Contains(address) {
			return true
		}

		if exact, exactErr := netip.ParseAddr(network); exactErr == nil && exact == address {
			return true
		}
	}

	return false
}

// runtimeWithinTimeWindow evaluates one source-owned recurring local-time schedule.
func (r *checkpointRuntime) runtimeWithinTimeWindow(fact decision.Value, reference string) bool {
	instant, ok := fact.Timestamp()
	if !ok {
		return false
	}

	name, ok := strings.CutPrefix(reference, "@time_window.")
	if !ok {
		return false
	}

	window, ok := r.timeWindows[name]

	return ok && window.Contains(instant)
}

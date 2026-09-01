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

package registry

import (
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/internal/identifier"
)

const (
	maximumExpressionValues     = 64
	maximumExpressionValueBytes = 64 * 1024
	maximumExpressionChildren   = 64
	maximumExpressionDepth      = 16
	maximumExpressionNodes      = 256
)

var (
	// ErrInvalidPolicyExpression identifies an incomplete or untyped rule condition.
	ErrInvalidPolicyExpression = errors.New("invalid policy expression")
)

// ExpressionKind identifies one closed logical condition-tree node shape.
type ExpressionKind string

const (
	// ExpressionKindAttribute identifies one exact typed fact predicate.
	ExpressionKindAttribute ExpressionKind = "attribute"

	// ExpressionKindAll requires every child to match.
	ExpressionKindAll ExpressionKind = "all"

	// ExpressionKindAny requires at least one child to match.
	ExpressionKindAny ExpressionKind = "any"

	// ExpressionKindNot negates its sole child.
	ExpressionKindNot ExpressionKind = "not"

	// ExpressionKindAlways matches without reading a fact.
	ExpressionKindAlways ExpressionKind = "always"

	// ExpressionKindRecordQuantifier evaluates one record-local predicate over one exact records fact.
	ExpressionKindRecordQuantifier ExpressionKind = "record_quantifier"
)

// RecordQuantifier identifies one closed record-local collection predicate.
type RecordQuantifier string

const (
	// RecordQuantifierAny matches when at least one record-local predicate matches.
	RecordQuantifierAny RecordQuantifier = "any"

	// RecordQuantifierAll matches when every admitted record-local predicate matches.
	RecordQuantifierAll RecordQuantifier = "all"

	// RecordQuantifierNone matches when no admitted record-local predicate matches.
	RecordQuantifierNone RecordQuantifier = "none"
)

// IsValid reports whether the quantifier belongs to the closed vocabulary.
func (q RecordQuantifier) IsValid() bool {
	return q == RecordQuantifierAny || q == RecordQuantifierAll || q == RecordQuantifierNone
}

// ExpressionOperator is the closed executable source-expression vocabulary.
type ExpressionOperator string

const (
	// ExpressionOperatorAlways matches without reading a fact.
	ExpressionOperatorAlways ExpressionOperator = "always"

	// ExpressionOperatorIs compares one fact with one exact typed value.
	ExpressionOperatorIs ExpressionOperator = "is"

	// ExpressionOperatorEqual compares one fact with one exact typed value.
	ExpressionOperatorEqual ExpressionOperator = "equal"

	// ExpressionOperatorEQ retains the canonical current-policy eq spelling.
	ExpressionOperatorEQ ExpressionOperator = "eq"

	// ExpressionOperatorNotEqual rejects one exact typed value.
	ExpressionOperatorNotEqual ExpressionOperator = "ne"

	// ExpressionOperatorIn compares one scalar fact with a bounded typed value set.
	ExpressionOperatorIn ExpressionOperator = "in"

	// ExpressionOperatorNotIn rejects a bounded typed value set.
	ExpressionOperatorNotIn ExpressionOperator = "not_in"

	// ExpressionOperatorMatches evaluates one bounded regular expression.
	ExpressionOperatorMatches ExpressionOperator = "matches"

	// ExpressionOperatorExists tests fact presence against a boolean operand.
	ExpressionOperatorExists ExpressionOperator = "exists"

	// ExpressionOperatorContains tests one string-list member.
	ExpressionOperatorContains ExpressionOperator = "contains"

	// ExpressionOperatorContainsAny tests a bounded string member set.
	ExpressionOperatorContainsAny ExpressionOperator = "contains_any"

	// ExpressionOperatorContainsAll tests a bounded string member set.
	ExpressionOperatorContainsAll ExpressionOperator = "contains_all"

	// ExpressionOperatorContainsNone rejects a bounded string member set.
	ExpressionOperatorContainsNone ExpressionOperator = "contains_none"

	// ExpressionOperatorGT compares an ordered fact with a lower bound.
	ExpressionOperatorGT ExpressionOperator = "gt"

	// ExpressionOperatorGTE compares an ordered fact with an inclusive lower bound.
	ExpressionOperatorGTE ExpressionOperator = "gte"

	// ExpressionOperatorLT compares an ordered fact with an upper bound.
	ExpressionOperatorLT ExpressionOperator = "lt"

	// ExpressionOperatorLTE compares an ordered fact with an inclusive upper bound.
	ExpressionOperatorLTE ExpressionOperator = "lte"

	// ExpressionOperatorCIDRContains tests an IP/CIDR encoded string against a network operand.
	ExpressionOperatorCIDRContains ExpressionOperator = "cidr_contains"

	// ExpressionOperatorWithinTimeWindow tests a timestamp against a source-owned window reference.
	ExpressionOperatorWithinTimeWindow ExpressionOperator = "within_time_window"
)

// PolicyExpressionInput carries one complete executable condition-tree node into its constructor.
type PolicyExpressionInput struct {
	Kind            ExpressionKind
	FactID          string
	FactKind        decision.ValueKind
	Operator        ExpressionOperator
	Reference       string
	Values          []decision.Value
	Children        []PolicyExpression
	RecordField     string
	RecordFieldKind decision.ValueKind
	Quantifier      RecordQuantifier
}

// PolicyExpression is one immutable executable condition-tree node.
type PolicyExpression struct {
	factID          string
	reference       string
	values          []decision.Value
	children        []PolicyExpression
	kind            ExpressionKind
	operator        ExpressionOperator
	factKind        decision.ValueKind
	recordField     string
	recordFieldKind decision.ValueKind
	quantifier      RecordQuantifier
}

// NewPolicyExpression validates and deeply owns one complete executable condition tree.
func NewPolicyExpression(input PolicyExpressionInput) (PolicyExpression, error) {
	expression := PolicyExpression{
		factID:          input.FactID,
		reference:       input.Reference,
		values:          append([]decision.Value(nil), input.Values...),
		children:        clonePolicyExpressions(input.Children),
		kind:            inferredExpressionKind(input),
		operator:        input.Operator,
		factKind:        input.FactKind,
		recordField:     input.RecordField,
		recordFieldKind: input.RecordFieldKind,
		quantifier:      input.Quantifier,
	}

	if expression.kind == ExpressionKindAlways && expression.operator == "" {
		expression.operator = ExpressionOperatorAlways
	}

	if expression.kind == ExpressionKindAttribute && !expression.factKind.IsValid() {
		expression.factKind = inferredFactKind(expression.operator, expression.values)
	}

	if expression.kind == ExpressionKindRecordQuantifier {
		expression.factKind = decision.ValueKindRecords
	}

	state := expressionValidationState{}
	if err := expression.validate(1, &state); err != nil {
		return PolicyExpression{}, err
	}

	return expression, nil
}

// Kind returns the exact logical node shape.
func (e PolicyExpression) Kind() ExpressionKind {
	return e.kind
}

// FactID returns the exact referenced fact or empty for logical nodes.
func (e PolicyExpression) FactID() string {
	return e.factID
}

// FactKind returns the exact schema kind required by an attribute node.
func (e PolicyExpression) FactKind() decision.ValueKind {
	return e.factKind
}

// Operator returns the executable comparison operator.
func (e PolicyExpression) Operator() ExpressionOperator {
	return e.operator
}

// Reference returns an optional source-owned condition-set reference.
func (e PolicyExpression) Reference() string {
	return e.reference
}

// Values returns detached immutable expected values.
func (e PolicyExpression) Values() []decision.Value {
	return append([]decision.Value(nil), e.values...)
}

// Children returns a deeply detached ordered logical child list.
func (e PolicyExpression) Children() []PolicyExpression {
	return clonePolicyExpressions(e.children)
}

// RecordField returns the exact schema-owned record-local field name.
func (e PolicyExpression) RecordField() string {
	return e.recordField
}

// RecordFieldKind returns the exact non-recursive field kind.
func (e PolicyExpression) RecordFieldKind() decision.ValueKind {
	return e.recordFieldKind
}

// Quantifier returns the closed record-list quantifier.
func (e PolicyExpression) Quantifier() RecordQuantifier {
	return e.quantifier
}

// FactContract returns the exact leaf fact/type requirement when this node is an attribute.
func (e PolicyExpression) FactContract() (FactContract, bool) {
	if e.kind != ExpressionKindAttribute && e.kind != ExpressionKindRecordQuantifier {
		return FactContract{}, false
	}

	return FactContract{id: e.factID, kind: e.factKind}, true
}

// FactContracts returns every exact tree fact/type requirement in first-use order.
func (e PolicyExpression) FactContracts() []FactContract {
	result := make([]FactContract, 0)
	seen := make(map[string]struct{})
	e.collectFactContracts(&result, seen)

	return result
}

// Valid reports whether the immutable expression satisfies its constructor invariant.
func (e PolicyExpression) Valid() bool {
	state := expressionValidationState{}

	return e.validate(1, &state) == nil
}

// valid reports whether the immutable expression satisfies its constructor invariant.
func (e PolicyExpression) valid() bool {
	return e.Valid()
}

// clone returns one deeply detached condition tree.
func (e PolicyExpression) clone() PolicyExpression {
	e.values = e.Values()
	e.children = e.Children()

	return e
}

// Equal reports exact immutable condition-tree equality.
func (e PolicyExpression) Equal(other PolicyExpression) bool {
	if e.kind != other.kind || e.factID != other.factID || e.factKind != other.factKind ||
		e.operator != other.operator || e.reference != other.reference ||
		e.recordField != other.recordField || e.recordFieldKind != other.recordFieldKind || e.quantifier != other.quantifier ||
		!equalDecisionValues(e.values, other.values) || len(e.children) != len(other.children) {
		return false
	}

	for index := range e.children {
		if !e.children[index].Equal(other.children[index]) {
			return false
		}
	}

	return true
}

// expressionValidationState bounds and type-checks one complete condition tree.
type expressionValidationState struct {
	facts map[string]decision.ValueKind
	nodes int
}

// validate enforces complete tree shape, bounds, operators, and consistent fact types.
func (e PolicyExpression) validate(depth int, state *expressionValidationState) error {
	state.nodes++
	if depth > maximumExpressionDepth || state.nodes > maximumExpressionNodes {
		return invalidExpression(e.factID, "condition tree exceeds depth or node bounds")
	}

	if e.kind == ExpressionKindAttribute {
		return e.validateAttribute(state)
	}

	if e.kind == ExpressionKindRecordQuantifier {
		return e.validateRecordQuantifier(state)
	}

	if err := e.validateLogical(); err != nil {
		return err
	}

	for _, child := range e.children {
		if err := child.validate(depth+1, state); err != nil {
			return err
		}
	}

	return nil
}

// validateLogical enforces one unconditional or compound logical node shape.
func (e PolicyExpression) validateLogical() error {
	switch e.kind {
	case ExpressionKindAlways:
		return e.validateAlways()
	case ExpressionKindAll, ExpressionKindAny:
		return e.validateMultiChildLogical()
	case ExpressionKindNot:
		return e.validateNot()
	default:
		return invalidExpression(e.factID, "condition node kind is invalid")
	}
}

// validateAlways rejects leaf and child state on an unconditional expression.
func (e PolicyExpression) validateAlways() error {
	if e.operator != ExpressionOperatorAlways || !e.logicalFieldsEmptyExceptOperator() || len(e.children) != 0 {
		return invalidExpression(e.factID, "always cannot declare fact, operands, reference, or children")
	}

	return nil
}

// validateMultiChildLogical enforces bounded all/any child lists.
func (e PolicyExpression) validateMultiChildLogical() error {
	if !e.logicalFieldsEmpty() || len(e.children) == 0 || len(e.children) > maximumExpressionChildren {
		return invalidExpression(e.factID, "all/any require bounded children and no attribute fields")
	}

	return nil
}

// validateNot enforces one exact logical child.
func (e PolicyExpression) validateNot() error {
	if !e.logicalFieldsEmpty() || len(e.children) != 1 {
		return invalidExpression(e.factID, "not requires one child and no attribute fields")
	}

	return nil
}

// validateAttribute enforces exact operator and operand compatibility.
func (e PolicyExpression) validateAttribute(state *expressionValidationState) error {
	if !identifier.Fact(e.factID) || !e.factKind.IsValid() || len(e.children) != 0 ||
		e.recordField != "" || e.recordFieldKind != "" || e.quantifier != "" {
		return invalidExpression(e.factID, "attribute nodes require one canonical typed fact and no children")
	}

	if state.facts == nil {
		state.facts = make(map[string]decision.ValueKind)
	}

	if current, exists := state.facts[e.factID]; exists && !decision.ValueKindsCompatible(current, e.factKind) {
		return invalidExpression(e.factID, "fact has incompatible kinds inside one condition tree")
	}

	state.facts[e.factID] = e.factKind

	if err := validateExpressionOperands(e); err != nil {
		return err
	}

	return nil
}

// validateRecordQuantifier enforces one flat record-local predicate without child state.
func (e PolicyExpression) validateRecordQuantifier(state *expressionValidationState) error {
	if !identifier.Fact(e.factID) || e.factKind != decision.ValueKindRecords ||
		!identifier.Action(e.recordField) || !e.recordFieldKind.IsValid() ||
		e.recordFieldKind == decision.ValueKindRecords || !e.quantifier.IsValid() || len(e.children) != 0 {
		return invalidExpression(e.factID, "record quantifiers require one exact records fact and one non-recursive local field")
	}

	if state.facts == nil {
		state.facts = make(map[string]decision.ValueKind)
	}

	if current, exists := state.facts[e.factID]; exists && current != decision.ValueKindRecords {
		return invalidExpression(e.factID, "fact has incompatible kinds inside one condition tree")
	}

	state.facts[e.factID] = decision.ValueKindRecords
	leaf := e
	leaf.kind = ExpressionKindAttribute
	leaf.factKind = e.recordFieldKind
	leaf.recordField = ""
	leaf.recordFieldKind = ""
	leaf.quantifier = ""

	return validateExpressionOperands(leaf)
}

// logicalFieldsEmpty reports whether a logical node carries no leaf-only state.
func (e PolicyExpression) logicalFieldsEmpty() bool {
	return e.factID == "" && e.factKind == "" && e.operator == "" && e.reference == "" && len(e.values) == 0 &&
		e.recordField == "" && e.recordFieldKind == "" && e.quantifier == ""
}

// logicalFieldsEmptyExceptOperator supports the immutable always marker.
func (e PolicyExpression) logicalFieldsEmptyExceptOperator() bool {
	return e.factID == "" && e.factKind == "" && e.reference == "" && len(e.values) == 0 &&
		e.recordField == "" && e.recordFieldKind == "" && e.quantifier == ""
}

type expressionOperandValidator func(PolicyExpression) error

var expressionOperandValidators = map[ExpressionOperator]expressionOperandValidator{
	ExpressionOperatorIs:               validateExactExpressionOperand,
	ExpressionOperatorEqual:            validateExactExpressionOperand,
	ExpressionOperatorEQ:               validateExactExpressionOperand,
	ExpressionOperatorNotEqual:         validateExactExpressionOperand,
	ExpressionOperatorIn:               validateMembershipExpressionOperand,
	ExpressionOperatorNotIn:            validateMembershipExpressionOperand,
	ExpressionOperatorMatches:          validatePatternExpressionOperand,
	ExpressionOperatorExists:           validateExistsExpressionOperand,
	ExpressionOperatorContains:         validateContainsExpressionOperand,
	ExpressionOperatorContainsAny:      validateContainsSetExpressionOperand,
	ExpressionOperatorContainsAll:      validateContainsSetExpressionOperand,
	ExpressionOperatorContainsNone:     validateContainsSetExpressionOperand,
	ExpressionOperatorGT:               validateOrderedExpressionOperand,
	ExpressionOperatorGTE:              validateOrderedExpressionOperand,
	ExpressionOperatorLT:               validateOrderedExpressionOperand,
	ExpressionOperatorLTE:              validateOrderedExpressionOperand,
	ExpressionOperatorCIDRContains:     validateNetworkExpressionOperand,
	ExpressionOperatorWithinTimeWindow: validateTimeWindowExpressionOperand,
}

// validateExpressionOperands applies the closed operator/type/cardinality matrix.
func validateExpressionOperands(expression PolicyExpression) error {
	if expression.reference != "" && len(expression.values) != 0 {
		return invalidExpression(expression.factID, "reference and inline operands are mutually exclusive")
	}

	if len(expression.values) > maximumExpressionValues || !constructedExpressionValues(expression.values) {
		return invalidExpression(expression.factID, "operands must be bounded constructed strict values")
	}

	if !expressionValuesWithinByteBound(expression.values) {
		return invalidExpression(expression.factID, "operands exceed the aggregate byte bound")
	}

	validator, exists := expressionOperandValidators[expression.operator]
	if !exists {
		return invalidExpression(expression.factID, "operator is outside the closed condition vocabulary")
	}

	return validator(expression)
}

// expressionValuesWithinByteBound rejects oversized inline strings, lists, and byte operands.
func expressionValuesWithinByteBound(values []decision.Value) bool {
	remaining := maximumExpressionValueBytes

	for _, value := range values {
		size := expressionValueBytes(value)
		if size > remaining {
			return false
		}

		remaining -= size
	}

	return true
}

// expressionValueBytes reports the bounded payload size of one strict value.
func expressionValueBytes(value decision.Value) int {
	switch value.Kind() {
	case decision.ValueKindString:
		text, _ := value.StringValue()

		return len(text)
	case decision.ValueKindStrings:
		members, _ := value.Strings()
		total := 0

		for _, member := range members {
			if len(member) > maximumExpressionValueBytes-total {
				return maximumExpressionValueBytes + 1
			}

			total += len(member)
		}

		return total
	case decision.ValueKindBytes:
		data, _ := value.Bytes()

		return len(data)
	case decision.ValueKindBoolean:
		return 1
	default:
		return 8
	}
}

// validateExactExpressionOperand checks is/eq/ne scalar equality operands.
func validateExactExpressionOperand(expression PolicyExpression) error {
	return requireExpressionValues(expression, 1, expression.factKind)
}

// validateMembershipExpressionOperand checks scalar inline or string-set membership.
func validateMembershipExpressionOperand(expression PolicyExpression) error {
	if expression.factKind == decision.ValueKindStrings || expression.factKind == decision.ValueKindBytes {
		return invalidExpression(expression.factID, "membership requires a scalar fact")
	}

	if expression.reference != "" {
		return requireExpressionReference(expression, "@string.")
	}

	return requireExpressionValueRange(expression, 1, maximumExpressionValues, expression.factKind)
}

// validatePatternExpressionOperand checks string facts and compilable patterns.
func validatePatternExpressionOperand(expression PolicyExpression) error {
	if expression.factKind != decision.ValueKindString {
		return invalidExpression(expression.factID, "matches requires a string fact")
	}

	if err := requireExpressionValues(expression, 1, decision.ValueKindString); err != nil {
		return err
	}

	pattern, _ := expression.values[0].StringValue()
	if _, err := regexp.Compile(pattern); err != nil {
		return invalidExpression(expression.factID, "matches operand must compile as a regular expression")
	}

	return nil
}

// validateExistsExpressionOperand checks the boolean presence selector.
func validateExistsExpressionOperand(expression PolicyExpression) error {
	return requireExpressionValues(expression, 1, decision.ValueKindBoolean)
}

// validateContainsExpressionOperand checks one string-list member.
func validateContainsExpressionOperand(expression PolicyExpression) error {
	if expression.factKind != decision.ValueKindStrings {
		return invalidExpression(expression.factID, "contains requires a string-list fact")
	}

	return requireExpressionValues(expression, 1, decision.ValueKindString)
}

// validateContainsSetExpressionOperand checks bounded string-list member sets.
func validateContainsSetExpressionOperand(expression PolicyExpression) error {
	if expression.factKind != decision.ValueKindStrings {
		return invalidExpression(expression.factID, "containment set operators require a string-list fact")
	}

	return requireExpressionValueRange(expression, 1, maximumExpressionValues, decision.ValueKindString)
}

// validateOrderedExpressionOperand checks comparable numeric or timestamp operands.
func validateOrderedExpressionOperand(expression PolicyExpression) error {
	if !slices.Contains([]decision.ValueKind{decision.ValueKindInteger, decision.ValueKindDouble, decision.ValueKindTimestamp}, expression.factKind) {
		return invalidExpression(expression.factID, "ordered comparison requires integer, double, or timestamp")
	}

	return requireExpressionValues(expression, 1, expression.factKind)
}

// validateNetworkExpressionOperand checks inline or referenced IP/CIDR operands.
func validateNetworkExpressionOperand(expression PolicyExpression) error {
	if expression.factKind != decision.ValueKindString {
		return invalidExpression(expression.factID, "cidr_contains requires an IP/CIDR string fact")
	}

	if expression.reference != "" {
		return requireExpressionReference(expression, "@network.")
	}

	if err := requireExpressionValues(expression, 1, decision.ValueKindString); err != nil {
		return err
	}

	network, _ := expression.values[0].StringValue()
	if _, prefixErr := netip.ParsePrefix(network); prefixErr == nil {
		return nil
	}

	if _, addressErr := netip.ParseAddr(network); addressErr != nil {
		return invalidExpression(expression.factID, "cidr_contains requires one IP or CIDR operand")
	}

	return nil
}

// validateTimeWindowExpressionOperand checks exact timestamp and source window reference semantics.
func validateTimeWindowExpressionOperand(expression PolicyExpression) error {
	if expression.factKind != decision.ValueKindTimestamp || expression.reference == "" || len(expression.values) != 0 {
		return invalidExpression(expression.factID, "within_time_window requires a timestamp fact and source-owned reference")
	}

	return requireExpressionReference(expression, "@time_window.")
}

// requireExpressionReference validates an operator-specific source-owned set family.
func requireExpressionReference(expression PolicyExpression, prefix string) error {
	name, found := strings.CutPrefix(expression.reference, prefix)
	if !found || !identifier.Action(name) {
		return invalidExpression(expression.factID, "operator has an incompatible condition-set reference")
	}

	return nil
}

// requireExpressionValues enforces exact operand count and kind.
func requireExpressionValues(expression PolicyExpression, count int, kind decision.ValueKind) error {
	return requireExpressionValueRange(expression, count, count, kind)
}

// requireExpressionValueRange enforces bounded homogeneous strict operands.
func requireExpressionValueRange(expression PolicyExpression, minimum int, maximum int, kind decision.ValueKind) error {
	if expression.reference != "" || len(expression.values) < minimum || len(expression.values) > maximum {
		return invalidExpression(expression.factID, "operator has invalid operand cardinality")
	}

	for _, value := range expression.values {
		if value.Kind() != kind {
			return invalidExpression(expression.factID, "operator operand kind is incompatible with its fact")
		}
	}

	return nil
}

// constructedExpressionValues reports whether all strict operands carry a valid kind.
func constructedExpressionValues(values []decision.Value) bool {
	for _, value := range values {
		if !value.Kind().IsValid() {
			return false
		}
	}

	return true
}

// inferredExpressionKind preserves the compact legacy leaf constructor surface.
func inferredExpressionKind(input PolicyExpressionInput) ExpressionKind {
	if input.Kind != "" {
		return input.Kind
	}

	if input.Operator == ExpressionOperatorAlways {
		return ExpressionKindAlways
	}

	return ExpressionKindAttribute
}

// inferredFactKind derives ordinary leaf types while keeping special operands explicit.
func inferredFactKind(operator ExpressionOperator, values []decision.Value) decision.ValueKind {
	if len(values) == 0 || operator == ExpressionOperatorExists {
		return ""
	}

	if slices.Contains(
		[]ExpressionOperator{ExpressionOperatorContains, ExpressionOperatorContainsAny, ExpressionOperatorContainsAll, ExpressionOperatorContainsNone},
		operator,
	) {
		return decision.ValueKindStrings
	}

	if operator == ExpressionOperatorCIDRContains {
		return decision.ValueKindString
	}

	return values[0].Kind()
}

// collectFactContracts preserves first-use order while the constructor guarantees compatible kinds.
func (e PolicyExpression) collectFactContracts(result *[]FactContract, seen map[string]struct{}) {
	if contract, exists := e.FactContract(); exists {
		if _, duplicate := seen[contract.ID()]; !duplicate {
			seen[contract.ID()] = struct{}{}
			*result = append(*result, contract)
		}
	}

	for _, child := range e.children {
		child.collectFactContracts(result, seen)
	}
}

// clonePolicyExpressions deeply owns one ordered child list.
func clonePolicyExpressions(values []PolicyExpression) []PolicyExpression {
	result := make([]PolicyExpression, 0, len(values))
	for _, value := range values {
		value.values = value.Values()
		value.children = clonePolicyExpressions(value.children)
		result = append(result, value)
	}

	return result
}

// equalDecisionValues compares exact ordered strict operands through their public members.
func equalDecisionValues(left []decision.Value, right []decision.Value) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if !equalDecisionValue(left[index], right[index]) {
			return false
		}
	}

	return true
}

// equalDecisionValue compares one strict value without depending on private representation.
func equalDecisionValue(left decision.Value, right decision.Value) bool {
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

// invalidExpression binds a stable validation error to the expression fact.
func invalidExpression(factID string, reason string) error {
	return newValidationError(ErrInvalidPolicyExpression, "policy_rule.expression", factID, reason)
}

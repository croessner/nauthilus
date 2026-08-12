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
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/internal/identifier"

	"golang.org/x/text/language"
)

const (
	// BuiltinStandardAuthPolicySet is the sole qualified builtin authn policy-set identity.
	BuiltinStandardAuthPolicySet = "authn/standard_auth"

	maximumPolicySetEntries        = 256
	builtinPolicyClassStandardAuth = "standard_auth"
	responseSourceAttribute        = "attribute"
	responseSourceAttributeDetail  = "attribute_detail"
	responseSourceDefault          = "default"
	responseSourceI18N             = "i18n"
	responseSourceLiteral          = "literal"
)

var (
	// ErrInvalidPolicySetIdentity identifies non-canonical or unqualified set names.
	ErrInvalidPolicySetIdentity = errors.New("invalid policy set identity")

	// ErrInvalidPolicySetDefinition identifies an incomplete set descriptor.
	ErrInvalidPolicySetDefinition = errors.New("invalid policy set definition")

	// ErrInvalidExportContract identifies an incomplete typed export capability.
	ErrInvalidExportContract = errors.New("invalid policy set export contract")

	// ErrBuiltinPolicySetImmutable identifies attempts to configure builtin policy-set metadata.
	ErrBuiltinPolicySetImmutable = errors.New("builtin policy set descriptor is immutable")

	// ErrInvalidCheckpoint identifies a non-canonical plan checkpoint.
	ErrInvalidCheckpoint = errors.New("invalid policy checkpoint")
)

// PolicySetID is one canonical namespace-nested policy-set identity.
type PolicySetID struct {
	namespace string
	name      string
}

// NewPolicySetID constructs one exact namespace/name policy-set identity.
func NewPolicySetID(namespace string, name string) (PolicySetID, error) {
	return ParsePolicySetID("policy_set", namespace+"/"+name)
}

// ParsePolicySetID validates one exact qualified policy-set reference.
func ParsePolicySetID(path string, value string) (PolicySetID, error) {
	if !identifier.Qualified(value) {
		return PolicySetID{}, newValidationError(
			ErrInvalidPolicySetIdentity,
			path,
			value,
			"must be an exact namespace/name identity without wildcards",
		)
	}

	separator := slices.Index([]byte(value), byte('/'))

	return PolicySetID{namespace: value[:separator], name: value[separator+1:]}, nil
}

// Namespace returns the owning set namespace.
func (i PolicySetID) Namespace() string {
	return i.namespace
}

// Name returns the namespace-local set name.
func (i PolicySetID) Name() string {
	return i.name
}

// String returns the canonical namespace/name identity.
func (i PolicySetID) String() string {
	return i.namespace + "/" + i.name
}

// IsZero reports whether no default policy-set identity was configured.
func (i PolicySetID) IsZero() bool {
	return i.namespace == "" && i.name == ""
}

// valid reports whether the identity satisfies its constructor invariant.
func (i PolicySetID) valid() bool {
	return identifier.Qualified(i.String())
}

// PolicySetVisibility controls exact cross-namespace import eligibility.
type PolicySetVisibility string

const (
	// PolicySetVisibilityPrivate keeps a set inside its owning namespace.
	PolicySetVisibilityPrivate PolicySetVisibility = "private"

	// PolicySetVisibilityExported permits exact typed cross-namespace imports.
	PolicySetVisibilityExported PolicySetVisibility = "exported"
)

// valid reports whether visibility belongs to the closed contract.
func (v PolicySetVisibility) valid() bool {
	return v == PolicySetVisibilityPrivate || v == PolicySetVisibilityExported
}

// FactContract is one exact fact/type requirement in an import capability.
type FactContract struct {
	id   string
	kind decision.ValueKind
}

// NewFactContract constructs one exact typed fact requirement.
func NewFactContract(id string, kind decision.ValueKind) (FactContract, error) {
	if !identifier.Fact(id) || !kind.IsValid() {
		return FactContract{}, newValidationError(
			ErrInvalidExportContract,
			"export_contract.facts",
			id,
			"must contain a canonical fact and exact value kind",
		)
	}

	return FactContract{id: id, kind: kind}, nil
}

// ID returns the exact fact identity.
func (c FactContract) ID() string {
	return c.id
}

// Kind returns the required strict value kind.
func (c FactContract) Kind() decision.ValueKind {
	return c.kind
}

// valid reports whether the fact contract is constructor validated.
func (c FactContract) valid() bool {
	return identifier.Fact(c.id) && c.kind.IsValid()
}

// ExportContract is one complete exact cross-namespace set capability.
type ExportContract struct {
	checkpoints []string
	facts       []FactContract
	decisions   []decision.Effect
	effects     []string
	constructed bool
}

// NewExportContract constructs one complete typed set capability.
func NewExportContract(
	checkpoint string,
	facts []FactContract,
	decisions []decision.Effect,
	effects []string,
) (ExportContract, error) {
	return NewExportContractForCheckpoints([]string{checkpoint}, facts, decisions, effects)
}

// NewExportContractForCheckpoints constructs one reusable exact typed set capability.
func NewExportContractForCheckpoints(
	checkpoints []string,
	facts []FactContract,
	decisions []decision.Effect,
	effects []string,
) (ExportContract, error) {
	clonedCheckpoints, err := cloneUniqueCheckpoints(checkpoints)
	if err != nil {
		return ExportContract{}, err
	}

	if len(decisions) == 0 {
		return ExportContract{}, newValidationError(
			ErrInvalidExportContract,
			"export_contract",
			"",
			"must declare compatible checkpoints and at least one decision",
		)
	}

	clonedFacts, err := cloneUniqueFactContracts(facts, "export_contract.facts")
	if err != nil {
		return ExportContract{}, err
	}

	clonedDecisions, err := cloneUniqueDecisions(decisions)
	if err != nil {
		return ExportContract{}, err
	}

	clonedEffects, err := cloneUniqueQualifiedIDs(effects, "export_contract.effects")
	if err != nil {
		return ExportContract{}, err
	}

	return ExportContract{
		checkpoints: clonedCheckpoints,
		facts:       clonedFacts,
		decisions:   clonedDecisions,
		effects:     clonedEffects,
		constructed: true,
	}, nil
}

// Checkpoints returns detached exact compatible checkpoints.
func (c ExportContract) Checkpoints() []string {
	return append([]string(nil), c.checkpoints...)
}

// SupportsCheckpoint reports whether the capability permits an exact checkpoint.
func (c ExportContract) SupportsCheckpoint(checkpoint string) bool {
	return slices.Contains(c.checkpoints, checkpoint)
}

// Facts returns detached exact fact requirements.
func (c ExportContract) Facts() []FactContract {
	return append([]FactContract(nil), c.facts...)
}

// Decisions returns detached allowed result effects.
func (c ExportContract) Decisions() []decision.Effect {
	return append([]decision.Effect(nil), c.decisions...)
}

// Effects returns detached exact effect identities.
func (c ExportContract) Effects() []string {
	return append([]string(nil), c.effects...)
}

// Complete reports whether the contract passed its constructor.
func (c ExportContract) Complete() bool {
	return c.constructed
}

// clone returns one detached contract value.
func (c ExportContract) clone() ExportContract {
	c.checkpoints = c.Checkpoints()
	c.facts = c.Facts()
	c.decisions = c.Decisions()
	c.effects = c.Effects()

	return c
}

// Equal reports exact typed capability equality independent of declaration ordering.
func (c ExportContract) Equal(other ExportContract) bool {
	if !c.Complete() || !other.Complete() {
		return false
	}

	return equalComparableSets(c.checkpoints, other.checkpoints) &&
		equalComparableSets(c.facts, other.facts) &&
		equalEffects(c.decisions, other.decisions) &&
		equalComparableSets(c.effects, other.effects)
}

// EffectUse is one typed policy-selected effect request.
type EffectUse struct {
	id         string
	parameters decision.ValueMap
}

// NewEffectUse constructs one immutable effect selection.
func NewEffectUse(id string, parameters map[string]decision.Value) (EffectUse, error) {
	if !identifier.Qualified(id) {
		return EffectUse{}, newValidationError(
			ErrInvalidPolicySetDefinition,
			"policy_rule.effects",
			id,
			"must use an exact qualified effect identity",
		)
	}

	values, err := decision.NewValueMap(parameters)
	if err != nil {
		return EffectUse{}, fmt.Errorf("policy rule effect %s: %w", id, err)
	}

	return EffectUse{id: id, parameters: values}, nil
}

// ID returns the exact selected effect identity.
func (u EffectUse) ID() string {
	return u.id
}

// Parameters returns detached typed parameters.
func (u EffectUse) Parameters() decision.ValueMap {
	values, _ := decision.NewValueMap(u.parameters.Values())

	return values
}

// Equal reports exact effect selection and typed-parameter equality.
func (u EffectUse) Equal(other EffectUse) bool {
	return u.id == other.id && equalValueMaps(u.parameters, other.parameters)
}

// equalValueMaps compares immutable strict-value maps by exact typed content.
func equalValueMaps(left decision.ValueMap, right decision.ValueMap) bool {
	return reflect.DeepEqual(left.Values(), right.Values())
}

// PolicyResponseMessageInput carries one current response-message source contract.
type PolicyResponseMessageInput struct {
	From      string
	Text      string
	I18NKey   string
	FactID    string
	Detail    string
	Fallback  string
	MaxLength int
}

// PolicyResponseMessage retains immutable decision response-message semantics.
type PolicyResponseMessage struct {
	from      string
	text      string
	i18nKey   string
	factID    string
	detail    string
	fallback  string
	maxLength int
	validated bool
}

// NewPolicyResponseMessage validates one complete response-message source.
func NewPolicyResponseMessage(input PolicyResponseMessageInput) (PolicyResponseMessage, error) {
	message := PolicyResponseMessage{
		from:      input.From,
		text:      input.Text,
		i18nKey:   input.I18NKey,
		factID:    input.FactID,
		detail:    input.Detail,
		fallback:  input.Fallback,
		maxLength: input.MaxLength,
		validated: true,
	}
	if !message.valid() {
		return PolicyResponseMessage{}, newValidationError(
			ErrInvalidPolicySetDefinition,
			"policy_rule.then.response_message",
			input.From,
			"contains an invalid or incomplete response source",
		)
	}

	return message, nil
}

// From returns default, literal, i18n, or attribute_detail.
func (m PolicyResponseMessage) From() string {
	return m.from
}

// Text returns literal response text.
func (m PolicyResponseMessage) Text() string {
	return m.text
}

// I18NKey returns the source-owned localization key.
func (m PolicyResponseMessage) I18NKey() string {
	return m.i18nKey
}

// FactID returns the exact fact used by attribute_detail.
func (m PolicyResponseMessage) FactID() string {
	return m.factID
}

// Detail returns the exact public response detail.
func (m PolicyResponseMessage) Detail() string {
	return m.detail
}

// Fallback returns bounded fallback text.
func (m PolicyResponseMessage) Fallback() string {
	return m.fallback
}

// MaxLength returns the compiled public detail bound.
func (m PolicyResponseMessage) MaxLength() int {
	return m.maxLength
}

// Equal reports exact response-message metadata equality.
func (m PolicyResponseMessage) Equal(other PolicyResponseMessage) bool {
	return m == other
}

// valid enforces the current response source one-of contract.
func (m PolicyResponseMessage) valid() bool {
	if !m.validated {
		return m == (PolicyResponseMessage{})
	}

	if !validResponseText(m.text, 4096) || !validResponseText(m.fallback, 4096) || m.maxLength < 0 || m.maxLength > 4096 {
		return false
	}

	switch m.from {
	case responseSourceDefault:
		return m.validDefault()
	case responseSourceLiteral:
		return m.validLiteral()
	case responseSourceI18N:
		return m.validI18N()
	case responseSourceAttributeDetail:
		return m.validAttributeDetail()
	default:
		return false
	}
}

// validDefault checks the response-source default field combination.
func (m PolicyResponseMessage) validDefault() bool {
	return m.text == "" && m.i18nKey == "" && m.factID == "" && m.detail == "" && m.fallback == "" && m.maxLength == 0
}

// validLiteral checks the response-source literal field combination.
func (m PolicyResponseMessage) validLiteral() bool {
	return m.text != "" && m.i18nKey == "" && m.factID == "" && m.detail == "" && m.maxLength == 0
}

// validI18N checks the response-source localization field combination.
func (m PolicyResponseMessage) validI18N() bool {
	return validLocalizationKey(m.i18nKey) && m.fallback != "" && m.text == "" && m.factID == "" && m.detail == "" && m.maxLength == 0
}

// validAttributeDetail checks the response-source public fact-detail combination.
func (m PolicyResponseMessage) validAttributeDetail() bool {
	return identifier.Fact(m.factID) && identifier.Action(m.detail) && m.text == "" && m.i18nKey == "" && m.maxLength > 0
}

// PolicyResponseLanguageInput carries one current response-language source contract.
type PolicyResponseLanguageInput struct {
	From     string
	Language string
	FactID   string
	Fallback string
}

// PolicyResponseLanguage retains immutable response-language semantics.
type PolicyResponseLanguage struct {
	from      string
	language  string
	factID    string
	fallback  string
	validated bool
}

// NewPolicyResponseLanguage validates one complete response-language source.
func NewPolicyResponseLanguage(input PolicyResponseLanguageInput) (PolicyResponseLanguage, error) {
	language := PolicyResponseLanguage{
		from: input.From, language: input.Language, factID: input.FactID, fallback: input.Fallback, validated: true,
	}
	if !language.valid() {
		return PolicyResponseLanguage{}, newValidationError(
			ErrInvalidPolicySetDefinition,
			"policy_rule.then.response_language",
			input.From,
			"contains an invalid or incomplete response-language source",
		)
	}

	return language, nil
}

// From returns literal or attribute.
func (l PolicyResponseLanguage) From() string {
	return l.from
}

// Language returns a bounded literal language tag.
func (l PolicyResponseLanguage) Language() string {
	return l.language
}

// FactID returns the exact language fact reference.
func (l PolicyResponseLanguage) FactID() string {
	return l.factID
}

// Fallback returns a bounded fallback language tag.
func (l PolicyResponseLanguage) Fallback() string {
	return l.fallback
}

// Equal reports exact response-language metadata equality.
func (l PolicyResponseLanguage) Equal(other PolicyResponseLanguage) bool {
	return l == other
}

// valid enforces the current response-language source one-of contract.
func (l PolicyResponseLanguage) valid() bool {
	if !l.validated {
		return l == (PolicyResponseLanguage{})
	}

	if !validResponseText(l.language, 128) || !validResponseText(l.fallback, 128) {
		return false
	}

	switch l.from {
	case responseSourceLiteral:
		return validLanguageTag(l.language) && l.factID == "" && l.fallback == ""
	case responseSourceAttribute:
		return identifier.Fact(l.factID) && l.language == "" && (l.fallback == "" || validLanguageTag(l.fallback))
	default:
		return false
	}
}

var localizationKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)

// validLocalizationKey retains bounded dotted current localization identities.
func validLocalizationKey(value string) bool {
	return localizationKeyPattern.MatchString(value)
}

// validLanguageTag retains the current strict BCP-47 response-language contract.
func validLanguageTag(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}

	_, err := language.Parse(value)

	return err == nil
}

// validResponseText bounds UTF-8 response and language fields.
func validResponseText(value string, maximum int) bool {
	return utf8.ValidString(value) && len(value) <= maximum
}

// PolicyRuleInput carries one explicitly targeted rule into its constructor.
type PolicyRuleInput struct {
	Name                             string
	Checkpoint                       string
	Actions                          []string
	RequiredProviders                []string
	Expression                       PolicyExpression
	Effects                          []EffectUse
	Advice                           []EffectUse
	Decision                         decision.Effect
	Reason                           string
	OutcomeMarker                    string
	FSMEventMarker                   string
	ResponseMarker                   string
	ResponseMessage                  PolicyResponseMessage
	ResponseLanguage                 PolicyResponseLanguage
	SkipRemainingCheckpointProviders bool
}

// PolicyRule is one immutable explicitly target/checkpoint-scoped rule descriptor.
type PolicyRule struct {
	name                             string
	checkpoint                       string
	actions                          []string
	requiredProviders                []string
	expression                       PolicyExpression
	effects                          []EffectUse
	advice                           []EffectUse
	decision                         decision.Effect
	reason                           string
	outcomeMarker                    string
	fsmEventMarker                   string
	responseMarker                   string
	responseMessage                  PolicyResponseMessage
	responseLanguage                 PolicyResponseLanguage
	skipRemainingCheckpointProviders bool
}

// NewPolicyRule validates one exact target-aware rule descriptor.
func NewPolicyRule(input PolicyRuleInput) (PolicyRule, error) {
	if err := validatePolicyRuleInput(input); err != nil {
		return PolicyRule{}, err
	}

	actions, requiredProviders, effects, advice, err := clonePolicyRuleSelections(input)
	if err != nil {
		return PolicyRule{}, err
	}

	return PolicyRule{
		name:                             input.Name,
		checkpoint:                       input.Checkpoint,
		actions:                          actions,
		requiredProviders:                requiredProviders,
		expression:                       input.Expression.clone(),
		effects:                          effects,
		advice:                           advice,
		decision:                         input.Decision,
		reason:                           input.Reason,
		outcomeMarker:                    input.OutcomeMarker,
		fsmEventMarker:                   input.FSMEventMarker,
		responseMarker:                   input.ResponseMarker,
		responseMessage:                  input.ResponseMessage,
		responseLanguage:                 input.ResponseLanguage,
		skipRemainingCheckpointProviders: input.SkipRemainingCheckpointProviders,
	}, nil
}

// validatePolicyRuleInput validates one rule's scalar and retained output metadata.
func validatePolicyRuleInput(input PolicyRuleInput) error {
	if !identifier.Action(input.Name) || !validCheckpoint(input.Checkpoint) || !input.Expression.valid() || !ruleDecision(input.Decision) {
		return newValidationError(
			ErrInvalidPolicySetDefinition,
			"policy_rule",
			input.Name,
			"must declare an exact target, checkpoint, name, and decision",
		)
	}

	if !validRuleTextFields(input) || !input.ResponseMessage.valid() || !input.ResponseLanguage.valid() {
		return newValidationError(
			ErrInvalidPolicySetDefinition,
			"policy_rule.then",
			input.Name,
			"contains invalid reason, marker, response-message, or response-language metadata",
		)
	}

	_, err := policyRuleFactContracts(input.Expression, input.ResponseMessage, input.ResponseLanguage)

	return err
}

// clonePolicyRuleSelections deeply owns action, provider, obligation, and advice lists.
func clonePolicyRuleSelections(input PolicyRuleInput) ([]string, []string, []EffectUse, []EffectUse, error) {
	actions, err := cloneUniqueActions(input.Actions, "policy_rule.actions")
	if err != nil {
		return nil, nil, nil, nil, err
	}

	requiredProviders, err := cloneUniqueQualifiedIDsForRule(input.RequiredProviders, "policy_rule.require_providers")
	if err != nil {
		return nil, nil, nil, nil, err
	}

	effects, err := cloneEffectUses(input.Effects)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	advice, err := cloneEffectUses(input.Advice)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return actions, requiredProviders, effects, advice, nil
}

// Name returns the namespace-local rule name.
func (r PolicyRule) Name() string {
	return r.name
}

// Actions returns detached optional action restrictions.
func (r PolicyRule) Actions() []string {
	return append([]string(nil), r.actions...)
}

// AllowsAction reports whether this rule applies to one exact target action.
func (r PolicyRule) AllowsAction(action string) bool {
	return len(r.actions) == 0 || slices.Contains(r.actions, action)
}

// RequiredProviders returns exact provider dependencies from the same checkpoint.
func (r PolicyRule) RequiredProviders() []string {
	return append([]string(nil), r.requiredProviders...)
}

// Checkpoint returns the exact rule checkpoint.
func (r PolicyRule) Checkpoint() string {
	return r.checkpoint
}

// Expression returns the immutable executable source predicate.
func (r PolicyRule) Expression() PolicyExpression {
	return r.expression.clone()
}

// Advice returns detached typed non-authoritative effect selections.
func (r PolicyRule) Advice() []EffectUse {
	cloned, _ := cloneEffectUses(r.advice)

	return cloned
}

// Effects returns detached typed effect selections.
func (r PolicyRule) Effects() []EffectUse {
	cloned, _ := cloneEffectUses(r.effects)

	return cloned
}

// Decision returns the selected generic effect.
func (r PolicyRule) Decision() decision.Effect {
	return r.decision
}

// Reason returns the stable selected decision reason.
func (r PolicyRule) Reason() string {
	return r.reason
}

// OutcomeMarker returns the selected outcome adapter marker.
func (r PolicyRule) OutcomeMarker() string {
	return r.outcomeMarker
}

// FSMEventMarker returns the selected authentication-state marker.
func (r PolicyRule) FSMEventMarker() string {
	return r.fsmEventMarker
}

// ResponseMarker returns the selected response-profile marker.
func (r PolicyRule) ResponseMarker() string {
	return r.responseMarker
}

// ResponseMessage returns immutable response-message source metadata.
func (r PolicyRule) ResponseMessage() PolicyResponseMessage {
	return r.responseMessage
}

// ResponseLanguage returns immutable response-language source metadata.
func (r PolicyRule) ResponseLanguage() PolicyResponseLanguage {
	return r.responseLanguage
}

// SkipRemainingCheckpointProviders reports the checkpoint-local control marker.
func (r PolicyRule) SkipRemainingCheckpointProviders() bool {
	return r.skipRemainingCheckpointProviders
}

// FactContracts returns expression and response metadata requirements in first-use order.
func (r PolicyRule) FactContracts() []FactContract {
	contracts, _ := policyRuleFactContracts(r.expression, r.responseMessage, r.responseLanguage)

	return contracts
}

// valid reports whether a source rule satisfies its constructor invariant.
func (r PolicyRule) valid() bool {
	if !identifier.Action(r.name) || !validCheckpoint(r.checkpoint) || !r.expression.valid() || !ruleDecision(r.decision) {
		return false
	}

	if !r.validSelections() {
		return false
	}

	return validBoundedRuleText(r.reason) &&
		validBoundedRuleText(r.outcomeMarker) &&
		validBoundedRuleText(r.fsmEventMarker) &&
		validBoundedRuleText(r.responseMarker) &&
		r.responseMessage.valid() &&
		r.responseLanguage.valid()
}

// validSelections revalidates every constructor-owned rule selection list.
func (r PolicyRule) validSelections() bool {
	input := PolicyRuleInput{
		Actions: r.actions, RequiredProviders: r.requiredProviders, Effects: r.effects, Advice: r.advice,
	}
	_, _, _, _, err := clonePolicyRuleSelections(input)

	return err == nil
}

// policyRuleFactContracts merges expression and response fact requirements exactly.
func policyRuleFactContracts(
	expression PolicyExpression,
	message PolicyResponseMessage,
	language PolicyResponseLanguage,
) ([]FactContract, error) {
	result := expression.FactContracts()
	seen := make(map[string]decision.ValueKind, len(result)+2)

	for _, fact := range result {
		seen[fact.ID()] = fact.Kind()
	}

	for _, factID := range []string{message.FactID(), language.FactID()} {
		if factID == "" {
			continue
		}

		if kind, exists := seen[factID]; exists {
			if kind != decision.ValueKindString {
				return nil, newValidationError(
					ErrInvalidPolicySetDefinition,
					"policy_rule.then.response",
					factID,
					"response fact conflicts with expression fact kind",
				)
			}

			continue
		}

		seen[factID] = decision.ValueKindString
		result = append(result, FactContract{id: factID, kind: decision.ValueKindString})
	}

	return result, nil
}

// PolicySetImport is one exact target/checkpoint-bound set reference.
type PolicySetImport struct {
	set        PolicySetID
	target     decision.Target
	checkpoint string
	path       string
	contract   ExportContract
}

// NewPolicySetImport constructs one explicit set import or plan binding.
func NewPolicySetImport(
	path string,
	setReference string,
	target decision.Target,
	checkpoint string,
	contract ExportContract,
) (PolicySetImport, error) {
	set, err := ParsePolicySetID(path, setReference)
	if err != nil {
		return PolicySetImport{}, err
	}

	validatedTarget, err := decision.NewTarget(target.Namespace(), target.Action())
	if err != nil || !validCheckpoint(checkpoint) {
		return PolicySetImport{}, newValidationError(
			ErrInvalidPolicySetDefinition,
			path,
			setReference,
			"must bind an exact target and checkpoint",
		)
	}

	return PolicySetImport{
		set:        set,
		target:     validatedTarget,
		checkpoint: checkpoint,
		path:       path,
		contract:   contract.clone(),
	}, nil
}

// Set returns the exact imported set identity.
func (i PolicySetImport) Set() PolicySetID {
	return i.set
}

// Target returns the exact instantiation target.
func (i PolicySetImport) Target() decision.Target {
	return i.target
}

// Checkpoint returns the exact instantiation checkpoint.
func (i PolicySetImport) Checkpoint() string {
	return i.checkpoint
}

// Contract returns a detached typed import contract.
func (i PolicySetImport) Contract() ExportContract {
	return i.contract.clone()
}

// Path returns the configuration-owned reference path.
func (i PolicySetImport) Path() string {
	return i.path
}

// Equal reports exact target, checkpoint, source path, and typed capability equality.
func (i PolicySetImport) Equal(other PolicySetImport) bool {
	return i.set.String() == other.set.String() &&
		i.target.String() == other.target.String() &&
		i.checkpoint == other.checkpoint &&
		i.path == other.path &&
		equalOptionalExportContracts(i.contract, other.contract)
}

// equalOptionalExportContracts treats two absent same-namespace contracts as equal.
func equalOptionalExportContracts(left ExportContract, right ExportContract) bool {
	if !left.Complete() || !right.Complete() {
		return !left.Complete() && !right.Complete()
	}

	return left.Equal(right)
}

// PolicySetDefinitionInput carries one namespace-nested set into its constructor.
type PolicySetDefinitionInput struct {
	ExportContract *ExportContract
	ID             PolicySetID
	Visibility     PolicySetVisibility
	Imports        []PolicySetImport
	Rules          []PolicyRule
	DiagnosticID   string
}

// PolicySetDefinition is one immutable contributed namespace-owned policy set.
type PolicySetDefinition struct {
	exportContract *ExportContract
	id             PolicySetID
	visibility     PolicySetVisibility
	imports        []PolicySetImport
	rules          []PolicyRule
	diagnosticID   string
	builtinClass   string
	finalDeny      bool
}

// NewPolicySetDefinition validates one operator- or extension-owned set descriptor.
func NewPolicySetDefinition(input PolicySetDefinitionInput) (PolicySetDefinition, error) {
	if !input.ID.valid() {
		return PolicySetDefinition{}, newValidationError(
			ErrInvalidPolicySetIdentity,
			"policy_set",
			input.ID.String(),
			"must be constructor validated",
		)
	}

	if input.ID.String() == BuiltinStandardAuthPolicySet {
		return PolicySetDefinition{}, newValidationError(
			ErrBuiltinPolicySetImmutable,
			input.ID.String(),
			input.ID.String(),
			"is supplied only by the immutable builtin catalog contributor",
		)
	}

	return newPolicySetDefinition(input)
}

// newPolicySetDefinition validates common set metadata for configured and builtin descriptors.
func newPolicySetDefinition(input PolicySetDefinitionInput) (PolicySetDefinition, error) {
	visibility := input.Visibility
	if visibility == "" {
		visibility = PolicySetVisibilityPrivate
	}

	if !visibility.valid() || len(input.Imports)+len(input.Rules) > maximumPolicySetEntries {
		return PolicySetDefinition{}, newValidationError(
			ErrInvalidPolicySetDefinition,
			input.ID.String(),
			input.ID.String(),
			"contains invalid visibility or too many entries",
		)
	}

	if err := validateDiagnosticPublicID(input.DiagnosticID, input.ID.String()+".diagnostics.public_id"); err != nil {
		return PolicySetDefinition{}, err
	}

	if visibility == PolicySetVisibilityExported && (input.ExportContract == nil || !input.ExportContract.Complete()) {
		return PolicySetDefinition{}, newValidationError(
			ErrInvalidExportContract,
			input.ID.String()+".export_contract",
			input.ID.String(),
			"exported policy sets require one complete typed contract",
		)
	}

	if visibility == PolicySetVisibilityPrivate && input.ExportContract != nil {
		return PolicySetDefinition{}, newValidationError(
			ErrInvalidExportContract,
			input.ID.String()+".export_contract",
			input.ID.String(),
			"private policy sets cannot declare an export contract",
		)
	}

	imports := clonePolicySetImports(input.Imports)

	rules, err := clonePolicyRules(input.Rules)
	if err != nil {
		return PolicySetDefinition{}, err
	}

	var contract *ExportContract

	if input.ExportContract != nil {
		cloned := input.ExportContract.clone()
		contract = &cloned
	}

	return PolicySetDefinition{
		exportContract: contract,
		id:             input.ID,
		visibility:     visibility,
		imports:        imports,
		rules:          rules,
		diagnosticID:   input.DiagnosticID,
	}, nil
}

// ID returns the canonical qualified set identity.
func (d PolicySetDefinition) ID() PolicySetID {
	return d.id
}

// Visibility returns the exact private/exported contract.
func (d PolicySetDefinition) Visibility() PolicySetVisibility {
	return d.visibility
}

// ExportContract returns a detached contract and its presence.
func (d PolicySetDefinition) ExportContract() (ExportContract, bool) {
	if d.exportContract == nil {
		return ExportContract{}, false
	}

	return d.exportContract.clone(), true
}

// Imports returns detached exact set imports.
func (d PolicySetDefinition) Imports() []PolicySetImport {
	return clonePolicySetImports(d.imports)
}

// Rules returns detached explicitly scoped rules.
func (d PolicySetDefinition) Rules() []PolicyRule {
	rules, _ := clonePolicyRules(d.rules)

	return rules
}

// DiagnosticID returns the optional target-local public alias.
func (d PolicySetDefinition) DiagnosticID() string {
	return d.diagnosticID
}

// IsBuiltinStandardAuth reports whether the set binds the existing builtin evaluator.
func (d PolicySetDefinition) IsBuiltinStandardAuth() bool {
	return d.builtinClass == builtinPolicyClassStandardAuth
}

// HasFinalDefaultDeny reports the immutable builtin final fallback contract.
func (d PolicySetDefinition) HasFinalDefaultDeny() bool {
	return d.finalDeny
}

// clone returns one deeply detached set descriptor.
func (d PolicySetDefinition) clone() PolicySetDefinition {
	if d.exportContract != nil {
		contract := d.exportContract.clone()
		d.exportContract = &contract
	}

	d.imports = clonePolicySetImports(d.imports)
	d.rules, _ = clonePolicyRules(d.rules)

	return d
}

// newBuiltinStandardAuthPolicySet constructs the unconfigurable authn evaluator binding.
func newBuiltinStandardAuthPolicySet() (PolicySetDefinition, error) {
	id, err := ParsePolicySetID("builtin.policy_set", BuiltinStandardAuthPolicySet)
	if err != nil {
		return PolicySetDefinition{}, err
	}

	set, err := newPolicySetDefinition(PolicySetDefinitionInput{ID: id})
	if err != nil {
		return PolicySetDefinition{}, err
	}

	set.builtinClass = builtinPolicyClassStandardAuth
	set.finalDeny = true

	return set, nil
}

// validateDiagnosticPublicID rejects internal paths and unbounded aliases.
func validateDiagnosticPublicID(value string, path string) error {
	if value == "" {
		return nil
	}

	if !identifier.Diagnostic(value) {
		return newValidationError(
			ErrInvalidDiagnosticPublicID,
			path,
			value,
			"must be one bounded lowercase target-local alias without a path",
		)
	}

	return nil
}

// validCheckpoint reports whether value is an exact bounded checkpoint name.
func validCheckpoint(value string) bool {
	return identifier.Action(value)
}

// cloneUniqueFactContracts owns and deduplicates exact fact requirements.
func cloneUniqueFactContracts(values []FactContract, path string) ([]FactContract, error) {
	result := append([]FactContract(nil), values...)
	seen := make(map[string]struct{}, len(result))

	for _, value := range result {
		if !value.valid() {
			return nil, newValidationError(ErrInvalidExportContract, path, value.ID(), "must be constructor validated")
		}

		if _, ok := seen[value.ID()]; ok {
			return nil, newValidationError(ErrDuplicateDefinition, path, value.ID(), "fact contract occurs more than once")
		}

		seen[value.ID()] = struct{}{}
	}

	return result, nil
}

// cloneUniqueDecisions owns and deduplicates allowed decisions.
func cloneUniqueDecisions(values []decision.Effect) ([]decision.Effect, error) {
	result := append([]decision.Effect(nil), values...)
	seen := make(map[decision.Effect]struct{}, len(result))

	for _, value := range result {
		if !ruleDecision(value) {
			return nil, newValidationError(ErrInvalidExportContract, "export_contract.decisions", string(value), "contains a non-rule decision")
		}

		if _, ok := seen[value]; ok {
			return nil, newValidationError(ErrDuplicateDefinition, "export_contract.decisions", string(value), "decision occurs more than once")
		}

		seen[value] = struct{}{}
	}

	return result, nil
}

// cloneUniqueQualifiedIDs owns and deduplicates qualified identities.
func cloneUniqueQualifiedIDs(values []string, path string) ([]string, error) {
	return cloneValidatedUniqueStrings(
		values,
		path,
		identifier.Qualified,
		ErrInvalidExportContract,
		"must contain exact qualified identities",
		"identity occurs more than once",
	)
}

// cloneUniqueCheckpoints owns and deduplicates compatible checkpoint identities.
func cloneUniqueCheckpoints(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > maximumPolicySetEntries {
		return nil, newValidationError(ErrInvalidExportContract, "export_contract.compatible_checkpoints", "", "must contain a bounded non-empty checkpoint set")
	}

	return cloneValidatedUniqueStrings(
		values,
		"export_contract.compatible_checkpoints",
		validCheckpoint,
		ErrInvalidExportContract,
		"must contain exact checkpoints",
		"checkpoint occurs more than once",
	)
}

// cloneUniqueActions owns and deduplicates optional action restrictions.
func cloneUniqueActions(values []string, path string) ([]string, error) {
	return cloneValidatedUniqueStrings(
		values,
		path,
		identifier.Action,
		ErrInvalidPolicySetDefinition,
		"must contain exact action names",
		"action occurs more than once",
	)
}

// cloneUniqueQualifiedIDsForRule owns exact provider dependencies with rule-specific errors.
func cloneUniqueQualifiedIDsForRule(values []string, path string) ([]string, error) {
	return cloneValidatedUniqueStrings(
		values,
		path,
		identifier.Qualified,
		ErrInvalidPolicySetDefinition,
		"must contain exact qualified provider identities",
		"provider identity occurs more than once",
	)
}

// validRuleTextFields bounds retained reason and adapter marker strings.
func validRuleTextFields(input PolicyRuleInput) bool {
	return validBoundedRuleText(input.Reason) &&
		validBoundedRuleText(input.OutcomeMarker) &&
		validBoundedRuleText(input.FSMEventMarker) &&
		validBoundedRuleText(input.ResponseMarker)
}

// validBoundedRuleText accepts empty or bounded printable UTF-8 source metadata.
func validBoundedRuleText(value string) bool {
	if !utf8.ValidString(value) || len(value) > 512 {
		return false
	}

	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}

	return true
}

// cloneValidatedUniqueStrings owns one validated collision-free identity list.
func cloneValidatedUniqueStrings(
	values []string,
	path string,
	valid func(string) bool,
	invalidCause error,
	invalidReason string,
	duplicateReason string,
) ([]string, error) {
	result := append([]string(nil), values...)
	seen := make(map[string]struct{}, len(result))

	for _, value := range result {
		if !valid(value) {
			return nil, newValidationError(invalidCause, path, value, invalidReason)
		}

		if _, exists := seen[value]; exists {
			return nil, newValidationError(ErrDuplicateDefinition, path, value, duplicateReason)
		}

		seen[value] = struct{}{}
	}

	return result, nil
}

// ruleDecision permits only authoritative configured rule outcomes.
func ruleDecision(value decision.Effect) bool {
	return value == decision.EffectPermit || value == decision.EffectDeny
}

// cloneEffectUses deeply owns selected typed effects.
func cloneEffectUses(values []EffectUse) ([]EffectUse, error) {
	result := make([]EffectUse, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		if !identifier.Qualified(value.ID()) {
			return nil, newValidationError(ErrInvalidPolicySetDefinition, "policy_rule.effects", value.ID(), "must be constructor validated")
		}

		if _, ok := seen[value.ID()]; ok {
			return nil, newValidationError(ErrDuplicateDefinition, "policy_rule.effects", value.ID(), "effect occurs more than once")
		}

		seen[value.ID()] = struct{}{}

		parameters, err := decision.NewValueMap(value.Parameters().Values())
		if err != nil {
			return nil, err
		}

		result = append(result, EffectUse{id: value.ID(), parameters: parameters})
	}

	return result, nil
}

// clonePolicyRules owns and deduplicates rule names.
func clonePolicyRules(values []PolicyRule) ([]PolicyRule, error) {
	result := make([]PolicyRule, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		if !value.valid() {
			return nil, newValidationError(ErrInvalidPolicySetDefinition, "policy_set.rules", value.Name(), "rule must be constructor validated")
		}

		if _, ok := seen[value.Name()]; ok {
			return nil, newValidationError(ErrDuplicateDefinition, "policy_set.rules", value.Name(), "rule name occurs more than once")
		}

		seen[value.Name()] = struct{}{}

		effects, err := cloneEffectUses(value.effects)
		if err != nil {
			return nil, err
		}

		value.actions = value.Actions()
		value.requiredProviders = value.RequiredProviders()
		value.expression = value.Expression()
		value.effects = effects

		advice, err := cloneEffectUses(value.advice)
		if err != nil {
			return nil, err
		}

		value.advice = advice
		result = append(result, value)
	}

	return result, nil
}

// clonePolicySetImports deeply owns imported contracts.
func clonePolicySetImports(values []PolicySetImport) []PolicySetImport {
	result := append([]PolicySetImport(nil), values...)
	for index := range result {
		result[index].contract = result[index].contract.clone()
	}

	return result
}

// equalComparableSets compares capability sets independent of declaration ordering.
func equalComparableSets[T comparable](left []T, right []T) bool {
	if len(left) != len(right) {
		return false
	}

	for _, value := range left {
		if !slices.Contains(right, value) {
			return false
		}
	}

	return true
}

// equalEffects compares the decision set independent of declaration ordering.
func equalEffects(left []decision.Effect, right []decision.Effect) bool {
	return equalComparableSets(left, right)
}

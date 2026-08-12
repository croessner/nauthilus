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

package decision

import "unicode/utf8"

const (
	maximumStatusMessageLength = 512
)

// Effect is the closed generic decision result set.
type Effect string

const (
	// EffectPermit means a configured rule explicitly permitted the operation.
	EffectPermit Effect = "permit"

	// EffectDeny means a configured rule explicitly denied the operation.
	EffectDeny Effect = "deny"

	// EffectNotApplicable means evaluation completed without an applicable rule.
	EffectNotApplicable Effect = "not_applicable"

	// EffectIndeterminate means an admitted request could not be evaluated reliably.
	EffectIndeterminate Effect = "indeterminate"
)

// Valid reports whether the effect belongs to the closed contract.
func (e Effect) Valid() bool {
	switch e {
	case EffectPermit, EffectDeny, EffectNotApplicable, EffectIndeterminate:
		return true
	default:
		return false
	}
}

// ValidationDetail is one safe stable field-level status detail.
type ValidationDetail struct {
	field  string
	reason string
}

// StatusCode is a closed machine-readable result taxonomy.
type StatusCode string

const (
	// StatusCodePermit reports successful explicit permission.
	StatusCodePermit StatusCode = "permit"

	// StatusCodePolicyDenied reports successful explicit denial.
	StatusCodePolicyDenied StatusCode = "policy_denied"

	// StatusCodeNotApplicable reports completed evaluation without an applicable rule.
	StatusCodeNotApplicable StatusCode = "not_applicable"

	// StatusCodeEvaluationFailed reports a retryable reliable-evaluation failure.
	StatusCodeEvaluationFailed StatusCode = "evaluation_failed"

	// StatusCodeProviderUnavailable reports a retryable required-provider outage.
	StatusCodeProviderUnavailable StatusCode = "provider_unavailable"

	// StatusCodeEffectOutcomeUnknown reports non-retryable ambiguous synchronous effect delivery.
	StatusCodeEffectOutcomeUnknown StatusCode = "effect_outcome_unknown"
)

// NewValidationDetail constructs a safe field-level detail for later status validation.
func NewValidationDetail(field string, reason string) ValidationDetail {
	return ValidationDetail{field: field, reason: reason}
}

// Field returns the public-shaped field path.
func (d ValidationDetail) Field() string {
	return d.field
}

// Reason returns the stable safe reason.
func (d ValidationDetail) Reason() string {
	return d.reason
}

// valid reports whether the detail contains bounded safe text.
func (d ValidationDetail) valid() bool {
	return validIdentityText(d.field) && validIdentityText(d.reason)
}

// Status is immutable safe machine and human-readable result metadata.
type Status struct {
	code      StatusCode
	message   string
	details   []ValidationDetail
	retryable bool
}

// NewStatus validates and deeply owns safe result status metadata.
func NewStatus(
	code StatusCode,
	message string,
	details []ValidationDetail,
) (Status, error) {
	if !code.valid() || len(message) > maximumStatusMessageLength || !utf8.ValidString(message) {
		return Status{}, invalidResponse("status", "contains an invalid code or unsafe message")
	}

	for _, detail := range details {
		if !detail.valid() {
			return Status{}, invalidResponse("status.details", "contains an invalid field or reason")
		}
	}

	return Status{
		code:      code,
		message:   message,
		details:   append([]ValidationDetail(nil), details...),
		retryable: code.retryable(),
	}, nil
}

// Code returns the stable machine code.
func (s Status) Code() StatusCode {
	return s.code
}

// Message returns the safe public message.
func (s Status) Message() string {
	return s.message
}

// Retryable returns taxonomy-owned retry guidance, not a caller retry control.
func (s Status) Retryable() bool {
	return s.retryable
}

// Details returns a detached validation-detail slice.
func (s Status) Details() []ValidationDetail {
	return append([]ValidationDetail(nil), s.details...)
}

// valid reports whether status satisfies its constructor invariant.
func (s Status) valid() bool {
	if !s.code.valid() ||
		s.retryable != s.code.retryable() ||
		len(s.message) > maximumStatusMessageLength ||
		!utf8.ValidString(s.message) {
		return false
	}

	for _, detail := range s.details {
		if !detail.valid() {
			return false
		}
	}

	return true
}

// EffectRequestInput is constructor input for one typed obligation or advice.
type EffectRequestInput struct {
	ID         string
	Parameters map[string]Value
}

// EffectRequest is one immutable typed obligation or advice selection.
type EffectRequest struct {
	id         string
	parameters ValueMap
}

// NewEffectRequest validates and deeply owns one typed effect selection.
func NewEffectRequest(input EffectRequestInput) (EffectRequest, error) {
	if !validQualifiedIdentity(input.ID) {
		return EffectRequest{}, invalidResponse("effect.id", "must be a qualified namespace identity")
	}

	parameters, err := NewValueMap(input.Parameters)
	if err != nil {
		return EffectRequest{}, err
	}

	return EffectRequest{id: input.ID, parameters: parameters}, nil
}

// ID returns the qualified effect identity.
func (r EffectRequest) ID() string {
	return r.id
}

// Parameters returns detached typed parameters.
func (r EffectRequest) Parameters() ValueMap {
	return cloneValueMap(r.parameters)
}

// valid reports whether the effect request satisfies its constructor invariant.
func (r EffectRequest) valid() bool {
	return validQualifiedIdentity(r.id)
}

// PolicyMetadata is bounded immutable selected-policy evidence.
type PolicyMetadata struct {
	policySet  string
	version    string
	rule       string
	generation uint64
}

// NewPolicyMetadata validates selected policy metadata.
func NewPolicyMetadata(
	policySet string,
	version string,
	rule string,
	generation uint64,
) (PolicyMetadata, error) {
	if !validQualifiedIdentity(policySet) || !validIdentityText(version) {
		return PolicyMetadata{}, invalidResponse("policy", "policy set and version must be valid identities")
	}

	if rule != "" && !validIdentityText(rule) {
		return PolicyMetadata{}, invalidResponse("policy.rule", "must be bounded valid UTF-8")
	}

	return PolicyMetadata{
		policySet:  policySet,
		version:    version,
		rule:       rule,
		generation: generation,
	}, nil
}

// PolicySet returns the qualified selected policy-set identity.
func (m PolicyMetadata) PolicySet() string {
	return m.policySet
}

// Version returns the selected policy-set version.
func (m PolicyMetadata) Version() string {
	return m.version
}

// Rule returns the selected rule identity when applicable.
func (m PolicyMetadata) Rule() string {
	return m.rule
}

// Generation returns the captured runtime generation.
func (m PolicyMetadata) Generation() uint64 {
	return m.generation
}

// valid reports whether metadata satisfies its constructor invariant.
func (m PolicyMetadata) valid() bool {
	return validQualifiedIdentity(m.policySet) &&
		validIdentityText(m.version) &&
		(m.rule == "" || validIdentityText(m.rule))
}

// Diagnostics is an immutable sanitized diagnostic projection.
type Diagnostics struct {
	entries ValueMap
}

// NewDiagnostics validates and owns sanitized diagnostic entries.
func NewDiagnostics(entries map[string]Value) (Diagnostics, error) {
	values, err := NewValueMap(entries)
	if err != nil {
		return Diagnostics{}, err
	}

	return Diagnostics{entries: values}, nil
}

// Entries returns a detached diagnostic map.
func (d Diagnostics) Entries() ValueMap {
	return cloneValueMap(d.entries)
}

// DecisionResponseInput is constructor input for one immutable result.
//
//nolint:revive // The binding contract requires the explicit DecisionResponse vocabulary.
type DecisionResponseInput struct {
	RequestID   string
	DecisionID  string
	Effect      Effect
	Status      Status
	Obligations []EffectRequest
	Advice      []EffectRequest
	Policy      PolicyMetadata
	Diagnostics *Diagnostics
}

// DecisionResponse is one deeply owned generic decision result.
//
//nolint:revive // The binding contract requires the explicit DecisionResponse vocabulary.
type DecisionResponse struct {
	obligations []EffectRequest
	advice      []EffectRequest
	diagnostics *Diagnostics
	requestID   RequestID
	decisionID  DecisionID
	status      Status
	policy      PolicyMetadata
	effect      Effect
}

// NewDecisionResponse validates and deeply owns one result.
func NewDecisionResponse(input DecisionResponseInput) (DecisionResponse, error) {
	requestID, err := NewRequestID(input.RequestID)
	if err != nil {
		return DecisionResponse{}, invalidResponse("request_id", "must be a valid correlation identifier")
	}

	decisionID, err := NewDecisionID(input.DecisionID)
	if err != nil {
		return DecisionResponse{}, err
	}

	if !input.Effect.Valid() || !input.Status.valid() || !input.Policy.valid() {
		return DecisionResponse{}, invalidResponse(
			"response",
			"effect, status, and policy metadata must be constructor-validated",
		)
	}

	if !validEffectRequests(input.Obligations) || !validEffectRequests(input.Advice) {
		return DecisionResponse{}, invalidResponse("response.effects", "contains an invalid effect request")
	}

	return DecisionResponse{
		obligations: append([]EffectRequest(nil), input.Obligations...),
		advice:      append([]EffectRequest(nil), input.Advice...),
		diagnostics: cloneDiagnostics(input.Diagnostics),
		requestID:   requestID,
		decisionID:  decisionID,
		status:      cloneStatus(input.Status),
		policy:      input.Policy,
		effect:      input.Effect,
	}, nil
}

// RequestID returns the correlation-only request ID.
func (r DecisionResponse) RequestID() RequestID {
	return r.requestID
}

// DecisionID returns the correlation-only server-generated decision ID.
func (r DecisionResponse) DecisionID() DecisionID {
	return r.decisionID
}

// Effect returns the closed decision effect.
func (r DecisionResponse) Effect() Effect {
	return r.effect
}

// Status returns detached safe status metadata.
func (r DecisionResponse) Status() Status {
	return cloneStatus(r.status)
}

// Obligations returns a detached obligation slice.
func (r DecisionResponse) Obligations() []EffectRequest {
	return append([]EffectRequest(nil), r.obligations...)
}

// Advice returns a detached advice slice.
func (r DecisionResponse) Advice() []EffectRequest {
	return append([]EffectRequest(nil), r.advice...)
}

// Policy returns immutable selected-policy metadata.
func (r DecisionResponse) Policy() PolicyMetadata {
	return r.policy
}

// Diagnostics returns a detached sanitized projection when requested and admitted.
func (r DecisionResponse) Diagnostics() *Diagnostics {
	return cloneDiagnostics(r.diagnostics)
}

// validEffectRequests validates every typed effect request.
func validEffectRequests(input []EffectRequest) bool {
	for _, request := range input {
		if !request.valid() {
			return false
		}
	}

	return true
}

// valid reports whether the status code belongs to the closed taxonomy.
func (c StatusCode) valid() bool {
	switch c {
	case StatusCodePermit,
		StatusCodePolicyDenied,
		StatusCodeNotApplicable,
		StatusCodeEvaluationFailed,
		StatusCodeProviderUnavailable,
		StatusCodeEffectOutcomeUnknown:
		return true
	default:
		return false
	}
}

// retryable derives retry guidance from the stable taxonomy.
func (c StatusCode) retryable() bool {
	return c == StatusCodeEvaluationFailed || c == StatusCodeProviderUnavailable
}

// validQualifiedIdentity validates a namespace/name identity.
func validQualifiedIdentity(input string) bool {
	for index := range len(input) {
		if input[index] != '/' {
			continue
		}

		return validNamespace(input[:index]) && validAction(input[index+1:])
	}

	return false
}

// cloneStatus creates detached status metadata.
func cloneStatus(input Status) Status {
	input.details = append([]ValidationDetail(nil), input.details...)

	return input
}

// cloneDiagnostics creates a detached diagnostic projection.
func cloneDiagnostics(input *Diagnostics) *Diagnostics {
	if input == nil {
		return nil
	}

	return &Diagnostics{entries: cloneValueMap(input.entries)}
}

// invalidResponse constructs a response taxonomy error.
func invalidResponse(field string, reason string) error {
	return newContractError(ErrInvalidResponse, ErrorCodeInvalidResponse, field, reason)
}

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

import (
	"strings"
	"unicode/utf8"
)

const (
	// ContractVersion is the initial unary internal decision contract version.
	ContractVersion = "1"

	maximumCorrelationIDLength = 128
	maximumEntityTextLength    = 512

	// RequestIDAttributeName is the stable log, audit, and span field name.
	RequestIDAttributeName = "nauthilus.policy.request_id"

	// DecisionIDAttributeName is the stable log, audit, and span field name.
	DecisionIDAttributeName = "nauthilus.policy.decision_id"
)

// CorrelationUse identifies a possible request/decision ID sink.
type CorrelationUse string

const (
	// CorrelationUseLog permits structured-log correlation.
	CorrelationUseLog CorrelationUse = "log"

	// CorrelationUseAudit permits controlled-audit correlation.
	CorrelationUseAudit CorrelationUse = "audit"

	// CorrelationUseTrace permits OpenTelemetry span correlation.
	CorrelationUseTrace CorrelationUse = "trace"

	// CorrelationUseAuthorization is permanently forbidden.
	CorrelationUseAuthorization CorrelationUse = "authorization"

	// CorrelationUseCache is permanently forbidden.
	CorrelationUseCache CorrelationUse = "cache"

	// CorrelationUseMetricLabel is permanently forbidden.
	CorrelationUseMetricLabel CorrelationUse = "metric_label"
)

// RequestID is a correlation-only caller request identifier.
type RequestID struct {
	value string
}

// NewRequestID validates a non-empty caller correlation identifier.
func NewRequestID(input string) (RequestID, error) {
	if !validCorrelationID(input) {
		return RequestID{}, invalidRequest("request_id", "must be a bounded safe correlation identifier")
	}

	return RequestID{value: input}, nil
}

// String returns the correlation value.
func (id RequestID) String() string {
	return id.value
}

// ValidateUse rejects authority, cache, and metric-label use.
func (id RequestID) ValidateUse(use CorrelationUse) error {
	return validateCorrelationUse(use)
}

// DecisionID is a correlation-only server-generated decision identifier.
//
//nolint:revive // The binding contract requires the explicit DecisionID vocabulary.
type DecisionID struct {
	value string
}

// NewDecisionID validates a non-empty server-generated correlation identifier.
func NewDecisionID(input string) (DecisionID, error) {
	if !validCorrelationID(input) {
		return DecisionID{}, newContractError(
			ErrInvalidResponse,
			ErrorCodeInvalidResponse,
			"decision_id",
			"must be a bounded safe correlation identifier",
		)
	}

	return DecisionID{value: input}, nil
}

// String returns the correlation value.
func (id DecisionID) String() string {
	return id.value
}

// ValidateUse rejects authority, cache, and metric-label use.
func (id DecisionID) ValidateUse(use CorrelationUse) error {
	return validateCorrelationUse(use)
}

// EntityInput is constructor input for a caller-asserted subject or resource.
type EntityInput struct {
	Type       string
	ID         string
	Attributes map[string]Value
}

// Entity is a deeply owned caller-asserted subject or resource.
type Entity struct {
	typeName   string
	id         string
	attributes ValueMap
}

// NewEntity validates and owns one caller-asserted entity.
func NewEntity(input EntityInput) (Entity, error) {
	if !validOptionalEntityText(input.Type) || !validOptionalEntityText(input.ID) {
		return Entity{}, invalidRequest("entity", "type and ID must be bounded valid UTF-8")
	}

	attributes, err := NewValueMap(input.Attributes)
	if err != nil {
		return Entity{}, err
	}

	return Entity{typeName: input.Type, id: input.ID, attributes: attributes}, nil
}

// Type returns the asserted entity type.
func (e Entity) Type() string {
	return e.typeName
}

// ID returns the asserted entity identifier.
func (e Entity) ID() string {
	return e.id
}

// Attributes returns a detached immutable value map.
func (e Entity) Attributes() ValueMap {
	return cloneValueMap(e.attributes)
}

// EnvironmentInput is constructor input for caller-asserted domain environment.
type EnvironmentInput struct {
	Service    string
	Instance   string
	Protocol   string
	Attributes map[string]Value
}

// Environment is deeply owned caller-asserted domain environment.
type Environment struct {
	service    string
	instance   string
	protocol   string
	attributes ValueMap
}

// NewEnvironment validates and owns caller-asserted domain environment.
func NewEnvironment(input EnvironmentInput) (Environment, error) {
	for _, value := range []string{input.Service, input.Instance, input.Protocol} {
		if !validOptionalEntityText(value) {
			return Environment{}, invalidRequest("environment", "text fields must be bounded valid UTF-8")
		}
	}

	attributes, err := NewValueMap(input.Attributes)
	if err != nil {
		return Environment{}, err
	}

	return Environment{
		service:    input.Service,
		instance:   input.Instance,
		protocol:   input.Protocol,
		attributes: attributes,
	}, nil
}

// Service returns the asserted domain service.
func (e Environment) Service() string {
	return e.service
}

// Instance returns the asserted domain instance.
func (e Environment) Instance() string {
	return e.instance
}

// Protocol returns the asserted domain protocol.
func (e Environment) Protocol() string {
	return e.protocol
}

// Attributes returns a detached immutable value map.
func (e Environment) Attributes() ValueMap {
	return cloneValueMap(e.attributes)
}

// EvaluationOptions contains the only initial public evaluation option.
type EvaluationOptions struct {
	IncludeDiagnostics bool
}

// DecisionRequestInput contains exactly one unary decision invocation.
//
//nolint:revive // The binding contract requires the explicit DecisionRequest vocabulary.
type DecisionRequestInput struct {
	Version     string
	RequestID   string
	Target      Target
	Subject     Entity
	Resource    Entity
	Environment Environment
	Attributes  map[string]Value
	Options     EvaluationOptions
}

// DecisionRequest is one deeply owned internal unary invocation.
//
//nolint:revive // The binding contract requires the explicit DecisionRequest vocabulary.
type DecisionRequest struct {
	version     string
	requestID   RequestID
	target      Target
	subject     Entity
	resource    Entity
	environment Environment
	attributes  ValueMap
	caller      CallerContext
	options     EvaluationOptions
}

// NewDecisionRequest validates and binds one public-shaped invocation to trusted caller context.
func NewDecisionRequest(input DecisionRequestInput, caller CallerContext) (DecisionRequest, error) {
	if input.Version != ContractVersion {
		return DecisionRequest{}, invalidRequest("version", "unsupported contract version")
	}

	if !input.Target.valid() {
		return DecisionRequest{}, invalidRequest("request.target", "must be constructor-validated")
	}

	if !caller.valid() {
		return DecisionRequest{}, invalidCaller("caller", "must be constructor-validated authenticator output")
	}

	requestID, err := optionalRequestID(input.RequestID)
	if err != nil {
		return DecisionRequest{}, err
	}

	attributes, err := NewValueMap(input.Attributes)
	if err != nil {
		return DecisionRequest{}, err
	}

	return DecisionRequest{
		version:     input.Version,
		requestID:   requestID,
		target:      input.Target,
		subject:     cloneEntity(input.Subject),
		resource:    cloneEntity(input.Resource),
		environment: cloneEnvironment(input.Environment),
		attributes:  attributes,
		caller:      cloneCaller(caller),
		options:     input.Options,
	}, nil
}

// Version returns the exact contract version.
func (r DecisionRequest) Version() string {
	return r.version
}

// RequestID returns the correlation-only request identifier.
func (r DecisionRequest) RequestID() RequestID {
	return r.requestID
}

// Target returns the single exact invocation target.
func (r DecisionRequest) Target() Target {
	return r.target
}

// Subject returns a detached caller-asserted subject.
func (r DecisionRequest) Subject() Entity {
	return cloneEntity(r.subject)
}

// Resource returns a detached caller-asserted resource.
func (r DecisionRequest) Resource() Entity {
	return cloneEntity(r.resource)
}

// Environment returns detached caller-asserted domain environment.
func (r DecisionRequest) Environment() Environment {
	return cloneEnvironment(r.environment)
}

// Attributes returns a detached immutable input map.
func (r DecisionRequest) Attributes() ValueMap {
	return cloneValueMap(r.attributes)
}

// Caller returns detached trusted caller evidence.
func (r DecisionRequest) Caller() CallerContext {
	return cloneCaller(r.caller)
}

// Options returns evaluation options for this invocation.
func (r DecisionRequest) Options() EvaluationOptions {
	return r.options
}

// validateCorrelationUse freezes IDs as log, audit, and trace correlation only.
func validateCorrelationUse(use CorrelationUse) error {
	switch use {
	case CorrelationUseLog, CorrelationUseAudit, CorrelationUseTrace:
		return nil
	default:
		return newContractError(
			ErrCorrelationOnly,
			ErrorCodeCorrelationOnly,
			"correlation_id",
			"cannot be used for authorization, caching, deduplication, replay, or metric labels",
		)
	}
}

// validCorrelationID validates safe bounded correlation text.
func validCorrelationID(input string) bool {
	if len(input) == 0 || len(input) > maximumCorrelationIDLength {
		return false
	}

	for index := range len(input) {
		current := input[index]
		if current >= 'a' && current <= 'z' ||
			current >= 'A' && current <= 'Z' ||
			current >= '0' && current <= '9' ||
			strings.ContainsRune("._:-", rune(current)) {
			continue
		}

		return false
	}

	return true
}

// optionalRequestID validates an optional caller-provided correlation value.
func optionalRequestID(input string) (RequestID, error) {
	if input == "" {
		return RequestID{}, nil
	}

	return NewRequestID(input)
}

// validOptionalEntityText validates empty or bounded UTF-8 caller text.
func validOptionalEntityText(input string) bool {
	return input == "" || len(input) <= maximumEntityTextLength && utf8.ValidString(input)
}

// cloneValueMap creates a detached map wrapper.
func cloneValueMap(input ValueMap) ValueMap {
	return ValueMap{values: input.Values()}
}

// cloneEntity creates a detached entity value.
func cloneEntity(input Entity) Entity {
	return Entity{typeName: input.typeName, id: input.id, attributes: cloneValueMap(input.attributes)}
}

// cloneEnvironment creates a detached environment value.
func cloneEnvironment(input Environment) Environment {
	return Environment{
		service:    input.service,
		instance:   input.instance,
		protocol:   input.protocol,
		attributes: cloneValueMap(input.attributes),
	}
}

// cloneCaller creates detached trusted caller context.
func cloneCaller(input CallerContext) CallerContext {
	input.scopes = append([]string(nil), input.scopes...)

	return input
}

// invalidRequest constructs a request taxonomy error.
func invalidRequest(field string, reason string) error {
	return newContractError(ErrInvalidRequest, ErrorCodeInvalidRequest, field, reason)
}

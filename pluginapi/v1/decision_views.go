// Copyright (C) 2026 Christian Roessner
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

package pluginapi

import "unicode/utf8"

const (
	maximumDecisionCallerIdentityLength = 512
	maximumDecisionCallerScopes         = 64
)

// DecisionCallerViewInput carries redacted caller identity into its immutable view.
type DecisionCallerViewInput struct {
	Scopes             []string
	Principal          string
	ClientID           string
	AuthenticationKind string
}

// DecisionCallerView exposes redacted caller identity without credentials or transport state.
type DecisionCallerView struct {
	scopes             []string
	principal          string
	clientID           string
	authenticationKind string
}

// NewDecisionCallerView validates and copies one redacted caller view.
func NewDecisionCallerView(input DecisionCallerViewInput) (DecisionCallerView, error) {
	result := DecisionCallerView{
		scopes:             append([]string(nil), input.Scopes...),
		principal:          input.Principal,
		clientID:           input.ClientID,
		authenticationKind: input.AuthenticationKind,
	}

	if !result.valid() {
		return DecisionCallerView{}, invalidDecisionContract("caller", "contains an invalid redacted identity member")
	}

	return result, nil
}

// Principal returns the redacted authenticated principal when present.
func (v DecisionCallerView) Principal() string {
	return v.principal
}

// ClientID returns the redacted caller client identity when present.
func (v DecisionCallerView) ClientID() string {
	return v.clientID
}

// AuthenticationKind returns the host-classified authentication kind when present.
func (v DecisionCallerView) AuthenticationKind() string {
	return v.authenticationKind
}

// Scopes returns an owned copy of the caller scope set.
func (v DecisionCallerView) Scopes() []string {
	return append([]string(nil), v.scopes...)
}

// clone returns a detached immutable caller view.
func (v DecisionCallerView) clone() DecisionCallerView {
	v.scopes = append([]string(nil), v.scopes...)

	return v
}

// valid checks the caller view constructor invariant.
func (v DecisionCallerView) valid() bool {
	if !validDecisionCallerIdentity(v.principal, false) ||
		!validDecisionCallerIdentity(v.clientID, true) ||
		!validDecisionCallerIdentity(v.authenticationKind, false) {
		return false
	}

	if !validDecisionAction(v.authenticationKind) || len(v.scopes) > maximumDecisionCallerScopes {
		return false
	}

	seen := make(map[string]struct{}, len(v.scopes))
	for _, scope := range v.scopes {
		if !validDecisionCallerIdentity(scope, false) || ValidateScopeToken(scope) != nil {
			return false
		}

		if _, exists := seen[scope]; exists {
			return false
		}

		seen[scope] = struct{}{}
	}

	return true
}

// validDecisionCallerIdentity checks bounded required and optional redacted identity text.
func validDecisionCallerIdentity(value string, optional bool) bool {
	if value == "" {
		return optional
	}

	return len(value) <= maximumDecisionCallerIdentityLength && utf8.ValidString(value)
}

// DecisionFactViewInput carries one trusted host fact into its redacted view.
type DecisionFactViewInput struct {
	ID       string
	Category DecisionFactCategory
	Value    DecisionValue
}

// DecisionFactView exposes a strict fact without provenance or mutation controls.
type DecisionFactView struct {
	id       string
	category DecisionFactCategory
	value    DecisionValue
}

// NewDecisionFactView validates one redacted host fact view.
func NewDecisionFactView(input DecisionFactViewInput) (DecisionFactView, error) {
	if !validDecisionFactName(input.ID) || !input.Category.IsValid() || !input.Value.valid() {
		return DecisionFactView{}, invalidDecisionContract("facts", "contains an invalid fact view")
	}

	return DecisionFactView{id: input.ID, category: input.Category, value: input.Value}, nil
}

// ID returns the canonical admitted fact identity.
func (v DecisionFactView) ID() string {
	return v.id
}

// Category returns the host-assigned fact category.
func (v DecisionFactView) Category() DecisionFactCategory {
	return v.category
}

// Value returns the immutable strict fact value.
func (v DecisionFactView) Value() DecisionValue {
	return v.value
}

// valid checks the fact view constructor invariant.
func (v DecisionFactView) valid() bool {
	return validDecisionFactName(v.id) && v.category.IsValid() && v.value.valid()
}

// DecisionFactRequest is an immutable redacted fact-collection input.
type DecisionFactRequest struct {
	facts  []DecisionFactView
	caller DecisionCallerView
	target DecisionTargetSelector
}

// NewDecisionFactRequest validates and copies one fact-collection input.
func NewDecisionFactRequest(
	target DecisionTargetSelector,
	caller DecisionCallerView,
	facts []DecisionFactView,
) (DecisionFactRequest, error) {
	if err := validateDecisionTargetSelector(target); err != nil {
		return DecisionFactRequest{}, err
	}

	if !caller.valid() {
		return DecisionFactRequest{}, invalidDecisionContract("caller", "must be constructor validated")
	}

	ownedFacts, err := cloneDecisionFactViews(facts)
	if err != nil {
		return DecisionFactRequest{}, err
	}

	return DecisionFactRequest{facts: ownedFacts, caller: caller.clone(), target: target}, nil
}

// Target returns the exact selected target.
func (r DecisionFactRequest) Target() DecisionTargetSelector {
	return r.target
}

// Caller returns a detached redacted caller view.
func (r DecisionFactRequest) Caller() DecisionCallerView {
	return r.caller.clone()
}

// Facts returns a detached fact-view list.
func (r DecisionFactRequest) Facts() []DecisionFactView {
	return append([]DecisionFactView(nil), r.facts...)
}

// DecisionEffectRequestInput carries one host-selected effect into its immutable request.
type DecisionEffectRequestInput struct {
	Parameters map[string]DecisionValue
	Facts      []DecisionFactView
	Target     DecisionTargetSelector
	Caller     DecisionCallerView
	Effect     string
}

// DecisionEffectRequest is an immutable policy-selected effect input.
type DecisionEffectRequest struct {
	parameters map[string]DecisionValue
	facts      []DecisionFactView
	caller     DecisionCallerView
	target     DecisionTargetSelector
	effect     string
}

// NewDecisionEffectRequest validates and copies one selected effect input.
func NewDecisionEffectRequest(input DecisionEffectRequestInput) (DecisionEffectRequest, error) {
	if err := validateDecisionTargetSelector(input.Target); err != nil {
		return DecisionEffectRequest{}, err
	}

	if !validDecisionAction(input.Effect) || !input.Caller.valid() {
		return DecisionEffectRequest{}, invalidDecisionContract("effect request", "contains an invalid effect or caller")
	}

	parameters, err := cloneDecisionParameters(input.Parameters)
	if err != nil {
		return DecisionEffectRequest{}, err
	}

	facts, err := cloneDecisionFactViews(input.Facts)
	if err != nil {
		return DecisionEffectRequest{}, err
	}

	return DecisionEffectRequest{
		parameters: parameters,
		facts:      facts,
		caller:     input.Caller.clone(),
		target:     input.Target,
		effect:     input.Effect,
	}, nil
}

// Target returns the exact selected target.
func (r DecisionEffectRequest) Target() DecisionTargetSelector {
	return r.target
}

// Caller returns a detached redacted caller view.
func (r DecisionEffectRequest) Caller() DecisionCallerView {
	return r.caller.clone()
}

// Effect returns the selected provider-local effect name.
func (r DecisionEffectRequest) Effect() string {
	return r.effect
}

// Facts returns a detached fact-view list.
func (r DecisionEffectRequest) Facts() []DecisionFactView {
	return append([]DecisionFactView(nil), r.facts...)
}

// Parameter returns one immutable selected parameter.
func (r DecisionEffectRequest) Parameter(name string) (DecisionValue, bool) {
	value, exists := r.parameters[name]

	return value, exists
}

// Parameters returns a detached strict parameter map.
func (r DecisionEffectRequest) Parameters() map[string]DecisionValue {
	result := make(map[string]DecisionValue, len(r.parameters))
	for name, value := range r.parameters {
		result[name] = value
	}

	return result
}

// cloneDecisionFactViews validates, de-duplicates, and owns fact views.
func cloneDecisionFactViews(input []DecisionFactView) ([]DecisionFactView, error) {
	if len(input) > maximumDecisionDefinitions {
		return nil, invalidDecisionContract("facts", "contains too many visible fact views")
	}

	result := append([]DecisionFactView(nil), input...)
	seen := make(map[string]struct{}, len(result))

	for _, fact := range result {
		if !fact.valid() {
			return nil, invalidDecisionContract("facts", "must contain constructor-validated views")
		}

		if _, exists := seen[fact.ID()]; exists {
			return nil, invalidDecisionContract("facts", "contains a duplicate fact identity")
		}

		seen[fact.ID()] = struct{}{}
	}

	return result, nil
}

// cloneDecisionParameters validates and owns one selected parameter map.
func cloneDecisionParameters(input map[string]DecisionValue) (map[string]DecisionValue, error) {
	if len(input) > maximumDecisionEffectParameters {
		return nil, invalidDecisionContract("effect parameters", "contains too many selected parameters")
	}

	result := make(map[string]DecisionValue, len(input))

	for name, value := range input {
		if !validDecisionAction(name) || !value.valid() {
			return nil, invalidDecisionContract("effect parameters", "contains an invalid name or value")
		}

		result[name] = value
	}

	return result, nil
}

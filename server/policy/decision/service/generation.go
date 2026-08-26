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
	"context"
	"fmt"
	"reflect"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

// Generation is a sealed captured policy authority generation.
//
// Only this package can construct a generation, so callers cannot replace its
// mandatory security authorities with transport-local implementations.
type Generation interface {
	decisionGeneration() *runtimeGeneration
}

// GenerationSource owns one complete generation for a bounded call or session scope.
type GenerationSource interface {
	WithGeneration(context.Context, func(Generation) error) error
}

type callerAuthenticator interface {
	Authenticate(context.Context, decision.AuthenticationInput) (decision.CallerContext, error)
}

type admissionPermit = policyruntime.AdmissionPermit

type admissionAuthority interface {
	Admit(context.Context, decision.CallerContext, decision.DecisionRequest) (admissionPermit, error)
}

type checkpointEvaluator interface {
	Evaluate(context.Context, checkpointEvaluation) (runtimeEvaluation, error)
}

// checkpointPlanSource exposes the target plan owned by the captured evaluator.
type checkpointPlanSource interface {
	Checkpoints(decision.Target) ([]CheckpointPlan, error)
}

type authorityModeSource interface {
	AuthorityMode(decision.Target) (string, bool)
}

type runtimeGenerationDependencies struct {
	material              policyruntime.DecisionServiceMaterial
	authenticator         callerAuthenticator
	admission             admissionAuthority
	evaluator             checkpointEvaluator
	supervisor            effectsupervisor.Acceptor
	hostProviders         map[string]policyruntime.AuthnHostProvider
	authnLuaFacts         []registry.AuthnLuaFactDeclaration
	authnPolicyAttributes map[string]registry.AttributeDefinition
}

type runtimeGeneration struct {
	messageResolver       policyruntime.MessageResolver
	config                policyruntime.GenerationConfig
	authenticator         callerAuthenticator
	admission             admissionAuthority
	evaluator             checkpointEvaluator
	supervisor            effectsupervisor.Acceptor
	authnHostProviders    map[string]policyruntime.AuthnHostProvider
	authnLuaFacts         []registry.AuthnLuaFactDeclaration
	authnPolicyAttributes map[string]registry.AttributeDefinition
	internalPresentations map[string]decision.AuthenticationInput
	apiAvailability       policyruntime.PolicyAPIAvailability
	id                    uint64
}

// GenerationID returns the immutable server-state generation identity.
func (g *runtimeGeneration) GenerationID() uint64 {
	if g == nil {
		return 0
	}

	return g.id
}

// newRuntimeGeneration constructs one complete immutable application authority generation.
func newRuntimeGeneration(id uint64, deps runtimeGenerationDependencies) (Generation, error) {
	if id == 0 || deps.material.Validate() != nil ||
		nilDependency(deps.authenticator) ||
		nilDependency(deps.admission) ||
		nilDependency(deps.evaluator) ||
		nilDependency(deps.supervisor) {
		return nil, fmt.Errorf("%w: complete generation authorities are required", ErrDecisionServiceDependencyMissing)
	}

	return &runtimeGeneration{
		messageResolver:       deps.material.MessageResolver(),
		config:                deps.material.Config(),
		authenticator:         deps.authenticator,
		admission:             deps.admission,
		evaluator:             deps.evaluator,
		supervisor:            deps.supervisor,
		authnHostProviders:    cloneAuthnHostProviders(deps.hostProviders),
		authnLuaFacts:         cloneAuthnLuaFacts(deps.authnLuaFacts),
		authnPolicyAttributes: cloneAuthnPolicyAttributes(deps.authnPolicyAttributes),
		internalPresentations: cloneInternalPresentations(deps.material.InternalPresentations()),
		apiAvailability:       deps.material.APIAvailability(),
		id:                    id,
	}, nil
}

// decisionGeneration unwraps the sealed generation for the application service only.
func (g *runtimeGeneration) decisionGeneration() *runtimeGeneration {
	return g
}

// valid reports whether the captured generation retains all mandatory authorities.
func (g *runtimeGeneration) valid() bool {
	return g != nil &&
		g.id > 0 &&
		!nilDependency(g.config) &&
		g.apiAvailability.Configured &&
		g.apiAvailability.MaxRequestBytes > 0 &&
		!nilDependency(g.messageResolver) &&
		!nilDependency(g.authenticator) &&
		!nilDependency(g.admission) &&
		!nilDependency(g.evaluator) &&
		!nilDependency(g.supervisor)
}

// cloneAuthnHostProviders detaches the index while retaining immutable prepared owners.
func cloneAuthnHostProviders(
	input map[string]policyruntime.AuthnHostProvider,
) map[string]policyruntime.AuthnHostProvider {
	if len(input) == 0 {
		return nil
	}

	result := make(map[string]policyruntime.AuthnHostProvider, len(input))
	for id, provider := range input {
		result[id] = provider
	}

	return result
}

// cloneAuthnLuaFacts deeply detaches generation-owned registry declarations.
func cloneAuthnLuaFacts(input []registry.AuthnLuaFactDeclaration) []registry.AuthnLuaFactDeclaration {
	result := make([]registry.AuthnLuaFactDeclaration, len(input))
	for index, declaration := range input {
		result[index] = declaration.Clone()
	}

	return result
}

// cloneAuthnPolicyAttributes deeply detaches generation-owned native auth declarations.
func cloneAuthnPolicyAttributes(
	input map[string]registry.AttributeDefinition,
) map[string]registry.AttributeDefinition {
	result := make(map[string]registry.AttributeDefinition, len(input))
	for id, definition := range input {
		result[id] = registry.CloneDefinition(definition)
	}

	return result
}

// cloneInternalPresentations owns the code-provisioned internal credential map.
func cloneInternalPresentations(input map[string]decision.AuthenticationInput) map[string]decision.AuthenticationInput {
	if len(input) == 0 {
		return nil
	}

	result := make(map[string]decision.AuthenticationInput, len(input))
	for id, presentation := range input {
		result[id] = presentation
	}

	return result
}

// nilDependency rejects nil and typed-nil injected interface values.
func nilDependency(input any) bool {
	if input == nil {
		return true
	}

	value := reflect.ValueOf(input)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

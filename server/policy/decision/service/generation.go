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

type admissionAuthority interface {
	Admit(context.Context, decision.CallerContext, decision.DecisionRequest) error
}

type checkpointEvaluator interface {
	Evaluate(context.Context, checkpointEvaluation) (runtimeEvaluation, error)
}

// checkpointPlanSource exposes the target plan owned by the captured evaluator.
type checkpointPlanSource interface {
	Checkpoints(decision.Target) ([]CheckpointPlan, error)
}

type authnPolicySnapshotSource interface {
	authnPolicySnapshot() *policyruntime.Snapshot
}

type runtimeGenerationDependencies struct {
	authenticator callerAuthenticator
	admission     admissionAuthority
	evaluator     checkpointEvaluator
	supervisor    effectsupervisor.Acceptor
}

type runtimeGeneration struct {
	authenticator callerAuthenticator
	admission     admissionAuthority
	evaluator     checkpointEvaluator
	supervisor    effectsupervisor.Acceptor
	id            uint64
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
	if id == 0 ||
		nilDependency(deps.authenticator) ||
		nilDependency(deps.admission) ||
		nilDependency(deps.evaluator) ||
		nilDependency(deps.supervisor) {
		return nil, fmt.Errorf("%w: complete generation authorities are required", ErrDecisionServiceDependencyMissing)
	}

	return &runtimeGeneration{
		authenticator: deps.authenticator,
		admission:     deps.admission,
		evaluator:     deps.evaluator,
		supervisor:    deps.supervisor,
		id:            id,
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
		!nilDependency(g.authenticator) &&
		!nilDependency(g.admission) &&
		!nilDependency(g.evaluator) &&
		!nilDependency(g.supervisor)
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

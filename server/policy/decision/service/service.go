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

// Package service owns the admission-enforcing policy decision application authority.
package service

import (
	"context"
	"errors"
	"fmt"
	"sync"

	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

var _ decision.Service = (*DecisionService)(nil)

// DecisionSessionFactory is the scoped authn adapter boundary of the same authority.
type DecisionSessionFactory interface {
	WithSession(context.Context, decision.Invocation, func(DecisionSession) error) error
}

// DecisionSession evaluates multiple checkpoints on one admitted captured generation.
type DecisionSession interface {
	Checkpoints() []CheckpointPlan
	RequestContext(context.Context) context.Context
	Evaluate(context.Context, decision.Checkpoint) (decision.DecisionResponse, error)
}

// CheckpointPlan is one detached checkpoint and its immutable provider order.
type CheckpointPlan struct {
	name        string
	providerIDs []string
}

// newCheckpointPlan constructs one detached runtime-owned checkpoint plan.
func newCheckpointPlan(name string, providerIDs []string) CheckpointPlan {
	return CheckpointPlan{name: name, providerIDs: append([]string(nil), providerIDs...)}
}

// NewCheckpointPlan constructs one detached session-boundary checkpoint descriptor.
func NewCheckpointPlan(name string, providerIDs []string) (CheckpointPlan, error) {
	if name == "" {
		return CheckpointPlan{}, fmt.Errorf("%w: checkpoint name is required", ErrDecisionEvaluation)
	}

	seen := make(map[string]struct{}, len(providerIDs))
	for _, providerID := range providerIDs {
		if providerID == "" {
			return CheckpointPlan{}, fmt.Errorf("%w: provider identity is required", ErrDecisionEvaluation)
		}

		if _, exists := seen[providerID]; exists {
			return CheckpointPlan{}, fmt.Errorf("%w: duplicate provider identity", ErrDecisionEvaluation)
		}

		seen[providerID] = struct{}{}
	}

	return newCheckpointPlan(name, providerIDs), nil
}

// Name returns the exact checkpoint identity.
func (p CheckpointPlan) Name() string {
	return p.name
}

// ProviderIDs returns the detached scheduled host-provider order.
func (p CheckpointPlan) ProviderIDs() []string {
	return append([]string(nil), p.providerIDs...)
}

// clone returns one deeply detached checkpoint plan.
func (p CheckpointPlan) clone() CheckpointPlan {
	return newCheckpointPlan(p.name, p.providerIDs)
}

// DecisionService is the sole callable policy decision application authority.
type DecisionService struct {
	generations GenerationSource
}

// NewDecisionService constructs the authority with a mandatory generation source.
func NewDecisionService(generations GenerationSource) (*DecisionService, error) {
	if nilDependency(generations) {
		return nil, fmt.Errorf("%w: generation source is required", ErrDecisionServiceDependencyMissing)
	}

	return &DecisionService{generations: generations}, nil
}

// Evaluate authenticates and admits one unary invocation before one final checkpoint.
func (s *DecisionService) Evaluate(
	ctx context.Context,
	invocation decision.Invocation,
) (decision.DecisionResponse, error) {
	var response decision.DecisionResponse

	err := s.withSession(ctx, invocation, false, func(session DecisionSession) error {
		facts, factErr := decision.NewFactSet(nil)
		if factErr != nil {
			return fmt.Errorf("%w: create unary fact set", ErrDecisionEvaluation)
		}

		checkpoint, checkpointErr := decision.NewCheckpoint(decision.CheckpointFinalDecision, facts)
		if checkpointErr != nil {
			return fmt.Errorf("%w: create unary checkpoint", ErrDecisionEvaluation)
		}

		var evaluationErr error

		response, evaluationErr = session.Evaluate(ctx, checkpoint)

		return evaluationErr
	})

	return response, err
}

// WithSession owns one admitted builtin authn session for the complete callback scope.
func (s *DecisionService) WithSession(
	ctx context.Context,
	invocation decision.Invocation,
	use func(DecisionSession) error,
) error {
	return s.withSession(ctx, invocation, true, use)
}

// withSession owns capture, authentication, admission, and scoped session release.
func (s *DecisionService) withSession(
	ctx context.Context,
	invocation decision.Invocation,
	requireInternalAuthn bool,
	use func(DecisionSession) error,
) error {
	ctx = normalizeContext(ctx)

	if use == nil {
		return fmt.Errorf("%w: session callback is required", ErrDecisionServiceDependencyMissing)
	}

	return s.withGeneration(ctx, func(generation *runtimeGeneration) error {
		generationCtx := policyruntime.ContextWithGeneration(ctx, generation.id)

		session, err := s.openSession(generationCtx, generation, invocation, requireInternalAuthn)
		if err != nil {
			return err
		}
		defer session.close()

		return use(session)
	})
}

// openSession authenticates and admits one invocation against an already captured generation.
func (s *DecisionService) openSession(
	ctx context.Context,
	generation *runtimeGeneration,
	invocation decision.Invocation,
	requireInternalAuthn bool,
) (*decisionSession, error) {
	caller, request, err := authenticateInvocation(ctx, generation, invocation)
	if err != nil {
		return nil, err
	}

	permit, err := generation.admission.Admit(ctx, caller, request)
	if err != nil {
		if !nilDependency(permit) {
			permit.Release()
		}

		return nil, newDecisionAdmissionError(err)
	}

	if nilDependency(permit) {
		return nil, fmt.Errorf("%w: caller or invocation was rejected", ErrDecisionAdmission)
	}

	if requireInternalAuthn && (!caller.Internal() || !validAuthnTarget(request.Target())) {
		permit.Release()

		return nil, fmt.Errorf("%w: authn sessions require the admitted builtin internal caller", ErrDecisionAdmission)
	}

	checkpoints, err := sessionCheckpointPlan(generation.evaluator, request.Target(), requireInternalAuthn)
	if err != nil {
		permit.Release()

		return nil, err
	}

	facts, err := decision.NewFactSet(permit.Facts().Facts())
	if err != nil {
		permit.Release()

		return nil, fmt.Errorf("%w: admission returned invalid facts", ErrDecisionAdmission)
	}

	return &decisionSession{
		generation:   generation,
		request:      request,
		facts:        facts,
		permit:       permit,
		finalization: invocation.Finalization,
		checkpoints:  checkpoints,
	}, nil
}

// sessionCheckpointPlan captures one target plan from the same generation evaluator.
func sessionCheckpointPlan(
	evaluator checkpointEvaluator,
	target decision.Target,
	requireCompiledPlan bool,
) ([]CheckpointPlan, error) {
	source, ok := evaluator.(checkpointPlanSource)
	if !ok {
		if requireCompiledPlan {
			return nil, fmt.Errorf("%w: authn evaluator has no compiled checkpoint plan", ErrDecisionEvaluation)
		}

		return []CheckpointPlan{newCheckpointPlan(decision.CheckpointFinalDecision, nil)}, nil
	}

	checkpoints, err := source.Checkpoints(target)
	if err != nil || len(checkpoints) == 0 {
		return nil, fmt.Errorf("%w: target has no compiled checkpoint plan", ErrDecisionEvaluation)
	}

	return cloneCheckpointPlans(checkpoints), nil
}

// validAuthnTarget restricts reusable sessions to the exact builtin authn operations.
func validAuthnTarget(target decision.Target) bool {
	if target.Namespace() != policy.AuthnNamespace {
		return false
	}

	switch policy.Operation(target.Action()) {
	case policy.OperationAuthenticate, policy.OperationLookupIdentity, policy.OperationListAccounts:
		return true
	default:
		return false
	}
}

// withGeneration validates and uses the sole generation owned by one call or session.
func (s *DecisionService) withGeneration(
	ctx context.Context,
	use func(*runtimeGeneration) error,
) error {
	if s == nil || nilDependency(s.generations) {
		return fmt.Errorf("%w: generation source is required", ErrDecisionServiceDependencyMissing)
	}

	return s.generations.WithGeneration(ctx, func(captured Generation) error {
		if nilDependency(captured) {
			return fmt.Errorf("%w: capture returned no generation", ErrDecisionGenerationUnavailable)
		}

		generation := captured.decisionGeneration()
		if !generation.valid() {
			return fmt.Errorf("%w: capture returned an incomplete generation", ErrDecisionGenerationUnavailable)
		}

		return use(generation)
	})
}

// authenticateInvocation creates the sole trusted caller-bound request representation.
func authenticateInvocation(
	ctx context.Context,
	generation *runtimeGeneration,
	invocation decision.Invocation,
) (decision.CallerContext, decision.DecisionRequest, error) {
	if !validAuthenticationInput(invocation.Authentication) {
		return decision.CallerContext{}, decision.DecisionRequest{}, fmt.Errorf(
			"%w: invalid authentication presentation",
			ErrDecisionAuthentication,
		)
	}

	caller, err := generation.authenticator.Authenticate(ctx, invocation.Authentication)
	if err != nil {
		return decision.CallerContext{}, decision.DecisionRequest{}, fmt.Errorf(
			"%w: credential evidence was rejected",
			ErrDecisionAuthentication,
		)
	}

	request, err := decision.NewDecisionRequest(invocation.Request, caller)
	if err != nil {
		if errors.Is(err, decision.ErrInvalidCaller) {
			return decision.CallerContext{}, decision.DecisionRequest{}, fmt.Errorf(
				"%w: authenticator returned invalid caller evidence",
				ErrDecisionAuthentication,
			)
		}

		return decision.CallerContext{}, decision.DecisionRequest{}, err
	}

	return caller, request, nil
}

// normalizeContext supplies a non-nil application context for direct callers.
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}

	return ctx
}

// validAuthenticationInput reuses the transport-neutral constructor invariant.
func validAuthenticationInput(input decision.AuthenticationInput) bool {
	_, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          input.Kind(),
		Credential:    input.Credential(),
		TransportKind: input.TransportKind(),
		Listener:      input.Listener(),
		HTTPRoute:     input.HTTPRoute(),
		GRPCMethod:    input.GRPCMethod(),
		Peer:          input.Peer(),
		MTLSIdentity:  input.MTLSIdentity(),
		Protected:     input.Protected(),
	})

	return err == nil
}

type decisionSession struct {
	generation   *runtimeGeneration
	request      decision.DecisionRequest
	facts        decision.FactSet
	permit       admissionPermit
	finalization decision.EvaluationFinalization
	checkpoints  []CheckpointPlan
	mu           sync.Mutex
	evaluations  sync.WaitGroup
	next         int
	evaluating   bool
	closed       bool
}

// RequestContext binds host work to the exact policy view captured by this session.
func (s *decisionSession) RequestContext(ctx context.Context) context.Context {
	ctx = normalizeContext(ctx)
	if s == nil || s.generation == nil {
		return ctx
	}

	ctx = policyruntime.ContextWithGeneration(ctx, s.generation.id)
	source, ok := s.generation.evaluator.(authnPolicySnapshotSource)

	if !ok {
		return ctx
	}

	return policyruntime.ContextWithPolicySnapshot(ctx, source.authnPolicySnapshot())
}

// Checkpoints returns the detached compiled plan while the session is in scope.
func (s *decisionSession) Checkpoints() []CheckpointPlan {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	return cloneCheckpointPlans(s.checkpoints)
}

// cloneCheckpointPlans detaches checkpoint identities and provider schedules together.
func cloneCheckpointPlans(plans []CheckpointPlan) []CheckpointPlan {
	result := make([]CheckpointPlan, 0, len(plans))
	for _, plan := range plans {
		result = append(result, plan.clone())
	}

	return result
}

// Evaluate runs one checkpoint on the generation and evaluator captured by the session.
func (s *decisionSession) Evaluate(
	ctx context.Context,
	checkpoint decision.Checkpoint,
) (decision.DecisionResponse, error) {
	if s == nil || !s.beginEvaluation(checkpoint.Name()) {
		return decision.DecisionResponse{}, fmt.Errorf("%w: invalid session or checkpoint", ErrDecisionEvaluation)
	}
	defer s.endEvaluation()

	ctx = policyruntime.ContextWithGeneration(ctx, s.generation.id)

	ownedCheckpoint, err := decision.NewCheckpoint(checkpoint.Name(), checkpoint.Facts())
	if err != nil {
		return decision.DecisionResponse{}, fmt.Errorf("%w: invalid session or checkpoint", ErrDecisionEvaluation)
	}

	evaluation := checkpointEvaluation{
		request:      s.request,
		checkpoint:   ownedCheckpoint,
		facts:        s.facts,
		finalization: s.finalization,
		supervisor:   s.generation.supervisor,
		generation:   s.generation.id,
	}
	if !evaluation.valid() {
		return decision.DecisionResponse{}, fmt.Errorf("%w: incomplete checkpoint runtime input", ErrDecisionEvaluation)
	}

	outcome, err := s.generation.evaluator.Evaluate(normalizeContext(ctx), evaluation)
	if err != nil {
		return decision.DecisionResponse{}, fmt.Errorf("%w: checkpoint execution failed", ErrDecisionEvaluation)
	}

	if !outcome.valid(s.generation.id, ownedCheckpoint.Name()) {
		return decision.DecisionResponse{}, fmt.Errorf("%w: evaluator returned an invalid boundary result", ErrDecisionEvaluation)
	}

	return outcome.response, nil
}

// beginEvaluation enforces compiled checkpoint order and serial session execution.
func (s *decisionSession) beginEvaluation(checkpoint string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || s.evaluating || !s.generation.valid() || s.next >= len(s.checkpoints) || s.checkpoints[s.next].Name() != checkpoint {
		return false
	}

	s.next++
	s.evaluating = true
	s.evaluations.Add(1)

	return true
}

// endEvaluation releases the serial checkpoint slot before session closure can finish.
func (s *decisionSession) endEvaluation() {
	s.mu.Lock()
	s.evaluating = false
	s.mu.Unlock()

	s.evaluations.Done()
}

// close rejects escaped checkpoints and waits for callbacks already in progress.
func (s *decisionSession) close() {
	if s == nil {
		return
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()

		return
	}

	s.closed = true
	permit := s.permit
	s.permit = nil
	s.mu.Unlock()

	s.evaluations.Wait()

	if permit != nil {
		permit.Release()
	}
}

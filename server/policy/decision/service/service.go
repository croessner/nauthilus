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

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	authnNamespace            = "authn"
	authnActionAuthenticate   = "authenticate"
	authnActionLookupIdentity = "lookup_identity"
	authnActionListAccounts   = "list_accounts"
)

var _ decision.Service = (*DecisionService)(nil)

// DecisionSessionFactory is the scoped authn adapter boundary of the same authority.
type DecisionSessionFactory interface {
	WithSession(context.Context, decision.Invocation, func(DecisionSession) error) error
}

// DecisionSession evaluates multiple checkpoints on one admitted captured generation.
type DecisionSession interface {
	Evaluate(context.Context, decision.Checkpoint) (decision.DecisionResponse, error)
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

	if err := generation.admission.Admit(ctx, caller, request); err != nil {
		return nil, fmt.Errorf("%w: caller or invocation was rejected", ErrDecisionAdmission)
	}

	if requireInternalAuthn && (!caller.Internal() || !validAuthnTarget(request.Target())) {
		return nil, fmt.Errorf("%w: authn sessions require the admitted builtin internal caller", ErrDecisionAdmission)
	}

	return &decisionSession{generation: generation, request: request, finalization: invocation.Finalization}, nil
}

// validAuthnTarget restricts reusable sessions to the exact builtin authn operations.
func validAuthnTarget(target decision.Target) bool {
	if target.Namespace() != authnNamespace {
		return false
	}

	switch target.Action() {
	case authnActionAuthenticate, authnActionLookupIdentity, authnActionListAccounts:
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
		Peer:          input.Peer(),
		MTLSIdentity:  input.MTLSIdentity(),
		Protected:     input.Protected(),
	})

	return err == nil
}

type decisionSession struct {
	generation   *runtimeGeneration
	request      decision.DecisionRequest
	finalization decision.EvaluationFinalization
	mu           sync.Mutex
	evaluations  sync.WaitGroup
	closed       bool
}

// Evaluate runs one checkpoint on the generation and evaluator captured by the session.
func (s *decisionSession) Evaluate(
	ctx context.Context,
	checkpoint decision.Checkpoint,
) (decision.DecisionResponse, error) {
	if s == nil || !s.beginEvaluation() {
		return decision.DecisionResponse{}, fmt.Errorf("%w: invalid session or checkpoint", ErrDecisionEvaluation)
	}
	defer s.evaluations.Done()

	ctx = policyruntime.ContextWithGeneration(ctx, s.generation.id)

	ownedCheckpoint, err := decision.NewCheckpoint(checkpoint.Name(), checkpoint.Facts())
	if err != nil {
		return decision.DecisionResponse{}, fmt.Errorf("%w: invalid session or checkpoint", ErrDecisionEvaluation)
	}

	evaluation := checkpointEvaluation{
		request:      s.request,
		checkpoint:   ownedCheckpoint,
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

// beginEvaluation prevents checkpoint work from starting after scoped session release.
func (s *decisionSession) beginEvaluation() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || !s.generation.valid() {
		return false
	}

	s.evaluations.Add(1)

	return true
}

// close rejects escaped checkpoints and waits for callbacks already in progress.
func (s *decisionSession) close() {
	if s == nil {
		return
	}

	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	s.evaluations.Wait()
}

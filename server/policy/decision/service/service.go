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

// DecisionSessionFactory is the narrow authn adapter boundary of the same authority.
type DecisionSessionFactory interface {
	OpenSession(context.Context, decision.Invocation) (DecisionSession, error)
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
	session, err := s.openSession(ctx, invocation, false)
	if err != nil {
		return decision.DecisionResponse{}, err
	}

	facts, err := decision.NewFactSet(nil)
	if err != nil {
		return decision.DecisionResponse{}, fmt.Errorf("%w: create unary fact set", ErrDecisionEvaluation)
	}

	checkpoint, err := decision.NewCheckpoint(decision.CheckpointFinalDecision, facts)
	if err != nil {
		return decision.DecisionResponse{}, fmt.Errorf("%w: create unary checkpoint", ErrDecisionEvaluation)
	}

	return session.Evaluate(ctx, checkpoint)
}

// OpenSession authenticates and admits one exact builtin internal authn invocation.
func (s *DecisionService) OpenSession(
	ctx context.Context,
	invocation decision.Invocation,
) (DecisionSession, error) {
	return s.openSession(ctx, invocation, true)
}

// openSession owns the single authentication, admission, and generation-capture path.
func (s *DecisionService) openSession(
	ctx context.Context,
	invocation decision.Invocation,
	requireInternalAuthn bool,
) (*decisionSession, error) {
	ctx = normalizeContext(ctx)

	generation, err := s.captureGeneration(ctx)
	if err != nil {
		return nil, err
	}

	ctx = policyruntime.ContextWithGeneration(ctx, generation.id)

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

// captureGeneration captures and validates the sole generation used by one call or session.
func (s *DecisionService) captureGeneration(ctx context.Context) (*runtimeGeneration, error) {
	if s == nil || nilDependency(s.generations) {
		return nil, fmt.Errorf("%w: generation source is required", ErrDecisionServiceDependencyMissing)
	}

	captured, err := s.generations.Capture(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: generation capture failed", ErrDecisionGenerationUnavailable)
	}

	if nilDependency(captured) {
		return nil, fmt.Errorf("%w: capture returned no generation", ErrDecisionGenerationUnavailable)
	}

	generation := captured.decisionGeneration()
	if !generation.valid() {
		return nil, fmt.Errorf("%w: capture returned an incomplete generation", ErrDecisionGenerationUnavailable)
	}

	return generation, nil
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
}

// Evaluate runs one checkpoint on the generation and evaluator captured by the session.
func (s *decisionSession) Evaluate(
	ctx context.Context,
	checkpoint decision.Checkpoint,
) (decision.DecisionResponse, error) {
	if s == nil || !s.generation.valid() {
		return decision.DecisionResponse{}, fmt.Errorf("%w: invalid session or checkpoint", ErrDecisionEvaluation)
	}

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

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

package core

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
)

const (
	authnCandidateSubjectType  = "authentication-subject"
	authnCandidateResourceType = "authentication-service"
)

type authnCandidateApplicationService struct {
	current        AuthApplicationService
	sessions       decisionservice.DecisionSessionFactory
	authentication authnAuthenticationPresentation
	facts          authnFactBuilder
}

type authnAuthenticationPresentation struct {
	credential []byte
	kind       string
}

type authnApplicationResult struct {
	auth     *AuthOutcome
	accounts *ListAccountsOutcome
}

// NewAuthnCandidateApplicationService constructs an inactive authn Decision Service adapter.
//
// Production wiring intentionally continues to use NewAuthApplicationService until the
// authority cutover activates the unified runtime. The caller supplies opaque host-created
// admission evidence; the adapter never derives that authority from user credentials.
func NewAuthnCandidateApplicationService(
	current AuthApplicationService,
	sessions decisionservice.DecisionSessionFactory,
	authentication decision.AuthenticationInput,
) (AuthApplicationService, error) {
	if nilAuthnCandidateDependency(current) || nilAuthnCandidateDependency(sessions) {
		return nil, fmt.Errorf("%w: authn candidate service", ErrAuthApplicationDependencyMissing)
	}

	presentation := authnAuthenticationPresentation{
		credential: authentication.Credential(),
		kind:       authentication.Kind(),
	}
	if presentation.kind == "" || len(presentation.credential) == 0 {
		return nil, fmt.Errorf("%w: authn candidate authentication", ErrAuthApplicationDependencyMissing)
	}

	facts, err := newAuthnFactBuilder()
	if err != nil {
		return nil, fmt.Errorf("build authn candidate fact mapper: %w", err)
	}

	return &authnCandidateApplicationService{
		current:        current,
		sessions:       sessions,
		authentication: presentation,
		facts:          facts,
	}, nil
}

// Authenticate runs the current password pipeline within one admitted candidate session.
func (s *authnCandidateApplicationService) Authenticate(
	ctx context.Context,
	input AuthInput,
) (*AuthOutcome, error) {
	result, err := s.run(ctx, input, policy.OperationAuthenticate)
	if err != nil {
		return nil, err
	}

	return result.auth, nil
}

// LookupIdentity runs the current identity lookup within one admitted candidate session.
func (s *authnCandidateApplicationService) LookupIdentity(
	ctx context.Context,
	input AuthInput,
) (*AuthOutcome, error) {
	result, err := s.run(ctx, input, policy.OperationLookupIdentity)
	if err != nil {
		return nil, err
	}

	return result.auth, nil
}

// ListAccounts runs the current account provider within one admitted candidate session.
func (s *authnCandidateApplicationService) ListAccounts(
	ctx context.Context,
	input AuthInput,
) (*ListAccountsOutcome, error) {
	result, err := s.run(ctx, input, policy.OperationListAccounts)
	if err != nil {
		return nil, err
	}

	return result.accounts, nil
}

// run owns validation, session admission, current execution, and final candidate mapping.
func (s *authnCandidateApplicationService) run(
	ctx context.Context,
	input AuthInput,
	operation policy.Operation,
) (authnApplicationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return authnApplicationResult{}, err
	}

	input = normalizeAuthInput(input, authModeForOperation(operation))
	if err := validateAuthnCandidateInput(input, operation); err != nil {
		return authnApplicationResult{}, err
	}

	invocation, err := newAuthnCandidateInvocation(ctx, input, operation, s.facts, s.authentication)
	if err != nil {
		return authnApplicationResult{}, fmt.Errorf("build authn candidate invocation: %w", err)
	}

	var (
		result    authnApplicationResult
		execution *authnCandidateExecution
	)

	err = s.sessions.WithSession(ctx, invocation, func(session decisionservice.DecisionSession) error {
		evaluationCtx := session.RequestContext(ctx)

		if host, ok := s.current.(authnCandidateHost); ok {
			var prepareErr error

			execution, evaluationCtx, prepareErr = host.prepareAuthnCandidateExecution(evaluationCtx, input, operation)
			if prepareErr != nil {
				return prepareErr
			}
		}

		var traversalErr error

		result, traversalErr = s.runCheckpointPlan(evaluationCtx, session, input, operation, execution)

		return traversalErr
	})
	if err != nil {
		return authnApplicationResult{}, fmt.Errorf("authn candidate decision session: %w", err)
	}

	if !result.validFor(operation) {
		return authnApplicationResult{}, ErrAuthOutcomeMissing
	}

	return result, nil
}

// runCheckpointPlan traverses the captured compiled order and runs host work before its final checkpoint.
func (s *authnCandidateApplicationService) runCheckpointPlan(
	ctx context.Context,
	session decisionservice.DecisionSession,
	input AuthInput,
	operation policy.Operation,
	execution *authnCandidateExecution,
) (authnApplicationResult, error) {
	checkpoints := session.Checkpoints()
	if len(checkpoints) == 0 {
		return authnApplicationResult{}, fmt.Errorf("authn candidate session has no compiled checkpoints")
	}

	lastCheckpoint := len(checkpoints) - 1
	current := authnApplicationResult{}

	for index, checkpoint := range checkpoints {
		final := index == lastCheckpoint
		if execution != nil {
			var err error

			current, err = execution.prepareCheckpoint(checkpoint)
			if err != nil {
				return authnApplicationResult{}, err
			}
		} else if final {
			var err error

			current, err = s.runCurrent(ctx, input, operation)
			if err != nil {
				return authnApplicationResult{}, err
			}
		}

		facts, err := s.checkpointFacts(input, operation, current, final)
		if err != nil {
			return authnApplicationResult{}, err
		}

		response, err := evaluateAuthnCandidateCheckpoint(ctx, session, checkpoint.Name(), facts)
		if err != nil {
			return authnApplicationResult{}, err
		}

		if final {
			if execution != nil {
				return execution.finalize(checkpoint.Name(), response, current)
			}

			return current.mapEffect(response.Effect())
		}

		if terminalAuthnCheckpointEffect(response.Effect()) {
			if execution != nil {
				return execution.finalize(checkpoint.Name(), response, current)
			}

			return newAuthnTerminalResult(operation, response.Effect())
		}

		if response.Effect() != decision.EffectNotApplicable {
			return authnApplicationResult{}, fmt.Errorf("unsupported intermediate authn candidate effect %q", response.Effect())
		}
	}

	return authnApplicationResult{}, ErrAuthOutcomeMissing
}

// checkpointFacts keeps pre-backend checkpoints empty and maps current state only at the final boundary.
func (s *authnCandidateApplicationService) checkpointFacts(
	input AuthInput,
	operation policy.Operation,
	current authnApplicationResult,
	final bool,
) (decision.FactSet, error) {
	if !final {
		facts, err := decision.NewFactSet(nil)
		if err != nil {
			return decision.FactSet{}, fmt.Errorf("build authn candidate checkpoint facts: %w", err)
		}

		return facts, nil
	}

	facts, err := s.facts.Build(input, operation, current, decision.FactSet{})
	if err != nil {
		return decision.FactSet{}, fmt.Errorf("build authn candidate facts: %w", err)
	}

	return facts, nil
}

// evaluateAuthnCandidateCheckpoint constructs and evaluates one plan-selected checkpoint.
func evaluateAuthnCandidateCheckpoint(
	ctx context.Context,
	session decisionservice.DecisionSession,
	name string,
	facts decision.FactSet,
) (decision.DecisionResponse, error) {
	checkpoint, err := decision.NewCheckpoint(name, facts)
	if err != nil {
		return decision.DecisionResponse{}, fmt.Errorf("build authn candidate checkpoint: %w", err)
	}

	return session.Evaluate(ctx, checkpoint)
}

// terminalAuthnCheckpointEffect identifies fail-closed decisions before later host work.
func terminalAuthnCheckpointEffect(effect decision.Effect) bool {
	return effect == decision.EffectDeny || effect == decision.EffectIndeterminate
}

// newAuthnTerminalResult preserves the established public category without fabricating backend payloads.
func newAuthnTerminalResult(
	operation policy.Operation,
	effect decision.Effect,
) (authnApplicationResult, error) {
	var mapped AuthDecision

	switch effect {
	case decision.EffectDeny:
		mapped = AuthDecisionFail
	case decision.EffectIndeterminate:
		mapped = AuthDecisionTempFail
	default:
		return authnApplicationResult{}, fmt.Errorf("unsupported terminal authn candidate effect %q", effect)
	}

	if operation == policy.OperationListAccounts {
		return authnApplicationResult{accounts: &ListAccountsOutcome{Decision: mapped}}, nil
	}

	return authnApplicationResult{auth: &AuthOutcome{Decision: mapped}}, nil
}

// runCurrent invokes exactly one existing operation while the captured session remains open.
func (s *authnCandidateApplicationService) runCurrent(
	ctx context.Context,
	input AuthInput,
	operation policy.Operation,
) (authnApplicationResult, error) {
	switch operation {
	case policy.OperationAuthenticate:
		outcome, err := s.current.Authenticate(ctx, input)

		return authnApplicationResult{auth: outcome}, err
	case policy.OperationLookupIdentity:
		outcome, err := s.current.LookupIdentity(ctx, input)

		return authnApplicationResult{auth: outcome}, err
	case policy.OperationListAccounts:
		outcome, err := s.current.ListAccounts(ctx, input)

		return authnApplicationResult{accounts: outcome}, err
	default:
		return authnApplicationResult{}, &AuthInputError{Field: authInputFieldMode, Reason: authInputReasonUnsupported}
	}
}

// mapEffect applies only the existing public outcome category at the final adapter boundary.
func (r authnApplicationResult) mapEffect(effect decision.Effect) (authnApplicationResult, error) {
	if effect == decision.EffectNotApplicable {
		return r, nil
	}

	var mapped AuthDecision

	switch effect {
	case decision.EffectPermit:
		mapped = AuthDecisionOK
	case decision.EffectDeny:
		mapped = AuthDecisionFail
	case decision.EffectIndeterminate:
		mapped = AuthDecisionTempFail
	default:
		return authnApplicationResult{}, fmt.Errorf("unsupported authn candidate effect %q", effect)
	}

	if r.auth != nil {
		outcome := cloneAuthnCandidateOutcome(r.auth)
		outcome.Decision = mapped
		if mapped == AuthDecisionTempFail {
			applyAuthnCandidateTempFail(outcome)
		}
		r.auth = outcome
	}

	if r.accounts != nil {
		outcome := cloneAuthnCandidateListOutcome(r.accounts)
		outcome.Decision = mapped
		if mapped == AuthDecisionTempFail {
			applyAuthnCandidateListTempFail(outcome)
		}
		r.accounts = outcome
	}

	return r, nil
}

// applyAuthnCandidateTempFail publishes the established complete temporary-failure surface.
func applyAuthnCandidateTempFail(outcome *AuthOutcome) {
	if outcome == nil {
		return
	}

	outcome.TerminalState = string(authFSMStateAuthTempFail)
	outcome.StatusMessage = definitions.TempFailDefault
	outcome.Error = definitions.TempFailDefault
	outcome.HTTPStatus = http.StatusInternalServerError
}

// applyAuthnCandidateListTempFail publishes the list-accounts temporary-failure surface.
func applyAuthnCandidateListTempFail(outcome *ListAccountsOutcome) {
	if outcome == nil {
		return
	}

	outcome.StatusMessage = definitions.TempFailDefault
	outcome.Error = definitions.TempFailDefault
	outcome.HTTPStatus = http.StatusInternalServerError
}

// validFor reports whether the current operation produced its established outcome type.
func (r authnApplicationResult) validFor(operation policy.Operation) bool {
	if operation == policy.OperationListAccounts {
		return r.accounts != nil && r.auth == nil
	}

	return r.auth != nil && r.accounts == nil
}

// cloneAuthnCandidateOutcome detaches mutable payloads before changing the candidate decision.
func cloneAuthnCandidateOutcome(input *AuthOutcome) *AuthOutcome {
	if input == nil {
		return nil
	}

	output := *input
	output.Attributes = input.Attributes.Clone()
	output.FSMEventPath = append([]string(nil), input.FSMEventPath...)
	output.Groups = append([]string(nil), input.Groups...)
	output.GroupDistinguishedNames = append([]string(nil), input.GroupDistinguishedNames...)

	return &output
}

// cloneAuthnCandidateListOutcome detaches the account list before changing the candidate decision.
func cloneAuthnCandidateListOutcome(input *ListAccountsOutcome) *ListAccountsOutcome {
	if input == nil {
		return nil
	}

	output := *input
	output.Accounts = append(AccountList(nil), input.Accounts...)

	return &output
}

// newAuthnCandidateInvocation maps one application operation into the internal decision contract.
func newAuthnCandidateInvocation(
	ctx context.Context,
	input AuthInput,
	operation policy.Operation,
	facts authnFactBuilder,
	authentication authnAuthenticationPresentation,
) (decision.Invocation, error) {
	requestAttributes, err := facts.RequestAttributes(input)
	if err != nil {
		return decision.Invocation{}, err
	}

	target, err := decision.NewTarget(policy.AuthnNamespace, string(operation))
	if err != nil {
		return decision.Invocation{}, err
	}

	subject, err := decision.NewEntity(decision.EntityInput{
		Type: authnCandidateSubjectType,
		ID:   input.Credentials.Username,
	})
	if err != nil {
		return decision.Invocation{}, err
	}

	resource, err := decision.NewEntity(decision.EntityInput{
		Type: authnCandidateResourceType,
		ID:   input.Service,
	})
	if err != nil {
		return decision.Invocation{}, err
	}

	environment, err := decision.NewEnvironment(decision.EnvironmentInput{
		Service:    input.Service,
		Protocol:   input.Context.Protocol,
		Attributes: requestAttributes.environment,
	})
	if err != nil {
		return decision.Invocation{}, err
	}

	authenticationInput, err := newAuthnCandidateAuthentication(ctx, input, authentication)
	if err != nil {
		return decision.Invocation{}, err
	}

	finalization := authnCandidateFinalization(ctx, input)
	if !finalization.Valid() {
		return decision.Invocation{}, fmt.Errorf("authn candidate finalization gate is unavailable")
	}

	return decision.Invocation{
		Request: decision.DecisionRequestInput{
			Version:     decision.ContractVersion,
			Target:      target,
			Subject:     subject,
			Resource:    resource,
			Environment: environment,
			Attributes:  requestAttributes.input,
		},
		Authentication: authenticationInput,
		Finalization:   finalization,
	}, nil
}

// authnCandidateFinalization selects the immutable application-response boundary.
func authnCandidateFinalization(ctx context.Context, input AuthInput) decision.EvaluationFinalization {
	gate := PostActionFinalizationGateFromContext(ctx)
	boundary := authnCandidateFinalizationBoundary(input)

	if gate == nil || gate.Boundary() != boundary {
		return decision.EvaluationFinalization{}
	}

	return decision.NewExternalEvaluationFinalization(boundary, gate.Done())
}

// authnCandidateFinalizationBoundary returns the transport-owned immutability boundary.
func authnCandidateFinalizationBoundary(input AuthInput) effectsupervisor.Boundary {
	boundary := effectsupervisor.BoundaryHTTPCommit
	if input.Service == definitions.ServGRPC || input.Context.Transport.Kind == requestPolicyTransportGRPC {
		boundary = effectsupervisor.BoundaryGRPCUnaryReturn
	}

	return boundary
}

// newAuthnCandidateAuthentication preserves server-observed transport metadata as opaque evidence.
func newAuthnCandidateAuthentication(
	ctx context.Context,
	input AuthInput,
	authentication authnAuthenticationPresentation,
) (decision.AuthenticationInput, error) {
	transport := input.Context.Transport
	if transport.Kind == "" {
		transport.Kind = requestTransportKindForService(input.Service)
	}

	if transport.Listener == "" {
		transport.Listener = requestListenerNameForService(input.Service)
	}

	if transport.GRPCMethod == "" {
		transport.GRPCMethod = grpcMethodFromContext(ctx)
	}

	if transport.Peer == "" && transport.Kind == requestPolicyTransportGRPC {
		transport.Peer = grpcPeerIP(ctx)
	}

	return decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          authentication.kind,
		Credential:    authentication.credential,
		TransportKind: strings.TrimSpace(transport.Kind),
		Listener:      strings.TrimSpace(transport.Listener),
		HTTPRoute:     strings.TrimSpace(transport.HTTPRoute),
		GRPCMethod:    normalizeGRPCMethod(transport.GRPCMethod),
		Peer:          strings.TrimSpace(transport.Peer),
		MTLSIdentity:  strings.TrimSpace(transport.MTLSIdentity),
		Protected:     transport.Protected,
	})
}

// authModeForOperation returns the established application mode for one authn action.
func authModeForOperation(operation policy.Operation) AuthMode {
	switch operation {
	case policy.OperationLookupIdentity:
		return AuthModeLookupIdentity
	case policy.OperationListAccounts:
		return AuthModeListAccounts
	default:
		return AuthModeAuthenticate
	}
}

// validateAuthnCandidateInput preserves existing validation before Decision Service admission.
func validateAuthnCandidateInput(input AuthInput, operation policy.Operation) error {
	switch operation {
	case policy.OperationAuthenticate:
		return validateAuthenticateInput(input)
	case policy.OperationLookupIdentity:
		return validateLookupIdentityInput(input)
	case policy.OperationListAccounts:
		return nil
	default:
		return &AuthInputError{Field: authInputFieldMode, Reason: authInputReasonUnsupported}
	}
}

// nilAuthnCandidateDependency rejects nil and typed-nil interface dependencies.
func nilAuthnCandidateDependency(value any) bool {
	if value == nil {
		return true
	}

	reflected := reflect.ValueOf(value)

	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

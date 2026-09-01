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

	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
)

const (
	authnCandidateSubjectType  = "authentication-subject"
	authnCandidateResourceType = "authentication-service"
	authnInputFieldEntryPoint  = "entry_point"
)

// AuthnEntryPoint identifies one host-owned authentication entry path.
//
// Transport adapters must select this value from trusted routing and flow state.
// Request routes, scopes, client identifiers, and other user input never select it.
type AuthnEntryPoint uint8

const (
	// AuthnEntryDefault preserves the operation-specific profile used by existing callers.
	AuthnEntryDefault AuthnEntryPoint = iota
	// AuthnEntryBackchannel explicitly selects the existing backchannel operation profile.
	AuthnEntryBackchannel
	// AuthnEntryIDPInternal selects protocol-unbound internal and self-service IdP paths.
	AuthnEntryIDPInternal
	// AuthnEntryIDPOIDCAuthorizationCode selects OIDC authorization-code IdP paths.
	AuthnEntryIDPOIDCAuthorizationCode
	// AuthnEntryIDPOIDCDeviceCode selects OIDC device-code IdP paths.
	AuthnEntryIDPOIDCDeviceCode
	// AuthnEntryIDPSAML selects SAML IdP paths.
	AuthnEntryIDPSAML
	// AuthnEntryIDPDelayedIdentity selects delayed-response identity hydration.
	AuthnEntryIDPDelayedIdentity
	// AuthnEntryIDPMasterFactor selects master-user factor identity hydration.
	AuthnEntryIDPMasterFactor
	// AuthnEntryIDPMFABackend selects specialized MFA backend identity lookup.
	AuthnEntryIDPMFABackend
)

// String returns the stable host-side name of the entry point.
func (e AuthnEntryPoint) String() string {
	switch e {
	case AuthnEntryDefault:
		return "default"
	case AuthnEntryBackchannel:
		return "backchannel"
	case AuthnEntryIDPInternal:
		return "idp-internal"
	case AuthnEntryIDPOIDCAuthorizationCode:
		return "idp-oidc-code"
	case AuthnEntryIDPOIDCDeviceCode:
		return "idp-oidc-device"
	case AuthnEntryIDPSAML:
		return "idp-saml"
	case AuthnEntryIDPDelayedIdentity:
		return "idp-delayed-identity"
	case AuthnEntryIDPMasterFactor:
		return "idp-master-factor"
	case AuthnEntryIDPMFABackend:
		return "idp-mfa-backend"
	default:
		return requestPolicyClientIPSourceUnknown
	}
}

// AuthnInternalProfileIDs returns the complete detached set of production internal caller identities.
func AuthnInternalProfileIDs() ([]decisionservice.InternalProfileID, error) {
	entryPoints := []AuthnEntryPoint{
		AuthnEntryBackchannel,
		AuthnEntryIDPInternal,
		AuthnEntryIDPOIDCAuthorizationCode,
		AuthnEntryIDPOIDCDeviceCode,
		AuthnEntryIDPSAML,
		AuthnEntryIDPDelayedIdentity,
		AuthnEntryIDPMasterFactor,
		AuthnEntryIDPMFABackend,
	}
	operations := authnOperations()
	profiles := make([]decisionservice.InternalProfileID, 0, len(entryPoints)*2)

	for _, entryPoint := range entryPoints {
		for _, operation := range operations {
			if !entryPoint.supports(operation) {
				continue
			}

			profileID, err := decisionservice.NewInternalProfileID(entryPoint.String(), string(operation))
			if err != nil {
				return nil, fmt.Errorf("build authn internal profile %s/%s: %w", entryPoint, operation, err)
			}

			profiles = append(profiles, profileID)
		}
	}

	return profiles, nil
}

// authnOperations returns the detached closed operation set shared by production authn bindings.
func authnOperations() []policy.Operation {
	return []policy.Operation{
		policy.OperationAuthenticate,
		policy.OperationLookupIdentity,
		policy.OperationListAccounts,
	}
}

type authnPolicyApplicationService struct {
	current          AuthApplicationService
	host             authnCandidateHost
	sessions         authnCandidateDecisionSessionFactory
	internalSessions authnInternalDecisionSessionFactory
	profiles         AuthnInternalCallerProfiles
	facts            authnFactBuilder
}

type authnCandidateDecisionSessionFactory interface {
	WithSession(context.Context, decision.Invocation, func(decisionservice.DecisionSession) error) error
}

type authnInternalDecisionSessionFactory interface {
	WithInternalSession(
		context.Context,
		decisionservice.InternalSessionInput,
		func(decisionservice.DecisionSession) error,
	) error
}

type authnAuthenticationPresentation struct {
	credential []byte
	kind       string
}

type authnEntryProfileKey struct {
	operation  policy.Operation
	entryPoint AuthnEntryPoint
}

// AuthnEntryCallerProfiles binds host-created authenticate and lookup evidence to one entry path.
type AuthnEntryCallerProfiles struct {
	// Authenticate is the opaque internal caller evidence for password authentication.
	Authenticate decision.AuthenticationInput
	// LookupIdentity is the opaque internal caller evidence for identity lookup.
	LookupIdentity decision.AuthenticationInput
	// EntryPoint is selected exclusively by the trusted host adapter.
	EntryPoint AuthnEntryPoint
}

// AuthnInternalCallerProfiles owns exact host-created admission presentations by authn operation.
//
// The bundle is candidate-only and contains no production configuration authority.
// Its opaque credentials are detached during construction and never derived from
// end-user authentication material.
type AuthnInternalCallerProfiles struct {
	entryProfiles  map[authnEntryProfileKey]authnAuthenticationPresentation
	authenticate   authnAuthenticationPresentation
	lookupIdentity authnAuthenticationPresentation
	listAccounts   authnAuthenticationPresentation
}

type authnApplicationResult struct {
	auth     *AuthOutcome
	accounts *ListAccountsOutcome
}

// attachMessageResolver carries the immutable Decision-generation catalog to response boundaries.
func (r *authnApplicationResult) attachMessageResolver(resolver localization.MessageResolver) {
	if r == nil || resolver == nil {
		return
	}

	if r.auth != nil {
		r.auth.MessageResolver = resolver
	}

	if r.accounts != nil {
		r.accounts.MessageResolver = resolver
	}
}

// NewAuthnInternalCallerProfiles constructs the complete candidate operation-profile bundle.
func NewAuthnInternalCallerProfiles(
	authenticate decision.AuthenticationInput,
	lookupIdentity decision.AuthenticationInput,
	listAccounts decision.AuthenticationInput,
) (AuthnInternalCallerProfiles, error) {
	authenticatePresentation, err := newAuthnAuthenticationPresentation(
		authenticate,
		policy.OperationAuthenticate,
	)
	if err != nil {
		return AuthnInternalCallerProfiles{}, err
	}

	lookupPresentation, err := newAuthnAuthenticationPresentation(
		lookupIdentity,
		policy.OperationLookupIdentity,
	)
	if err != nil {
		return AuthnInternalCallerProfiles{}, err
	}

	listPresentation, err := newAuthnAuthenticationPresentation(
		listAccounts,
		policy.OperationListAccounts,
	)
	if err != nil {
		return AuthnInternalCallerProfiles{}, err
	}

	return AuthnInternalCallerProfiles{
		authenticate:   authenticatePresentation,
		lookupIdentity: lookupPresentation,
		listAccounts:   listPresentation,
	}, nil
}

// NewAuthnInternalCallerProfilesWithEntries adds exact host-owned entry presentations to generic defaults.
func NewAuthnInternalCallerProfilesWithEntries(
	defaults AuthnInternalCallerProfiles,
	entries ...AuthnEntryCallerProfiles,
) (AuthnInternalCallerProfiles, error) {
	if err := defaults.validate(); err != nil {
		return AuthnInternalCallerProfiles{}, err
	}

	profiles := defaults.clone()
	for _, entry := range entries {
		if err := profiles.addEntryProfiles(entry); err != nil {
			return AuthnInternalCallerProfiles{}, err
		}
	}

	return profiles, nil
}

// NewAuthnCandidateApplicationService constructs an explicit-evidence Decision Service adapter for tests.
func NewAuthnCandidateApplicationService(
	current AuthApplicationService,
	sessions authnCandidateDecisionSessionFactory,
	authentication decision.AuthenticationInput,
) (AuthApplicationService, error) {
	profiles, err := NewAuthnInternalCallerProfiles(authentication, authentication, authentication)
	if err != nil {
		return nil, err
	}

	return NewAuthnCandidateApplicationServiceWithInternalProfiles(current, sessions, profiles)
}

// NewAuthnCandidateApplicationServiceWithInternalProfiles constructs an explicit-evidence test adapter.
func NewAuthnCandidateApplicationServiceWithInternalProfiles(
	current AuthApplicationService,
	sessions authnCandidateDecisionSessionFactory,
	profiles AuthnInternalCallerProfiles,
) (AuthApplicationService, error) {
	if nilAuthnCandidateDependency(current) || nilAuthnCandidateDependency(sessions) {
		return nil, fmt.Errorf("%w: authn candidate service", ErrAuthApplicationDependencyMissing)
	}

	if err := profiles.validate(); err != nil {
		return nil, err
	}

	facts, err := newAuthnFactBuilder()
	if err != nil {
		return nil, fmt.Errorf("build authn candidate fact mapper: %w", err)
	}

	service := &authnPolicyApplicationService{
		current:  current,
		sessions: sessions,
		profiles: profiles,
		facts:    facts,
	}
	if host, ok := current.(authnCandidateHost); ok {
		service.host = host
	}

	return service, nil
}

// NewProductionAuthApplicationService constructs the sole generation-captured auth application authority.
func NewProductionAuthApplicationService(
	deps AuthDeps,
	decisions *decisionservice.DecisionService,
) (AuthApplicationService, error) {
	if nilAuthnCandidateDependency(decisions) {
		return nil, fmt.Errorf("%w: production Decision Service", ErrAuthApplicationDependencyMissing)
	}

	if err := deps.HostServices.validate(); err != nil {
		return nil, err
	}

	if err := validateAuthApplicationLDAPQueues(deps); err != nil {
		return nil, err
	}

	if _, err := AuthnInternalProfileIDs(); err != nil {
		return nil, err
	}

	facts, err := newAuthnFactBuilder()
	if err != nil {
		return nil, fmt.Errorf("build production authn fact mapper: %w", err)
	}

	return &authnPolicyApplicationService{
		host:             newAuthApplicationServiceHost(deps),
		internalSessions: decisions,
		facts:            facts,
	}, nil
}

// validateAuthApplicationLDAPQueues requires both process-owned queues when LDAP is configured.
func validateAuthApplicationLDAPQueues(deps AuthDeps) error {
	if deps.Cfg == nil || !deps.Cfg.HaveLDAPBackend() {
		return nil
	}

	if deps.LDAPQueue == nil {
		return fmt.Errorf("%w: LDAP lookup queue", ErrAuthApplicationDependencyMissing)
	}

	if deps.LDAPAuthQueue == nil {
		return fmt.Errorf("%w: LDAP authentication queue", ErrAuthApplicationDependencyMissing)
	}

	return nil
}

// Authenticate runs the current password pipeline within one admitted Policy session.
func (s *authnPolicyApplicationService) Authenticate(
	ctx context.Context,
	input AuthInput,
) (*AuthOutcome, error) {
	result, err := s.run(ctx, input, policy.OperationAuthenticate)
	if err != nil {
		return nil, err
	}

	return result.auth, nil
}

// LookupIdentity runs the current identity lookup within one admitted Policy session.
func (s *authnPolicyApplicationService) LookupIdentity(
	ctx context.Context,
	input AuthInput,
) (*AuthOutcome, error) {
	result, err := s.run(ctx, input, policy.OperationLookupIdentity)
	if err != nil {
		return nil, err
	}

	return result.auth, nil
}

// ListAccounts runs the current account provider within one admitted Policy session.
func (s *authnPolicyApplicationService) ListAccounts(
	ctx context.Context,
	input AuthInput,
) (*ListAccountsOutcome, error) {
	result, err := s.run(ctx, input, policy.OperationListAccounts)
	if err != nil {
		return nil, err
	}

	return result.accounts, nil
}

// run owns validation, session admission, current execution, and final Policy mapping.
func (s *authnPolicyApplicationService) run(
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

	var (
		result    authnApplicationResult
		execution *authnCandidateExecution
	)

	err := s.withAuthnSession(ctx, input, operation, func(session decisionservice.DecisionSession) error {
		evaluationCtx := session.RequestContext(ctx)
		messageResolver, _ := decisionservice.CapturedMessageResolverFromContext(evaluationCtx)

		if s.host != nil {
			var prepareErr error

			execution, evaluationCtx, prepareErr = s.host.prepareAuthnCandidateExecution(evaluationCtx, input, operation)
			if prepareErr != nil {
				return prepareErr
			}

			defer execution.release()

			if prepareErr = execution.installAuthnLuaFactDeclarations(session, s.internalSessions != nil); prepareErr != nil {
				return prepareErr
			}
		}

		var traversalErr error

		result, traversalErr = s.runCheckpointPlan(evaluationCtx, session, input, operation, execution)
		result.attachMessageResolver(messageResolver)

		return traversalErr
	})
	if err != nil {
		return authnApplicationResult{}, fmt.Errorf("authn Policy decision session: %w", err)
	}

	if !result.validFor(operation) {
		return authnApplicationResult{}, ErrAuthOutcomeMissing
	}

	return result, nil
}

// withAuthnSession selects generation-owned production admission or explicit-evidence test admission.
func (s *authnPolicyApplicationService) withAuthnSession(
	ctx context.Context,
	input AuthInput,
	operation policy.Operation,
	use func(decisionservice.DecisionSession) error,
) error {
	if s.internalSessions != nil {
		request, finalization, err := newAuthnInternalSessionRequest(ctx, input, operation, s.facts)
		if err != nil {
			return fmt.Errorf("build production authn invocation: %w", err)
		}

		profileID, err := decisionservice.NewInternalProfileID(input.EntryPoint.String(), string(operation))
		if err != nil || input.EntryPoint == AuthnEntryDefault || !input.EntryPoint.supports(operation) {
			return &AuthInputError{Field: authnInputFieldEntryPoint, Reason: authInputReasonUnsupported}
		}

		return s.internalSessions.WithInternalSession(ctx, decisionservice.InternalSessionInput{
			ProfileID:    profileID,
			Request:      request,
			Finalization: finalization,
		}, use)
	}

	authentication, err := s.profiles.authenticationFor(input.EntryPoint, operation)
	if err != nil {
		return err
	}

	invocation, err := newAuthnCandidateInvocation(ctx, input, operation, s.facts, authentication)
	if err != nil {
		return fmt.Errorf("build authn Policy invocation: %w", err)
	}

	return s.sessions.WithSession(ctx, invocation, use)
}

// runCheckpointPlan traverses the captured compiled order and runs host work before its final checkpoint.
func (s *authnPolicyApplicationService) runCheckpointPlan(
	ctx context.Context,
	session decisionservice.DecisionSession,
	input AuthInput,
	operation policy.Operation,
	execution *authnCandidateExecution,
) (authnApplicationResult, error) {
	checkpoints := session.Checkpoints()
	if len(checkpoints) == 0 {
		return authnApplicationResult{}, fmt.Errorf("authn Policy session has no compiled checkpoints")
	}

	lastCheckpoint := len(checkpoints) - 1
	current := authnApplicationResult{}

	for index, checkpoint := range checkpoints {
		final := index == lastCheckpoint
		result, done, err := s.runCheckpoint(
			ctx, session, checkpoint, input, operation, execution, current, final,
		)

		if err != nil || done {
			return result, err
		}

		current = result
	}

	return authnApplicationResult{}, ErrAuthOutcomeMissing
}

// runCheckpoint prepares host state, evaluates one checkpoint, and classifies terminal progress.
func (s *authnPolicyApplicationService) runCheckpoint(
	ctx context.Context,
	session decisionservice.DecisionSession,
	checkpoint decisionservice.CheckpointPlan,
	input AuthInput,
	operation policy.Operation,
	execution *authnCandidateExecution,
	current authnApplicationResult,
	final bool,
) (authnApplicationResult, bool, error) {
	prepared, err := s.prepareCheckpointResult(ctx, session, checkpoint, input, operation, execution, current, final)
	if err != nil {
		return authnApplicationResult{}, true, err
	}

	facts, err := s.checkpointFacts(input, operation, prepared, final)
	if err != nil {
		return authnApplicationResult{}, true, err
	}

	response, err := evaluateAuthnCandidateCheckpoint(ctx, session, checkpoint.Name(), facts)
	if err != nil {
		return authnApplicationResult{}, true, err
	}

	logAuthnDecisionFailure(execution, checkpoint.Name(), response)

	return resolveAuthnCheckpointResult(checkpoint.Name(), operation, execution, prepared, response, final)
}

// logAuthnDecisionFailure records bounded diagnostics for fail-closed internal evaluations.
func logAuthnDecisionFailure(
	execution *authnCandidateExecution,
	checkpoint string,
	response decision.DecisionResponse,
) {
	if execution == nil || execution.auth == nil || response.Effect() != decision.EffectIndeterminate {
		return
	}

	fields := []any{
		definitions.LogKeyGUID, execution.auth.Runtime.GUID,
		definitions.LogKeyMsg, "Authn policy evaluation indeterminate",
		"checkpoint", checkpoint,
		"status_code", response.Status().Code(),
		"policy_set", response.Policy().PolicySet(),
		"policy_rule", response.Policy().Rule(),
	}

	if diagnostics := response.Diagnostics(); diagnostics != nil {
		fields = append(fields, "diagnostics", authnDecisionDiagnostics(diagnostics.Entries()))
	}

	level.Debug(execution.auth.Logger()).Log(fields...)
}

// authnDecisionDiagnostics converts bounded strict values into structured log fields.
func authnDecisionDiagnostics(entries decision.ValueMap) map[string]any {
	values := entries.Values()
	result := make(map[string]any, len(values))

	for key, value := range values {
		if member, ok := value.Any(); ok {
			result[key] = member
		}
	}

	return result
}

// prepareCheckpointResult runs only host work associated with the current compiled checkpoint.
func (s *authnPolicyApplicationService) prepareCheckpointResult(
	ctx context.Context,
	session decisionservice.DecisionSession,
	checkpoint decisionservice.CheckpointPlan,
	input AuthInput,
	operation policy.Operation,
	execution *authnCandidateExecution,
	current authnApplicationResult,
	final bool,
) (authnApplicationResult, error) {
	if execution != nil {
		return execution.prepareCheckpoint(session, checkpoint)
	}

	if final {
		return s.runCurrent(ctx, input, operation)
	}

	return current, nil
}

// resolveAuthnCheckpointResult maps one evaluated effect to continued, final, or terminal host state.
func resolveAuthnCheckpointResult(
	checkpoint string,
	operation policy.Operation,
	execution *authnCandidateExecution,
	current authnApplicationResult,
	response decision.DecisionResponse,
	final bool,
) (authnApplicationResult, bool, error) {
	if final || terminalAuthnCheckpointEffect(response.Effect()) {
		if execution != nil {
			result, err := execution.finalize(checkpoint, response, current)

			return result, true, err
		}

		if final {
			result, err := current.mapEffect(response.Effect())

			return result, true, err
		}

		result, err := newAuthnTerminalResult(operation, response.Effect())

		return result, true, err
	}

	if response.Effect() != decision.EffectNotApplicable {
		return authnApplicationResult{}, true, fmt.Errorf("unsupported intermediate authn Policy effect %q", response.Effect())
	}

	return current, false, nil
}

// checkpointFacts keeps pre-backend checkpoints empty and maps current state only at the final boundary.
func (s *authnPolicyApplicationService) checkpointFacts(
	input AuthInput,
	operation policy.Operation,
	current authnApplicationResult,
	final bool,
) (decision.FactSet, error) {
	if !final {
		facts, err := decision.NewFactSet(nil)
		if err != nil {
			return decision.FactSet{}, fmt.Errorf("build authn Policy checkpoint facts: %w", err)
		}

		return facts, nil
	}

	facts, err := s.facts.Build(input, operation, current, decision.FactSet{})
	if err != nil {
		return decision.FactSet{}, fmt.Errorf("build authn Policy facts: %w", err)
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
		return decision.DecisionResponse{}, fmt.Errorf("build authn Policy checkpoint: %w", err)
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
		return authnApplicationResult{}, fmt.Errorf("unsupported terminal authn Policy effect %q", effect)
	}

	if operation == policy.OperationListAccounts {
		return authnApplicationResult{accounts: &ListAccountsOutcome{Decision: mapped}}, nil
	}

	return authnApplicationResult{auth: &AuthOutcome{Decision: mapped, PolicyTerminal: true}}, nil
}

// runCurrent invokes exactly one existing operation while the captured session remains open.
func (s *authnPolicyApplicationService) runCurrent(
	ctx context.Context,
	input AuthInput,
	operation policy.Operation,
) (authnApplicationResult, error) {
	if nilAuthnCandidateDependency(s.current) {
		return authnApplicationResult{}, fmt.Errorf("%w: test auth application", ErrAuthApplicationDependencyMissing)
	}

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
		return authnApplicationResult{}, fmt.Errorf("unsupported authn Policy effect %q", effect)
	}

	if r.auth != nil {
		outcome := cloneAuthnCandidateOutcome(r.auth)

		outcome.Decision = mapped
		if terminalAuthnCheckpointEffect(effect) {
			outcome.PolicyTerminal = true
			outcome.DelayedResponseEligible = false
		}

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
	outcome.TerminalState = string(authFSMStateAuthTempFail)
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
	output.ResponseHeaders = input.ResponseHeaders.Clone()
	output.ResponseHeaderDeletes = append([]string(nil), input.ResponseHeaderDeletes...)
	output.FSMEventPath = append([]string(nil), input.FSMEventPath...)
	output.Groups = append([]string(nil), input.Groups...)
	output.GroupDistinguishedNames = append([]string(nil), input.GroupDistinguishedNames...)

	return &output
}

// cloneAuthnCandidateListOutcome detaches mutable list projection fields before changing the candidate decision.
func cloneAuthnCandidateListOutcome(input *ListAccountsOutcome) *ListAccountsOutcome {
	if input == nil {
		return nil
	}

	output := *input
	output.ResponseHeaders = input.ResponseHeaders.Clone()
	output.ResponseHeaderDeletes = append([]string(nil), input.ResponseHeaderDeletes...)
	output.FSMEventPath = append([]string(nil), input.FSMEventPath...)
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
	request, finalization, err := newAuthnInternalSessionRequest(ctx, input, operation, facts)
	if err != nil {
		return decision.Invocation{}, err
	}

	authenticationInput, err := newAuthnCandidateAuthentication(ctx, input, authentication)
	if err != nil {
		return decision.Invocation{}, err
	}

	return decision.Invocation{
		Request:        request,
		Authentication: authenticationInput,
		Finalization:   finalization,
	}, nil
}

// newAuthnInternalSessionRequest maps one application operation without selecting caller authority.
func newAuthnInternalSessionRequest(
	ctx context.Context,
	input AuthInput,
	operation policy.Operation,
	facts authnFactBuilder,
) (decision.DecisionRequestInput, decision.EvaluationFinalization, error) {
	requestAttributes, err := facts.RequestAttributes(input)
	if err != nil {
		return decision.DecisionRequestInput{}, decision.EvaluationFinalization{}, err
	}

	target, err := decision.NewTarget(policy.AuthnNamespace, string(operation))
	if err != nil {
		return decision.DecisionRequestInput{}, decision.EvaluationFinalization{}, err
	}

	subject, err := decision.NewEntity(decision.EntityInput{
		Type: authnCandidateSubjectType,
		ID:   input.Credentials.Username,
	})
	if err != nil {
		return decision.DecisionRequestInput{}, decision.EvaluationFinalization{}, err
	}

	resource, err := decision.NewEntity(decision.EntityInput{
		Type: authnCandidateResourceType,
		ID:   input.Service,
	})
	if err != nil {
		return decision.DecisionRequestInput{}, decision.EvaluationFinalization{}, err
	}

	environment, err := decision.NewEnvironment(decision.EnvironmentInput{
		Service:    input.Service,
		Protocol:   input.Context.Protocol,
		Attributes: requestAttributes.environment,
	})
	if err != nil {
		return decision.DecisionRequestInput{}, decision.EvaluationFinalization{}, err
	}

	finalization := authnCandidateFinalization(ctx, input)
	if !finalization.Valid() {
		return decision.DecisionRequestInput{}, decision.EvaluationFinalization{}, fmt.Errorf(
			"authn finalization gate is unavailable",
		)
	}

	return decision.DecisionRequestInput{
		Version:     decision.ContractVersion,
		Target:      target,
		Subject:     subject,
		Resource:    resource,
		Environment: environment,
		Attributes:  requestAttributes.input,
		Options:     decision.EvaluationOptions{IncludeDiagnostics: true},
	}, finalization, nil
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

// newAuthnAuthenticationPresentation validates and owns one opaque operation presentation.
func newAuthnAuthenticationPresentation(
	input decision.AuthenticationInput,
	operation policy.Operation,
) (authnAuthenticationPresentation, error) {
	presentation := authnAuthenticationPresentation{
		credential: append([]byte(nil), input.Credential()...),
		kind:       input.Kind(),
	}

	if err := validateAuthnAuthenticationPresentation(presentation, operation); err != nil {
		return authnAuthenticationPresentation{}, err
	}

	return presentation, nil
}

// authenticationFor returns the exact host-selected entry and operation presentation.
func (p AuthnInternalCallerProfiles) authenticationFor(
	entryPoint AuthnEntryPoint,
	operation policy.Operation,
) (authnAuthenticationPresentation, error) {
	if entryPoint == AuthnEntryDefault || entryPoint == AuthnEntryBackchannel {
		return p.defaultAuthenticationFor(operation)
	}

	if !entryPoint.valid() || !entryPoint.supports(operation) {
		return authnAuthenticationPresentation{}, &AuthInputError{
			Field:  authnInputFieldEntryPoint,
			Reason: authInputReasonUnsupported,
		}
	}

	presentation, found := p.entryProfiles[authnEntryProfileKey{entryPoint: entryPoint, operation: operation}]

	if !found {
		return authnAuthenticationPresentation{}, fmt.Errorf(
			"%w: authn candidate %s profile for entry %s",
			ErrAuthApplicationDependencyMissing,
			operation,
			entryPoint.String(),
		)
	}

	presentation.credential = append([]byte(nil), presentation.credential...)

	return presentation, nil
}

// defaultAuthenticationFor returns the detached generic operation presentation.
func (p AuthnInternalCallerProfiles) defaultAuthenticationFor(
	operation policy.Operation,
) (authnAuthenticationPresentation, error) {
	var presentation authnAuthenticationPresentation

	switch operation {
	case policy.OperationAuthenticate:
		presentation = p.authenticate
	case policy.OperationLookupIdentity:
		presentation = p.lookupIdentity
	case policy.OperationListAccounts:
		presentation = p.listAccounts
	default:
		return authnAuthenticationPresentation{}, &AuthInputError{
			Field:  authInputFieldMode,
			Reason: authInputReasonUnsupported,
		}
	}

	presentation.credential = append([]byte(nil), presentation.credential...)

	return presentation, nil
}

// clone detaches the mutable entry-profile map and every opaque credential.
func (p AuthnInternalCallerProfiles) clone() AuthnInternalCallerProfiles {
	result := p
	result.authenticate.credential = append([]byte(nil), p.authenticate.credential...)
	result.lookupIdentity.credential = append([]byte(nil), p.lookupIdentity.credential...)
	result.listAccounts.credential = append([]byte(nil), p.listAccounts.credential...)
	result.entryProfiles = make(map[authnEntryProfileKey]authnAuthenticationPresentation, len(p.entryProfiles))

	for key, presentation := range p.entryProfiles {
		presentation.credential = append([]byte(nil), presentation.credential...)
		result.entryProfiles[key] = presentation
	}

	return result
}

// addEntryProfiles validates and owns every supplied presentation for one entry path.
func (p *AuthnInternalCallerProfiles) addEntryProfiles(entry AuthnEntryCallerProfiles) error {
	if p == nil || !entry.EntryPoint.configurable() {
		return &AuthInputError{Field: authnInputFieldEntryPoint, Reason: authInputReasonUnsupported}
	}

	added := false
	candidates := []struct {
		authentication decision.AuthenticationInput
		operation      policy.Operation
	}{
		{authentication: entry.Authenticate, operation: policy.OperationAuthenticate},
		{authentication: entry.LookupIdentity, operation: policy.OperationLookupIdentity},
	}

	for _, candidate := range candidates {
		if !authnAuthenticationInputPresent(candidate.authentication) {
			continue
		}

		if err := p.addEntryProfile(entry.EntryPoint, candidate.operation, candidate.authentication); err != nil {
			return err
		}

		added = true
	}

	if !added {
		return fmt.Errorf(
			"%w: authn candidate profile for entry %s",
			ErrAuthApplicationDependencyMissing,
			entry.EntryPoint.String(),
		)
	}

	return nil
}

// addEntryProfile validates and stores one exact entry and operation presentation.
func (p *AuthnInternalCallerProfiles) addEntryProfile(
	entryPoint AuthnEntryPoint,
	operation policy.Operation,
	authentication decision.AuthenticationInput,
) error {
	if !entryPoint.supports(operation) {
		return &AuthInputError{Field: authnInputFieldEntryPoint, Reason: authInputReasonUnsupported}
	}

	key := authnEntryProfileKey{entryPoint: entryPoint, operation: operation}
	if _, duplicate := p.entryProfiles[key]; duplicate {
		return fmt.Errorf("duplicate authn candidate %s profile for entry %s", operation, entryPoint.String())
	}

	presentation, err := newAuthnAuthenticationPresentation(authentication, operation)
	if err != nil {
		return err
	}

	p.entryProfiles[key] = presentation

	return nil
}

// authnAuthenticationInputPresent distinguishes an omitted profile from malformed supplied evidence.
func authnAuthenticationInputPresent(input decision.AuthenticationInput) bool {
	return input.Kind() != "" || len(input.Credential()) > 0
}

// valid reports whether the identifier belongs to the closed host-owned entry set.
func (e AuthnEntryPoint) valid() bool {
	switch e {
	case AuthnEntryDefault,
		AuthnEntryBackchannel,
		AuthnEntryIDPInternal,
		AuthnEntryIDPOIDCAuthorizationCode,
		AuthnEntryIDPOIDCDeviceCode,
		AuthnEntryIDPSAML,
		AuthnEntryIDPDelayedIdentity,
		AuthnEntryIDPMasterFactor,
		AuthnEntryIDPMFABackend:
		return true
	default:
		return false
	}
}

// configurable reports whether an entry may own profiles beyond the generic defaults.
func (e AuthnEntryPoint) configurable() bool {
	return e.valid() && e != AuthnEntryDefault && e != AuthnEntryBackchannel
}

// supports reports whether one entry path permits the requested authn operation.
func (e AuthnEntryPoint) supports(operation policy.Operation) bool {
	switch e {
	case AuthnEntryDefault, AuthnEntryBackchannel:
		return operation == policy.OperationAuthenticate ||
			operation == policy.OperationLookupIdentity ||
			operation == policy.OperationListAccounts
	case AuthnEntryIDPInternal, AuthnEntryIDPOIDCAuthorizationCode, AuthnEntryIDPOIDCDeviceCode, AuthnEntryIDPSAML:
		return operation == policy.OperationAuthenticate || operation == policy.OperationLookupIdentity
	case AuthnEntryIDPDelayedIdentity, AuthnEntryIDPMasterFactor, AuthnEntryIDPMFABackend:
		return operation == policy.OperationLookupIdentity
	default:
		return false
	}
}

// validate requires an exact non-empty presentation for every authn operation.
func (p AuthnInternalCallerProfiles) validate() error {
	for _, operation := range []policy.Operation{
		policy.OperationAuthenticate,
		policy.OperationLookupIdentity,
		policy.OperationListAccounts,
	} {
		presentation, err := p.defaultAuthenticationFor(operation)
		if err != nil {
			return err
		}

		if err = validateAuthnAuthenticationPresentation(presentation, operation); err != nil {
			return err
		}
	}

	for key, presentation := range p.entryProfiles {
		if !key.entryPoint.configurable() || !key.entryPoint.supports(key.operation) {
			return &AuthInputError{Field: authnInputFieldEntryPoint, Reason: authInputReasonUnsupported}
		}

		if err := validateAuthnAuthenticationPresentation(presentation, key.operation); err != nil {
			return err
		}
	}

	return nil
}

// validateAuthnAuthenticationPresentation enforces one complete opaque profile presentation.
func validateAuthnAuthenticationPresentation(
	presentation authnAuthenticationPresentation,
	operation policy.Operation,
) error {
	if presentation.kind == "" || len(presentation.credential) == 0 {
		return fmt.Errorf(
			"%w: authn candidate %s authentication",
			ErrAuthApplicationDependencyMissing,
			operation,
		)
	}

	return nil
}

// validateAuthnCandidateInput preserves existing validation before Decision Service admission.
func validateAuthnCandidateInput(input AuthInput, operation policy.Operation) error {
	switch operation {
	case policy.OperationAuthenticate:
		return validateAuthenticateInput(input)
	case policy.OperationLookupIdentity:
		return validateUsernameInput(input)
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

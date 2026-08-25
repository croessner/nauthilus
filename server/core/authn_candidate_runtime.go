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
	"sync"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/report"

	"github.com/gin-gonic/gin"
)

const (
	authnCandidateRuntimeOwnerKey                = "authn_candidate_runtime_owner"
	authnCandidatePostActionFailureKey           = "authn_candidate_post_action_failure"
	authnCandidateOutcomeEffectAcceptanceFailure = "auth.outcome.effect_acceptance_failure"
	authnCandidateResponseSourceEffectAcceptance = "effect_acceptance"
)

type authnCandidateHost interface {
	prepareAuthnCandidateExecution(
		context.Context,
		AuthInput,
		policy.Operation,
	) (*authnCandidateExecution, context.Context, error)
}

type authnCandidateExecution struct {
	executeEffect  func(report.EffectRequest) effectsupervisor.Result
	preparePost    func(report.EffectRequest, uint32) (effectsupervisor.ExecutableWork, error)
	auth           *AuthState
	ginCtx         *gin.Context
	capture        *CaptureResponseWriter
	selected       map[string]*report.FinalDecision
	accounts       AccountList
	operation      policy.Operation
	mu             sync.Mutex
	authResult     definitions.AuthResult
	preAuthResult  definitions.AuthResult
	preAuthReady   bool
	finalReady     bool
	bruteForceRun  bool
	environmentRun bool
}

// prepareAuthnCandidateExecution creates request-local host state after Decision Service admission.
func (s *authApplicationService) prepareAuthnCandidateExecution(
	ctx context.Context,
	input AuthInput,
	operation policy.Operation,
) (*authnCandidateExecution, context.Context, error) {
	hostCtx := ctx
	gate := PostActionFinalizationGateFromContext(hostCtx)

	if gate == nil || gate.Boundary() != authnCandidateFinalizationBoundary(input) {
		return nil, ctx, fmt.Errorf("%w: authn candidate finalization gate", ErrAuthApplicationDependencyMissing)
	}

	auth, ginCtx, capture, err := s.newAuthState(hostCtx, input)
	if err != nil {
		return nil, ctx, err
	}

	if operation == policy.OperationListAccounts && !auth.Request.ListAccounts {
		return nil, ctx, &AuthPermissionDeniedError{Reason: "missing required scope: " + definitions.ScopeListAccounts}
	}

	ginCtx.Set(authnCandidateRuntimeOwnerKey, true)
	execution := &authnCandidateExecution{
		auth:      auth,
		ginCtx:    ginCtx,
		capture:   capture,
		selected:  make(map[string]*report.FinalDecision),
		operation: operation,
	}
	hostCtx = decisionservice.ContextWithAuthnDecisionSource(hostCtx, execution)
	hostCtx = contextWithAuthnPolicyEffectOwner(hostCtx, execution)

	return execution, hostCtx, nil
}

// prepareCheckpoint runs only the ordered host providers owned by one compiled checkpoint.
func (e *authnCandidateExecution) prepareCheckpoint(
	checkpoint decisionservice.CheckpointPlan,
) (authnApplicationResult, error) {
	if e == nil || e.auth == nil || e.ginCtx == nil {
		return authnApplicationResult{}, ErrAuthOutcomeMissing
	}

	providers := checkpoint.ProviderIDs()
	for index := 0; index < len(providers); {
		next, terminal, err := e.prepareProviderGroup(providers, index)
		if err != nil {
			return authnApplicationResult{}, fmt.Errorf(
				"prepare authn candidate checkpoint %q: %w",
				checkpoint.Name(),
				err,
			)
		}

		index = next

		if terminal {
			break
		}
	}

	return e.currentResult(), nil
}

// prepareProviderGroup executes one provider or one existing atomic host pipeline segment.
func (e *authnCandidateExecution) prepareProviderGroup(
	providers []string,
	index int,
) (int, bool, error) {
	switch providers[index] {
	case policy.AuthnProviderBruteForce:
		return index + 1, e.prepareBruteForceProvider(), nil
	case policy.AuthnProviderEnvironment:
		plan, next, err := authnEnvironmentPlanFromProviders(providers, index)
		if err != nil {
			return index, false, err
		}

		return next, e.prepareEnvironmentProviders(plan), nil
	case policy.AuthnProviderBackend:
		if index+1 >= len(providers) || providers[index+1] != policy.AuthnProviderSubject {
			return index, false, fmt.Errorf("backend provider is not followed by subject provider")
		}

		e.prepareBackendAndSubjectProviders()

		return index + 2, false, nil
	case policy.AuthnProviderAccount:
		e.prepareAccountProvider()

		return index + 1, false, nil
	default:
		return index, false, fmt.Errorf("unsupported or out-of-order host provider %q", providers[index])
	}
}

// prepareBruteForceProvider executes the request-local brute-force owner once.
func (e *authnCandidateExecution) prepareBruteForceProvider() bool {
	if e.preAuthReady || e.bruteForceRun {
		return e.preAuthResult != definitions.AuthResultUnset && e.preAuthResult != definitions.AuthResultOK
	}

	e.bruteForceRun = true
	if !e.auth.CheckBruteForce(e.ginCtx) {
		return false
	}

	e.preAuthResult = definitions.AuthResultFail

	return true
}

// prepareEnvironmentProviders executes the exact selected environment subplan once.
func (e *authnCandidateExecution) prepareEnvironmentProviders(plan authnEnvironmentProviderPlan) bool {
	if e.preAuthReady || e.environmentRun {
		return e.preAuthResult != definitions.AuthResultUnset && e.preAuthResult != definitions.AuthResultOK
	}

	e.environmentRun = true
	e.preAuthResult = e.auth.handleEnvironmentProviders(e.ginCtx, plan)

	return e.preAuthResult != definitions.AuthResultOK
}

// prepareBackendAndSubjectProviders runs the existing cache/backend/subject owner once.
func (e *authnCandidateExecution) prepareBackendAndSubjectProviders() {
	if e.finalReady {
		return
	}

	e.finalReady = true
	e.authResult = e.auth.HandlePassword(e.ginCtx)
}

// prepareAccountProvider runs the existing account provider once.
func (e *authnCandidateExecution) prepareAccountProvider() {
	if e.finalReady {
		return
	}

	e.finalReady = true
	e.accounts = e.auth.ListUserAccounts()
}

// authnEnvironmentPlanFromProviders validates one contiguous environment provider segment.
func authnEnvironmentPlanFromProviders(
	providers []string,
	index int,
) (authnEnvironmentProviderPlan, int, error) {
	plan := authnEnvironmentProviderPlan{environment: true}
	next := index + 1
	lastRank := 0

	for next < len(providers) {
		rank := authnEnvironmentProviderRank(providers[next])
		if rank == 0 {
			return plan, next, nil
		}

		if rank <= lastRank {
			return authnEnvironmentProviderPlan{}, index, fmt.Errorf(
				"out-of-order environment provider %q",
				providers[next],
			)
		}

		switch providers[next] {
		case policy.AuthnProviderTLSEncryption:
			plan.tls = true
		case policy.AuthnProviderRelayDomains:
			plan.relay = true
		case policy.AuthnProviderRBL:
			plan.rbl = true
		}

		lastRank = rank
		next++
	}

	return plan, next, nil
}

// authnEnvironmentProviderRank defines the canonical order within one environment segment.
func authnEnvironmentProviderRank(providerID string) int {
	switch providerID {
	case policy.AuthnProviderTLSEncryption:
		return 1
	case policy.AuthnProviderRelayDomains:
		return 2
	case policy.AuthnProviderRBL:
		return 3
	default:
		return 0
	}
}

// currentResult projects collected host state without publishing a terminal response.
func (e *authnCandidateExecution) currentResult() authnApplicationResult {
	if e.operation == policy.OperationListAccounts {
		return authnApplicationResult{accounts: listAccountsSuccessOutcome(e.auth, e.ginCtx, e.accounts)}
	}

	result := e.authResult
	if result == definitions.AuthResultUnset {
		result = e.preAuthResult
	}

	return authnApplicationResult{auth: authnCandidateOutcomeFromRuntime(e.auth, result)}
}

// authnCandidateOutcomeFromRuntime projects backend-owned payloads before final policy presentation.
func authnCandidateOutcomeFromRuntime(auth *AuthState, result definitions.AuthResult) *AuthOutcome {
	if auth == nil {
		return nil
	}

	decision := authnCandidateDecisionFromResult(result)
	status := auth.Runtime.StatusCodeOK

	switch decision {
	case AuthDecisionFail:
		status = auth.Runtime.StatusCodeFail
	case AuthDecisionTempFail:
		status = auth.Runtime.StatusCodeInternalError
	}

	ctx := auth.Request.HTTPClientContext

	return authOutcomeFromState(
		ctx,
		auth,
		decision,
		authTerminalState(decision),
		"",
		status,
		newAuthResponseSettings(auth.Cfg()),
	)
}

// authnCandidateDecisionFromResult maps the existing backend result before policy selection.
func authnCandidateDecisionFromResult(result definitions.AuthResult) AuthDecision {
	switch result {
	case definitions.AuthResultOK:
		return AuthDecisionOK
	case definitions.AuthResultFail, definitions.AuthResultEmptyPassword:
		return AuthDecisionFail
	case definitions.AuthResultTempFail, definitions.AuthResultEmptyUsername:
		return AuthDecisionTempFail
	default:
		return AuthDecisionUnset
	}
}

// StandardAuthEffectsEnabled reports the established request-local obligation gate.
func (e *authnCandidateExecution) StandardAuthEffectsEnabled(
	ctx context.Context,
	target decision.Target,
	checkpoint string,
) bool {
	if e == nil || e.ginCtx == nil || target.Action() != string(e.operation) {
		return false
	}

	if checkpoint != string(policy.StagePreAuth) && checkpoint != string(policy.StageAuthDecision) {
		return false
	}

	if policyCtx := existingPolicyContext(e.ginCtx); policyCtx != nil {
		mode, _, _ := policyCtx.SnapshotMetadata()

		return policyEffectsEnabled(mode)
	}

	mode, ok := decisionservice.CapturedPolicyMode(ctx)
	if !ok {
		return false
	}

	return policyEffectsEnabled(mode)
}

// CaptureAuthnDecision retains presentation metadata before effect execution starts.
func (e *authnCandidateExecution) CaptureAuthnDecision(
	_ context.Context,
	_ decision.Target,
	checkpoint string,
	final *report.FinalDecision,
) {
	if e == nil || final == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.selected[checkpoint] = report.CloneFinalDecision(final)
	e.captureAuthnPolicyReport(checkpoint, final)
}

// captureAuthnPolicyReport records catalog selections in the established diagnostic vocabulary.
func (e *authnCandidateExecution) captureAuthnPolicyReport(
	checkpoint string,
	final *report.FinalDecision,
) {
	if e == nil || e.auth == nil || final == nil {
		return
	}

	policyReport := e.auth.policyReport(e.ginCtx)
	if policyReport == nil {
		return
	}

	if e.deferAuthnPreAuthPassReport(checkpoint, final) {
		return
	}

	if checkpoint == string(policy.StageAuthDecision) && final.Stage != policy.StagePreAuth {
		e.appendDeferredAuthnPreAuthPass(policyReport)
	}

	appendAuthnPolicyReportDecision(policyReport, final)
}

// deferAuthnPreAuthPassReport waits until authenticate has completed its semantic pre-auth providers.
func (e *authnCandidateExecution) deferAuthnPreAuthPassReport(
	checkpoint string,
	final *report.FinalDecision,
) bool {
	return e.operation == policy.OperationAuthenticate &&
		checkpoint == string(policy.StagePreAuth) &&
		final.PolicyName == "implicit_pre_auth_pass"
}

// appendDeferredAuthnPreAuthPass restores the legacy report order before a final auth decision.
func (e *authnCandidateExecution) appendDeferredAuthnPreAuthPass(policyReport *report.DecisionReport) {
	for _, selected := range policyReport.Policies {
		if selected.Stage == policy.StagePreAuth {
			return
		}
	}

	preAuth := e.selected[string(policy.StagePreAuth)]
	if preAuth != nil {
		appendAuthnPolicyReportDecision(policyReport, preAuth)
	}
}

// appendAuthnPolicyReportDecision appends one detached catalog selection to the legacy report shape.
func appendAuthnPolicyReportDecision(
	policyReport *report.DecisionReport,
	final *report.FinalDecision,
) {
	if policyReport == nil || final == nil {
		return
	}

	cloned := report.CloneFinalDecision(final)
	markAuthnPolicyResponseDetail(policyReport, cloned.ResponseMessage)
	policyReport.Policies = append(policyReport.Policies, report.PolicyDecision{
		Name: cloned.PolicyName, Reason: cloned.Reason, OutcomeMarker: cloned.OutcomeMarker,
		ResponseMarker: cloned.ResponseMarker, FSMEventMarker: cloned.FSMEventMarker,
		Stage: cloned.Stage, Effect: cloned.Effect, Control: cloned.Control,
		ResponseMessage: cloned.ResponseMessage, ResponseLanguage: cloned.ResponseLanguage,
		Obligations: cloned.Obligations, Advice: cloned.Advice,
	})

	policyReport.Stage = final.Stage
	if final.Effect != policy.DecisionNeutral {
		policyReport.Final = report.CloneFinalDecision(final)
	}
}

// markAuthnPolicyResponseDetail preserves legacy evidence that a public detail was selected.
func markAuthnPolicyResponseDetail(
	policyReport *report.DecisionReport,
	selection *report.ResponseMessageSelection,
) {
	if policyReport == nil || selection == nil || selection.Source != policy.ResponseSourceAttributeDetail ||
		selection.FallbackUsed || selection.AttributeID == "" || selection.Detail == "" {
		return
	}

	attribute, exists := policyReport.Attributes[selection.AttributeID]
	if !exists || attribute.Details == nil {
		return
	}

	detail, exists := attribute.Details[selection.Detail]
	if !exists {
		return
	}

	detail.Selected = true
	attribute.Details[selection.Detail] = detail
	policyReport.Attributes[selection.AttributeID] = attribute
}

// selectedDecision returns a detached checkpoint-local selection.
func (e *authnCandidateExecution) selectedDecision(checkpoint string) *report.FinalDecision {
	if e == nil {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	return report.CloneFinalDecision(e.selected[checkpoint])
}

// finalize applies captured presentation and FSM metadata after the shared runtime owns all effects.
func (e *authnCandidateExecution) finalize(
	checkpoint string,
	response decision.DecisionResponse,
	current authnApplicationResult,
) (authnApplicationResult, error) {
	effect := response.Effect()
	final := e.selectedDecision(checkpoint)

	if final == nil {
		return e.finalizeUnselected(effect, current)
	}

	presentation, acceptanceFailure := e.authnCandidatePresentation(response, final)

	if err := e.auth.applyAuthFSMMarkers(e.authnCandidateFSMEventMarkers(presentation)); err != nil {
		return authnApplicationResult{}, err
	}

	e.auth.applyPolicyResponseMessage(presentation)
	e.clearAuthnCandidateTempFailLocalization(effect, presentation)

	if acceptanceFailure {
		e.auth.AuthTempFail(e.ginCtx, definitions.TempFailDefault)
		e.ginCtx.Abort()

		return e.capturedResult(), nil
	}

	if e.operation == policy.OperationListAccounts && effect == decision.EffectPermit {
		return e.permittedListResult(current), nil
	}

	return e.applySelectedAuthEffect(effect, presentation, current)
}

// clearAuthnCandidateTempFailLocalization removes language state not selected by the replacement response.
func (e *authnCandidateExecution) clearAuthnCandidateTempFailLocalization(
	effect decision.Effect,
	presentation *report.FinalDecision,
) {
	if e == nil || e.auth == nil || effect != decision.EffectIndeterminate {
		return
	}

	if presentation == nil || presentation.ResponseMessage == nil || presentation.ResponseMessage.I18NKey == "" {
		e.auth.Runtime.StatusMessageI18NKey = ""
		e.auth.Runtime.ResponseLanguage = ""

		return
	}

	if presentation.ResponseLanguage == nil || presentation.ResponseLanguage.Language == "" {
		e.auth.Runtime.ResponseLanguage = ""
	}
}

// authnCandidateFSMEventMarkers projects the captured checkpoint selections without a second evaluator.
func (e *authnCandidateExecution) authnCandidateFSMEventMarkers(final *report.FinalDecision) []string {
	markers := []string{policy.FSMEventMarkerParseOK}
	if final == nil {
		return markers
	}

	if final.Stage == policy.StagePreAuth {
		return append(markers, final.FSMEventMarker)
	}

	preAuthMarker := policy.FSMEventMarkerPreAuthOK
	if selected := e.selectedDecision(string(policy.StagePreAuth)); selected != nil && selected.FSMEventMarker != "" {
		preAuthMarker = selected.FSMEventMarker
	}

	markers = append(markers, preAuthMarker)

	if e.operation == policy.OperationListAccounts {
		markers = append(markers, policy.FSMEventMarkerAccountProviderEvaluated)
	} else {
		markers = append(markers, policy.FSMEventMarkerAuthEvaluated)
	}

	return append(markers, final.FSMEventMarker)
}

// finalizeUnselected maps a checkpoint result when no application presentation was selected.
func (e *authnCandidateExecution) finalizeUnselected(
	effect decision.Effect,
	current authnApplicationResult,
) (authnApplicationResult, error) {
	if current.validFor(e.operation) {
		return current.mapEffect(effect)
	}

	return newAuthnTerminalResult(e.operation, effect)
}

// authnCandidatePresentation selects the explicit acceptance-failure response when required.
func (e *authnCandidateExecution) authnCandidatePresentation(
	response decision.DecisionResponse,
	final *report.FinalDecision,
) (*report.FinalDecision, bool) {
	presentation, acceptanceFailure := authnCandidateRuntimePresentation(response, final)

	state, failed := authnCandidatePostActionFailure(e.ginCtx)
	if !failed {
		return presentation, acceptanceFailure
	}

	marker := "auth.outcome.post_action_preparation_failure"
	source := "post_action_preparation"

	switch state {
	case PostActionStateAcceptanceRejected:
		marker = authnCandidateOutcomeEffectAcceptanceFailure
		source = authnCandidateResponseSourceEffectAcceptance
	case PostActionStateCanceled:
		marker = "auth.outcome.post_action_canceled"
		source = "post_action_cancellation"
	}

	return authnCandidateTempFailDecision(final, marker, source), true
}

// authnCandidateRuntimePresentation maps only runtime failures onto truthful tempfail metadata.
func authnCandidateRuntimePresentation(
	response decision.DecisionResponse,
	final *report.FinalDecision,
) (*report.FinalDecision, bool) {
	if response.Effect() != decision.EffectIndeterminate || final == nil {
		return final, false
	}

	code := response.Status().Code()
	if final.Effect == policy.DecisionTempFail && !authnCandidateDistinctRuntimeFailure(code) {
		return final, false
	}

	marker, source := authnCandidateRuntimeFailureMetadata(code)
	acceptanceFailure := code == decision.StatusCodeEffectAcceptanceRejected

	return authnCandidateTempFailDecision(final, marker, source), acceptanceFailure
}

// authnCandidateDistinctRuntimeFailure identifies causes that supersede a selected semantic tempfail.
func authnCandidateDistinctRuntimeFailure(code decision.StatusCode) bool {
	return code == decision.StatusCodeEffectAcceptanceRejected ||
		code == decision.StatusCodeEffectOutcomeUnknown ||
		code == decision.StatusCodeProviderUnavailable
}

// authnCandidateRuntimeFailureMetadata distinguishes acceptance, ambiguity, and evaluation failures.
func authnCandidateRuntimeFailureMetadata(code decision.StatusCode) (string, string) {
	switch code {
	case decision.StatusCodeEffectAcceptanceRejected:
		return authnCandidateOutcomeEffectAcceptanceFailure, authnCandidateResponseSourceEffectAcceptance
	case decision.StatusCodeEffectOutcomeUnknown:
		return "auth.outcome.effect_outcome_unknown", "effect_outcome"
	case decision.StatusCodeProviderUnavailable:
		return "auth.outcome.provider_unavailable", "decision_provider"
	default:
		return "auth.outcome.evaluation_failure", "decision_evaluation"
	}
}

// applySelectedAuthEffect publishes one non-acceptance terminal decision.
func (e *authnCandidateExecution) applySelectedAuthEffect(
	effect decision.Effect,
	final *report.FinalDecision,
	current authnApplicationResult,
) (authnApplicationResult, error) {
	switch effect {
	case decision.EffectPermit:
		e.auth.AuthOK(e.ginCtx)
	case decision.EffectDeny:
		e.auth.AuthFail(e.ginCtx)
		e.ginCtx.Abort()
	case decision.EffectIndeterminate:
		e.auth.AuthTempFail(e.ginCtx, tempFailReasonFromPolicy(final))
		e.ginCtx.Abort()
	default:
		return current.mapEffect(effect)
	}

	return e.capturedResult(), nil
}

// authnCandidateTempFailDecision replaces only terminal metadata after a runtime failure.
func authnCandidateTempFailDecision(
	input *report.FinalDecision,
	outcomeMarker string,
	responseSource string,
) *report.FinalDecision {
	output := report.CloneFinalDecision(input)
	output.Effect = policy.DecisionTempFail
	output.OutcomeMarker = outcomeMarker
	output.ResponseMarker = policy.ResponseMarkerTempFail

	output.ResponseMessage = &report.ResponseMessageSelection{
		Source:  responseSource,
		Message: definitions.TempFailDefault,
	}

	output.ResponseLanguage = nil
	if output.Stage == policy.StagePreAuth {
		output.FSMEventMarker = policy.FSMEventMarkerPreAuthTempFail
	} else {
		output.FSMEventMarker = policy.FSMEventMarkerAuthTempFail
	}

	return output
}

// capturedResult projects the terminal response writer outcome for the active operation.
func (e *authnCandidateExecution) capturedResult() authnApplicationResult {
	captured := e.capture.Outcome()
	if e.operation == policy.OperationListAccounts {
		return authnApplicationResult{accounts: listAccountsOutcomeFromCaptured(captured)}
	}

	return authnApplicationResult{auth: authOutcomeFromCaptured(captured)}
}

// permittedListResult preserves account payloads while applying selected localization metadata.
func (e *authnCandidateExecution) permittedListResult(current authnApplicationResult) authnApplicationResult {
	result := cloneAuthnCandidateListOutcome(current.accounts)
	if result == nil {
		result = &ListAccountsOutcome{}
	}

	result.Decision = AuthDecisionOK
	result.Session = e.auth.Runtime.GUID
	result.StatusMessage = e.auth.Runtime.StatusMessage
	result.StatusMessageI18NKey = e.auth.Runtime.StatusMessageI18NKey
	result.ResponseLanguage = e.auth.Runtime.ResponseLanguage
	result.HTTPStatus = http.StatusOK

	return authnApplicationResult{accounts: result}
}

// authnCandidateRuntimeOwnsPolicy reports whether the shared runtime owns selection and effects.
func authnCandidateRuntimeOwnsPolicy(ctx *gin.Context) bool {
	return ctx != nil && ctx.GetBool(authnCandidateRuntimeOwnerKey)
}

// markAuthnCandidatePostActionFailure retains one pre-finalization failure cause.
func markAuthnCandidatePostActionFailure(ctx *gin.Context, result PostActionResult) {
	if ctx != nil && authnCandidateRuntimeOwnsPolicy(ctx) && !result.Succeeded() {
		ctx.Set(authnCandidatePostActionFailureKey, result.State())
	}
}

// authnCandidatePostActionAcceptanceFailed reports existing supervisor rejection to final mapping.
func authnCandidatePostActionAcceptanceFailed(ctx *gin.Context) bool {
	state, failed := authnCandidatePostActionFailure(ctx)

	return failed && state == PostActionStateAcceptanceRejected
}

// authnCandidatePostActionFailure returns the exact retained synchronous failure cause.
func authnCandidatePostActionFailure(ctx *gin.Context) (PostActionState, bool) {
	if ctx == nil {
		return "", false
	}

	value, exists := ctx.Get(authnCandidatePostActionFailureKey)
	if !exists {
		return "", false
	}

	state, ok := value.(PostActionState)

	return state, ok
}

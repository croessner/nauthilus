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

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/report"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

const (
	authnCandidateRuntimeOwnerKey                = "authn_candidate_runtime_owner"
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
	auth           *AuthState
	backendResult  *PassDBResult
	ginCtx         *gin.Context
	capture        *CaptureResponseWriter
	selected       map[string]*report.FinalDecision
	accounts       AccountList
	backendPlan    backendExecutionPlan
	backendAccount string
	operation      policy.Operation
	mu             sync.Mutex
	authResult     definitions.AuthResult
	preAuthResult  definitions.AuthResult
	preAuthReady   bool
	finalReady     bool
	bruteForceRun  bool
	environmentRun bool
	backendReady   bool
	backendCached  bool
	subjectReady   bool
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
	hostCtx = contextWithAuthnLuaActionOwner(hostCtx, execution)
	hostCtx = decisionservice.ContextWithAuthnNativeEffectHost(hostCtx, execution)

	return execution, hostCtx, nil
}

// installAuthnLuaFactDeclarations registers exact generation-owned script facts before any Lua callback runs.
func (e *authnCandidateExecution) installAuthnLuaFactDeclarations(
	session decisionservice.DecisionSession,
	required bool,
) error {
	policyCtx := e.auth.requestPolicyContext(e.ginCtx)
	if policyCtx == nil {
		return fmt.Errorf("authn Policy context is unavailable")
	}

	attributeSession, attributesOK := session.(decisionservice.AuthnPolicyAttributeSession)
	if !attributesOK {
		if required {
			return fmt.Errorf("authn Policy attribute session is unavailable")
		}
	} else if err := policyCtx.AddAuthnPolicyAttributes(attributeSession.AuthnPolicyAttributes()); err != nil {
		return err
	}

	factSession, ok := session.(decisionservice.AuthnLuaFactSession)
	if !ok {
		if required {
			return fmt.Errorf("authn Lua fact session is unavailable")
		}

		return nil
	}

	return policyCtx.AddAuthnLuaFactDeclarations(factSession.AuthnLuaFacts())
}

// prepareCheckpoint runs only the ordered host providers owned by one compiled checkpoint.
func (e *authnCandidateExecution) prepareCheckpoint(
	session decisionservice.DecisionSession,
	checkpoint decisionservice.CheckpointPlan,
) (authnApplicationResult, error) {
	if e == nil || e.auth == nil || e.ginCtx == nil {
		return authnApplicationResult{}, ErrAuthOutcomeMissing
	}

	hostSession, ok := session.(decisionservice.AuthnHostExecutionSession)
	if !ok {
		return authnApplicationResult{}, fmt.Errorf("authn host execution session is unavailable")
	}

	for {
		facts, err := e.authnHostScheduleFacts(checkpoint.Name())
		if err != nil {
			return authnApplicationResult{}, fmt.Errorf("build authn host schedule facts: %w", err)
		}

		directive, found, err := hostSession.NextAuthnHostProvider(decisionservice.AuthnHostScheduleInput{
			Checkpoint: checkpoint.Name(), Facts: facts, Authenticated: e.auth.Runtime.Authenticated,
		})
		if err != nil {
			return authnApplicationResult{}, fmt.Errorf("schedule authn checkpoint %q: %w", checkpoint.Name(), err)
		}

		if !found {
			break
		}

		if directive.Disposition() == decisionservice.AuthnHostDispositionSkipped {
			continue
		}

		if directive.Disposition() != decisionservice.AuthnHostDispositionRun {
			return authnApplicationResult{}, fmt.Errorf(
				"authn checkpoint %q returned unsupported host disposition %q",
				checkpoint.Name(),
				directive.Disposition(),
			)
		}

		instance := directive.Instance()
		terminal, state, executeErr := e.prepareProviderInstance(session, instance.Use())

		receiptErr := hostSession.RecordAuthnHostProvider(decisionservice.AuthnHostReceipt{
			Checkpoint: checkpoint.Name(), Instance: instance.Name(), State: state,
			Authenticated: e.auth.Runtime.Authenticated, Terminal: terminal,
		})
		if receiptErr != nil {
			return authnApplicationResult{}, fmt.Errorf("record authn host provider %q: %w", instance.Name(), receiptErr)
		}

		if executeErr != nil {
			return authnApplicationResult{}, fmt.Errorf("execute authn host provider %q: %w", instance.Name(), executeErr)
		}

		if terminal {
			if completeErr := hostSession.CompleteAuthnHostSchedule(checkpoint.Name()); completeErr != nil {
				return authnApplicationResult{}, fmt.Errorf(
					"complete terminal authn checkpoint %q: %w",
					checkpoint.Name(),
					completeErr,
				)
			}

			break
		}
	}

	if checkpoint.Name() == string(policy.StageSubjectAnalysis) {
		e.completeSubjectCheckpoint()
	}

	return e.currentResult(), nil
}

// authnHostScheduleFacts projects current request observations for the next plan-local guard.
func (e *authnCandidateExecution) authnHostScheduleFacts(checkpoint string) (decision.FactSet, error) {
	target, err := decision.NewTarget(policy.AuthnNamespace, string(e.operation))
	if err != nil {
		return decision.FactSet{}, err
	}

	return e.StandardAuthFacts(e.ginCtx.Request.Context(), target, checkpoint)
}

// prepareProviderInstance executes only the exact instance yielded by the captured scheduler.
func (e *authnCandidateExecution) prepareProviderInstance(
	session decisionservice.DecisionSession,
	providerID string,
) (bool, decisionservice.AuthnHostReceiptState, error) {
	receipt := decisionservice.AuthnHostReceiptCompleted

	var (
		terminal bool
		err      error
	)

	switch providerID {
	case policy.AuthnProviderBruteForce:
		terminal = e.prepareBruteForceProvider()
	case policy.AuthnProviderEnvironment:
		terminal = e.prepareBuiltinEnvironmentProvider()
	case policy.AuthnProviderTLSEncryption:
		terminal = e.prepareEnvironmentProviders(authnEnvironmentProviderPlan{tls: true})
	case policy.AuthnProviderRelayDomains:
		terminal = e.prepareEnvironmentProviders(authnEnvironmentProviderPlan{relay: true})
	case policy.AuthnProviderRBL:
		terminal = e.prepareEnvironmentProviders(authnEnvironmentProviderPlan{rbl: true})
	case policy.AuthnProviderBackend:
		terminal, err = e.prepareBuiltinBackendProvider()
	case policy.AuthnProviderLDAPBackend, policy.AuthnProviderLuaBackend, policy.AuthnProviderPluginBackendOrder:
		terminal, err = e.prepareTypedBackendProvider(providerID)
	case policy.AuthnProviderSubject:
		terminal, err = e.prepareBuiltinSubjectProvider()
	case policy.AuthnProviderAccount:
		e.prepareAccountProvider()
	default:
		terminal, err = e.prepareConfiguredHostProvider(session, providerID)
	}

	if err != nil {
		receipt = decisionservice.AuthnHostReceiptFailed
		if e.ginCtx.Request.Context().Err() == context.DeadlineExceeded {
			receipt = decisionservice.AuthnHostReceiptTimedOut
		}
	}

	return terminal, receipt, err
}

// prepareBuiltinEnvironmentProvider completes the code-owned environment slot without selecting legacy scripts.
func (e *authnCandidateExecution) prepareBuiltinEnvironmentProvider() bool {
	e.environmentRun = true

	return false
}

type authnCompiledLuaSource interface {
	OpenCompiledLuaSource() (string, *lua.FunctionProto, error)
	LuaPoolKey() string
	LuaPoolManager() *vmpool.Manager
	SealedLuaModules() *luaseal.Modules
}

// prepareConfiguredHostProvider dispatches one exact generation-owned source binding.
func (e *authnCandidateExecution) prepareConfiguredHostProvider(
	session decisionservice.DecisionSession,
	providerID string,
) (bool, error) {
	provider, err := resolveConfiguredAuthnHostProvider(session, providerID)
	if err != nil {
		return false, err
	}

	if terminal, handled, nativeErr := e.prepareConfiguredNativeHostProvider(providerID, provider); handled {
		return terminal, nativeErr
	}

	return e.prepareConfiguredLuaHostProvider(providerID, provider)
}

// resolveConfiguredAuthnHostProvider selects one exact provider from the admitted generation session.
func resolveConfiguredAuthnHostProvider(
	session decisionservice.DecisionSession,
	providerID string,
) (decisionservice.AuthnHostProvider, error) {
	hostSession, ok := session.(decisionservice.AuthnHostProviderSession)
	if !ok {
		return nil, fmt.Errorf("authn host provider session is unavailable")
	}

	provider, found := hostSession.AuthnHostProvider(providerID)
	if !found || provider == nil || provider.ID() != providerID {
		return nil, fmt.Errorf("configured authn host provider %q is unavailable", providerID)
	}

	return provider, nil
}

// prepareConfiguredNativeHostProvider dispatches native source kinds and reports whether it handled the provider.
func (e *authnCandidateExecution) prepareConfiguredNativeHostProvider(
	providerID string,
	provider decisionservice.AuthnHostProvider,
) (bool, bool, error) {
	switch provider.Kind() {
	case decisionservice.AuthnHostProviderKindNativeEnvironment:
		native, ok := provider.(decisionservice.AuthnNativeEnvironmentProvider)
		if !ok {
			return false, true, fmt.Errorf("configured authn host provider %q has no native environment owner", providerID)
		}

		terminal, err := e.prepareNativeEnvironmentSource(providerID, native)

		return terminal, true, err
	case decisionservice.AuthnHostProviderKindNativeSubject:
		native, ok := provider.(decisionservice.AuthnNativeSubjectProvider)
		if !ok {
			return false, true, fmt.Errorf("configured authn host provider %q has no native subject owner", providerID)
		}

		terminal, err := e.prepareNativeSubjectSource(providerID, native)

		return terminal, true, err
	default:
		return false, false, nil
	}
}

// prepareConfiguredLuaHostProvider opens and dispatches one compiled Lua source owner.
func (e *authnCandidateExecution) prepareConfiguredLuaHostProvider(
	providerID string,
	provider decisionservice.AuthnHostProvider,
) (bool, error) {
	compiled, ok := provider.(authnCompiledLuaSource)
	if !ok {
		return false, fmt.Errorf("configured authn host provider %q has no compiled source", providerID)
	}

	name, prototype, err := compiled.OpenCompiledLuaSource()
	if err != nil {
		return false, fmt.Errorf("open configured authn host provider %q: %w", providerID, err)
	}

	poolKey := vmpool.PoolKey(compiled.LuaPoolKey())
	pools := compiled.LuaPoolManager()

	if name == "" || prototype == nil || poolKey == "" || pools == nil {
		return false, fmt.Errorf("configured authn host provider %q is incomplete", providerID)
	}

	switch provider.Kind() {
	case decisionservice.AuthnHostProviderKindLuaEnvironment:
		return e.prepareLuaEnvironmentSource(name, prototype, pools, poolKey, compiled.SealedLuaModules())
	case decisionservice.AuthnHostProviderKindLuaSubject:
		return e.prepareLuaSubjectSource(name, prototype, pools, poolKey, compiled.SealedLuaModules())
	default:
		return false, fmt.Errorf(
			"configured authn host provider %q has unsupported kind %q",
			providerID,
			provider.Kind(),
		)
	}
}

// prepareLuaEnvironmentSource applies one captured script result to request-local host state.
func (e *authnCandidateExecution) prepareLuaEnvironmentSource(
	name string,
	prototype *lua.FunctionProto,
	pools *vmpool.Manager,
	poolKey vmpool.PoolKey,
	modules *luaseal.Modules,
) (bool, error) {
	triggered, aborted, err := e.auth.EnvironmentLuaSource(e.ginCtx, name, prototype, pools, poolKey, modules)

	e.environmentRun = true
	if err != nil {
		e.preAuthResult = definitions.AuthResultTempFail

		return true, nil
	}

	if triggered {
		e.auth.processEnvironmentAction(e.ginCtx, definitions.ControlLua)
		markEnvironmentRejected(e.ginCtx, true)
		e.preAuthResult = definitions.AuthResultLuaEnvironment

		return true, nil
	}

	if aborted {
		e.preAuthResult = definitions.AuthResultOK

		return false, nil
	}

	return false, nil
}

// prepareLuaSubjectSource applies one captured subject script after backend state exists.
func (e *authnCandidateExecution) prepareLuaSubjectSource(
	name string,
	prototype *lua.FunctionProto,
	pools *vmpool.Manager,
	poolKey vmpool.PoolKey,
	modules *luaseal.Modules,
) (bool, error) {
	if e.backendResult == nil || !e.backendReady {
		return false, fmt.Errorf("generation-owned Lua subject provider has no backend result")
	}

	subject := e.auth.deps.HostServices.subject
	if subject == nil {
		return false, fmt.Errorf("generation-owned Lua subject runner is unavailable")
	}

	e.authResult = subject.AnalyzeSource(
		e.ginCtx,
		e.auth.View(),
		e.backendResult,
		name,
		prototype,
		pools,
		poolKey,
		modules,
	)
	e.subjectReady = true

	return e.authResult != definitions.AuthResultOK && e.authResult != definitions.AuthResultUnset, nil
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
	if e.preAuthReady {
		return e.preAuthResult != definitions.AuthResultUnset && e.preAuthResult != definitions.AuthResultOK
	}

	e.environmentRun = true
	e.preAuthResult = e.auth.handleEnvironmentProviders(e.ginCtx, plan)

	return e.preAuthResult != definitions.AuthResultOK
}

// prepareBuiltinBackendProvider executes the configured backend order without selecting legacy subject scripts.
func (e *authnCandidateExecution) prepareBuiltinBackendProvider() (bool, error) {
	return e.prepareBackendPlan(e.auth.buildBackendExecutionPlan())
}

// prepareTypedBackendProvider executes one exact backend family without running subject work.
func (e *authnCandidateExecution) prepareTypedBackendProvider(providerID string) (bool, error) {
	plan, err := e.auth.buildAuthnTypedBackendExecutionPlan(providerID)
	if err != nil {
		return false, err
	}

	return e.prepareBackendPlan(plan)
}

// prepareBackendPlan stages one request-owned backend result for the separate subject checkpoint.
func (e *authnCandidateExecution) prepareBackendPlan(plan backendExecutionPlan) (bool, error) {
	if e.backendReady || e.backendResult != nil {
		return false, fmt.Errorf("authn backend provider already executed")
	}

	if result := e.auth.usernamePasswordChecks(); result != definitions.AuthResultUnset {
		e.authResult = result

		return true, nil
	}

	if e.prepareCachedBackendResult(plan) {
		return false, nil
	}

	return e.prepareVerifiedBackendResult(plan)
}

// prepareCachedBackendResult installs one request-compatible positive cache hit.
func (e *authnCandidateExecution) prepareCachedBackendResult(plan backendExecutionPlan) bool {
	result, found := e.auth.takePositiveBackendAuthenticationCache(e.ginCtx)
	if !found {
		return false
	}

	e.auth.recordPolicyBackendResult(e.ginCtx, definitions.AuthResultOK, result, nil)
	e.backendResult = result
	e.backendPlan = plan
	e.backendAccount = result.Account
	e.backendReady = true
	e.backendCached = true
	e.authResult = definitions.AuthResultOK

	return true
}

// prepareVerifiedBackendResult executes the selected backend plan and captures its request-owned result.
func (e *authnCandidateExecution) prepareVerifiedBackendResult(plan backendExecutionPlan) (bool, error) {
	result, err := e.auth.processVerifyPassword(e.ginCtx, plan.passDBs)
	if err != nil {
		e.recordBackendFailure(result, err)

		return true, nil
	}

	if result == nil {
		e.recordBackendFailure(nil, nil)

		return true, nil
	}

	accountName, err := e.auth.processUserFound(result)
	if err != nil {
		PutPassDBResultToPool(result)

		e.recordBackendFailure(nil, err)

		return true, nil
	}

	e.installVerifiedBackendResult(plan, result, accountName)

	return false, nil
}

// recordBackendFailure projects one backend failure onto request-local auth and Policy state.
func (e *authnCandidateExecution) recordBackendFailure(result *PassDBResult, err error) {
	e.auth.Runtime.Authenticated = false
	e.auth.recordPolicyBackendResult(e.ginCtx, definitions.AuthResultTempFail, result, err)
	e.authResult = definitions.AuthResultTempFail
}

// installVerifiedBackendResult completes the staged backend state after identity normalization succeeds.
func (e *authnCandidateExecution) installVerifiedBackendResult(
	plan backendExecutionPlan,
	result *PassDBResult,
	accountName string,
) {
	e.auth.loadBruteForceHistories(e.ginCtx, accountName)
	e.auth.applyBackendResult(e.ginCtx, result)
	e.auth.storePositiveBackendAuthentication(e.ginCtx, result)
	e.backendResult = result
	e.backendPlan = plan
	e.backendAccount = accountName

	e.backendReady = true
	if result.Authenticated {
		e.authResult = definitions.AuthResultOK
	} else {
		e.authResult = definitions.AuthResultFail
	}
}

// prepareBuiltinSubjectProvider records exact backend subject state without selecting legacy scripts.
func (e *authnCandidateExecution) prepareBuiltinSubjectProvider() (bool, error) {
	if !e.backendReady || e.backendResult == nil {
		return false, fmt.Errorf("authn subject provider has no exact backend result")
	}

	e.subjectReady = true

	return e.authResult != definitions.AuthResultOK && e.authResult != definitions.AuthResultUnset, nil
}

// completeSubjectCheckpoint finalizes backend ownership after every selected subject provider has run.
func (e *authnCandidateExecution) completeSubjectCheckpoint() {
	if !e.backendReady || e.backendResult == nil {
		return
	}

	e.subjectReady = true
	e.finalReady = true
	e.finishTypedBackendProvider()
}

// finishTypedBackendProvider applies cache/post-action projection and releases the request-owned backend result.
func (e *authnCandidateExecution) finishTypedBackendProvider() {
	if e.backendResult == nil {
		return
	}

	if !e.backendCached {
		if err := e.auth.processFinalAuthCache(
			e.ginCtx,
			e.backendResult,
			e.authResult,
			e.backendAccount,
			e.backendPlan,
		); err != nil {
			e.auth.Runtime.Authenticated = false
			e.auth.recordPolicyBackendResult(e.ginCtx, definitions.AuthResultTempFail, e.backendResult, err)
			e.authResult = definitions.AuthResultTempFail
		}
	}

	e.auth.storePolicyPostActionResult(e.ginCtx, e.backendResult)
	PutPassDBResultToPool(e.backendResult)
	e.backendResult = nil
}

// release drops request-owned backend state when a terminal checkpoint prevents subject execution.
func (e *authnCandidateExecution) release() {
	if e == nil {
		return
	}

	if e.backendResult != nil {
		PutPassDBResultToPool(e.backendResult)
		e.backendResult = nil
	}

	if result, owned := takePolicyPostActionResult(e.ginCtx); owned {
		PutPassDBResultToPool(result)
	}
}

// prepareAccountProvider runs the existing account provider once.
func (e *authnCandidateExecution) prepareAccountProvider() {
	if e.finalReady {
		return
	}

	e.finalReady = true
	e.accounts = e.auth.ListUserAccounts()
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

// authnCandidatePresentation projects runtime failures onto the final response.
func (e *authnCandidateExecution) authnCandidatePresentation(
	response decision.DecisionResponse,
	final *report.FinalDecision,
) (*report.FinalDecision, bool) {
	return authnCandidateRuntimePresentation(response, final)
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

	outcome := authOutcomeFromCaptured(captured)
	selected := e.terminalDecision()

	if outcome != nil && selected != nil {
		outcome.PolicyTerminal = true
		outcome.DelayedResponseEligible = authOutcomeIsIDPPasswordFailure(e.auth, outcome.Decision) &&
			configuredPolicyAllowsIDPDelayedResponse(selected)
	}

	return authnApplicationResult{auth: outcome}
}

// terminalDecision returns the catalog-selected terminal presentation for the request.
func (e *authnCandidateExecution) terminalDecision() *report.FinalDecision {
	if e == nil {
		return nil
	}

	for _, checkpoint := range []string{string(policy.StageAuthDecision), string(policy.StagePreAuth)} {
		selected := e.selectedDecision(checkpoint)
		if selected != nil && (selected.Effect == policy.DecisionDeny || selected.Effect == policy.DecisionTempFail) {
			return selected
		}
	}

	return nil
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

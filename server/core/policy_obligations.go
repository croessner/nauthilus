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
	"fmt"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/observability"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/gin-gonic/gin"
)

const (
	policyModeEnforce = "enforce"
)

type policyObligationHandlers struct {
	updateBruteForce func(*gin.Context, bruteForceUpdateObligation) bool
	dispatchLua      func(*gin.Context, luaActionObligation) bool
	enqueuePost      func(*gin.Context) bool
}

type policyObligationExecutor struct {
	auth     *AuthState
	handlers policyObligationHandlers
	recorder observability.Recorder
}

type luaActionObligation struct {
	environmentName string
	actionName      string
	luaAction       definitions.LuaAction
	wait            bool
}

type bruteForceUpdateObligation struct {
	environmentName string
	featureName     string
}

func newPolicyObligationExecutor(auth *AuthState) policyObligationExecutor {
	executor := policyObligationExecutor{
		auth:     auth,
		recorder: observability.DefaultRecorder(),
	}
	executor.handlers = policyObligationHandlers{
		updateBruteForce: auth.executeBruteForceUpdateObligation,
		dispatchLua:      auth.executeLuaActionObligation,
		enqueuePost:      auth.enqueuePolicyPostAction,
	}

	return executor
}

func (e policyObligationExecutor) Execute(ctx *gin.Context, final *report.FinalDecision) bool {
	if e.auth == nil || final == nil {
		return true
	}

	if !policyObligationsEnabled(ctx) {
		return true
	}

	postActionPlan := make([]PostActionPlanStep, 0)

	for index, obligation := range final.Obligations {
		ordinal := uint32(index + 1)
		if e.collectPostActionPlanStep(ctx, obligation, ordinal, &postActionPlan) {
			continue
		}

		e.executeOne(ctx, obligation)
	}

	return e.executePostActionPlan(ctx, postActionPlan)
}

// executeOne invokes one selected synchronous owner and reports its exact result.
func (e policyObligationExecutor) executeOne(ctx *gin.Context, obligation report.EffectRequest) bool {
	started := time.Now()
	result := observability.ResultSuccess

	switch obligation.ID {
	case policy.ObligationBruteForceUpdate:
		request, ok := bruteForceUpdateObligationFromEffect(obligation)
		if !ok {
			result = observability.ResultError

			break
		}

		if !e.handlers.updateBruteForce(ctx, request) {
			result = observability.ResultFailure
		}
	case policy.ObligationLuaActionDispatch:
		request, ok := luaActionObligationFromEffect(obligation)
		if !ok {
			result = observability.ResultError

			break
		}

		if !e.handlers.dispatchLua(ctx, request) {
			result = observability.ResultFailure
		}
	case policy.ObligationLuaPostActionEnqueue:
		if !e.handlers.enqueuePost(ctx) {
			result = observability.ResultFailure
		}
	default:
		handled, ok := e.executePluginEffect(ctx, obligation)
		if !handled {
			result = observability.ResultError

			break
		}

		if !ok {
			result = observability.ResultFailure
		}
	}

	e.record(ctx, obligation.ID, time.Since(started), result)

	return result == observability.ResultSuccess
}

// preparePostActionWork captures one selected post-action without accepting or executing it.
func (e policyObligationExecutor) preparePostActionWork(
	ctx *gin.Context,
	obligation report.EffectRequest,
	ordinal uint32,
) (effectsupervisor.ExecutableWork, error) {
	steps := make([]PostActionPlanStep, 0, 1)
	if !e.collectPostActionPlanStep(ctx, obligation, ordinal, &steps) || len(steps) != 1 {
		return nil, fmt.Errorf("post-action effect %q has no preparer", obligation.ID)
	}

	step := steps[0]
	if runner, ok := step.LuaStep(); ok {
		works, err := newLuaPostActionStepWorks([]PostActionPlanRunner{runner}, steps)
		if err != nil {
			ReleasePostActionPlanSteps(steps)

			return nil, err
		}

		return works[0], nil
	}

	preparer, ok := getPluginEffectBridge().(PluginPostActionWorkPreparer)
	if !ok || preparer == nil {
		ReleasePostActionPlanSteps(steps)

		return nil, fmt.Errorf("post-action effect %q has no native preparer", obligation.ID)
	}

	work, ok := preparer.PreparePostActionWork(ctx, e.auth.View(), step)
	if !ok || work == nil {
		ReleasePostActionPlanSteps(steps)

		return nil, fmt.Errorf("post-action effect %q preparation failed", obligation.ID)
	}

	return work, nil
}

func (e policyObligationExecutor) record(
	ctx *gin.Context,
	id string,
	duration time.Duration,
	result observability.Result,
) {
	recorder := e.recorder
	if recorder == nil {
		recorder = observability.DefaultRecorder()
	}

	recorder.RecordObligation(contextFromGin(ctx), observability.ObligationMeasurement{
		Duration:   duration,
		Obligation: id,
		Result:     result,
	})
	observability.Debug(
		contextFromGin(ctx),
		e.auth.Cfg(),
		e.auth.Logger(),
		observability.ComponentEval,
		definitions.LogKeyGUID, e.auth.Runtime.GUID,
		"obligation", id,
		"result", string(result),
	)
}

func (e policyObligationExecutor) executePluginEffect(ctx *gin.Context, obligation report.EffectRequest) (bool, bool) {
	bridge := getPluginEffectBridge()
	if bridge == nil || e.auth == nil {
		return false, false
	}

	return bridge.ExecutePolicyEffect(ctx, e.auth.View(), obligation)
}

// collectPostActionPlanStep appends post-action obligations for one ordered plan enqueue.
func (e policyObligationExecutor) collectPostActionPlanStep(
	ctx *gin.Context,
	obligation report.EffectRequest,
	ordinal uint32,
	postActionPlan *[]PostActionPlanStep,
) bool {
	if e.collectPluginPostAction(obligation, ordinal, postActionPlan) {
		return true
	}

	return e.collectLuaPostAction(ctx, obligation, ordinal, postActionPlan)
}

// collectPluginPostAction appends native post-action effects for one later plan enqueue.
func (e policyObligationExecutor) collectPluginPostAction(
	obligation report.EffectRequest,
	ordinal uint32,
	postActionPlan *[]PostActionPlanStep,
) bool {
	if postActionPlan == nil {
		return false
	}

	bridge := getPluginEffectBridge()
	if bridge == nil || !bridge.IsPostActionEffect(obligation) {
		return false
	}

	*postActionPlan = append(*postActionPlan, NewNativePostActionPlanStep(obligation).WithEffectOrdinal(ordinal))

	return true
}

// collectLuaPostAction appends the default Lua post-action dispatcher as a plan step.
func (e policyObligationExecutor) collectLuaPostAction(
	ctx *gin.Context,
	obligation report.EffectRequest,
	ordinal uint32,
	postActionPlan *[]PostActionPlanStep,
) bool {
	if postActionPlan == nil || obligation.ID != policy.ObligationLuaPostActionEnqueue || e.auth == nil {
		return false
	}

	preparer, ok := getPostAction().(PostActionPlanPreparer)
	if !ok || preparer == nil {
		return false
	}

	input, cleanup := e.luaPostActionPlanInput(ctx)
	runner := preparer.PreparePlanStep(input)

	if runner == nil {
		cleanup()

		return false
	}

	*postActionPlan = append(*postActionPlan, NewLuaPostActionPlanStep(obligation.ID, runner, cleanup).WithEffectOrdinal(ordinal))

	return true
}

// luaPostActionPlanInput captures the post-action result until the accepted plan consumes it.
func (e policyObligationExecutor) luaPostActionPlanInput(ctx *gin.Context) (PostActionInput, func()) {
	result, release := takePolicyPostActionResult(ctx)
	if result == nil {
		result = GetPassDBResultFromPool()
		release = true
	}

	cleanup := func() {
		if release {
			PutPassDBResultToPool(result)
		}
	}

	return e.auth.newPostActionInput(ctx, result), cleanup
}

// executePostActionPlan enqueues collected post-actions once per final decision.
func (e policyObligationExecutor) executePostActionPlan(
	ctx *gin.Context,
	steps []PostActionPlanStep,
) bool {
	if len(steps) == 0 {
		return true
	}

	started := time.Now()
	result := observability.ResultSuccess

	handled, ok := e.enqueuePostActionPlan(ctx, steps)
	if !handled {
		result = observability.ResultError
	} else if !ok {
		result = observability.ResultFailure
	}

	duration := time.Since(started)
	for _, step := range steps {
		e.record(ctx, step.ID(), duration, result)
	}

	if !handled {
		ReleasePostActionPlanSteps(steps)
	}

	return handled && ok
}

// enqueuePostActionPlan delegates post-action scheduling to the runtime bridge.
func (e policyObligationExecutor) enqueuePostActionPlan(
	ctx *gin.Context,
	steps []PostActionPlanStep,
) (bool, bool) {
	bridge := getPluginEffectBridge()

	if e.auth == nil {
		return false, false
	}

	if bridge == nil {
		ok := e.runLuaPostActionFallback(ctx, steps)

		return true, ok
	}

	return bridge.EnqueuePostActionPlan(ctx, e.auth.View(), steps)
}

// runLuaPostActionFallback accepts Lua-only plans through the shared supervisor primitive.
func (e policyObligationExecutor) runLuaPostActionFallback(ctx *gin.Context, steps []PostActionPlanStep) bool {
	runners := make([]PostActionPlanRunner, 0, len(steps))
	for _, step := range steps {
		runner, ok := step.LuaStep()
		if !ok {
			ReleasePostActionPlanSteps(steps)

			return false
		}

		runners = append(runners, runner)
	}

	if _, err := EnqueueLuaPostActionPlan(ctx, e.auth.View(), 1, runners, steps); err != nil {
		ReleasePostActionPlanSteps(steps)

		return false
	}

	return true
}

func policyObligationsEnabled(ctx *gin.Context) bool {
	policyCtx := existingPolicyContext(ctx)
	if policyCtx == nil {
		return false
	}

	mode, _, _ := policyCtx.SnapshotMetadata()

	return policyEffectsEnabled(mode)
}

// policyEffectsEnabled applies the shared enforce-versus-observe effect gate.
func policyEffectsEnabled(mode string) bool {
	return mode == "" || mode == policyModeEnforce
}

func luaActionObligationFromEffect(effect report.EffectRequest) (luaActionObligation, bool) {
	actionName, ok := effect.Args[policy.ObligationArgAction].(string)
	if !ok || !policy.LuaActionDispatchActionAllowed(actionName) {
		return luaActionObligation{}, false
	}

	luaAction, ok := luaActionFromPolicyName(actionName)
	if !ok {
		return luaActionObligation{}, false
	}

	environmentName, _ := effect.Args[policy.ObligationArgEnvironment].(string)
	if environmentName == "" {
		environmentName = actionName
	}

	wait := true
	if value, exists := effect.Args[policy.ObligationArgWait]; exists {
		wait, ok = value.(bool)
		if !ok {
			return luaActionObligation{}, false
		}
	}

	return luaActionObligation{
		environmentName: environmentName,
		actionName:      actionName,
		luaAction:       luaAction,
		wait:            wait,
	}, true
}

// bruteForceUpdateObligationFromEffect validates optional learning metadata for one bucket update.
func bruteForceUpdateObligationFromEffect(effect report.EffectRequest) (bruteForceUpdateObligation, bool) {
	request := bruteForceUpdateObligation{}

	for key, value := range effect.Args {
		stringValue, ok := value.(string)
		if !ok {
			return bruteForceUpdateObligation{}, false
		}

		switch key {
		case policy.ObligationArgEnvironment:
			request.environmentName = stringValue
		case policy.ObligationArgFeature:
			if strings.TrimSpace(stringValue) == "" {
				return bruteForceUpdateObligation{}, false
			}

			request.featureName = stringValue
		default:
			return bruteForceUpdateObligation{}, false
		}
	}

	return request, true
}

// executeBruteForceUpdateObligation performs the selected update without dispatching Lua actions.
func (a *AuthState) executeBruteForceUpdateObligation(ctx *gin.Context, request bruteForceUpdateObligation) bool {
	if a == nil || ctx == nil || ctx.Request == nil {
		return false
	}

	if !a.shouldRunBruteForceUpdate(request) {
		return true
	}

	if request.environmentName != "" {
		a.Runtime.EnvironmentName = request.environmentName
	}

	a.updateBruteForceBucketsCounter(ctx, request.featureName)

	return true
}

// shouldRunBruteForceUpdate applies the configured learning gate to conditional updates.
func (a *AuthState) shouldRunBruteForceUpdate(request bruteForceUpdateObligation) bool {
	if request.featureName == "" {
		return true
	}

	bruteForce := a.cfg().GetBruteForce()
	if bruteForce == nil {
		return false
	}

	return bruteForceLearningEnabled(bruteForce, request.featureName, request.environmentName)
}

func luaActionFromPolicyName(name string) (definitions.LuaAction, bool) {
	switch name {
	case policy.LuaActionDispatchBruteForce:
		return definitions.LuaActionBruteForce, true
	case policy.LuaActionDispatchLua:
		return definitions.LuaActionLua, true
	case policy.LuaActionDispatchTLS:
		return definitions.LuaActionTLS, true
	case policy.LuaActionDispatchRelayDomains:
		return definitions.LuaActionRelayDomains, true
	case policy.LuaActionDispatchRBL:
		return definitions.LuaActionRBL, true
	default:
		return definitions.LuaActionNone, false
	}
}

func (a *AuthState) executeLuaActionObligation(ctx *gin.Context, request luaActionObligation) bool {
	if a == nil || ctx == nil || ctx.Request == nil {
		return false
	}

	if util.IsHTTPRequestCanceled(a.Logger(), ctx.Request, a.Runtime.GUID, "policy.lua_action") {
		return false
	}

	a.Runtime.EnvironmentName = request.environmentName

	if request.luaAction == definitions.LuaActionBruteForce {
		a.dispatchBruteForceLuaAction(ctx, request)

		return true
	}

	a.performAction(request.luaAction, request.actionName)

	return true
}

func (a *AuthState) dispatchBruteForceLuaAction(ctx *gin.Context, request luaActionObligation) {
	if !a.cfg().HaveLuaActions() {
		return
	}

	restore := a.prepareBruteForceLuaActionState()
	defer restore()

	resource := util.RequestResource(ctx, ctx.Request, a.Request.Service)

	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromBruteForce, "bf_lua_action_total", resource); stop != nil {
		defer stop()
	}

	if dispatcher := GetActionDispatcher(); dispatcher != nil {
		dispatcher.Dispatch(a.View(), request.environmentName, request.luaAction)
	}
}

func (a *AuthState) prepareBruteForceLuaActionState() func() {
	originalName := a.Security.BruteForceName
	if ruleName, _, found := strings.Cut(originalName, ","); found {
		a.Security.BruteForceName = ruleName
	}

	a.refreshBruteForceLuaActionAccount()

	return func() {
		a.Security.BruteForceName = originalName
	}
}

func (a *AuthState) refreshBruteForceLuaActionAccount() {
	if a.GetAccount() != "" {
		return
	}

	accountName := a.refreshUserAccount()
	if accountName == "" {
		return
	}

	if a.Runtime.AccountField == "" {
		a.Runtime.AccountField = definitions.MetaUserAccount
	}

	if len(a.Attributes.Attributes) == 0 {
		attrs := make(bktype.AttributeMapping)
		attrs[definitions.MetaUserAccount] = []any{accountName}
		a.ReplaceAllAttributes(attrs)
	}
}

func (a *AuthState) enqueuePolicyPostAction(ctx *gin.Context) bool {
	result, release := takePolicyPostActionResult(ctx)
	if result == nil {
		result = GetPassDBResultFromPool()
		release = true
	}

	accepted := a.PostLuaAction(ctx, result)

	if release {
		PutPassDBResultToPool(result)
	}

	return accepted
}

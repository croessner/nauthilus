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
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
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
	updateBruteForce func(*gin.Context)
	dispatchLua      func(*gin.Context, luaActionObligation) bool
	enqueuePost      func(*gin.Context)
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

func newPolicyObligationExecutor(auth *AuthState) policyObligationExecutor {
	executor := policyObligationExecutor{
		auth:     auth,
		recorder: observability.DefaultRecorder(),
	}
	executor.handlers = policyObligationHandlers{
		updateBruteForce: func(ctx *gin.Context) {
			auth.UpdateBruteForceBucketsCounter(ctx)
		},
		dispatchLua: auth.executeLuaActionObligation,
		enqueuePost: func(ctx *gin.Context) {
			auth.enqueuePolicyPostAction(ctx)
		},
	}

	return executor
}

func (e policyObligationExecutor) Execute(ctx *gin.Context, final *report.FinalDecision) {
	if e.auth == nil || final == nil {
		return
	}

	if !policyObligationsEnabled(ctx) {
		return
	}

	for _, obligation := range final.Obligations {
		e.executeOne(ctx, obligation)
	}
}

func (e policyObligationExecutor) executeOne(ctx *gin.Context, obligation report.EffectRequest) {
	started := time.Now()
	result := observability.ResultSuccess

	switch obligation.ID {
	case policy.ObligationBruteForceUpdate:
		e.handlers.updateBruteForce(ctx)
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
		e.handlers.enqueuePost(ctx)
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

func policyObligationsEnabled(ctx *gin.Context) bool {
	policyCtx := existingPolicyContext(ctx)
	if policyCtx == nil {
		return false
	}

	mode, _, _ := policyCtx.SnapshotMetadata()

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

	a.learnFromLuaActionObligation(ctx, request)
	a.performAction(request.luaAction, request.actionName)

	return true
}

func (a *AuthState) learnFromLuaActionObligation(ctx *gin.Context, request luaActionObligation) {
	bruteForce := a.cfg().GetBruteForce()
	if bruteForce == nil {
		return
	}

	if !bruteForce.LearnFromControl(request.environmentName) && !bruteForce.LearnFromControl(request.actionName) {
		return
	}

	a.UpdateBruteForceBucketsCounter(ctx)
}

func (a *AuthState) dispatchBruteForceLuaAction(ctx *gin.Context, request luaActionObligation) {
	if !a.cfg().HaveLuaActions() {
		return
	}

	restore := a.prepareBruteForceLuaActionState()
	defer restore()

	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromBruteForce, "bf_lua_action_total", ctx.FullPath()); stop != nil {
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

func (a *AuthState) enqueuePolicyPostAction(ctx *gin.Context) {
	result, release := takePolicyPostActionResult(ctx)
	if result == nil {
		result = GetPassDBResultFromPool()
		release = true
	}

	a.PostLuaAction(ctx, result)
	if release {
		PutPassDBResultToPool(result)
	}
}

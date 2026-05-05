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
	"strings"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	"github.com/croessner/nauthilus/server/policy/evaluation"
	"github.com/croessner/nauthilus/server/policy/observability"
	"github.com/croessner/nauthilus/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"

	"github.com/gin-gonic/gin"
)

const (
	policyConfiguredPreAuthDecisionContextKey = "policy_configured_pre_auth_decision"
	policyConfiguredAuthDecisionContextKey    = "policy_configured_auth_decision"
	policyPostActionResultContextKey          = "policy_post_action_result"
	policySkipPreAuthChecksContextKey         = "policy_skip_pre_auth_checks"
)

type configuredDecisionEvaluator func(context.Context, *policyruntime.Snapshot, *report.DecisionReport, evaluation.CompareInput) evaluation.Result

type configuredDecisionResolver struct {
	authoritative func(*policycollection.DecisionContext) bool
	load          func(*gin.Context) (*report.FinalDecision, bool)
	store         func(*gin.Context, *report.FinalDecision)
	evaluate      configuredDecisionEvaluator
}

func (a *AuthState) defaultPolicyPreAuthResult(ctx *gin.Context, current definitions.AuthResult) definitions.AuthResult {
	final, ok := a.defaultPolicyPreAuthDecision(ctx)
	if !ok || final == nil {
		return current
	}

	a.applyPolicyResponseMessage(final)

	return preAuthResultFromPolicy(final, current)
}

func (a *AuthState) configuredPolicyPreAuthResult(ctx *gin.Context, current definitions.AuthResult) (definitions.AuthResult, bool) {
	final, ok := a.configuredPolicyPreAuthDecision(ctx)
	if !ok || final == nil {
		return current, false
	}

	a.applyPolicyResponseMessage(final)
	if configuredPreAuthControl(final) {
		return definitions.AuthResultOK, true
	}

	if !configuredPreAuthTerminal(final) {
		return current, false
	}

	return preAuthResultFromPolicy(final, current), true
}

func (a *AuthState) defaultPolicyAuthResult(ctx *gin.Context, current definitions.AuthResult) definitions.AuthResult {
	final, ok := a.defaultPolicyAuthDecision(ctx)
	if !ok || final == nil {
		return current
	}

	a.applyPolicyResponseMessage(final)

	return authResultFromPolicy(final, current)
}

func (a *AuthState) configuredPolicyAuthResult(ctx *gin.Context, current definitions.AuthResult) (definitions.AuthResult, bool) {
	final, ok := a.configuredPolicyAuthDecision(ctx)
	if !ok || final == nil {
		return current, false
	}

	a.applyPolicyResponseMessage(final)
	a.applyPolicyObligations(ctx, final)
	releasePolicyPostActionResult(ctx)

	return authResultFromPolicy(final, current), true
}

func (a *AuthState) applyDefaultPreAuthDecision(ctx *gin.Context) bool {
	final, ok := a.defaultPolicyPreAuthDecision(ctx)
	if !ok || final == nil {
		return false
	}

	a.applyPolicyDecision(ctx, final)

	return true
}

// ApplyDefaultPreAuthDecision applies a built-in default pre-auth decision when it is authoritative.
func (a *AuthState) ApplyDefaultPreAuthDecision(ctx *gin.Context) bool {
	return a.applyDefaultPreAuthDecision(ctx)
}

// ApplyConfiguredPreAuthDecision applies a terminal configured pre-auth decision when it is authoritative.
func (a *AuthState) ApplyConfiguredPreAuthDecision(ctx *gin.Context) bool {
	return a.applyConfiguredPreAuthDecision(ctx)
}

// ApplyConfiguredPreAuthControl applies a configured pre-auth control when it is authoritative.
func (a *AuthState) ApplyConfiguredPreAuthControl(ctx *gin.Context) bool {
	return a.applyConfiguredPreAuthControl(ctx, definitions.AuthResultFail)
}

// HasConfiguredPreAuthPolicyAuthority reports whether configured pre-auth rules own production decisions.
func (a *AuthState) HasConfiguredPreAuthPolicyAuthority(ctx *gin.Context) bool {
	policyCtx := a.requestPolicyContext(ctx)

	return policyCtx != nil && policyCtx.ConfiguredPreAuthAuthoritative()
}

// HasConfiguredAuthPolicyAuthority reports whether configured final auth rules own production decisions.
func (a *AuthState) HasConfiguredAuthPolicyAuthority(ctx *gin.Context) bool {
	policyCtx := a.requestPolicyContext(ctx)

	return policyCtx != nil && policyCtx.ConfiguredAuthDecisionAuthoritative()
}

func (a *AuthState) applyConfiguredPreAuthDecision(ctx *gin.Context) bool {
	final, ok := a.configuredPolicyPreAuthDecision(ctx)
	if !ok || final == nil || !configuredPreAuthTerminal(final) {
		return false
	}

	a.applyPolicyDecision(ctx, final)

	return true
}

func (a *AuthState) applyConfiguredPreAuthControl(ctx *gin.Context, current definitions.AuthResult) bool {
	final, ok := a.configuredPolicyPreAuthDecision(ctx)
	if !ok || !configuredPreAuthControl(final) {
		return false
	}

	a.applyPolicyResponseMessage(final)
	a.markConfiguredPreAuthChecksSkipped(ctx)

	return true
}

func (a *AuthState) markConfiguredPreAuthChecksSkipped(ctx *gin.Context) {
	if ctx == nil {
		return
	}

	ctx.Set(policySkipPreAuthChecksContextKey, true)
}

func (a *AuthState) configuredPreAuthChecksSkipped(ctx *gin.Context) bool {
	return ctx != nil && ctx.GetBool(policySkipPreAuthChecksContextKey)
}

func (a *AuthState) configuredPolicyPreAuthDecision(ctx *gin.Context) (*report.FinalDecision, bool) {
	return a.configuredPolicyDecision(ctx, configuredDecisionResolver{
		authoritative: func(policyCtx *policycollection.DecisionContext) bool {
			return policyCtx.ConfiguredPreAuthAuthoritative()
		},
		load:     configuredPreAuthDecisionFromContext,
		store:    storeConfiguredPreAuthDecision,
		evaluate: evaluation.EvaluateConfiguredPreAuth,
	})
}

func (a *AuthState) configuredPolicyAuthDecision(ctx *gin.Context) (*report.FinalDecision, bool) {
	return a.configuredPolicyDecision(ctx, configuredDecisionResolver{
		authoritative: func(policyCtx *policycollection.DecisionContext) bool {
			return policyCtx.ConfiguredAuthDecisionAuthoritative()
		},
		load:     configuredAuthDecisionFromContext,
		store:    storeConfiguredAuthDecision,
		evaluate: evaluation.EvaluateConfiguredAuth,
	})
}

func (a *AuthState) configuredPolicyDecision(ctx *gin.Context, resolver configuredDecisionResolver) (*report.FinalDecision, bool) {
	policyCtx := a.requestPolicyContext(ctx)
	if policyCtx == nil || !resolver.authoritative(policyCtx) {
		return nil, false
	}

	if final, exists := resolver.load(ctx); exists {
		return final, true
	}

	mode, defaultPolicy, generation := policyCtx.SnapshotMetadata()
	result := resolver.evaluate(contextFromGin(ctx), policyCtx.Snapshot(), policyCtx.Report(), evaluation.CompareInput{
		Mode:       mode,
		Set:        defaultPolicy,
		Generation: generation,
		Recorder:   observability.DefaultRecorder(),
		Logger:     a.logger(),
		Surface:    a.policyResponseSurface(),
	})
	if result.Final != nil {
		a.storeConfiguredPolicyDecision(ctx, policyCtx, generation, result.Final, resolver.store)
	}

	return result.Final, true
}

func (a *AuthState) storeConfiguredPolicyDecision(
	ctx *gin.Context,
	policyCtx *policycollection.DecisionContext,
	generation uint64,
	final *report.FinalDecision,
	store func(*gin.Context, *report.FinalDecision),
) {
	store(ctx, final)
	observability.Debug(
		contextFromGin(ctx),
		a.Cfg(),
		a.Logger(),
		observability.ComponentEval,
		definitions.LogKeyGUID, a.Runtime.GUID,
		"operation", string(policyCtx.Report().Operation),
		"stage", string(final.Stage),
		"snapshot_generation", generation,
		"policy_name", final.PolicyName,
		"decision", string(final.Effect),
		"response_marker", final.ResponseMarker,
		"fsm_event_marker", final.FSMEventMarker,
	)
}

func configuredPreAuthDecisionFromContext(ctx *gin.Context) (*report.FinalDecision, bool) {
	if ctx == nil {
		return nil, false
	}

	value, ok := ctx.Get(policyConfiguredPreAuthDecisionContextKey)
	if !ok {
		return nil, false
	}

	final, ok := value.(*report.FinalDecision)

	return final, ok
}

func storeConfiguredPreAuthDecision(ctx *gin.Context, final *report.FinalDecision) {
	if ctx == nil || final == nil {
		return
	}

	ctx.Set(policyConfiguredPreAuthDecisionContextKey, final)
}

func configuredAuthDecisionFromContext(ctx *gin.Context) (*report.FinalDecision, bool) {
	if ctx == nil {
		return nil, false
	}

	value, ok := ctx.Get(policyConfiguredAuthDecisionContextKey)
	if !ok {
		return nil, false
	}

	final, ok := value.(*report.FinalDecision)

	return final, ok
}

func storeConfiguredAuthDecision(ctx *gin.Context, final *report.FinalDecision) {
	if ctx == nil || final == nil {
		return
	}

	ctx.Set(policyConfiguredAuthDecisionContextKey, final)
}

func (a *AuthState) defaultPolicyPreAuthDecision(ctx *gin.Context) (*report.FinalDecision, bool) {
	policyCtx, ok := a.defaultPolicyContext(ctx, policy.StagePreAuth)
	if !ok {
		return nil, false
	}

	return evaluation.EvaluateStandardPreAuth(policyCtx.Report()).Final, true
}

func (a *AuthState) defaultPolicyAuthDecision(ctx *gin.Context) (*report.FinalDecision, bool) {
	policyCtx, ok := a.defaultPolicyContext(ctx, policy.StageAuthDecision)
	if !ok {
		return nil, false
	}

	return evaluation.EvaluateStandardAuth(policyCtx.Report()).Final, true
}

func (a *AuthState) defaultPolicyContext(ctx *gin.Context, stage policy.Stage) (*policycollection.DecisionContext, bool) {
	policyCtx := a.requestPolicyContext(ctx)
	if policyCtx == nil || !policyCtx.BuiltinDefaultAuthoritativeForStage(stage) {
		return nil, false
	}

	return policyCtx, true
}

func configuredPreAuthTerminal(final *report.FinalDecision) bool {
	if final == nil || final.Stage != policy.StagePreAuth {
		return false
	}

	return final.Effect == policy.DecisionDeny || final.Effect == policy.DecisionTempFail
}

func configuredPreAuthControl(final *report.FinalDecision) bool {
	return final != nil &&
		final.Stage == policy.StagePreAuth &&
		final.Effect == policy.DecisionNeutral &&
		final.Control != nil &&
		final.Control.SkipRemainingStageChecks
}

func (a *AuthState) applyPolicyDecision(ctx *gin.Context, final *report.FinalDecision) {
	if final == nil {
		return
	}

	if final.Stage == policy.StagePreAuth && final.Effect == policy.DecisionDeny {
		a.markFeatureRejected(ctx)
	}

	if err := a.applyAuthFSMMarkers(evaluation.TargetFSMEventMarkers(a.policyReport(ctx), final)); err != nil {
		ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)

		return
	}

	a.applyPolicyResponseMessage(final)
	a.applyPolicyObligations(ctx, final)

	switch final.Effect {
	case policy.DecisionPermit:
		a.AuthOK(ctx)
	case policy.DecisionDeny:
		a.AuthFail(ctx)
		ctx.Abort()
	case policy.DecisionTempFail:
		a.AuthTempFail(ctx, tempFailReasonFromPolicy(final))
		ctx.Abort()
	default:
	}
}

func (a *AuthState) policyReport(ctx *gin.Context) *report.DecisionReport {
	if policyCtx := existingPolicyContext(ctx); policyCtx != nil {
		return policyCtx.Report()
	}

	return nil
}

func (a *AuthState) applyPolicyResponseMessage(final *report.FinalDecision) {
	if a == nil || final == nil || final.ResponseMessage == nil || final.ResponseMessage.Message == "" {
		return
	}

	a.Runtime.StatusMessage = final.ResponseMessage.Message
}

func (a *AuthState) applyPolicyObligations(ctx *gin.Context, final *report.FinalDecision) {
	if a == nil || final == nil {
		return
	}

	for _, obligation := range final.Obligations {
		switch obligation.ID {
		case policy.ObligationBruteForceUpdate:
			a.UpdateBruteForceBucketsCounter(ctx)
		case policy.ObligationLuaPostActionEnqueue:
			result, release := takePolicyPostActionResult(ctx)
			if result == nil {
				result = GetPassDBResultFromPool()
				release = true
			}

			a.PostLuaAction(ctx, result)
			if release {
				PutPassDBResultToPool(result)
			}
		default:
		}
	}
}

func (a *AuthState) storePolicyPostActionResult(ctx *gin.Context, result *PassDBResult) {
	if ctx == nil || result == nil {
		return
	}

	if previous, release := takePolicyPostActionResult(ctx); release {
		PutPassDBResultToPool(previous)
	}

	ctx.Set(policyPostActionResultContextKey, result.Clone())
}

func takePolicyPostActionResult(ctx *gin.Context) (*PassDBResult, bool) {
	if ctx == nil {
		return nil, false
	}

	value, ok := ctx.Get(policyPostActionResultContextKey)
	if !ok {
		return nil, false
	}

	ctx.Set(policyPostActionResultContextKey, nil)
	result, ok := value.(*PassDBResult)

	return result, ok && result != nil
}

func releasePolicyPostActionResult(ctx *gin.Context) {
	if result, release := takePolicyPostActionResult(ctx); release {
		PutPassDBResultToPool(result)
	}
}

func preAuthResultFromPolicy(final *report.FinalDecision, current definitions.AuthResult) definitions.AuthResult {
	switch final.FSMEventMarker {
	case policy.FSMEventMarkerPreAuthDeny:
		return preAuthDenyResult(final, current)
	case policy.FSMEventMarkerPreAuthTempFail:
		if final.ResponseMarker == policy.ResponseMarkerTempFailNoTLS {
			return definitions.AuthResultFeatureTLS
		}

		return definitions.AuthResultTempFail
	case policy.FSMEventMarkerPreAuthAbort, policy.FSMEventMarkerPreAuthOK:
		return definitions.AuthResultOK
	default:
		return current
	}
}

func preAuthDenyResult(final *report.FinalDecision, current definitions.AuthResult) definitions.AuthResult {
	name := final.PolicyName
	switch {
	case strings.Contains(name, "_relay_domain_"):
		return definitions.AuthResultFeatureRelayDomain
	case strings.Contains(name, "_rbl_"):
		return definitions.AuthResultFeatureRBL
	case strings.Contains(name, "_lua_control_"):
		return definitions.AuthResultFeatureLua
	case strings.Contains(name, "_brute_force_"):
		return definitions.AuthResultFail
	default:
		return definitions.AuthResultFeatureLua
	}
}

func authResultFromPolicy(final *report.FinalDecision, current definitions.AuthResult) definitions.AuthResult {
	switch final.FSMEventMarker {
	case policy.FSMEventMarkerAuthPermit:
		return definitions.AuthResultOK
	case policy.FSMEventMarkerAuthDeny:
		return definitions.AuthResultFail
	case policy.FSMEventMarkerAuthTempFail:
		return definitions.AuthResultTempFail
	case policy.FSMEventMarkerAuthEmptyUser:
		return definitions.AuthResultEmptyUsername
	case policy.FSMEventMarkerAuthEmptyPass:
		return definitions.AuthResultEmptyPassword
	default:
		return current
	}
}

func tempFailReasonFromPolicy(final *report.FinalDecision) string {
	if final == nil {
		return definitions.TempFailDefault
	}

	switch {
	case final.ResponseMarker == policy.ResponseMarkerTempFailNoTLS:
		return definitions.TempFailNoTLS
	case final.FSMEventMarker == policy.FSMEventMarkerAuthEmptyUser:
		return definitions.TempFailEmptyUser
	case final.ResponseMessage != nil && final.ResponseMessage.Message != "":
		return final.ResponseMessage.Message
	default:
		return definitions.TempFailDefault
	}
}

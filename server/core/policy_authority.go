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

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	"github.com/croessner/nauthilus/server/policy/evaluation"
	"github.com/croessner/nauthilus/server/policy/report"

	"github.com/gin-gonic/gin"
)

const policyDirectOutcomeContextKey = "policy_direct_outcome"

func (a *AuthState) defaultPolicyPreAuthResult(ctx *gin.Context, current definitions.AuthResult) definitions.AuthResult {
	final, ok := a.defaultPolicyPreAuthDecision(ctx)
	if !ok || final == nil {
		return current
	}

	a.storeDirectPolicyDiagnostic(ctx, preAuthProductionOutcome(current, a.Runtime.StatusMessage))
	a.applyPolicyResponseMessage(final)

	return preAuthResultFromPolicy(final, current)
}

func (a *AuthState) defaultPolicyAuthResult(ctx *gin.Context, current definitions.AuthResult) definitions.AuthResult {
	final, ok := a.defaultPolicyAuthDecision(ctx)
	if !ok || final == nil {
		return current
	}

	a.storeDirectPolicyDiagnostic(ctx, authProductionOutcome(current, a.Runtime.StatusMessage))
	a.applyPolicyResponseMessage(final)

	return authResultFromPolicy(final, current)
}

func (a *AuthState) applyDefaultPreAuthDecision(ctx *gin.Context) bool {
	final, ok := a.defaultPolicyPreAuthDecision(ctx)
	if !ok || final == nil {
		return false
	}

	a.storeDirectPolicyDiagnostic(ctx, preAuthProductionOutcome(preAuthResultFromPolicy(final, definitions.AuthResultUnset), a.Runtime.StatusMessage))
	a.applyPolicyDecision(ctx, final)

	return true
}

// ApplyDefaultPreAuthDecision applies a built-in default pre-auth decision when it is authoritative.
func (a *AuthState) ApplyDefaultPreAuthDecision(ctx *gin.Context) bool {
	return a.applyDefaultPreAuthDecision(ctx)
}

func (a *AuthState) defaultPolicyPreAuthDecision(ctx *gin.Context) (*report.FinalDecision, bool) {
	policyCtx, ok := a.defaultPolicyContext(ctx)
	if !ok {
		return nil, false
	}

	return evaluation.EvaluateStandardPreAuth(policyCtx.Report()).Final, true
}

func (a *AuthState) defaultPolicyAuthDecision(ctx *gin.Context) (*report.FinalDecision, bool) {
	policyCtx, ok := a.defaultPolicyContext(ctx)
	if !ok {
		return nil, false
	}

	return evaluation.EvaluateStandardAuth(policyCtx.Report()).Final, true
}

func (a *AuthState) defaultPolicyContext(ctx *gin.Context) (*policycollection.DecisionContext, bool) {
	policyCtx := a.requestPolicyContext(ctx)
	if policyCtx == nil || !policyCtx.BuiltinDefaultAuthoritative() {
		return nil, false
	}

	return policyCtx, true
}

func (a *AuthState) applyPolicyDecision(ctx *gin.Context, final *report.FinalDecision) {
	if final == nil {
		return
	}

	if final.Stage == policy.StagePreAuth && final.Effect == policy.DecisionDeny {
		a.markFeatureRejected(ctx)
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
			result := GetPassDBResultFromPool()
			a.PostLuaAction(ctx, result)
			PutPassDBResultToPool(result)
		default:
		}
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
		return current
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

func (a *AuthState) storeDirectPolicyDiagnostic(ctx *gin.Context, outcome evaluation.ProductionOutcome) {
	if ctx == nil || outcome.Effect == "" {
		return
	}

	ctx.Set(policyDirectOutcomeContextKey, outcome)
}

func directPolicyDiagnostic(ctx *gin.Context) (evaluation.ProductionOutcome, bool) {
	if ctx == nil {
		return evaluation.ProductionOutcome{}, false
	}

	value, ok := ctx.Get(policyDirectOutcomeContextKey)
	if !ok {
		return evaluation.ProductionOutcome{}, false
	}

	outcome, ok := value.(evaluation.ProductionOutcome)

	return outcome, ok
}

func preAuthProductionOutcome(current definitions.AuthResult, responseMessage string) evaluation.ProductionOutcome {
	message := preAuthResponseMessage(current, responseMessage)

	switch current {
	case definitions.AuthResultFeatureTLS:
		return evaluation.ProductionOutcome{
			Effect:          policy.DecisionTempFail,
			ResponseMarker:  policy.ResponseMarkerTempFailNoTLS,
			FSMEventMarker:  policy.FSMEventMarkerPreAuthTempFail,
			ResponseMessage: message,
		}
	case definitions.AuthResultFeatureRelayDomain, definitions.AuthResultFeatureRBL, definitions.AuthResultFeatureLua, definitions.AuthResultFail:
		return evaluation.ProductionOutcome{
			Effect:          policy.DecisionDeny,
			ResponseMarker:  policy.ResponseMarkerFail,
			FSMEventMarker:  policy.FSMEventMarkerPreAuthDeny,
			ResponseMessage: message,
		}
	case definitions.AuthResultTempFail:
		return evaluation.ProductionOutcome{
			Effect:          policy.DecisionTempFail,
			ResponseMarker:  policy.ResponseMarkerTempFail,
			FSMEventMarker:  policy.FSMEventMarkerPreAuthTempFail,
			ResponseMessage: message,
		}
	default:
		return evaluation.ProductionOutcome{}
	}
}

func authProductionOutcome(current definitions.AuthResult, responseMessage string) evaluation.ProductionOutcome {
	message := authResponseMessage(current, responseMessage)

	switch current {
	case definitions.AuthResultOK:
		return evaluation.ProductionOutcome{
			Effect:          policy.DecisionPermit,
			ResponseMarker:  policy.ResponseMarkerOK,
			FSMEventMarker:  policy.FSMEventMarkerAuthPermit,
			ResponseMessage: message,
		}
	case definitions.AuthResultFail:
		return evaluation.ProductionOutcome{
			Effect:          policy.DecisionDeny,
			ResponseMarker:  policy.ResponseMarkerFail,
			FSMEventMarker:  policy.FSMEventMarkerAuthDeny,
			ResponseMessage: message,
		}
	case definitions.AuthResultTempFail:
		return evaluation.ProductionOutcome{
			Effect:          policy.DecisionTempFail,
			ResponseMarker:  policy.ResponseMarkerTempFail,
			FSMEventMarker:  policy.FSMEventMarkerAuthTempFail,
			ResponseMessage: message,
		}
	case definitions.AuthResultEmptyUsername:
		return evaluation.ProductionOutcome{
			Effect:          policy.DecisionTempFail,
			ResponseMarker:  policy.ResponseMarkerTempFail,
			FSMEventMarker:  policy.FSMEventMarkerAuthEmptyUser,
			ResponseMessage: message,
		}
	case definitions.AuthResultEmptyPassword:
		return evaluation.ProductionOutcome{
			Effect:          policy.DecisionDeny,
			ResponseMarker:  policy.ResponseMarkerFail,
			FSMEventMarker:  policy.FSMEventMarkerAuthEmptyPass,
			ResponseMessage: message,
		}
	default:
		return evaluation.ProductionOutcome{}
	}
}

func preAuthResponseMessage(current definitions.AuthResult, responseMessage string) string {
	if responseMessage != "" {
		return responseMessage
	}

	switch current {
	case definitions.AuthResultFeatureTLS:
		return definitions.TempFailNoTLS
	case definitions.AuthResultFeatureRelayDomain, definitions.AuthResultFeatureRBL, definitions.AuthResultFeatureLua, definitions.AuthResultFail:
		return definitions.PasswordFail
	case definitions.AuthResultTempFail:
		return definitions.TempFailDefault
	default:
		return ""
	}
}

func authResponseMessage(current definitions.AuthResult, responseMessage string) string {
	if responseMessage != "" {
		return responseMessage
	}

	switch current {
	case definitions.AuthResultOK:
		return "OK"
	case definitions.AuthResultFail, definitions.AuthResultEmptyPassword:
		return definitions.PasswordFail
	case definitions.AuthResultTempFail:
		return definitions.TempFailDefault
	case definitions.AuthResultEmptyUsername:
		return definitions.TempFailEmptyUser
	default:
		return ""
	}
}

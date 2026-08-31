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
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/report"

	"github.com/gin-gonic/gin"
)

const policyPostActionResultContextKey = "policy_post_action_result"

// policyReport returns the request-local diagnostic report populated by the catalog runtime.
func (a *AuthState) policyReport(ctx *gin.Context) *report.DecisionReport {
	if policyCtx := existingPolicyContext(ctx); policyCtx != nil {
		return policyCtx.Report()
	}

	return nil
}

// applyPolicyResponseMessage projects the selected catalog presentation onto the compatibility host.
func (a *AuthState) applyPolicyResponseMessage(final *report.FinalDecision) {
	if a == nil || final == nil || final.ResponseMessage == nil || final.ResponseMessage.Message == "" {
		return
	}

	a.Runtime.StatusMessage = final.ResponseMessage.Message
	a.Runtime.StatusMessageI18NKey = final.ResponseMessage.I18NKey

	if final.ResponseMessage.I18NKey != "" && final.ResponseLanguage != nil {
		a.Runtime.ResponseLanguage = final.ResponseLanguage.Language
	}
}

// storePolicyPostActionResult retains a detached backend result for generation-owned effects.
func (a *AuthState) storePolicyPostActionResult(ctx *gin.Context, result *PassDBResult) {
	if ctx == nil || result == nil {
		return
	}

	if previous, release := takePolicyPostActionResult(ctx); release {
		PutPassDBResultToPool(previous)
	}

	ctx.Set(policyPostActionResultContextKey, result.Clone())
}

// takePolicyPostActionResult removes the detached backend result from the request context.
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

// configuredPolicyAllowsIDPDelayedResponse classifies the selected password-failure presentation.
func configuredPolicyAllowsIDPDelayedResponse(final *report.FinalDecision) bool {
	return final != nil &&
		final.Stage == policy.StageAuthDecision &&
		final.Effect == policy.DecisionDeny &&
		final.OutcomeMarker == policy.OutcomeMarkerAuthFailure &&
		final.ResponseMarker == policy.ResponseMarkerFail
}

// tempFailReasonFromPolicy selects the compatibility reason for one catalog decision.
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

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

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/observability"
	"github.com/croessner/nauthilus/v4/server/policy/report"

	"github.com/gin-gonic/gin"
)

const (
	policyModeEnforce = "enforce"
)

type policyObligationHandlers struct {
	updateBruteForce func(*gin.Context, bruteForceUpdateObligation) bool
}

type policyObligationExecutor struct {
	auth     *AuthState
	handlers policyObligationHandlers
	recorder observability.Recorder
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
	}

	return executor
}

// executeOne invokes one selected synchronous owner and reports its exact result.
func (e policyObligationExecutor) executeOne(ctx *gin.Context, obligation report.EffectRequest) bool {
	started := time.Now()
	result := observability.ResultSuccess

	switch obligation.ID {
	case policy.EffectBruteForceUpdate:
		request, ok := bruteForceUpdateObligationFromEffect(obligation)
		if !ok {
			result = observability.ResultError

			break
		}

		if !e.handlers.updateBruteForce(ctx, request) {
			result = observability.ResultFailure
		}
	default:
		result = observability.ResultError
	}

	e.record(ctx, obligation.ID, time.Since(started), result)

	return result == observability.ResultSuccess
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

// policyEffectsEnabled applies the shared enforce-versus-observe effect gate.
func policyEffectsEnabled(mode string) bool {
	return mode == "" || mode == policyModeEnforce
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

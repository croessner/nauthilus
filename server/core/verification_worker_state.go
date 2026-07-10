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
	"maps"
	"slices"

	"github.com/croessner/nauthilus/v3/server/definitions"

	"github.com/gin-gonic/gin"
)

// verificationWorkResult keeps detached worker state with its backend result.
type verificationWorkResult struct {
	owner  *AuthState
	auth   *AuthState
	result *PassDBResult
}

// newVerificationWorkerState creates request and auth carriers owned only by the singleflight callback.
func (a *AuthState) newVerificationWorkerState(ctx *gin.Context) (*AuthState, *gin.Context) {
	workerCtx := ctx.Copy()
	workerCtx.Request = ctx.Request.Clone(ctx.Request.Context())
	worker := &AuthState{
		operationContext: ctx.Request.Context(),
		deps:             a.deps,
		Request:          cloneVerificationRequest(a.Request, workerCtx),
		Runtime:          cloneVerificationRuntime(a.Runtime),
		Security:         cloneVerificationSecurity(a.Security, uint(a.Cfg().GetServer().GetMaxLoginAttempts())),
		Attributes:       AuthAttributes{Attributes: a.GetAttributesCopy()},
	}
	worker.SetResolvedGroups(a.GetGroups(), a.GetGroupDistinguishedNames())

	return worker, workerCtx
}

// cloneVerificationRequest detaches mutable request metadata and HTTP carriers.
func cloneVerificationRequest(request AuthRequest, ctx *gin.Context) AuthRequest {
	request.HTTPClientContext = ctx
	request.HTTPClientRequest = ctx.Request

	if request.RequestMetadata != nil {
		request.RequestMetadata = make(map[string][]string, len(request.RequestMetadata))
		for key, values := range request.RequestMetadata {
			request.RequestMetadata[key] = slices.Clone(values)
		}
	}

	return request
}

// cloneVerificationRuntime detaches mutable request-runtime collections.
func cloneVerificationRuntime(runtime AuthRuntime) AuthRuntime {
	runtime.AdditionalLogs = slices.Clone(runtime.AdditionalLogs)
	runtime.MonitoringFlags = slices.Clone(runtime.MonitoringFlags)
	runtime.BruteForceBuckets = slices.Clone(runtime.BruteForceBuckets)
	runtime.AccountProviderPluginFacts = slices.Clone(runtime.AccountProviderPluginFacts)
	runtime.AuthFSMEventPath = slices.Clone(runtime.AuthFSMEventPath)
	runtime.AdditionalAttributes = maps.Clone(runtime.AdditionalAttributes)

	if runtime.Context != nil {
		runtime.Context = runtime.Context.Clone()
	}

	return runtime
}

// cloneVerificationSecurity detaches mutable security collections used by backends.
func cloneVerificationSecurity(security AuthSecurity, maxAttempts uint) AuthSecurity {
	security.BruteForceCounter = maps.Clone(security.BruteForceCounter)
	if security.attempts != nil {
		attempts := *security.attempts
		security.attempts = &attempts
	} else {
		security.attempts = newLoginAttemptManager(maxAttempts)
		security.attempts.failCount = security.LoginAttempts
	}

	if security.Logs != nil {
		logs := slices.Clone(*security.Logs)
		security.Logs = &logs
	}

	return security
}

// applyVerificationWorkerState publishes completed worker state on the request-owned AuthState.
func (a *AuthState) applyVerificationWorkerState(ctx *gin.Context, worker *AuthState, result *PassDBResult) {
	if a == nil || worker == nil {
		return
	}

	a.Runtime = cloneVerificationRuntime(worker.Runtime)
	a.Security = cloneVerificationSecurity(worker.Security, uint(a.Cfg().GetServer().GetMaxLoginAttempts()))
	a.ReplaceAllAttributes(worker.GetAttributesCopy())
	a.SetResolvedGroups(worker.GetGroups(), worker.GetGroupDistinguishedNames())

	if result != nil && len(result.AdditionalAttributes) > 0 {
		ctx.Set(definitions.CtxAdditionalAttributesKey, maps.Clone(result.AdditionalAttributes))
	}

	if account := worker.GetAccount(); account != "" {
		ctx.Set(definitions.CtxAccountKey, account)
	}
}

// Copyright (C) 2024-2025 Christian Rößner
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
	stderrors "errors"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/gin-gonic/gin"
)

// PasswordVerifier abstracts the PassDB verification pipeline.
type PasswordVerifier interface {
	Verify(ctx *gin.Context, a *AuthState, passDBs []*PassDBMap) (*PassDBResult, error)
}

type passwordPipelineState struct {
	configErrors map[definitions.Backend]error
	tempfailErr  error
	finalRes     *PassDBResult
}

// newPasswordPipelineState creates the mutable state for one password pipeline run.
func newPasswordPipelineState() passwordPipelineState {
	return passwordPipelineState{
		configErrors: make(map[definitions.Backend]error),
	}
}

// VerifyPasswordPipeline coordinates authentication processes across multiple password databases and backends.
// It iterates through the provided PassDBMap, invoking their associated functions to authenticate a user or locate credentials.
// Handles backend-specific configuration errors and logs failures while trying successive backends, as necessary.
// Returns a successful PassDBResult upon user authentication or relevant errors if all attempts fail.
func VerifyPasswordPipeline(ctx *gin.Context, auth *AuthState, passDBs []*PassDBMap) (*PassDBResult, error) {
	if len(passDBs) == 0 {
		return nil, errors.ErrAllBackendConfigError
	}

	if util.IsHTTPRequestCanceled(auth.Logger(), ctx.Request, auth.Runtime.GUID, "verify.start") {
		return nil, util.HTTPRequestContextError(ctx.Request)
	}

	state := newPasswordPipelineState()

	for i, passDB := range passDBs {
		if res, done, err := state.tryPasswordBackend(ctx, auth, passDBs, passDB, i); err != nil {
			return nil, err
		} else if done {
			if res == nil {
				break
			}

			return res, nil
		}
	}

	return state.finalPasswordResult()
}

// tryPasswordBackend executes one PassDB backend and updates pipeline state.
func (state *passwordPipelineState) tryPasswordBackend(ctx *gin.Context, auth *AuthState, passDBs []*PassDBMap, passDB *PassDBMap, index int) (*PassDBResult, bool, error) {
	if util.IsHTTPRequestCanceled(auth.Logger(), ctx.Request, auth.Runtime.GUID, "verify.next_backend") {
		return nil, true, util.HTTPRequestContextError(ctx.Request)
	}

	res, err := passDB.fn(auth)
	if err != nil {
		return nil, false, state.handlePasswordBackendError(index, passDBs, passDB, err, auth)
	}

	if res == nil {
		return nil, true, errors.ErrNoPassDBResult
	}

	if util.IsHTTPRequestCanceled(auth.Logger(), ctx.Request, auth.Runtime.GUID, "verify.process_result") {
		PutPassDBResultToPool(res)

		return nil, true, util.HTTPRequestContextError(ctx.Request)
	}

	if !processPasswordBackendResult(ctx, auth, passDB, res) {
		return nil, false, nil
	}

	state.storePasswordResult(ctx, auth, passDB, res)

	if res.Authenticated {
		return res, true, nil
	}

	return nil, res.UserFound, nil
}

// handlePasswordBackendError records temporary backend failures and delegates configured error handling.
func (state *passwordPipelineState) handlePasswordBackendError(index int, passDBs []*PassDBMap, passDB *PassDBMap, err error, auth *AuthState) error {
	if stderrors.Is(err, errors.ErrLDAPPoolExhausted) || stderrors.Is(err, errors.ErrBackendTemporaryFailure) {
		state.tempfailErr = err
	}

	e := HandleBackendErrors(index, passDBs, passDB, err, auth, state.configErrors)
	if stderrors.Is(e, errors.ErrAllBackendConfigError) {
		return e
	}

	return nil
}

// processPasswordBackendResult applies result post-processing and releases failed results.
func processPasswordBackendResult(ctx *gin.Context, auth *AuthState, passDB *PassDBMap, res *PassDBResult) bool {
	if e := ProcessPassDBResult(ctx, res, auth, passDB); e != nil {
		level.Error(auth.Logger()).Log(
			definitions.LogKeyGUID, auth.Runtime.GUID,
			definitions.LogKeyMsg, "Error processing passdb result",
			definitions.LogKeyError, e,
		)

		PutPassDBResultToPool(res)

		return false
	}

	return true
}

// storePasswordResult keeps the latest usable result and preserves no-auth semantics.
func (state *passwordPipelineState) storePasswordResult(ctx *gin.Context, auth *AuthState, passDB *PassDBMap, res *PassDBResult) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		auth.deps.Cfg,
		auth.deps.Logger,
		definitions.DbgAuth,
		definitions.LogKeyGUID, auth.Runtime.GUID,
		"passdb", passDB.backend.String(),
		"result", res.String(),
	)

	if state.finalRes != nil {
		PutPassDBResultToPool(state.finalRes)
	}

	state.finalRes = res

	if auth.Request.NoAuth && res.UserFound && !res.Authenticated {
		res.Authenticated = true
	}
}

// finalPasswordResult returns the completed pipeline result or the preserved temporary failure.
func (state *passwordPipelineState) finalPasswordResult() (*PassDBResult, error) {
	if state.finalRes == nil {
		if state.tempfailErr != nil {
			return nil, state.tempfailErr
		}

		return nil, errors.ErrNoPassDBResult
	}

	if !state.finalRes.Authenticated && !state.finalRes.UserFound && state.tempfailErr != nil {
		return nil, state.tempfailErr
	}

	return state.finalRes, nil
}

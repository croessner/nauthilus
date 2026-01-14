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
	"fmt"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
)

// PasswordVerifier abstracts the PassDB verification pipeline.
type PasswordVerifier interface {
	Verify(ctx *gin.Context, a *AuthState, passDBs []*PassDBMap) (*PassDBResult, error)
}

// VerifyPasswordPipeline coordinates authentication processes across multiple password databases and backends.
// It iterates through the provided PassDBMap, invoking their associated functions to authenticate a user or locate credentials.
// Handles backend-specific configuration errors and logs failures while trying successive backends, as necessary.
// Returns a successful PassDBResult upon user authentication or relevant errors if all attempts fail.
func VerifyPasswordPipeline(ctx *gin.Context, auth *AuthState, passDBs []*PassDBMap) (*PassDBResult, error) {
	if len(passDBs) == 0 {
		return nil, errors.ErrAllBackendConfigError
	}

	configErrors := make(map[definitions.Backend]error)
	// Track temporary failures (e.g., pool exhaustion) to avoid mapping
	// technical issues to "user not found" later in the pipeline.
	var tempfailErr error

	var finalRes *PassDBResult

	for i, passDB := range passDBs {
		res, err := passDB.fn(auth)
		if err != nil {
			// Prefer treating pool exhaustion as a tempfail over negative results
			// from other backends (e.g., cache). We remember it and may return it
			// at the end if no definitive success/user-found result exists.
			if stderrors.Is(err, errors.ErrLDAPPoolExhausted) {
				tempfailErr = err
			}

			if e := HandleBackendErrors(i, passDBs, passDB, err, auth, configErrors); e != nil {
				if stderrors.Is(e, errors.ErrAllBackendConfigError) {
					return nil, e
				}
			}

			continue
		}

		if res == nil {
			return nil, errors.ErrNoPassDBResult
		}

		if e := ProcessPassDBResult(ctx, res, auth, passDB); e != nil {
			level.Error(auth.Logger()).Log(
				definitions.LogKeyGUID, auth.GUID,
				definitions.LogKeyMsg, "Error processing passdb result",
				definitions.LogKeyError, e,
			)

			continue
		}

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			auth.deps.Cfg,
			auth.deps.Logger,
			definitions.DbgAuth,
			definitions.LogKeyGUID, auth.GUID,
			"passdb", passDB.backend.String(),
			"result", fmt.Sprintf("%v", res),
		)

		finalRes = res

		// Restore legacy no-auth semantics: if a backend finds the user in no-auth
		// mode, treat it as authenticated. This keeps followers/SingleFlight safe
		// because we only mutate the local PassDBResult, not AuthState.
		if auth.NoAuth && res.UserFound && !res.Authenticated {
			res.Authenticated = true
		}

		// Consolidated exit condition: use PassDBResult.Authenticated as the
		// single stop criterion. In no-auth, the mapping above ensures the
		// correct behavior without sprinkling special cases here.
		if res.Authenticated {
			return res, nil
		}

		// No matter what, if the user was found, we're done.
		if res.UserFound {
			break
		}
	}

	if finalRes == nil {
		if tempfailErr != nil {
			return nil, tempfailErr
		}

		return nil, errors.ErrNoPassDBResult
	}

	// If no backend authenticated or found the user, but we encountered a
	// pool exhaustion earlier, surface it as a temporary failure instead of
	// silently degrading to "not found".
	if !finalRes.Authenticated && !finalRes.UserFound && tempfailErr != nil {
		return nil, tempfailErr
	}

	return finalRes, nil
}

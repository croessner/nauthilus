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
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
)

// PasswordVerifier abstracts the PassDB verification pipeline.
type PasswordVerifier interface {
	Verify(ctx *gin.Context, a *AuthState, passDBs []*PassDBMap) (*PassDBResult, error)
}

// VerifyPasswordPipeline is the exported, package-internal implementation of the
// legacy password verification loop. It is used by the default implementation
// provided from subpackage core/auth to avoid accessing unexported fields.
func VerifyPasswordPipeline(ctx *gin.Context, auth *AuthState, passDBs []*PassDBMap) (*PassDBResult, error) {
	if len(passDBs) == 0 {
		return nil, errors.ErrAllBackendConfigError
	}

	configErrors := make(map[definitions.Backend]error)

	var finalRes *PassDBResult

	for i, passDB := range passDBs {
		res, err := passDB.fn(auth)
		if err != nil {
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
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, auth.GUID,
				definitions.LogKeyMsg, "Error processing passdb result",
				definitions.LogKeyError, e,
			)

			continue
		}

		util.DebugModule(
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
	}

	if finalRes == nil {
		return nil, errors.ErrNoPassDBResult
	}

	return finalRes, nil
}

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
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

// PasswordVerifier abstracts the PassDB verification pipeline.
//
// Note: In this phase we keep the parameters tightly coupled to the existing
// AuthState to avoid behavioral changes. Later phases can introduce decoupled
// domain models and context.
//
// Verify runs the full PassDB verification across configured backends and
// returns the aggregated PassDBResult and a terminal error (when no backend
// decision could be made or configuration errors occurred).
// Behavior is intentionally identical to the previous inline implementation.
//
// The passDBs slice is the ordered list of backends produced by handleBackendTypes.
//
// No external behavior changes intended.
//
// (kept simple for now; will evolve with the orchestrator)
//
//goland:nointerface
type PasswordVerifier interface {
	Verify(ctx *gin.Context, a *AuthState, passDBs []*PassDBMap) (*PassDBResult, error)
}

// DefaultPasswordVerifier is the current implementation that mirrors the
// previous logic from AuthState.verifyPassword.
// It lives in the same package to reuse existing helper functions without
// changing signatures or visibility.
type DefaultPasswordVerifier struct{}

var defaultPasswordVerifier PasswordVerifier = DefaultPasswordVerifier{}

func (DefaultPasswordVerifier) Verify(ctx *gin.Context, a *AuthState, passDBs []*PassDBMap) (*PassDBResult, error) {
	var (
		passDBResult *PassDBResult
		err          error
	)

	configErrors := make(map[definitions.Backend]error, len(passDBs))
	for passDBIndex, passDB := range passDBs {
		passDBResult, err = passDB.fn(a)
		logDebugModule(a, passDB, passDBResult)

		if err != nil {
			err = handleBackendErrors(passDBIndex, passDBs, passDB, err, a, configErrors)
			if err != nil {
				break
			}
		} else {
			err = processPassDBResult(ctx, passDBResult, a, passDB)
			// Break only on the local backend decision, not on global state carried over from previous passes
			if err != nil || (passDBResult != nil && passDBResult.UserFound) {
				break
			}
		}
	}

	// Enforce authentication
	if a.NoAuth && passDBResult != nil && passDBResult.UserFound {
		passDBResult.Authenticated = true
	}

	return passDBResult, err
}

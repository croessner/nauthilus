// Copyright (C) 2024 Christian Rößner
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

package jwtutil

import (
	"fmt"
	"log/slog"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/jwtclaims"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
)

// HasRoleWithDeps checks if the user has the specified role in their JWT token using provided dependencies.
func HasRoleWithDeps(ctx *gin.Context, cfg config.File, logger *slog.Logger, role string) bool {
	// Get JWT claims from context
	claimsValue, exists := ctx.Get(definitions.CtxJWTClaimsKey)
	if !exists {
		util.DebugModuleWithCfg(
			cfg,
			logger,
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "JWT claims not found in context",
		)

		return false
	}

	// Accept only real ClaimsWithRoles implementations
	if cl, ok := claimsValue.(jwtclaims.ClaimsWithRoles); ok {
		found := cl.HasRole(role)
		msg := fmt.Sprintf("%s role %s in JWT claims", tern(found, "Found", "Missing"), role)

		util.DebugModuleWithCfg(
			cfg,
			logger,
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, msg,
		)

		return found
	}

	// If we get here, the claims are in an unexpected format
	util.DebugModuleWithCfg(
		cfg,
		logger,
		definitions.DbgJWT,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, fmt.Sprintf("JWT claims in unexpected format: %T", claimsValue),
	)

	return false
}

// HasRole checks if the user has the specified role in their JWT token.
func HasRole(ctx *gin.Context, role string) bool {
	return HasRoleWithDeps(ctx, nil, nil, role)
}

// tiny generic ternary helper (local)
func tern[T any](cond bool, a, b T) T {
	if cond {
		return a
	}

	return b
}

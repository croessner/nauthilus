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

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/jwtclaims"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
)

// HasRole checks if the user has the specified role in their JWT token.
// It retrieves the JWT claims from the context and checks if the user has the required role.
// If JWT authentication is not enabled or no claims are found, it returns false.
func HasRole(ctx *gin.Context, role string) bool {
	// Get JWT claims from context
	claimsValue, exists := ctx.Get(definitions.CtxJWTClaimsKey)
	if !exists {
		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "JWT claims not found in context",
		)

		return false
	}

	// First, try to handle the case where claims implements the ClaimsWithRoles interface
	if claims, ok := claimsValue.(jwtclaims.ClaimsWithRoles); ok {
		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "JWT claims matched ClaimsWithRoles interface",
		)

		if claims.HasRole(role) {
			util.DebugModule(
				definitions.DbgJWT,
				definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
				definitions.LogKeyMsg, fmt.Sprintf("Found role %s in JWT claims", role),
			)

			return true
		}

		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, fmt.Sprintf("Role %s not found in JWT claims", role),
		)

		return false
	}

	// Try to handle the case where claims is a *jwtclaims.JWTClaims
	if claims, ok := claimsValue.(*jwtclaims.JWTClaims); ok {
		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, fmt.Sprintf("JWT claims matched *jwtclaims.JWTClaims, roles: %v", claims.Roles),
		)

		if claims.HasRole(role) {
			util.DebugModule(
				definitions.DbgJWT,
				definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
				definitions.LogKeyMsg, fmt.Sprintf("Found role %s in JWT claims", role),
			)

			return true
		}

		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, fmt.Sprintf("Role %s not found in JWT claims", role),
		)

		return false
	}

	// Try with a local struct that matches the structure of JWTClaims
	type localClaimsWithRoles struct {
		Username string
		Roles    []string
	}

	// Check for struct pointer with Roles field
	if claims, ok := claimsValue.(*localClaimsWithRoles); ok {
		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, fmt.Sprintf("JWT claims matched *localClaimsWithRoles struct, roles: %v", claims.Roles),
		)

		for _, r := range claims.Roles {
			if r == role {
				util.DebugModule(
					definitions.DbgJWT,
					definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
					definitions.LogKeyMsg, fmt.Sprintf("Found role %s in JWT claims", role),
				)

				return true
			}
		}

		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, fmt.Sprintf("Role %s not found in JWT claims", role),
		)

		return false
	}

	// Try with the specific struct used in tests
	if claims, ok := claimsValue.(*struct {
		Username string   `json:"username"`
		Roles    []string `json:"roles,omitempty"`
	}); ok {
		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, fmt.Sprintf("JWT claims matched anonymous struct, roles: %v", claims.Roles),
		)

		for _, r := range claims.Roles {
			if r == role {
				util.DebugModule(
					definitions.DbgJWT,
					definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
					definitions.LogKeyMsg, fmt.Sprintf("Found role %s in JWT claims", role),
				)

				return true
			}
		}

		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, fmt.Sprintf("Role %s not found in JWT claims", role),
		)

		return false
	}

	// Handle map[string]any claims, which are the most common case
	if claims, ok := claimsValue.(map[string]any); ok {
		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, fmt.Sprintf("JWT claims matched map[string]interface{}, keys: %v", getMapKeys(claims)),
		)

		if rolesValue, exists := claims["roles"]; exists {
			// Try as []string first
			if roles, ok := rolesValue.([]string); ok {
				util.DebugModule(
					definitions.DbgJWT,
					definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
					definitions.LogKeyMsg, fmt.Sprintf("JWT roles as []string: %v", roles),
				)

				for _, r := range roles {
					if r == role {
						util.DebugModule(
							definitions.DbgJWT,
							definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
							definitions.LogKeyMsg, fmt.Sprintf("Found role %s in JWT claims", role),
						)

						return true
					}
				}
			}

			// Then try as []any
			if roles, ok := rolesValue.([]any); ok {
				util.DebugModule(
					definitions.DbgJWT,
					definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
					definitions.LogKeyMsg, fmt.Sprintf("JWT roles as []interface{}: %v", roles),
				)

				for _, r := range roles {
					if roleStr, ok := r.(string); ok && roleStr == role {
						util.DebugModule(
							definitions.DbgJWT,
							definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
							definitions.LogKeyMsg, fmt.Sprintf("Found role %s in JWT claims", role),
						)

						return true
					}
				}
			}
		}

		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, fmt.Sprintf("Role %s not found in JWT claims", role),
		)

		return false
	}

	// If we get here, the claims are in an unexpected format
	util.DebugModule(
		definitions.DbgJWT,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, fmt.Sprintf("JWT claims in unexpected format: %v", claimsValue),
	)

	return false
}

// getMapKeys returns the keys of a map as a slice of strings
// This is a helper function to avoid using reflection for getting map keys
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))

	for k := range m {
		keys = append(keys, k)
	}

	return keys
}

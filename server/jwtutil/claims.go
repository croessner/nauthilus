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
	"reflect"

	"github.com/croessner/nauthilus/server/definitions"
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

	// Log the type of claims for debugging
	util.DebugModule(
		definitions.DbgJWT,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, fmt.Sprintf("JWT claims type: %s", reflect.TypeOf(claimsValue)),
	)

	// Try to handle the case where claims is a pointer to a struct with Username and Roles fields
	// This is a more generic approach that should work with *core.JWTClaims
	if claimsStruct := reflect.ValueOf(claimsValue); claimsStruct.Kind() == reflect.Ptr && claimsStruct.Elem().Kind() == reflect.Struct {
		structValue := claimsStruct.Elem()
		rolesField := structValue.FieldByName("Roles")

		if rolesField.IsValid() && rolesField.Kind() == reflect.Slice {
			util.DebugModule(
				definitions.DbgJWT,
				definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
				definitions.LogKeyMsg, fmt.Sprintf("JWT claims matched struct with Roles field, roles: %v", rolesField.Interface()),
			)

			// Iterate through the roles slice
			for i := 0; i < rolesField.Len(); i++ {
				roleValue := rolesField.Index(i)
				if roleValue.Kind() == reflect.String && roleValue.String() == role {
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
	}

	// Try to handle the case where claims is a *JWTClaims struct from core package
	if claims, ok := claimsValue.(*struct {
		Username string   `json:"username"`
		Roles    []string `json:"roles,omitempty"`
	}); ok {
		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, fmt.Sprintf("JWT claims matched *JWTClaims struct, roles: %v", claims.Roles),
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

	// Try direct type assertion for the most common case
	if claims, ok := claimsValue.(map[string]interface{}); ok {
		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, fmt.Sprintf("JWT claims matched map[string]interface{}, keys: %v", reflect.ValueOf(claims).MapKeys()),
		)

		if rolesValue, exists := claims["roles"]; exists {
			if roles, ok := rolesValue.([]interface{}); ok {
				util.DebugModule(
					definitions.DbgJWT,
					definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
					definitions.LogKeyMsg, fmt.Sprintf("JWT roles: %v", roles),
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

	// Try to handle the case where roles might be a []string
	if claims, ok := claimsValue.(map[string]any); ok {
		util.DebugModule(
			definitions.DbgJWT,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, fmt.Sprintf("JWT claims matched map[string]any, keys: %v", reflect.ValueOf(claims).MapKeys()),
		)

		if rolesValue, exists := claims["roles"]; exists {
			if roles, ok := rolesValue.([]string); ok {
				util.DebugModule(
					definitions.DbgJWT,
					definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
					definitions.LogKeyMsg, fmt.Sprintf("JWT roles: %v", roles),
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

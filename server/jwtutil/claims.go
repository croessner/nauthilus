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
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

// HasRole checks if the user has the specified role in their JWT token.
// It retrieves the JWT claims from the context and checks if the user has the required role.
// If JWT authentication is not enabled or no claims are found, it returns false.
func HasRole(ctx *gin.Context, role string) bool {
	// Get JWT claims from context
	claimsValue, exists := ctx.Get(definitions.CtxJWTClaimsKey)
	if !exists {
		return false
	}

	// Try direct type assertion for the most common case
	if claims, ok := claimsValue.(map[string]interface{}); ok {
		if rolesValue, exists := claims["roles"]; exists {
			if roles, ok := rolesValue.([]interface{}); ok {
				for _, r := range roles {
					if roleStr, ok := r.(string); ok && roleStr == role {
						return true
					}
				}
			}
		}

		return false
	}

	// Try to handle the case where roles might be a []string
	if claims, ok := claimsValue.(map[string]any); ok {
		if rolesValue, exists := claims["roles"]; exists {
			if roles, ok := rolesValue.([]string); ok {
				for _, r := range roles {
					if r == role {
						return true
					}
				}
			}
		}

		return false
	}

	// If we get here, the claims are in an unexpected format
	return false
}

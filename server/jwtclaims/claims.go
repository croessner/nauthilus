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

package jwtclaims

import (
	"github.com/golang-jwt/jwt/v5"
)

// ClaimsWithRoles is an interface for any type that can check if it has a specific role
type ClaimsWithRoles interface {
	HasRole(role string) bool
}

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// HasRole checks if the JWTClaims contains the specified role
func (c *JWTClaims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}

	return false
}

var _ ClaimsWithRoles = (*JWTClaims)(nil)

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

// Claims represents the claims in a JWT token
type Claims struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles,omitempty"`

	jwt.RegisteredClaims

	// internal cache to speed up repeated role checks; excluded from JSON
	roleSet RoleSet
}

// HasRole checks if the Claims contains the specified role (with a lazy RoleSet cache)
func (c *Claims) HasRole(role string) bool {
	if c == nil {
		return false
	}

	// Lazily build or refresh the set if sizes differ (simple, fast heuristic)
	if c.roleSet == nil || len(c.roleSet) != len(c.Roles) {
		c.roleSet = NewRoleSet(c.Roles)
	}

	return c.roleSet.HasRole(role)
}

var _ ClaimsWithRoles = (*Claims)(nil)

// RoleSet represents a set of roles with O(1) membership checks
type RoleSet map[string]struct{}

// NewRoleSet builds a RoleSet from a slice of roles, skipping empty strings
func NewRoleSet(roles []string) RoleSet {
	set := make(RoleSet, len(roles))

	for _, r := range roles {
		if r == "" {
			continue
		}

		set[r] = struct{}{}
	}

	return set
}

// HasRole checks whether the role exists in the set
func (rs RoleSet) HasRole(role string) bool {
	if role == "" {
		return false
	}

	_, ok := rs[role]

	return ok
}

// Ensure RoleSet also satisfies ClaimsWithRoles
var _ ClaimsWithRoles = (RoleSet)(nil)

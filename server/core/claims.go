// Copyright (C) 2025 Christian Rößner
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
	"github.com/croessner/nauthilus/server/config"
)

// FillIdTokenClaims populates a map of claims from IdTokenClaims configuration.
func (a *AuthState) FillIdTokenClaims(cfgClaims *config.IdTokenClaims, claims map[string]any, requestedScopes []string) {
	if a == nil || cfgClaims == nil {
		return
	}

	manager := NewClaimManager(a, requestedScopes)
	mappings := cfgClaims.GetMappings()

	if len(mappings) == 0 {
		return
	}

	manager.ApplyMappings(mappings, claims)
}

// FillAccessTokenClaims populates a map of claims from AccessTokenClaims configuration.
func (a *AuthState) FillAccessTokenClaims(cfgClaims *config.AccessTokenClaims, claims map[string]any, requestedScopes []string) {
	if a == nil || cfgClaims == nil {
		return
	}

	manager := NewClaimManager(a, requestedScopes)
	mappings := cfgClaims.GetMappings()

	if len(mappings) == 0 {
		return
	}

	manager.ApplyMappings(mappings, claims)
}

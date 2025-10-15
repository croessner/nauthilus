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

//go:build !hydra
// +build !hydra

package core

import "github.com/croessner/nauthilus/server/config"

// processClaim is a no-op in non-hydra builds.
func (a *AuthState) processClaim(claimName string, claimValue string, claims map[string]any) {}

// processClientClaims is a passthrough in non-hydra builds.
func (a *AuthState) processClientClaims(client *config.Oauth2Client, claims map[string]any) map[string]any {
	return claims
}

// applyClientClaimHandlers is a passthrough in non-hydra builds.
func (a *AuthState) applyClientClaimHandlers(client *config.Oauth2Client, claims map[string]any) map[string]any {
	return claims
}

// processGroupsClaim is a no-op in non-hydra builds.
func (a *AuthState) processGroupsClaim(index int, claims map[string]any) {}

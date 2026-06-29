// Copyright (C) 2026 Christian Rößner
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

package idp

import (
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/golang-jwt/jwt/v5"
)

// copyCustomAccessTokenClaims copies only non-reserved custom claims into access-token claims.
func copyCustomAccessTokenClaims(dst jwt.MapClaims, src map[string]any) {
	for claimName, value := range src {
		if definitions.IsReservedAccessTokenClaim(claimName) {
			continue
		}

		dst[claimName] = value
	}
}

// copyCustomIDTokenClaims copies only non-reserved custom claims into ID-token claims.
func copyCustomIDTokenClaims(dst jwt.MapClaims, src map[string]any) {
	for claimName, value := range src {
		if definitions.IsReservedIDTokenClaim(claimName) {
			continue
		}

		dst[claimName] = value
	}
}

// accessTokenAudience returns the resource audience for an access-token session.
func accessTokenAudience(session *OIDCSession) string {
	if session == nil {
		return ""
	}

	if session.AccessTokenAudience != "" {
		return session.AccessTokenAudience
	}

	return session.ClientID
}

// clientCredentialsAccessTokenAudience binds client-credentials tokens to the Nauthilus resource.
func clientCredentialsAccessTokenAudience(_ []string) string {
	return definitions.AudienceBackchannelAPI
}

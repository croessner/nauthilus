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
	"github.com/croessner/nauthilus/v4/server/definitions"
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

// copyClientIdentityClaims adds the issuer-owned client identity: service tokens carry client_id and
// their issuer, user tokens name the client they were issued to in azp.
func copyClientIdentityClaims(dst jwt.MapClaims, session *OIDCSession) {
	if session == nil {
		return
	}

	if !session.ServiceToken {
		dst[definitions.ClaimAuthorizedParty] = session.ClientID

		return
	}

	dst[definitions.ClaimClientID] = session.ClientID
	dst[oidcClaimIssuer] = session.AccessTokenIssuer
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

// accessTokenAudience returns the resource audience for an access-token session. Service tokens keep
// their dedicated resource. A user token is bound to its client and, when resources were granted, to
// those resources as well; without resources the audience stays the plain client id.
func accessTokenAudience(session *OIDCSession) any {
	if session == nil {
		return ""
	}

	if session.AccessTokenAudience != "" {
		return session.AccessTokenAudience
	}

	if len(session.AccessTokenResources) == 0 {
		return session.ClientID
	}

	return uniqueResources(append([]string{session.ClientID}, session.AccessTokenResources...))
}

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

package definitions

import "strings"

const (
	// ClaimTokenType identifies the issuer-owned access-token purpose claim.
	ClaimTokenType = "token_type"

	// TokenTypeAccessToken marks bearer tokens that may authorize protected APIs.
	TokenTypeAccessToken = "access_token"

	// TokenTypeIDToken marks identity assertions that must not authorize protected APIs.
	TokenTypeIDToken = "id_token"

	// AudienceBackchannelAPI is the protected resource audience for Nauthilus backchannel APIs.
	AudienceBackchannelAPI = "nauthilus:backchannel"
)

const (
	reservedClaimAudience  = "aud"
	reservedClaimExpiresAt = "exp"
	reservedClaimIssuedAt  = "iat"
	reservedClaimIssuer    = "iss"
	reservedClaimSubject   = "sub"
)

var reservedAccessTokenClaims = map[string]struct{}{
	"active":               {},
	reservedClaimAudience:  {},
	"client_id":            {},
	reservedClaimExpiresAt: {},
	reservedClaimIssuedAt:  {},
	reservedClaimIssuer:    {},
	"jti":                  {},
	"nbf":                  {},
	"scope":                {},
	reservedClaimSubject:   {},
	ClaimTokenType:         {},
}

var reservedIDTokenClaims = map[string]struct{}{
	"acr":                  {},
	"amr":                  {},
	"at_hash":              {},
	reservedClaimAudience:  {},
	"auth_time":            {},
	"azp":                  {},
	"c_hash":               {},
	reservedClaimExpiresAt: {},
	reservedClaimIssuedAt:  {},
	reservedClaimIssuer:    {},
	"nonce":                {},
	reservedClaimSubject:   {},
	ClaimTokenType:         {},
}

// IsReservedAccessTokenClaim reports whether a claim is owned by the token issuer.
func IsReservedAccessTokenClaim(claimName string) bool {
	return isReservedOIDCClaim(claimName, reservedAccessTokenClaims)
}

// IsReservedIDTokenClaim reports whether a claim is owned by the ID-token issuer.
func IsReservedIDTokenClaim(claimName string) bool {
	return isReservedOIDCClaim(claimName, reservedIDTokenClaims)
}

// isReservedOIDCClaim checks a normalized claim name against one reserved registry.
func isReservedOIDCClaim(claimName string, reserved map[string]struct{}) bool {
	_, ok := reserved[strings.TrimSpace(claimName)]

	return ok
}

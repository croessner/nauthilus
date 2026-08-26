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

package callerauth

import (
	"context"
	"strings"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/golang-jwt/jwt/v5"
)

const (
	claimAudience = "aud"
	claimClientID = definitions.ClaimClientID
	claimIssuer   = "iss"
	claimScope    = "scope"
	claimSubject  = "sub"
)

// ClaimsTokenValidator validates an opaque token and returns issuer-owned claims.
type ClaimsTokenValidator interface {
	ValidateToken(context.Context, string) (jwt.MapClaims, error)
}

// claimsAccessTokenValidator normalizes exact claims from one captured OAuth validator and issuer.
type claimsAccessTokenValidator struct {
	underlying     ClaimsTokenValidator
	expectedIssuer string
}

// NewClaimsAccessTokenValidator adapts the current OAuth validator to Policy access-token evidence.
func NewClaimsAccessTokenValidator(underlying ClaimsTokenValidator, expectedIssuer string) (AccessTokenValidator, error) {
	if underlying == nil || typedNilInterface(underlying) || !validCallerIdentity(expectedIssuer) {
		return nil, ErrConfiguration
	}

	return &claimsAccessTokenValidator{
		underlying:     underlying,
		expectedIssuer: expectedIssuer,
	}, nil
}

// ValidateAccessToken validates opaque material and extracts only exact issuer-owned claims.
func (v *claimsAccessTokenValidator) ValidateAccessToken(ctx context.Context, credential []byte) (ValidatedAccessToken, error) {
	if v == nil || v.underlying == nil || ctx == nil || len(credential) == 0 {
		return ValidatedAccessToken{}, ErrAuthentication
	}

	claims, err := v.underlying.ValidateToken(ctx, string(credential))
	if err != nil {
		return ValidatedAccessToken{}, ErrAuthentication
	}

	token, ok := v.parseClaims(claims)
	if !ok {
		return ValidatedAccessToken{}, ErrAuthentication
	}

	return token, nil
}

// parseClaims copies the accepted claim shapes into detached trusted evidence.
func (v *claimsAccessTokenValidator) parseClaims(claims jwt.MapClaims) (ValidatedAccessToken, bool) {
	clientID, ok := requiredStringClaim(claims, claimClientID)
	if !ok {
		return ValidatedAccessToken{}, false
	}

	issuer, ok := requiredStringClaim(claims, claimIssuer)
	if !ok || issuer != v.expectedIssuer {
		return ValidatedAccessToken{}, false
	}

	tokenType, ok := requiredStringClaim(claims, definitions.ClaimTokenType)
	if !ok || tokenType != definitions.TokenTypeAccessToken {
		return ValidatedAccessToken{}, false
	}

	audiences, ok := parseAudienceClaim(claims[claimAudience])
	if !ok {
		return ValidatedAccessToken{}, false
	}

	scopes, ok := parseScopeClaim(claims[claimScope])
	if !ok {
		return ValidatedAccessToken{}, false
	}

	subject, ok := optionalStringClaim(claims, claimSubject)
	if !ok {
		return ValidatedAccessToken{}, false
	}

	return ValidatedAccessToken{
		Audiences: audiences,
		Scopes:    scopes,
		ClientID:  clientID,
		Subject:   subject,
		Issuer:    issuer,
		TokenType: tokenType,
	}, true
}

// requiredStringClaim returns one exact non-empty string without fallback or normalization.
func requiredStringClaim(claims jwt.MapClaims, name string) (string, bool) {
	value, found := claims[name]
	if !found {
		return "", false
	}

	result, ok := value.(string)
	if !ok || result == "" {
		return "", false
	}

	return result, true
}

// optionalStringClaim accepts an absent claim or one exact string value.
func optionalStringClaim(claims jwt.MapClaims, name string) (string, bool) {
	value, found := claims[name]
	if !found {
		return "", true
	}

	result, ok := value.(string)

	return result, ok
}

// parseAudienceClaim copies supported JWT audience representations without normalizing the set.
func parseAudienceClaim(value any) ([]string, bool) {
	switch audiences := value.(type) {
	case string:
		if audiences == "" {
			return nil, false
		}

		return []string{audiences}, true
	case []string:
		return copyAudienceStrings(audiences)
	case jwt.ClaimStrings:
		return copyAudienceStrings([]string(audiences))
	case []any:
		result := make([]string, len(audiences))

		for index, audience := range audiences {
			parsed, ok := audience.(string)
			if !ok || parsed == "" {
				return nil, false
			}

			result[index] = parsed
		}

		if len(result) == 0 {
			return nil, false
		}

		return result, true
	default:
		return nil, false
	}
}

// copyAudienceStrings detaches a non-empty audience representation.
func copyAudienceStrings(audiences []string) ([]string, bool) {
	if len(audiences) == 0 {
		return nil, false
	}

	result := append([]string(nil), audiences...)
	for _, audience := range result {
		if audience == "" {
			return nil, false
		}
	}

	return result, true
}

// parseScopeClaim applies the RFC space-delimited scope grammar to one exact string claim.
func parseScopeClaim(value any) ([]string, bool) {
	raw, ok := value.(string)
	if !ok {
		return nil, false
	}

	scopes := strings.Fields(raw)
	if len(scopes) == 0 {
		return nil, false
	}

	return scopes, true
}

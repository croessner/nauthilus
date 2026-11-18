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
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/tokenclaims"
	"github.com/golang-jwt/jwt/v5"
)

// ErrNotUserAccessToken reports a token that verified but is not a current user access token of this issuer: an ID
// token, a service token, a token without expiry, or one of another issuer.
var ErrNotUserAccessToken = errors.New("not a user access token of this issuer")

// UserAccessToken is the verified, format-independent view of a user access token. Resource servers hosted by
// Nauthilus decide on it and never branch on JWT or opaque token formats.
type UserAccessToken struct {
	Claims    jwt.MapClaims
	Audiences []string
	Scopes    []string
	Issuer    string
	Subject   string
	ClientID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// HasScope reports whether the token grants scope exactly.
func (t UserAccessToken) HasScope(scope string) bool {
	return scope != "" && slices.Contains(t.Scopes, scope)
}

// ValidateUserAccessToken verifies a JWT or opaque access token like ValidateToken (signature, revocation epoch,
// denylist, opaque state) and then requires a user access token of this issuer: token type access_token, an
// authorized party and a subject, no service-token client_id claim, an expiry in the future, and the configured
// issuer. An opaque token carries no iss claim; its presence in this issuer's token store is the proof of issuance.
// Technical failures stay classified by ValidateToken, so callers can tell them from rejected tokens.
func (n *NauthilusIDP) ValidateUserAccessToken(ctx context.Context, tokenString string) (UserAccessToken, error) {
	claims, err := n.ValidateToken(ctx, tokenString)
	if err != nil {
		return UserAccessToken{}, err
	}

	return newUserAccessToken(claims, n.deps.Cfg.GetIDP().OIDC.Issuer, !strings.Contains(tokenString, "."), time.Now())
}

// newUserAccessToken checks and projects already verified access-token claims.
func newUserAccessToken(claims jwt.MapClaims, issuer string, opaque bool, now time.Time) (UserAccessToken, error) {
	token := UserAccessToken{Claims: claims, Scopes: tokenclaims.Scopes(claims)}

	if issuer == "" || !tokenclaims.HasTokenType(claims, definitions.TokenTypeAccessToken) {
		return UserAccessToken{}, ErrNotUserAccessToken
	}

	if _, serviceToken := claims[definitions.ClaimClientID]; serviceToken {
		return UserAccessToken{}, ErrNotUserAccessToken
	}

	token.ClientID, _ = claims[definitions.ClaimAuthorizedParty].(string)
	token.Subject, _ = claims[oidcClaimSubject].(string)

	if token.ClientID == "" || token.Subject == "" {
		return UserAccessToken{}, ErrNotUserAccessToken
	}

	if !userAccessTokenIssuerMatches(claims, issuer, opaque) {
		return UserAccessToken{}, ErrNotUserAccessToken
	}

	token.Issuer = issuer

	if err := token.applyTimes(claims, opaque, now); err != nil {
		return UserAccessToken{}, err
	}

	audiences, ok := tokenclaims.AudienceSet(claims)
	if !ok {
		return UserAccessToken{}, ErrNotUserAccessToken
	}

	for audience := range audiences {
		token.Audiences = append(token.Audiences, audience)
	}

	slices.Sort(token.Audiences)

	return token, nil
}

// userAccessTokenIssuerMatches requires the exact configured issuer on JWTs. Opaque tokens have no iss claim, and
// an opaque token that carries one anyway must name this issuer as well.
func userAccessTokenIssuerMatches(claims jwt.MapClaims, issuer string, opaque bool) bool {
	raw, present := claims[oidcClaimIssuer]
	if !present {
		return opaque
	}

	value, ok := raw.(string)

	return ok && value == issuer
}

// applyTimes requires an expiry in the future and, for JWTs, an issue time not after it. Opaque-session claims
// carry integer dates, so the shared NumericDate reader decides for both formats.
func (t *UserAccessToken) applyTimes(claims jwt.MapClaims, opaque bool, now time.Time) error {
	expiresAt, _, ok := tokenclaims.NumericDate(claims, oidcClaimExpiresAt)
	if !ok || !now.Before(expiresAt) {
		return ErrNotUserAccessToken
	}

	t.ExpiresAt = expiresAt

	issuedAt, present, ok := tokenclaims.NumericDate(claims, oidcClaimIssuedAt)

	switch {
	case !present:
		if !opaque {
			return ErrNotUserAccessToken
		}

		return nil
	case !ok || issuedAt.After(t.ExpiresAt):
		return ErrNotUserAccessToken
	}

	t.IssuedAt = issuedAt

	return nil
}

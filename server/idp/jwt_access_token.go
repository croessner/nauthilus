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

package idp

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/idp/signing"
	"github.com/golang-jwt/jwt/v5"
)

// JWTAccessToken implements the AccessToken interface using JWT.
type JWTAccessToken struct {
	signer   signing.Signer
	issuer   string
	session  *OIDCSession
	lifetime time.Duration
}

// NewJWTAccessToken creates a new JWTAccessToken.
func NewJWTAccessToken(issuer string, signer signing.Signer, session *OIDCSession, lifetime time.Duration) *JWTAccessToken {
	return &JWTAccessToken{
		signer:   signer,
		issuer:   issuer,
		session:  session,
		lifetime: lifetime,
	}
}

// Issue generates a JWT access token.
func (t *JWTAccessToken) Issue(_ context.Context) (string, time.Duration, error) {
	now := time.Now()

	accessClaims := jwt.MapClaims{
		"iss":   t.issuer,
		"sub":   t.session.UserID,
		"aud":   t.session.ClientID,
		"exp":   now.Add(t.lifetime).Unix(),
		"iat":   now.Unix(),
		"scope": strings.Join(t.session.Scopes, " "),
	}

	maps.Copy(accessClaims, t.session.AccessTokenClaims)

	accessTokenString, err := t.signer.Sign(accessClaims)
	if err != nil {
		return "", 0, fmt.Errorf("failed to sign access token: %w", err)
	}

	return accessTokenString, t.lifetime, nil
}

// Validate is not implemented here as it's handled by NauthilusIdP for now.
func (t *JWTAccessToken) Validate(_ context.Context, _ string) (jwt.MapClaims, error) {
	return nil, fmt.Errorf("use NauthilusIdP.ValidateToken for JWT validation")
}

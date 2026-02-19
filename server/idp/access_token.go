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
	"time"

	"github.com/croessner/nauthilus/server/idp/signing"
	"github.com/golang-jwt/jwt/v5"
)

// AccessToken defines the interface for OIDC access tokens.
type AccessToken interface {
	// Issue generates the token string and returns its lifetime.
	Issue(ctx context.Context) (string, time.Duration, error)

	// Validate verifies the token string and returns the claims.
	Validate(ctx context.Context, tokenString string) (jwt.MapClaims, error)
}

// TokenIssuer is a helper to issue tokens using the appropriate implementation.
type TokenIssuer struct {
	signer   signing.Signer
	issuer   string
	session  *OIDCSession
	storage  *RedisTokenStorage
	tokenGen TokenGenerator
}

// NewTokenIssuer creates a new TokenIssuer.
func NewTokenIssuer(issuer string, signer signing.Signer, session *OIDCSession, storage *RedisTokenStorage, tokenGen TokenGenerator) *TokenIssuer {
	return &TokenIssuer{
		signer:   signer,
		issuer:   issuer,
		session:  session,
		storage:  storage,
		tokenGen: tokenGen,
	}
}

// IssueJWT creates a JWT access token.
func (ti *TokenIssuer) IssueJWT(ctx context.Context, lifetime time.Duration) (string, time.Duration, error) {
	token := NewJWTAccessToken(ti.issuer, ti.signer, ti.session, lifetime)

	return token.Issue(ctx)
}

// IssueOpaque creates an opaque access token.
func (ti *TokenIssuer) IssueOpaque(ctx context.Context, lifetime time.Duration) (string, time.Duration, error) {
	token := NewOpaqueAccessToken(ti.session, ti.storage, ti.tokenGen, lifetime)

	return token.Issue(ctx)
}

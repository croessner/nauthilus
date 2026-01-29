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
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/golang-jwt/jwt/v5"
)

// OpaqueAccessToken implements the AccessToken interface using opaque strings stored in Redis.
type OpaqueAccessToken struct {
	session  *OIDCSession
	storage  *RedisTokenStorage
	tokenGen TokenGenerator
	lifetime time.Duration
}

// NewOpaqueAccessToken creates a new OpaqueAccessToken.
func NewOpaqueAccessToken(session *OIDCSession, storage *RedisTokenStorage, tokenGen TokenGenerator, lifetime time.Duration) *OpaqueAccessToken {
	return &OpaqueAccessToken{
		session:  session,
		storage:  storage,
		tokenGen: tokenGen,
		lifetime: lifetime,
	}
}

// Issue generates an opaque access token and stores it in Redis.
func (t *OpaqueAccessToken) Issue(ctx context.Context) (string, time.Duration, error) {
	token := t.tokenGen.GenerateToken(definitions.OIDCTokenPrefixAccessToken)

	err := t.storage.StoreAccessToken(ctx, token, t.session, t.lifetime)
	if err != nil {
		return "", 0, fmt.Errorf("failed to store opaque access token: %w", err)
	}

	return token, t.lifetime, nil
}

// Validate verifies an opaque access token against Redis.
func (t *OpaqueAccessToken) Validate(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	session, err := t.storage.GetAccessToken(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired opaque token: %w", err)
	}

	claims := jwt.MapClaims{
		"sub":   session.UserID,
		"aud":   session.ClientID,
		"scope": strings.Join(session.Scopes, " "),
	}

	// Add basic info from session
	for k, v := range session.Claims {
		claims[k] = v
	}

	return claims, nil
}

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
	"crypto/sha256"
	"encoding/hex"
	"time"
)

const (
	// oidcDeniedAccessTokenKeyKind keeps denylist entries in the existing oidc:<kind>:<value> namespace.
	oidcDeniedAccessTokenKeyKind = "denied_access_token"
	// oidcDeniedAccessTokenDigestMarker separates digest keys from legacy raw-token keys.
	// A raw JWT starts with its base64url header and can never carry this marker.
	oidcDeniedAccessTokenDigestMarker = "sha256:"
	// oidcDeniedAccessTokenDigestDomain domain-separates denylist digests from every other token digest.
	oidcDeniedAccessTokenDigestDomain = "nauthilus-oidc-denied-access-token\x00"
)

// DenyJWTAccessToken adds a JWT access token to the denylist in Redis.
// The token is stored with a TTL so it expires automatically when the original token would have expired.
//
// During the digest migration both the digest key and the legacy raw-token key are written with the same
// TTL, so an instance rolled back to a release that only reads the legacy key still sees the revocation.
// TODO: Write only the digest key from the release after the one that introduced digest keys.
func (s *RedisTokenStorage) DenyJWTAccessToken(ctx context.Context, token string, ttl time.Duration) error {
	if token == "" || ttl <= 0 {
		return nil
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	// The keys live in different cluster slots, so a plain pipeline is used instead of a transaction.
	pipe := s.redis.GetWriteHandle().Pipeline()
	pipe.Set(writeCtx, s.deniedAccessTokenKey(token), "1", ttl)
	pipe.Set(writeCtx, s.legacyDeniedAccessTokenKey(token), "1", ttl)

	_, err := pipe.Exec(writeCtx)

	return err
}

// IsJWTAccessTokenDenied checks authoritative revocation state without collapsing backend failures into absence.
// It reads the digest key and the legacy raw-token key in one round trip, so tokens revoked before the
// digest keys existed stay revoked.
func (s *RedisTokenStorage) IsJWTAccessTokenDenied(ctx context.Context, token string) (bool, error) {
	readCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	pipe := s.redis.GetWriteHandle().Pipeline()
	digestEntry := pipe.Exists(readCtx, s.deniedAccessTokenKey(token))
	legacyEntry := pipe.Exists(readCtx, s.legacyDeniedAccessTokenKey(token))

	// EXISTS never answers with redis.Nil, so any pipeline error is a backend failure.
	if _, err := pipe.Exec(readCtx); err != nil {
		return false, err
	}

	return digestEntry.Val() > 0 || legacyEntry.Val() > 0, nil
}

// deniedAccessTokenKey returns the denylist key for a JWT access token.
//
// The key holds an unkeyed, domain-separated SHA-256 digest instead of the token. An unkeyed digest is
// deliberate: a digest keyed with the rotatable storage secret would silently stop matching after a
// rotation and revive every revoked token, while the JWT signature still verifies. The token's signature
// entropy makes the unkeyed digest neither invertible nor guessable. The jti claim is not used because
// the denylist must also cover tokens that carry no jti.
func (s *RedisTokenStorage) deniedAccessTokenKey(token string) string {
	sum := sha256.Sum256([]byte(oidcDeniedAccessTokenDigestDomain + token))

	return s.oidcKey(oidcDeniedAccessTokenKeyKind, oidcDeniedAccessTokenDigestMarker+hex.EncodeToString(sum[:]))
}

// legacyDeniedAccessTokenKey returns the pre-digest denylist key that embeds the raw token.
//
// TODO: Stop writing this key in the release after the digest migration. Remove the read fallback once
// every legacy entry has expired: entries carry the revoked token's access-token lifetime as TTL, i.e.
// identity.oidc.clients[].access_token_lifetime or identity.oidc.tokens.default_access_token_lifetime, so the
// read is obsolete once the largest of these lifetimes has elapsed after the last legacy write.
func (s *RedisTokenStorage) legacyDeniedAccessTokenKey(token string) string {
	return s.oidcKey(oidcDeniedAccessTokenKeyKind, token)
}

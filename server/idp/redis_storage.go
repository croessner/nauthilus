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
	"time"

	"github.com/croessner/nauthilus/server/rediscli"
	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// OIDCSession represents the data stored in Redis for an OIDC authorization flow.
type OIDCSession struct {
	ClientID          string         `json:"client_id"`
	UserID            string         `json:"user_id"`
	Username          string         `json:"username"`
	DisplayName       string         `json:"display_name"`
	Scopes            []string       `json:"scopes"`
	RedirectURI       string         `json:"redirect_uri"`
	AuthTime          time.Time      `json:"auth_time"`
	Nonce             string         `json:"nonce,omitempty"`
	AccessToken       string         `json:"access_token,omitempty"`
	IdTokenClaims     map[string]any `json:"id_token_claims"`
	AccessTokenClaims map[string]any `json:"access_token_claims"`
}

// RedisTokenStorage handles OIDC token/session persistence in Redis.
type RedisTokenStorage struct {
	redis  rediscli.Client
	prefix string
}

// NewRedisTokenStorage creates a new RedisTokenStorage.
func NewRedisTokenStorage(redis rediscli.Client, prefix string) *RedisTokenStorage {
	return &RedisTokenStorage{redis: redis, prefix: prefix}
}

// StoreSession stores an OIDC session with a given code and TTL.
func (s *RedisTokenStorage) StoreSession(ctx context.Context, code string, session *OIDCSession, ttl time.Duration) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	encryptedData, err := s.redis.GetSecurityManager().Encrypt(string(data))
	if err != nil {
		return err
	}

	key := s.prefix + fmt.Sprintf("oidc:code:%s", code)
	return s.redis.GetWriteHandle().Set(ctx, key, encryptedData, ttl).Err()
}

// GetSession retrieves an OIDC session from Redis.
func (s *RedisTokenStorage) GetSession(ctx context.Context, code string) (*OIDCSession, error) {
	key := s.prefix + fmt.Sprintf("oidc:code:%s", code)
	data, err := s.redis.GetReadHandle().Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	decryptedData, err := s.redis.GetSecurityManager().Decrypt(data)
	if err != nil {
		return nil, err
	}

	session := &OIDCSession{}
	if err := json.Unmarshal([]byte(decryptedData), session); err != nil {
		return nil, err
	}

	return session, nil
}

// DeleteSession removes an OIDC session from Redis.
func (s *RedisTokenStorage) DeleteSession(ctx context.Context, code string) error {
	key := s.prefix + fmt.Sprintf("oidc:code:%s", code)
	return s.redis.GetWriteHandle().Del(ctx, key).Err()
}

// StoreRefreshToken stores a refresh token session in Redis and tracks it for the user.
func (s *RedisTokenStorage) StoreRefreshToken(ctx context.Context, token string, session *OIDCSession, ttl time.Duration) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	encryptedData, err := s.redis.GetSecurityManager().Encrypt(string(data))
	if err != nil {
		return err
	}

	key := s.prefix + fmt.Sprintf("oidc:refresh_token:%s", token)
	userKey := s.prefix + fmt.Sprintf("oidc:user_refresh_tokens:%s", session.UserID)

	pipe := s.redis.GetWriteHandle().Pipeline()
	pipe.Set(ctx, key, encryptedData, ttl)
	pipe.SAdd(ctx, userKey, token)
	// Keep the user mapping alive as long as there might be active tokens
	pipe.Expire(ctx, userKey, 30*24*time.Hour)

	_, err = pipe.Exec(ctx)

	return err
}

// GetRefreshToken retrieves a refresh token session from Redis.
func (s *RedisTokenStorage) GetRefreshToken(ctx context.Context, token string) (*OIDCSession, error) {
	key := s.prefix + fmt.Sprintf("oidc:refresh_token:%s", token)
	data, err := s.redis.GetReadHandle().Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	decryptedData, err := s.redis.GetSecurityManager().Decrypt(data)
	if err != nil {
		return nil, err
	}

	session := &OIDCSession{}
	if err := json.Unmarshal([]byte(decryptedData), session); err != nil {
		return nil, err
	}

	return session, nil
}

// DeleteRefreshToken removes a refresh token session from Redis and its user tracking.
func (s *RedisTokenStorage) DeleteRefreshToken(ctx context.Context, token string) error {
	session, err := s.GetRefreshToken(ctx, token)
	if err == nil && session != nil {
		userKey := s.prefix + fmt.Sprintf("oidc:user_refresh_tokens:%s", session.UserID)
		_ = s.redis.GetWriteHandle().SRem(ctx, userKey, token).Err()
	}

	key := s.prefix + fmt.Sprintf("oidc:refresh_token:%s", token)

	return s.redis.GetWriteHandle().Del(ctx, key).Err()
}

// DeleteUserRefreshTokens removes all refresh tokens for a given user from Redis.
func (s *RedisTokenStorage) DeleteUserRefreshTokens(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}

	userKey := s.prefix + fmt.Sprintf("oidc:user_refresh_tokens:%s", userID)

	tokens, err := s.redis.GetReadHandle().SMembers(ctx, userKey).Result()
	if err != nil {
		return err
	}

	if len(tokens) == 0 {
		return nil
	}

	pipe := s.redis.GetWriteHandle().Pipeline()

	for _, token := range tokens {
		pipe.Del(ctx, s.prefix+fmt.Sprintf("oidc:refresh_token:%s", token))
	}

	pipe.Del(ctx, userKey)

	_, err = pipe.Exec(ctx)

	return err
}

// StoreAccessToken stores an opaque access token in Redis and tracks it for the user.
func (s *RedisTokenStorage) StoreAccessToken(ctx context.Context, token string, session *OIDCSession, ttl time.Duration) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	encryptedData, err := s.redis.GetSecurityManager().Encrypt(string(data))
	if err != nil {
		return err
	}

	key := s.prefix + fmt.Sprintf("oidc:access_token:%s", token)
	userKey := s.prefix + fmt.Sprintf("oidc:user_access_tokens:%s", session.UserID)

	pipe := s.redis.GetWriteHandle().Pipeline()
	pipe.Set(ctx, key, encryptedData, ttl)
	pipe.SAdd(ctx, userKey, token)
	// Keep the user mapping alive as long as there might be active tokens
	pipe.Expire(ctx, userKey, 30*24*time.Hour)

	_, err = pipe.Exec(ctx)

	return err
}

// GetAccessToken retrieves an opaque access token session from Redis.
func (s *RedisTokenStorage) GetAccessToken(ctx context.Context, token string) (*OIDCSession, error) {
	key := s.prefix + fmt.Sprintf("oidc:access_token:%s", token)
	data, err := s.redis.GetReadHandle().Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	decryptedData, err := s.redis.GetSecurityManager().Decrypt(data)
	if err != nil {
		return nil, err
	}

	session := &OIDCSession{}
	if err := json.Unmarshal([]byte(decryptedData), session); err != nil {
		return nil, err
	}

	return session, nil
}

// DeleteAccessToken removes an opaque access token from Redis and its user tracking.
func (s *RedisTokenStorage) DeleteAccessToken(ctx context.Context, token string) error {
	session, err := s.GetAccessToken(ctx, token)
	if err == nil && session != nil {
		userKey := s.prefix + fmt.Sprintf("oidc:user_access_tokens:%s", session.UserID)
		_ = s.redis.GetWriteHandle().SRem(ctx, userKey, token).Err()
	}

	key := s.prefix + fmt.Sprintf("oidc:access_token:%s", token)

	return s.redis.GetWriteHandle().Del(ctx, key).Err()
}

// DenyJWTAccessToken adds a JWT access token to the denylist in Redis.
// The token is stored with a TTL so it expires automatically when the original token would have expired.
func (s *RedisTokenStorage) DenyJWTAccessToken(ctx context.Context, token string, ttl time.Duration) error {
	if token == "" || ttl <= 0 {
		return nil
	}

	key := s.prefix + fmt.Sprintf("oidc:denied_access_token:%s", token)

	return s.redis.GetWriteHandle().Set(ctx, key, "1", ttl).Err()
}

// IsJWTAccessTokenDenied checks whether a JWT access token has been denied (invalidated).
func (s *RedisTokenStorage) IsJWTAccessTokenDenied(ctx context.Context, token string) bool {
	key := s.prefix + fmt.Sprintf("oidc:denied_access_token:%s", token)

	_, err := s.redis.GetReadHandle().Get(ctx, key).Result()

	return err == nil
}

// ListUserSessions returns all active OIDC sessions (via access tokens) for a user.
func (s *RedisTokenStorage) ListUserSessions(ctx context.Context, userID string) (map[string]*OIDCSession, error) {
	userKey := s.prefix + fmt.Sprintf("oidc:user_access_tokens:%s", userID)

	tokens, err := s.redis.GetReadHandle().SMembers(ctx, userKey).Result()
	if err != nil {
		return nil, err
	}

	sessions := make(map[string]*OIDCSession)

	for _, token := range tokens {
		session, err := s.GetAccessToken(ctx, token)
		if err == nil {
			sessions[token] = session
		} else {
			// Clean up expired token from set
			_ = s.redis.GetWriteHandle().SRem(ctx, userKey, token).Err()
		}
	}

	return sessions, nil
}

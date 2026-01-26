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
	ClientID    string         `json:"client_id"`
	UserID      string         `json:"user_id"`
	Username    string         `json:"username"`
	DisplayName string         `json:"display_name"`
	Scopes      []string       `json:"scopes"`
	RedirectURI string         `json:"redirect_uri"`
	AuthTime    time.Time      `json:"auth_time"`
	Claims      map[string]any `json:"claims"`
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

	key := s.prefix + fmt.Sprintf("nauthilus:oidc:code:%s", code)
	return s.redis.GetWriteHandle().Set(ctx, key, string(data), ttl).Err()
}

// GetSession retrieves an OIDC session from Redis.
func (s *RedisTokenStorage) GetSession(ctx context.Context, code string) (*OIDCSession, error) {
	key := s.prefix + fmt.Sprintf("nauthilus:oidc:code:%s", code)
	data, err := s.redis.GetReadHandle().Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	session := &OIDCSession{}
	if err := json.Unmarshal([]byte(data), session); err != nil {
		return nil, err
	}

	return session, nil
}

// DeleteSession removes an OIDC session from Redis.
func (s *RedisTokenStorage) DeleteSession(ctx context.Context, code string) error {
	key := s.prefix + fmt.Sprintf("nauthilus:oidc:code:%s", code)
	return s.redis.GetWriteHandle().Del(ctx, key).Err()
}

// StoreRefreshToken stores a refresh token session in Redis.
func (s *RedisTokenStorage) StoreRefreshToken(ctx context.Context, token string, session *OIDCSession, ttl time.Duration) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	key := s.prefix + fmt.Sprintf("nauthilus:oidc:refresh_token:%s", token)
	return s.redis.GetWriteHandle().Set(ctx, key, string(data), ttl).Err()
}

// GetRefreshToken retrieves a refresh token session from Redis.
func (s *RedisTokenStorage) GetRefreshToken(ctx context.Context, token string) (*OIDCSession, error) {
	key := s.prefix + fmt.Sprintf("nauthilus:oidc:refresh_token:%s", token)
	data, err := s.redis.GetReadHandle().Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	session := &OIDCSession{}
	if err := json.Unmarshal([]byte(data), session); err != nil {
		return nil, err
	}

	return session, nil
}

// DeleteRefreshToken removes a refresh token session from Redis.
func (s *RedisTokenStorage) DeleteRefreshToken(ctx context.Context, token string) error {
	key := s.prefix + fmt.Sprintf("nauthilus:oidc:refresh_token:%s", token)
	return s.redis.GetWriteHandle().Del(ctx, key).Err()
}

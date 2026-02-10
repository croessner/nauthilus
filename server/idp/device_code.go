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
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/redis/go-redis/v9"
)

// DeviceCodeStatus represents the current state of a device code request.
type DeviceCodeStatus string

const (
	// DeviceCodeStatusPending indicates the user has not yet completed authorization.
	DeviceCodeStatusPending DeviceCodeStatus = "pending"

	// DeviceCodeStatusAuthorized indicates the user has approved the authorization request.
	DeviceCodeStatusAuthorized DeviceCodeStatus = "authorized"

	// DeviceCodeStatusDenied indicates the user has denied the authorization request.
	DeviceCodeStatusDenied DeviceCodeStatus = "denied"
)

// DeviceCodeRequest represents the stored data for a device authorization request.
type DeviceCodeRequest struct {
	ClientID  string           `json:"client_id"`
	Scopes    []string         `json:"scopes"`
	UserCode  string           `json:"user_code"`
	Status    DeviceCodeStatus `json:"status"`
	UserID    string           `json:"user_id,omitempty"`
	ExpiresAt time.Time        `json:"expires_at"`
	Interval  int              `json:"interval"`
	LastPoll  time.Time        `json:"last_poll,omitzero"`
}

// DeviceCodeStore defines the interface for device code persistence.
type DeviceCodeStore interface {
	// StoreDeviceCode stores a device code request with the given TTL.
	StoreDeviceCode(ctx context.Context, deviceCode string, request *DeviceCodeRequest, ttl time.Duration) error

	// GetDeviceCode retrieves a device code request by device code.
	GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCodeRequest, error)

	// GetDeviceCodeByUserCode retrieves a device code by user code.
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (string, *DeviceCodeRequest, error)

	// UpdateDeviceCode updates the stored device code request.
	UpdateDeviceCode(ctx context.Context, deviceCode string, request *DeviceCodeRequest) error

	// DeleteDeviceCode removes a device code from storage.
	DeleteDeviceCode(ctx context.Context, deviceCode string) error
}

// UserCodeGenerator defines the interface for generating user-facing codes.
type UserCodeGenerator interface {
	// GenerateUserCode generates a human-readable user code of the given length.
	GenerateUserCode(length int) (string, error)
}

// DefaultUserCodeGenerator generates user codes using uppercase letters (excluding confusing characters).
type DefaultUserCodeGenerator struct{}

// GenerateUserCode generates a user code consisting of uppercase letters,
// formatted with a hyphen in the middle for readability (e.g., "ABCD-EFGH").
func (g *DefaultUserCodeGenerator) GenerateUserCode(length int) (string, error) {
	// Use characters that are unambiguous (exclude O, I, L, 0, 1)
	const charset = "ABCDEFGHJKMNPQRSTVWXYZ"

	code := make([]byte, length)

	for i := range length {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random index: %w", err)
		}

		code[i] = charset[idx.Int64()]
	}

	// Insert hyphen in the middle for readability
	half := length / 2

	return string(code[:half]) + "-" + string(code[half:]), nil
}

// RedisDeviceCodeStore implements DeviceCodeStore using Redis.
type RedisDeviceCodeStore struct {
	redis  rediscli.Client
	prefix string
}

// NewRedisDeviceCodeStore creates a new RedisDeviceCodeStore.
func NewRedisDeviceCodeStore(redis rediscli.Client, prefix string) *RedisDeviceCodeStore {
	return &RedisDeviceCodeStore{redis: redis, prefix: prefix}
}

// StoreDeviceCode stores a device code request in Redis.
// It stores both the device code entry and a user code -> device code mapping.
func (s *RedisDeviceCodeStore) StoreDeviceCode(ctx context.Context, deviceCode string, request *DeviceCodeRequest, ttl time.Duration) error {
	data, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal device code request: %w", err)
	}

	encryptedData, err := s.redis.GetSecurityManager().Encrypt(string(data))
	if err != nil {
		return fmt.Errorf("failed to encrypt device code data: %w", err)
	}

	// Store the device code entry
	deviceKey := s.deviceCodeKey(deviceCode)

	if err := s.redis.GetWriteHandle().Set(ctx, deviceKey, encryptedData, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store device code: %w", err)
	}

	// Store the user code -> device code mapping
	userCodeKey := s.userCodeKey(request.UserCode)

	if err := s.redis.GetWriteHandle().Set(ctx, userCodeKey, deviceCode, ttl).Err(); err != nil {
		// Clean up the device code entry on failure
		_ = s.redis.GetWriteHandle().Del(ctx, deviceKey).Err()

		return fmt.Errorf("failed to store user code mapping: %w", err)
	}

	return nil
}

// GetDeviceCode retrieves a device code request from Redis.
func (s *RedisDeviceCodeStore) GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCodeRequest, error) {
	key := s.deviceCodeKey(deviceCode)

	data, err := s.redis.GetReadHandle().Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("device code not found or expired")
		}

		return nil, fmt.Errorf("failed to get device code: %w", err)
	}

	decryptedData, err := s.redis.GetSecurityManager().Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt device code data: %w", err)
	}

	request := &DeviceCodeRequest{}

	if err := json.Unmarshal([]byte(decryptedData), request); err != nil {
		return nil, fmt.Errorf("failed to unmarshal device code request: %w", err)
	}

	return request, nil
}

// GetDeviceCodeByUserCode retrieves a device code request by looking up the user code.
func (s *RedisDeviceCodeStore) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (string, *DeviceCodeRequest, error) {
	// Normalize user code: uppercase, remove hyphens and spaces
	normalizedCode := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(userCode))

	// Reconstruct the formatted code for lookup
	if len(normalizedCode) >= definitions.OIDCDeviceCodeDefaultUserCodeLength {
		half := len(normalizedCode) / 2
		userCode = normalizedCode[:half] + "-" + normalizedCode[half:]
	}

	userCodeKey := s.userCodeKey(userCode)

	deviceCode, err := s.redis.GetReadHandle().Get(ctx, userCodeKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", nil, fmt.Errorf("user code not found or expired")
		}

		return "", nil, fmt.Errorf("failed to get user code mapping: %w", err)
	}

	request, err := s.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return "", nil, err
	}

	return deviceCode, request, nil
}

// UpdateDeviceCode updates the stored device code request, preserving the original TTL.
func (s *RedisDeviceCodeStore) UpdateDeviceCode(ctx context.Context, deviceCode string, request *DeviceCodeRequest) error {
	key := s.deviceCodeKey(deviceCode)

	// Get remaining TTL
	ttl, err := s.redis.GetReadHandle().TTL(ctx, key).Result()
	if err != nil || ttl <= 0 {
		return fmt.Errorf("device code not found or expired")
	}

	data, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal device code request: %w", err)
	}

	encryptedData, err := s.redis.GetSecurityManager().Encrypt(string(data))
	if err != nil {
		return fmt.Errorf("failed to encrypt device code data: %w", err)
	}

	return s.redis.GetWriteHandle().Set(ctx, key, encryptedData, ttl).Err()
}

// DeleteDeviceCode removes a device code and its user code mapping from Redis.
func (s *RedisDeviceCodeStore) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	// Get the request to find the user code
	request, err := s.GetDeviceCode(ctx, deviceCode)
	if err == nil && request != nil {
		userCodeKey := s.userCodeKey(request.UserCode)
		_ = s.redis.GetWriteHandle().Del(ctx, userCodeKey).Err()
	}

	deviceKey := s.deviceCodeKey(deviceCode)

	return s.redis.GetWriteHandle().Del(ctx, deviceKey).Err()
}

// deviceCodeKey returns the Redis key for a device code.
func (s *RedisDeviceCodeStore) deviceCodeKey(deviceCode string) string {
	return s.prefix + "oidc:device_code:" + deviceCode
}

// userCodeKey returns the Redis key for a user code mapping.
func (s *RedisDeviceCodeStore) userCodeKey(userCode string) string {
	return s.prefix + "oidc:user_code:" + userCode
}

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

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/util"
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

// ErrDeviceCodeNotFound reports an absent or expired device request.
// ErrDeviceCodeConflict reports a replay or mismatched device transition.
var (
	ErrDeviceCodeNotFound = errors.New("device code not found")
	ErrDeviceCodeConflict = errors.New("device code state conflict")
)

// DeviceCodeRequest represents the stored data for a device authorization request.
type DeviceCodeRequest struct {
	ClientID                    string                  `json:"client_id"`
	Scopes                      []string                `json:"scopes"`
	UserCode                    string                  `json:"user_code"`
	Status                      DeviceCodeStatus        `json:"status"`
	UserID                      string                  `json:"user_id,omitempty"`
	Username                    string                  `json:"username,omitempty"`
	DisplayName                 string                  `json:"display_name,omitempty"`
	UserAttributes              bktype.AttributeMapping `json:"user_attributes,omitempty"`
	UserGroups                  []string                `json:"user_groups,omitempty"`
	UserGroupDistinguishedNames []string                `json:"user_group_dns,omitempty"`
	IDTokenClaims               map[string]any          `json:"id_token_claims,omitempty"`
	AccessTokenClaims           map[string]any          `json:"access_token_claims,omitempty"`
	MFACompleted                bool                    `json:"mfa_completed,omitempty"`
	MFAMethod                   string                  `json:"mfa_method,omitempty"`
	ExpiresAt                   time.Time               `json:"expires_at"`
	Interval                    int                     `json:"interval"`
	LastPoll                    time.Time               `json:"last_poll,omitzero"`
	VerificationLocked          bool                    `json:"verification_locked"`
}

// StoreUserSnapshot copies user identity data into the request.
func (r *DeviceCodeRequest) StoreUserSnapshot(user *backend.User) {
	if r == nil || user == nil {
		return
	}

	r.UserID = user.ID
	r.Username = user.Name
	r.DisplayName = user.DisplayName
	r.UserAttributes = user.Attributes.Clone()
	r.UserGroups = append([]string(nil), user.Groups...)
	r.UserGroupDistinguishedNames = append([]string(nil), user.GroupDistinguishedNames...)
}

// UserFromSnapshot rebuilds a backend user from the stored snapshot.
func (r *DeviceCodeRequest) UserFromSnapshot() *backend.User {
	if r == nil || r.UserID == "" {
		return nil
	}

	user := backend.NewUser(r.Username, r.DisplayName, r.UserID)
	user.Attributes = r.UserAttributes.Clone()
	user.Groups = append([]string(nil), r.UserGroups...)
	user.GroupDistinguishedNames = append([]string(nil), r.UserGroupDistinguishedNames...)

	return user
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
	cfg    config.File
	prefix string
}

// NewRedisDeviceCodeStore creates a new RedisDeviceCodeStore.
func NewRedisDeviceCodeStore(redis rediscli.Client, prefix string) *RedisDeviceCodeStore {
	return NewRedisDeviceCodeStoreWithConfig(redis, prefix, nil)
}

// NewRedisDeviceCodeStoreWithConfig creates a RedisDeviceCodeStore with configured Redis operation deadlines.
func NewRedisDeviceCodeStoreWithConfig(redis rediscli.Client, prefix string, cfg config.File) *RedisDeviceCodeStore {
	return &RedisDeviceCodeStore{redis: redis, cfg: cfg, prefix: prefix}
}

func (s *RedisDeviceCodeStore) redisReadContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return util.GetCtxWithDeadlineRedisRead(ctx, s.cfg)
}

func (s *RedisDeviceCodeStore) redisWriteContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return util.GetCtxWithDeadlineRedisWrite(ctx, s.cfg)
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

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	if err := s.redis.GetWriteHandle().Set(writeCtx, deviceKey, encryptedData, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store device code: %w", err)
	}

	// Store the user code -> device code mapping
	userCodeKey := s.userCodeKey(request.UserCode)

	if err := s.redis.GetWriteHandle().Set(writeCtx, userCodeKey, deviceCode, ttl).Err(); err != nil {
		// Clean up the device code entry on failure
		_ = s.redis.GetWriteHandle().Del(writeCtx, deviceKey).Err()

		return fmt.Errorf("failed to store user code mapping: %w", err)
	}

	return nil
}

// GetDeviceCode retrieves a device code request from Redis.
func (s *RedisDeviceCodeStore) GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCodeRequest, error) {
	key := s.deviceCodeKey(deviceCode)

	readCtx, cancel := s.redisReadContext(ctx)
	defer cancel()

	data, err := s.redis.GetReadHandle().Get(readCtx, key).Result()
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
	userCode = NormalizeDeviceUserCode(userCode)

	userCodeKey := s.userCodeKey(userCode)
	readCtx, cancel := s.redisReadContext(ctx)

	deviceCode, err := s.redis.GetReadHandle().Get(readCtx, userCodeKey).Result()

	cancel()

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

// NormalizeDeviceUserCode returns the one canonical lookup representation.
func NormalizeDeviceUserCode(userCode string) string {
	normalized := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(userCode))
	if len(normalized) < definitions.OIDCDeviceCodeDefaultUserCodeLength {
		return normalized
	}

	half := len(normalized) / 2

	return normalized[:half] + "-" + normalized[half:]
}

func redisDeviceCodeString(ctx context.Context, commands redis.Cmdable, key string) (string, error) {
	value, err := commands.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrDeviceCodeNotFound
	}

	if err != nil {
		return "", err
	}

	return value, nil
}

func redisDeviceCodeTTL(ctx context.Context, commands redis.Cmdable, key string) (time.Duration, error) {
	ttl, err := commands.TTL(ctx, key).Result()
	if err != nil || ttl <= 0 {
		return 0, ErrDeviceCodeNotFound
	}

	return ttl, nil
}

func deviceCodeClaimable(request *DeviceCodeRequest, userCode string) bool {
	return request != nil && request.Status == DeviceCodeStatusPending && !request.VerificationLocked &&
		NormalizeDeviceUserCode(request.UserCode) == userCode
}

func deviceCodeTerminalTransitionValid(current *DeviceCodeRequest, desired *DeviceCodeRequest) bool {
	return current != nil && current.Status == DeviceCodeStatusPending && current.VerificationLocked &&
		current.ClientID == desired.ClientID &&
		NormalizeDeviceUserCode(current.UserCode) == NormalizeDeviceUserCode(desired.UserCode) &&
		current.ExpiresAt.Equal(desired.ExpiresAt) && deviceCodeScopesBounded(desired.Scopes, current.Scopes)
}

func (s *RedisDeviceCodeStore) claimDeviceCodeTransaction(
	ctx context.Context,
	tx *redis.Tx,
	userKey string,
	deviceKey string,
	deviceCode string,
	userCode string,
) (*DeviceCodeRequest, error) {
	mapped, err := redisDeviceCodeString(ctx, tx, userKey)
	if err != nil {
		return nil, err
	}

	if mapped != deviceCode {
		return nil, ErrDeviceCodeConflict
	}

	encoded, err := redisDeviceCodeString(ctx, tx, deviceKey)
	if err != nil {
		return nil, err
	}

	request, err := s.decodeDeviceCodeRequest(encoded)
	if err != nil {
		return nil, err
	}

	if !deviceCodeClaimable(request, userCode) {
		return nil, ErrDeviceCodeConflict
	}

	ttl, err := redisDeviceCodeTTL(ctx, tx, deviceKey)
	if err != nil {
		return nil, err
	}

	request.VerificationLocked = true

	encoded, err = s.encodeDeviceCodeRequest(request)
	if err != nil {
		return nil, err
	}

	_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Del(ctx, userKey)
		pipe.Set(ctx, deviceKey, encoded, ttl)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return request, nil
}

func (s *RedisDeviceCodeStore) completeDeviceCodeTransaction(
	ctx context.Context,
	tx *redis.Tx,
	deviceKey string,
	desired *DeviceCodeRequest,
) error {
	encoded, err := redisDeviceCodeString(ctx, tx, deviceKey)
	if err != nil {
		return err
	}

	current, err := s.decodeDeviceCodeRequest(encoded)
	if err != nil {
		return err
	}

	if !deviceCodeTerminalTransitionValid(current, desired) {
		return ErrDeviceCodeConflict
	}

	ttl, err := redisDeviceCodeTTL(ctx, tx, deviceKey)
	if err != nil {
		return err
	}

	encoded, err = s.encodeDeviceCodeRequest(desired)
	if err != nil {
		return err
	}

	_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, deviceKey, encoded, ttl)

		return nil
	})

	return err
}

// ClaimDeviceCodeByUserCode atomically consumes the user-code index and locks its device request.
func (s *RedisDeviceCodeStore) ClaimDeviceCodeByUserCode(
	ctx context.Context,
	userCode string,
) (string, *DeviceCodeRequest, error) {
	userCode = NormalizeDeviceUserCode(userCode)
	if userCode == "" {
		return "", nil, ErrDeviceCodeNotFound
	}

	handle := s.redis.GetWriteHandle()

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	userKey := s.userCodeKey(userCode)

	deviceCode, err := redisDeviceCodeString(writeCtx, handle, userKey)
	if err != nil {
		return "", nil, fmt.Errorf("claim device code mapping: %w", err)
	}

	deviceKey := s.deviceCodeKey(deviceCode)

	var claimed *DeviceCodeRequest

	err = handle.Watch(writeCtx, func(tx *redis.Tx) error {
		claimed, err = s.claimDeviceCodeTransaction(
			writeCtx, tx, userKey, deviceKey, deviceCode, userCode,
		)

		return err
	}, userKey, deviceKey)
	if errors.Is(err, redis.TxFailedErr) {
		err = ErrDeviceCodeConflict
	}

	if err != nil {
		return "", nil, fmt.Errorf("claim device code: %w", err)
	}

	return deviceCode, claimed, nil
}

// CompleteClaimedDeviceCode performs the only terminal transition for a claimed request.
func (s *RedisDeviceCodeStore) CompleteClaimedDeviceCode(
	ctx context.Context,
	deviceCode string,
	desired *DeviceCodeRequest,
) error {
	if desired == nil || !desired.VerificationLocked ||
		(desired.Status != DeviceCodeStatusAuthorized && desired.Status != DeviceCodeStatusDenied) {
		return ErrDeviceCodeConflict
	}

	deviceKey := s.deviceCodeKey(deviceCode)
	handle := s.redis.GetWriteHandle()

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	err := handle.Watch(writeCtx, func(tx *redis.Tx) error {
		return s.completeDeviceCodeTransaction(writeCtx, tx, deviceKey, desired)
	}, deviceKey)
	if errors.Is(err, redis.TxFailedErr) {
		err = ErrDeviceCodeConflict
	}

	if err != nil {
		return fmt.Errorf("complete claimed device code: %w", err)
	}

	return nil
}

func deviceCodeScopesBounded(granted []string, requested []string) bool {
	if len(granted) == 0 || len(granted) > len(requested) {
		return false
	}

	allowed := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		allowed[scope] = struct{}{}
	}

	seen := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		if _, ok := allowed[scope]; !ok {
			return false
		}

		if _, duplicate := seen[scope]; duplicate {
			return false
		}

		seen[scope] = struct{}{}
	}

	return true
}

func (s *RedisDeviceCodeStore) decodeDeviceCodeRequest(encoded string) (*DeviceCodeRequest, error) {
	plain, err := s.redis.GetSecurityManager().Decrypt(encoded)
	if err != nil {
		return nil, fmt.Errorf("decrypt device code data: %w", err)
	}

	request := &DeviceCodeRequest{}
	if err = json.Unmarshal([]byte(plain), request); err != nil {
		return nil, fmt.Errorf("unmarshal device code request: %w", err)
	}

	return request, nil
}

func (s *RedisDeviceCodeStore) encodeDeviceCodeRequest(request *DeviceCodeRequest) (string, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("marshal device code request: %w", err)
	}

	encoded, err := s.redis.GetSecurityManager().Encrypt(string(data))
	if err != nil {
		return "", fmt.Errorf("encrypt device code data: %w", err)
	}

	return encoded, nil
}

// UpdateDeviceCode updates the stored device code request, preserving the original TTL.
func (s *RedisDeviceCodeStore) UpdateDeviceCode(ctx context.Context, deviceCode string, request *DeviceCodeRequest) error {
	key := s.deviceCodeKey(deviceCode)
	readCtx, readCancel := s.redisReadContext(ctx)

	// Get remaining TTL
	ttl, err := s.redis.GetReadHandle().TTL(readCtx, key).Result()

	readCancel()

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

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	return s.redis.GetWriteHandle().Set(writeCtx, key, encryptedData, ttl).Err()
}

// DeleteDeviceCode removes a device code and its user code mapping from Redis.
func (s *RedisDeviceCodeStore) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	// Get the request to find the user code
	request, err := s.GetDeviceCode(ctx, deviceCode)
	if err == nil && request != nil {
		userCodeKey := s.userCodeKey(request.UserCode)
		writeCtx, cancel := s.redisWriteContext(ctx)
		_ = s.redis.GetWriteHandle().Del(writeCtx, userCodeKey).Err()

		cancel()
	}

	deviceKey := s.deviceCodeKey(deviceCode)

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	return s.redis.GetWriteHandle().Del(writeCtx, deviceKey).Err()
}

// deviceCodeKey returns the Redis key for a device code.
func (s *RedisDeviceCodeStore) deviceCodeKey(deviceCode string) string {
	return s.prefix + "oidc:device_code:" + deviceCode
}

// userCodeKey returns the Redis key for a user code mapping.
func (s *RedisDeviceCodeStore) userCodeKey(userCode string) string {
	return s.prefix + "oidc:user_code:" + userCode
}

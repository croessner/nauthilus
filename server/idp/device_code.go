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
	"encoding/json"
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
// ErrDeviceUserCodeCollision reports that a freshly generated user code is already in use.
var (
	ErrDeviceCodeNotFound      = errors.New("device code not found")
	ErrDeviceCodeConflict      = errors.New("device code state conflict")
	ErrDeviceUserCodeCollision = errors.New("device user code collision")
)

// deviceCodeTransitionAttempts bounds optimistic retries when a concurrent write touched the same request.
const deviceCodeTransitionAttempts = 3

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

	// RecordDeviceCodePoll stores only the poll timestamp of a live request.
	RecordDeviceCodePoll(ctx context.Context, deviceCode string, polledAt time.Time) error

	// ClaimAuthorizedDeviceCode atomically consumes an authorized request for one client.
	ClaimAuthorizedDeviceCode(ctx context.Context, deviceCode string, clientID string) (*DeviceCodeRequest, error)

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

const (
	// deviceCodeDigestNamespace domain-separates device-code key digests from every other digest.
	deviceCodeDigestNamespace = "oidc-device-code"
	// deviceUserCodeDigestNamespace domain-separates user-code locator digests from every other digest.
	deviceUserCodeDigestNamespace = "oidc-device-user-code"
)

// deviceCodeEnvelope is the encrypted Redis value of one device request.
//
// Keys only carry digests, so the bearer device code travels inside the encrypted value. That lets the
// browser flow recover it from a user code without a plaintext mapping.
type deviceCodeEnvelope struct {
	Request    *DeviceCodeRequest `json:"request"`
	DeviceCode string             `json:"device_code"`
}

// StoreDeviceCode stores a device code request and the user-code locator that points to it.
//
// Redis Cluster layout: the request lives at oidc:device_code:{<device digest>} and the locator at
// oidc:device_user_code:{<user-code digest>}. Every transaction touches only the request key, so no
// operation spans two slots.
func (s *RedisDeviceCodeStore) StoreDeviceCode(ctx context.Context, deviceCode string, request *DeviceCodeRequest, ttl time.Duration) error {
	encoded, err := s.encodeDeviceCodeRequest(deviceCode, request)
	if err != nil {
		return fmt.Errorf("failed to encode device code request: %w", err)
	}

	reference := s.deviceCodeReference(deviceCode)
	deviceKey := s.deviceCodeKey(reference)

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	handle := s.redis.GetWriteHandle()

	if err := handle.Set(writeCtx, deviceKey, encoded, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store device code: %w", err)
	}

	stored, err := handle.SetNX(writeCtx, s.userCodeKey(request.UserCode), reference, ttl).Result()
	if err == nil && stored {
		return nil
	}

	_ = handle.Del(writeCtx, deviceKey).Err()

	if err != nil {
		return fmt.Errorf("failed to store user code mapping: %w", err)
	}

	return ErrDeviceUserCodeCollision
}

// GetDeviceCode retrieves a device code request from Redis.
func (s *RedisDeviceCodeStore) GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCodeRequest, error) {
	request, _, err := s.readDeviceCode(ctx, s.deviceCodeReference(deviceCode))

	return request, err
}

// GetDeviceCodeByUserCode retrieves a device code request by looking up the user code.
func (s *RedisDeviceCodeStore) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (string, *DeviceCodeRequest, error) {
	readCtx, cancel := s.redisReadContext(ctx)
	reference, err := s.resolveUserCode(readCtx, s.redis.GetReadHandle(), userCode)

	cancel()

	if err != nil {
		if errors.Is(err, ErrDeviceCodeNotFound) {
			return "", nil, fmt.Errorf("user code not found or expired")
		}

		return "", nil, fmt.Errorf("failed to get user code mapping: %w", err)
	}

	request, deviceCode, err := s.readDeviceCode(ctx, reference)
	if err != nil {
		return "", nil, err
	}

	return deviceCode, request, nil
}

// readDeviceCode loads and decodes one device request by its digest reference.
func (s *RedisDeviceCodeStore) readDeviceCode(ctx context.Context, reference string) (*DeviceCodeRequest, string, error) {
	readCtx, cancel := s.redisReadContext(ctx)
	defer cancel()

	data, err := s.redis.GetReadHandle().Get(readCtx, s.deviceCodeKey(reference)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, "", fmt.Errorf("device code not found or expired")
		}

		return nil, "", fmt.Errorf("failed to get device code: %w", err)
	}

	return s.decodeDeviceCodeRequest(data)
}

// resolveUserCode follows a user-code locator to the digest reference of its device request.
func (s *RedisDeviceCodeStore) resolveUserCode(ctx context.Context, commands redis.Cmdable, userCode string) (string, error) {
	reference, err := redisDeviceCodeString(ctx, commands, s.userCodeKey(userCode))
	if err != nil {
		return "", err
	}

	if !isHexDigest(reference) {
		return "", ErrDeviceCodeNotFound
	}

	return reference, nil
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

// transitionDeviceCode runs one optimistic single-key transaction on a device request.
//
// WATCH covers only the request key, so the transaction stays in one Redis Cluster slot. The decision
// needs the decrypted request, which is why it runs in Go instead of Lua. The transition callback returns
// the request to persist (nil deletes the key) and the TTL is preserved. A transaction aborted by a
// concurrent write is re-evaluated on fresh state a bounded number of times.
func (s *RedisDeviceCodeStore) transitionDeviceCode(
	ctx context.Context,
	deviceKey string,
	transition func(current *DeviceCodeRequest, deviceCode string) (*DeviceCodeRequest, error),
) error {
	for range deviceCodeTransitionAttempts {
		err := s.transitionDeviceCodeOnce(ctx, deviceKey, transition)
		if !errors.Is(err, redis.TxFailedErr) {
			return err
		}
	}

	return ErrDeviceCodeConflict
}

// transitionDeviceCodeOnce performs a single WATCH/MULTI attempt of transitionDeviceCode.
func (s *RedisDeviceCodeStore) transitionDeviceCodeOnce(
	ctx context.Context,
	deviceKey string,
	transition func(current *DeviceCodeRequest, deviceCode string) (*DeviceCodeRequest, error),
) error {
	return s.redis.GetWriteHandle().Watch(ctx, func(tx *redis.Tx) error {
		encoded, err := redisDeviceCodeString(ctx, tx, deviceKey)
		if err != nil {
			return err
		}

		current, deviceCode, err := s.decodeDeviceCodeRequest(encoded)
		if err != nil {
			return err
		}

		next, err := transition(current, deviceCode)
		if err != nil {
			return err
		}

		return s.persistDeviceCodeTransition(ctx, tx, deviceKey, deviceCode, next)
	}, deviceKey)
}

// persistDeviceCodeTransition writes or deletes the request inside the watched MULTI/EXEC block.
func (s *RedisDeviceCodeStore) persistDeviceCodeTransition(
	ctx context.Context,
	tx *redis.Tx,
	deviceKey string,
	deviceCode string,
	next *DeviceCodeRequest,
) error {
	if next == nil {
		_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Del(ctx, deviceKey)

			return nil
		})

		return err
	}

	ttl, err := redisDeviceCodeTTL(ctx, tx, deviceKey)
	if err != nil {
		return err
	}

	encoded, err := s.encodeDeviceCodeRequest(deviceCode, next)
	if err != nil {
		return err
	}

	_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, deviceKey, encoded, ttl)

		return nil
	})

	return err
}

// ClaimAuthorizedDeviceCode atomically consumes an authorized request for its bound client.
func (s *RedisDeviceCodeStore) ClaimAuthorizedDeviceCode(
	ctx context.Context,
	deviceCode string,
	clientID string,
) (*DeviceCodeRequest, error) {
	if deviceCode == "" || clientID == "" {
		return nil, ErrDeviceCodeConflict
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	var claimed *DeviceCodeRequest

	err := s.transitionDeviceCode(writeCtx, s.deviceCodeKey(s.deviceCodeReference(deviceCode)),
		func(request *DeviceCodeRequest, storedCode string) (*DeviceCodeRequest, error) {
			if storedCode != deviceCode || request.ClientID != clientID || request.Status != DeviceCodeStatusAuthorized ||
				!request.VerificationLocked || time.Now().After(request.ExpiresAt) {
				return nil, ErrDeviceCodeConflict
			}

			claimed = request

			return nil, nil
		})
	if err != nil {
		return nil, fmt.Errorf("claim authorized device code: %w", err)
	}

	return claimed, nil
}

// ClaimDeviceCodeByUserCode resolves the user code and locks its device request in one transaction.
//
// The lock flag inside the request makes the claim single-use; the user-code locator lives in another
// slot and is removed afterwards on a best-effort basis.
func (s *RedisDeviceCodeStore) ClaimDeviceCodeByUserCode(
	ctx context.Context,
	userCode string,
) (string, *DeviceCodeRequest, error) {
	userCode = NormalizeDeviceUserCode(userCode)
	if userCode == "" {
		return "", nil, ErrDeviceCodeNotFound
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	handle := s.redis.GetWriteHandle()

	reference, err := s.resolveUserCode(writeCtx, handle, userCode)
	if err != nil {
		return "", nil, fmt.Errorf("claim device code mapping: %w", err)
	}

	var (
		claimed    *DeviceCodeRequest
		deviceCode string
	)

	err = s.transitionDeviceCode(writeCtx, s.deviceCodeKey(reference),
		func(request *DeviceCodeRequest, storedCode string) (*DeviceCodeRequest, error) {
			if !deviceCodeClaimable(request, userCode) {
				return nil, ErrDeviceCodeConflict
			}

			request.VerificationLocked = true
			claimed, deviceCode = request, storedCode

			return request, nil
		})
	if err != nil {
		return "", nil, fmt.Errorf("claim device code: %w", err)
	}

	_ = handle.Del(writeCtx, s.userCodeKey(userCode)).Err()

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

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	err := s.transitionDeviceCode(writeCtx, s.deviceCodeKey(s.deviceCodeReference(deviceCode)),
		func(current *DeviceCodeRequest, storedCode string) (*DeviceCodeRequest, error) {
			if storedCode != deviceCode || !deviceCodeTerminalTransitionValid(current, desired) {
				return nil, ErrDeviceCodeConflict
			}

			return desired, nil
		})
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

// decodeDeviceCodeRequest decrypts one stored envelope and returns the request with its device code.
func (s *RedisDeviceCodeStore) decodeDeviceCodeRequest(encoded string) (*DeviceCodeRequest, string, error) {
	plain, err := s.redis.GetSecurityManager().Decrypt(encoded)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt device code data: %w", err)
	}

	envelope := &deviceCodeEnvelope{}
	if err = json.Unmarshal([]byte(plain), envelope); err != nil {
		return nil, "", fmt.Errorf("unmarshal device code request: %w", err)
	}

	if envelope.Request == nil || envelope.DeviceCode == "" {
		return nil, "", fmt.Errorf("unmarshal device code request: incomplete envelope")
	}

	return envelope.Request, envelope.DeviceCode, nil
}

// encodeDeviceCodeRequest encrypts one request together with its device code.
func (s *RedisDeviceCodeStore) encodeDeviceCodeRequest(deviceCode string, request *DeviceCodeRequest) (string, error) {
	data, err := json.Marshal(deviceCodeEnvelope{Request: request, DeviceCode: deviceCode})
	if err != nil {
		return "", fmt.Errorf("marshal device code request: %w", err)
	}

	encoded, err := s.redis.GetSecurityManager().Encrypt(string(data))
	if err != nil {
		return "", fmt.Errorf("encrypt device code data: %w", err)
	}

	return encoded, nil
}

// UpdateDeviceCode overwrites a live request and keeps its TTL.
//
// SET XX KEEPTTL never recreates a request that was claimed, deleted, or expired in the meantime.
func (s *RedisDeviceCodeStore) UpdateDeviceCode(ctx context.Context, deviceCode string, request *DeviceCodeRequest) error {
	encoded, err := s.encodeDeviceCodeRequest(deviceCode, request)
	if err != nil {
		return fmt.Errorf("failed to encode device code request: %w", err)
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	key := s.deviceCodeKey(s.deviceCodeReference(deviceCode))

	err = s.redis.GetWriteHandle().SetArgs(writeCtx, key, encoded, redis.SetArgs{Mode: "XX", KeepTTL: true}).Err()
	if errors.Is(err, redis.Nil) {
		return fmt.Errorf("device code not found or expired")
	}

	return err
}

// RecordDeviceCodePoll merges only the poll timestamp into the stored request.
//
// Every other field keeps its stored value, so a poll can never overwrite a concurrent claim or completion,
// and a consumed request stays consumed.
func (s *RedisDeviceCodeStore) RecordDeviceCodePoll(ctx context.Context, deviceCode string, polledAt time.Time) error {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	return s.transitionDeviceCode(writeCtx, s.deviceCodeKey(s.deviceCodeReference(deviceCode)),
		func(current *DeviceCodeRequest, storedCode string) (*DeviceCodeRequest, error) {
			if storedCode != deviceCode {
				return nil, ErrDeviceCodeConflict
			}

			current.LastPoll = polledAt

			return current, nil
		})
}

// DeleteDeviceCode removes a device code and its user code mapping from Redis.
func (s *RedisDeviceCodeStore) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	// Get the request to find the user code
	request, err := s.GetDeviceCode(ctx, deviceCode)
	if err == nil && request != nil {
		writeCtx, cancel := s.redisWriteContext(ctx)
		_ = s.redis.GetWriteHandle().Del(writeCtx, s.userCodeKey(request.UserCode)).Err()

		cancel()
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	return s.redis.GetWriteHandle().Del(writeCtx, s.deviceCodeKey(s.deviceCodeReference(deviceCode))).Err()
}

// deviceCodeReference hides the bearer device code behind a keyed, domain-separated digest.
func (s *RedisDeviceCodeStore) deviceCodeReference(deviceCode string) string {
	return s.redis.GetSecurityManager().IndexDigest(deviceCodeDigestNamespace, deviceCode)
}

// deviceCodeKey returns the request key of one device-code digest in its own hash slot.
func (s *RedisDeviceCodeStore) deviceCodeKey(reference string) string {
	return s.prefix + "oidc:device_code:{" + reference + "}"
}

// userCodeKey returns the locator key of one normalized user code in its own hash slot.
func (s *RedisDeviceCodeStore) userCodeKey(userCode string) string {
	reference := s.redis.GetSecurityManager().IndexDigest(deviceUserCodeDigestNamespace, NormalizeDeviceUserCode(userCode))

	return s.prefix + "oidc:device_user_code:{" + reference + "}"
}

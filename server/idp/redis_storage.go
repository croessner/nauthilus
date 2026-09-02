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
	"crypto/sha256"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/idp/clientauth"
	"github.com/croessner/nauthilus/v4/server/idp/dcr"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/util"
	jsoniter "github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

var (
	// ErrClientAssertionReplayUnavailable indicates replay state could not be reserved.
	ErrClientAssertionReplayUnavailable = stderrors.New("client assertion replay protection is unavailable")
	// ErrClientAssertionReplayDetected indicates a private_key_jwt assertion was reused.
	ErrClientAssertionReplayDetected = stderrors.New("client assertion replay detected")
	// ErrDynamicRefreshTokenReuse indicates reuse of a consumed dynamic-client refresh token.
	ErrDynamicRefreshTokenReuse = stderrors.New("dynamic refresh token reuse detected")
	// ErrDynamicTokenRevoked indicates a concurrent user-wide token revocation won the race.
	ErrDynamicTokenRevoked = stderrors.New("dynamic user tokens were revoked")
)

const (
	oidcAccessTokenKeyKind       = "access_token"
	oidcRefreshTokenKeyKind      = "refresh_token"
	oidcUserAccessTokensKeyKind  = "user_access_tokens"
	oidcUserRefreshTokensKeyKind = "user_refresh_tokens"
	oidcDynamicRefreshConsumed   = "dynamic_refresh_consumed"
	oidcDynamicRefreshFamily     = "dynamic_refresh_family"
	oidcDynamicRefreshRevoked    = "dynamic_refresh_revoked"
	oidcDynamicUserEpoch         = "dynamic_user_epoch"
	oidcStaticRefreshToken       = "static_refresh_token"
	oidcStaticUserRefreshTokens  = "static_user_refresh_tokens"
)

const dynamicTrackedStoreScript = `
local epoch = redis.call('GET', KEYS[3]) or '0'
if epoch ~= ARGV[4] then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('SADD', KEYS[2], ARGV[3])
local current_ttl = redis.call('PTTL', KEYS[2])
if current_ttl < tonumber(ARGV[2]) then redis.call('PEXPIRE', KEYS[2], ARGV[2]) end
return 1
`

const dynamicInitialRefreshStoreScript = `
local epoch = redis.call('GET', KEYS[4]) or '0'
if epoch ~= ARGV[4] then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('SADD', KEYS[2], ARGV[3])
local current_ttl = redis.call('PTTL', KEYS[2])
if current_ttl < tonumber(ARGV[2]) then redis.call('PEXPIRE', KEYS[2], ARGV[2]) end
redis.call('SET', KEYS[3], ARGV[3], 'PX', ARGV[2])
return 1
`

const dynamicRefreshRotateScript = `
local epoch = redis.call('GET', KEYS[7]) or '0'
if epoch ~= ARGV[7] then return 4 end
if redis.call('EXISTS', KEYS[6]) == 1 then return 3 end
if redis.call('EXISTS', KEYS[1]) == 0 then
  if redis.call('EXISTS', KEYS[3]) == 1 then
    local active = redis.call('GET', KEYS[5])
    if active then redis.call('DEL', ARGV[6] .. active) end
    redis.call('DEL', KEYS[5])
    redis.call('SET', KEYS[6], '1', 'PX', ARGV[4])
    return 2
  end
  return 0
end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[4], ARGV[1])
redis.call('SET', KEYS[3], ARGV[3], 'PX', ARGV[4])
redis.call('SET', KEYS[2], ARGV[5], 'PX', ARGV[4])
redis.call('SADD', KEYS[4], ARGV[2])
redis.call('PEXPIRE', KEYS[4], ARGV[4])
redis.call('SET', KEYS[5], ARGV[2], 'PX', ARGV[4])
return 1
`

const dynamicRefreshResolveScript = `
local data = redis.call('GET', KEYS[1])
if data then return {1, data} end
local family = redis.call('GET', KEYS[2])
if not family then return {0} end
local active = redis.call('GET', ARGV[1] .. family)
if active then redis.call('DEL', ARGV[2] .. active) end
redis.call('DEL', ARGV[1] .. family)
redis.call('SET', ARGV[3] .. family, '1', 'PX', ARGV[4])
return {2}
`

const staticRefreshConsumeScript = `
local epoch = redis.call('GET', KEYS[3]) or '0'
if epoch ~= ARGV[2] then return {2} end
local data = redis.call('GET', KEYS[1])
if not data then return {0} end
if data ~= ARGV[3] then return {3} end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
return {1, data}
`

const staticRefreshDeleteScript = `
local existed = redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
return existed
`

// ClientAssertionReplayStore reserves private_key_jwt assertion identifiers.
type ClientAssertionReplayStore interface {
	ReserveClientAssertionJWTID(ctx context.Context, clientID, audience, jwtID string, expiresAt time.Time) error
}

// OIDCSession represents the data stored in Redis for an OIDC authorization flow.
type OIDCSession struct {
	Scopes               []string `json:"scopes"`
	ClientID             string   `json:"client_id"`
	UserID               string   `json:"user_id"`
	Username             string   `json:"username"`
	DisplayName          string   `json:"display_name"`
	RedirectURI          string   `json:"redirect_uri"`
	MFAMethod            string   `json:"mfa_method,omitempty"`
	Nonce                string   `json:"nonce,omitempty"`
	CodeChallenge        string   `json:"code_challenge,omitempty"`
	CodeChallengeMethod  string   `json:"code_challenge_method,omitempty"`
	AccessToken          string   `json:"access_token,omitempty"`
	AccessTokenAudience  string   `json:"access_token_audience,omitempty"`
	AccessTokenIssuer    string   `json:"access_token_issuer,omitempty"`
	RefreshFamilyID      string   `json:"refresh_family_id,omitempty"`
	DynamicUserEpoch     string   `json:"dynamic_user_epoch,omitempty"`
	staticRefreshData    string
	IDTokenClaims        map[string]any `json:"id_token_claims"`
	AccessTokenClaims    map[string]any `json:"access_token_claims"`
	AuthTime             time.Time      `json:"auth_time"`
	AccessTokenIssuedAt  time.Time      `json:"access_token_issued_at,omitzero"`
	AccessTokenExpiresAt time.Time      `json:"access_token_expires_at,omitzero"`
	RequiredMFALevel     int            `json:"required_mfa_level,omitempty"`
	MFACompleted         bool           `json:"mfa_completed,omitempty"`
	ServiceToken         bool           `json:"service_token,omitempty"`
}

// RedisTokenStorage handles OIDC token/session persistence in Redis.
type RedisTokenStorage struct {
	redis   rediscli.Client
	cfg     config.File
	auditor dcr.Auditor
	prefix  string
}

// NewRedisTokenStorage creates a new RedisTokenStorage.
func NewRedisTokenStorage(redis rediscli.Client, prefix string) *RedisTokenStorage {
	return NewRedisTokenStorageWithConfig(redis, prefix, nil)
}

// NewRedisTokenStorageWithConfig creates a new RedisTokenStorage with configured Redis operation deadlines.
func NewRedisTokenStorageWithConfig(redis rediscli.Client, prefix string, cfg config.File, auditors ...dcr.Auditor) *RedisTokenStorage {
	auditor := dcr.NewSlogAuditor(nil)
	if len(auditors) > 0 && auditors[0] != nil {
		auditor = auditors[0]
	}

	return &RedisTokenStorage{redis: redis, cfg: cfg, auditor: auditor, prefix: prefix}
}

func (s *RedisTokenStorage) redisReadContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return util.GetCtxWithDeadlineRedisRead(ctx, s.cfg)
}

func (s *RedisTokenStorage) redisWriteContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return util.GetCtxWithDeadlineRedisWrite(ctx, s.cfg)
}

// ReserveClientAssertionJWTID atomically stores a scoped private_key_jwt jti replay marker.
func (s *RedisTokenStorage) ReserveClientAssertionJWTID(ctx context.Context, clientID, audience, jwtID string, expiresAt time.Time) error {
	clientID = strings.TrimSpace(clientID)
	audience = strings.TrimSpace(audience)
	jwtID = strings.TrimSpace(jwtID)

	if s == nil || s.redis == nil || clientID == "" || audience == "" || jwtID == "" || expiresAt.IsZero() {
		return ErrClientAssertionReplayUnavailable
	}

	ttl := time.Until(expiresAt) + clientauth.DefaultPrivateKeyJWTClockSkew
	if ttl <= 0 {
		return ErrClientAssertionReplayUnavailable
	}

	handle := s.redis.GetWriteHandle()
	if handle == nil {
		return ErrClientAssertionReplayUnavailable
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	stored, err := handle.SetNX(writeCtx, s.clientAssertionReplayKey(clientID, audience, jwtID), "1", ttl).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrClientAssertionReplayUnavailable, err)
	}

	if !stored {
		return ErrClientAssertionReplayDetected
	}

	return nil
}

// clientAssertionReplayKey returns the bounded Redis key for a scoped assertion jti.
func (s *RedisTokenStorage) clientAssertionReplayKey(clientID, audience, jwtID string) string {
	replayScope := strings.TrimSpace(clientID) + "\x1f" + strings.TrimSpace(audience) + "\x1f" + strings.TrimSpace(jwtID)
	sum := sha256.Sum256([]byte(replayScope))

	return s.prefix + "oidc:client_assertion:replay:" + hex.EncodeToString(sum[:])
}

// oidcKey returns a Redis key in the existing oidc:<kind>:<value> namespace.
func (s *RedisTokenStorage) oidcKey(kind string, value string) string {
	return s.prefix + fmt.Sprintf("oidc:%s:%s", kind, value)
}

// StoreSession stores an OIDC session with a given code and TTL.
func (s *RedisTokenStorage) StoreSession(ctx context.Context, code string, session *OIDCSession, ttl time.Duration) error {
	return s.storeSessionAtKey(ctx, s.oidcKey("code", code), session, ttl)
}

// GetSession retrieves an OIDC session from Redis.
func (s *RedisTokenStorage) GetSession(ctx context.Context, code string) (*OIDCSession, error) {
	return s.getSessionAtKey(ctx, s.oidcKey("code", code))
}

// ConsumeSession atomically reads and removes a one-time authorization code.
func (s *RedisTokenStorage) ConsumeSession(ctx context.Context, code string) (*OIDCSession, error) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	data, err := s.redis.GetWriteHandle().GetDel(writeCtx, s.oidcKey("code", code)).Result()
	if err != nil {
		return nil, err
	}

	return s.decryptSession(data)
}

// DeleteSession removes an OIDC session from Redis.
func (s *RedisTokenStorage) DeleteSession(ctx context.Context, code string) error {
	return s.deleteKey(ctx, s.oidcKey("code", code))
}

// StoreRefreshToken stores a refresh token session in Redis and tracks it for the user.
func (s *RedisTokenStorage) StoreRefreshToken(ctx context.Context, token string, session *OIDCSession, ttl time.Duration) error {
	return s.storeStaticRefreshToken(ctx, token, session, ttl)
}

// GetRefreshToken retrieves authoritative epoch-bound static refresh state.
func (s *RedisTokenStorage) GetRefreshToken(ctx context.Context, token string) (*OIDCSession, error) {
	reference := s.staticRefreshTokenReference(token)

	return s.getEpochBoundSession(ctx, s.dynamicRefreshKey(oidcStaticRefreshToken, reference))
}

// ConsumeRefreshToken atomically claims one static refresh token for a single exchange.
func (s *RedisTokenStorage) ConsumeRefreshToken(ctx context.Context, token string, expected *OIDCSession) (*OIDCSession, error) {
	if expected == nil || expected.UserID == "" || expected.DynamicUserEpoch == "" {
		return nil, ErrDynamicTokenRevoked
	}

	if expected.staticRefreshData == "" {
		return nil, ErrDynamicTokenRevoked
	}

	reference := s.staticRefreshTokenReference(token)

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	keys := []string{
		s.dynamicRefreshKey(oidcStaticRefreshToken, reference),
		s.dynamicRefreshKey(oidcStaticUserRefreshTokens, expected.UserID),
		s.dynamicUserEpochKey(expected.UserID),
	}

	result, err := s.redis.GetWriteHandle().Eval(
		writeCtx,
		staticRefreshConsumeScript,
		keys,
		reference,
		expected.DynamicUserEpoch,
		expected.staticRefreshData,
	).Slice()
	if err != nil {
		return nil, err
	}

	return s.resolveStaticRefreshConsumeResult(result)
}

// resolveStaticRefreshConsumeResult decodes the bounded Lua consume response.
func (s *RedisTokenStorage) resolveStaticRefreshConsumeResult(result []any) (*OIDCSession, error) {
	if len(result) > 0 {
		status, ok := result[0].(int64)
		if !ok {
			return nil, fmt.Errorf("unexpected static refresh consume result")
		}

		switch status {
		case 1:
			if len(result) != 2 {
				return nil, fmt.Errorf("missing static refresh session")
			}

			data, ok := result[1].(string)
			if !ok {
				return nil, fmt.Errorf("invalid static refresh session")
			}

			return s.decryptSession(data)
		case 2:
			return nil, ErrDynamicTokenRevoked
		case 3:
			return nil, redis.Nil
		}
	}

	return nil, redis.Nil
}

// StoreInitialDynamicRefreshToken stores the first token and active family pointer atomically.
func (s *RedisTokenStorage) StoreInitialDynamicRefreshToken(ctx context.Context, token string, session *OIDCSession, ttl time.Duration) error {
	encryptedData, err := s.encryptSession(session)
	if err != nil {
		return err
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	tokenReference := s.dynamicTokenReference(token)
	keys := []string{
		s.dynamicRefreshKey(oidcRefreshTokenKeyKind, tokenReference),
		s.dynamicRefreshKey(oidcUserRefreshTokensKeyKind, session.UserID),
		s.dynamicRefreshFamilyKey(session.RefreshFamilyID),
		s.dynamicUserEpochKey(session.UserID),
	}

	result, err := s.redis.GetWriteHandle().Eval(
		writeCtx,
		dynamicInitialRefreshStoreScript,
		keys,
		encryptedData,
		ttl.Milliseconds(),
		tokenReference,
		session.DynamicUserEpoch,
	).Int64()
	if err != nil {
		return err
	}

	if result != 1 {
		return ErrDynamicTokenRevoked
	}

	return nil
}

// GetDynamicRefreshToken reads current state from the authoritative handle and revokes reused families.
func (s *RedisTokenStorage) GetDynamicRefreshToken(ctx context.Context, token string) (*OIDCSession, error) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	tokenReference := s.dynamicTokenReference(token)
	keys := []string{
		s.dynamicRefreshKey(oidcRefreshTokenKeyKind, tokenReference),
		s.dynamicRefreshKey(oidcDynamicRefreshConsumed, tokenReference),
	}
	arguments := []any{
		s.dynamicRefreshKey(oidcDynamicRefreshFamily, ""),
		s.dynamicRefreshKey(oidcRefreshTokenKeyKind, ""),
		s.dynamicRefreshKey(oidcDynamicRefreshRevoked, ""),
		(30 * 24 * time.Hour).Milliseconds(),
	}

	result, err := s.redis.GetWriteHandle().Eval(writeCtx, dynamicRefreshResolveScript, keys, arguments...).Slice()
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, redis.Nil
	}

	status, ok := result[0].(int64)
	if !ok {
		return nil, fmt.Errorf("unexpected dynamic refresh resolution result")
	}

	switch status {
	case 0:
		return nil, redis.Nil
	case 1:
		if len(result) != 2 {
			return nil, fmt.Errorf("missing dynamic refresh session")
		}

		data, ok := result[1].(string)
		if !ok {
			return nil, fmt.Errorf("invalid dynamic refresh session")
		}

		session, err := s.decryptSession(data)
		if err != nil {
			return nil, err
		}

		if err := s.validateDynamicUserEpoch(writeCtx, session); err != nil {
			return nil, err
		}

		return session, nil
	case 2:
		s.auditor.Record(ctx, dcr.AuditEvent{Operation: "refresh_replay", Outcome: dcr.AuditOutcomeRevoked, Reason: "ancestor_reuse"})

		return nil, ErrDynamicRefreshTokenReuse
	default:
		return nil, fmt.Errorf("unexpected dynamic refresh resolution status %d", status)
	}
}

// RotateDynamicRefreshToken atomically consumes the current token and installs its successor.
func (s *RedisTokenStorage) RotateDynamicRefreshToken(ctx context.Context, oldToken string, newToken string, session *OIDCSession, ttl time.Duration) error {
	encryptedData, err := s.encryptSession(session)
	if err != nil {
		return err
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	oldReference := s.dynamicTokenReference(oldToken)
	newReference := s.dynamicTokenReference(newToken)
	keys := []string{
		s.dynamicRefreshKey(oidcRefreshTokenKeyKind, oldReference),
		s.dynamicRefreshKey(oidcRefreshTokenKeyKind, newReference),
		s.dynamicRefreshKey(oidcDynamicRefreshConsumed, oldReference),
		s.dynamicRefreshKey(oidcUserRefreshTokensKeyKind, session.UserID),
		s.dynamicRefreshFamilyKey(session.RefreshFamilyID),
		s.dynamicRefreshKey(oidcDynamicRefreshRevoked, session.RefreshFamilyID),
		s.dynamicUserEpochKey(session.UserID),
	}
	arguments := []any{oldReference, newReference, session.RefreshFamilyID, ttl.Milliseconds(), encryptedData, s.dynamicRefreshKey(oidcRefreshTokenKeyKind, ""), session.DynamicUserEpoch}

	result, err := s.redis.GetWriteHandle().Eval(writeCtx, dynamicRefreshRotateScript, keys, arguments...).Int64()
	if err != nil {
		return err
	}

	switch result {
	case 1:
		return nil
	case 2, 3:
		return ErrDynamicRefreshTokenReuse
	case 4:
		s.auditor.Record(ctx, dcr.AuditEvent{Operation: "refresh_rotation", Outcome: dcr.AuditOutcomeRevoked, Reason: "user_epoch_changed", ClientID: session.ClientID})

		return ErrDynamicTokenRevoked
	default:
		return redis.Nil
	}
}

// dynamicRefreshFamilyKey returns the active-token pointer for one refresh family.
func (s *RedisTokenStorage) dynamicRefreshFamilyKey(familyID string) string {
	return s.dynamicRefreshKey(oidcDynamicRefreshFamily, familyID)
}

// dynamicRefreshKey pins refresh-family state to one Redis Cluster hash slot.
func (s *RedisTokenStorage) dynamicRefreshKey(kind string, value string) string {
	return s.prefix + "oidc:dcr:{dynamic}:" + kind + ":" + value
}

// dynamicUserEpochKey returns the per-user revocation authority key.
func (s *RedisTokenStorage) dynamicUserEpochKey(userID string) string {
	return s.dynamicRefreshKey(oidcDynamicUserEpoch, userID)
}

// DynamicUserEpoch reads the authoritative user-wide token revocation epoch.
func (s *RedisTokenStorage) DynamicUserEpoch(ctx context.Context, userID string) (string, error) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	epoch, err := s.redis.GetWriteHandle().Get(writeCtx, s.dynamicUserEpochKey(userID)).Result()
	if stderrors.Is(err, redis.Nil) {
		return "0", nil
	}

	if err != nil {
		return "", err
	}

	return epoch, nil
}

// validateDynamicUserEpoch rejects epoch-bound state issued before a user-wide revocation.
func (s *RedisTokenStorage) validateDynamicUserEpoch(ctx context.Context, session *OIDCSession) error {
	if session == nil || session.DynamicUserEpoch == "" {
		return ErrDynamicTokenRevoked
	}

	epoch, err := s.redis.GetWriteHandle().Get(ctx, s.dynamicUserEpochKey(session.UserID)).Result()
	if stderrors.Is(err, redis.Nil) {
		epoch = "0"
	} else if err != nil {
		return err
	}

	if epoch != session.DynamicUserEpoch {
		return ErrDynamicTokenRevoked
	}

	return nil
}

// advanceDynamicUserEpoch invalidates every epoch-bound token minted for an earlier epoch.
func (s *RedisTokenStorage) advanceDynamicUserEpoch(ctx context.Context, userID string) error {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	return s.redis.GetWriteHandle().Incr(writeCtx, s.dynamicUserEpochKey(userID)).Err()
}

// dynamicTokenReference hides bearer credentials from Redis keys and indices.
func (s *RedisTokenStorage) dynamicTokenReference(token string) string {
	return s.redis.GetSecurityManager().IndexDigest("oidc-dynamic-refresh", token)
}

// DeleteRefreshToken removes a refresh token session from Redis and its user tracking.
func (s *RedisTokenStorage) DeleteRefreshToken(ctx context.Context, token string) error {
	session, err := s.GetRefreshToken(ctx, token)
	if stderrors.Is(err, redis.Nil) {
		return nil
	}

	if err != nil {
		return err
	}

	reference := s.staticRefreshTokenReference(token)

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	staticKeys := []string{
		s.dynamicRefreshKey(oidcStaticRefreshToken, reference),
		s.dynamicRefreshKey(oidcStaticUserRefreshTokens, session.UserID),
	}

	return s.redis.GetWriteHandle().Eval(writeCtx, staticRefreshDeleteScript, staticKeys, reference).Err()
}

// DeleteUserRefreshTokens removes all refresh tokens for a given user from Redis.
func (s *RedisTokenStorage) DeleteUserRefreshTokens(ctx context.Context, userID string) error {
	staticErr := s.deleteUserStaticRefreshTokens(ctx, userID)
	dynamicErr := s.deleteUserDynamicRefreshTokens(ctx, userID)

	return stderrors.Join(staticErr, dynamicErr)
}

// deleteUserStaticRefreshTokens removes epoch-bound static refresh state authoritatively.
func (s *RedisTokenStorage) deleteUserStaticRefreshTokens(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	handle := s.redis.GetWriteHandle()
	indexKey := s.dynamicRefreshKey(oidcStaticUserRefreshTokens, userID)

	references, err := handle.SMembers(writeCtx, indexKey).Result()
	if err != nil && !stderrors.Is(err, redis.Nil) {
		return err
	}

	pipe := handle.Pipeline()
	for _, reference := range references {
		pipe.Del(writeCtx, s.dynamicRefreshKey(oidcStaticRefreshToken, reference))
	}

	pipe.Del(writeCtx, indexKey)
	_, err = pipe.Exec(writeCtx)

	return err
}

// DeleteDynamicRefreshToken revokes one active dynamic refresh family.
func (s *RedisTokenStorage) DeleteDynamicRefreshToken(ctx context.Context, token string) error {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	tokenReference := s.dynamicTokenReference(token)

	session, err := s.dynamicRefreshSessionByReference(writeCtx, tokenReference)
	if err != nil {
		return err
	}

	return s.revokeDynamicRefreshSession(writeCtx, tokenReference, session)
}

// deleteUserDynamicRefreshTokens revokes every active DCR refresh family for a user.
func (s *RedisTokenStorage) deleteUserDynamicRefreshTokens(ctx context.Context, userID string) error {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	handle := s.redis.GetWriteHandle()
	indexKey := s.dynamicRefreshKey(oidcUserRefreshTokensKeyKind, userID)

	references, err := handle.SMembers(writeCtx, indexKey).Result()
	if err != nil && !stderrors.Is(err, redis.Nil) {
		return err
	}

	var result error

	for _, reference := range references {
		session, getErr := s.dynamicRefreshSessionByReference(writeCtx, reference)
		if stderrors.Is(getErr, redis.Nil) {
			continue
		}

		if getErr != nil {
			result = stderrors.Join(result, getErr)

			continue
		}

		result = stderrors.Join(result, s.revokeDynamicRefreshSession(writeCtx, reference, session))
	}

	result = stderrors.Join(result, handle.Del(writeCtx, indexKey).Err())

	return result
}

// dynamicRefreshSessionByReference loads an active dynamic refresh session without bearer material.
func (s *RedisTokenStorage) dynamicRefreshSessionByReference(ctx context.Context, reference string) (*OIDCSession, error) {
	data, err := s.redis.GetWriteHandle().Get(ctx, s.dynamicRefreshKey(oidcRefreshTokenKeyKind, reference)).Result()
	if err != nil {
		return nil, err
	}

	return s.decryptSession(data)
}

// revokeDynamicRefreshSession removes active state and leaves a bounded family marker.
func (s *RedisTokenStorage) revokeDynamicRefreshSession(ctx context.Context, reference string, session *OIDCSession) error {
	pipe := s.redis.GetWriteHandle().TxPipeline()
	pipe.Del(ctx, s.dynamicRefreshKey(oidcRefreshTokenKeyKind, reference))
	pipe.SRem(ctx, s.dynamicRefreshKey(oidcUserRefreshTokensKeyKind, session.UserID), reference)
	pipe.Del(ctx, s.dynamicRefreshFamilyKey(session.RefreshFamilyID))
	pipe.Set(ctx, s.dynamicRefreshKey(oidcDynamicRefreshRevoked, session.RefreshFamilyID), "1", 30*24*time.Hour)
	_, err := pipe.Exec(ctx)

	return err
}

// StoreAccessToken stores an opaque access token in Redis and tracks it for the user.
func (s *RedisTokenStorage) StoreAccessToken(ctx context.Context, token string, session *OIDCSession, ttl time.Duration) error {
	return s.storeDynamicAccessToken(ctx, s.accessTokenReference(token), session, ttl)
}

// GetAccessToken retrieves an opaque access token session from Redis.
func (s *RedisTokenStorage) GetAccessToken(ctx context.Context, token string) (*OIDCSession, error) {
	return s.getDynamicAccessToken(ctx, s.accessTokenReference(token))
}

// GetAccessTokenAuthoritative retrieves an opaque access token from the write handle.
func (s *RedisTokenStorage) GetAccessTokenAuthoritative(ctx context.Context, token string) (*OIDCSession, error) {
	return s.getDynamicAccessToken(ctx, s.accessTokenReference(token))
}

// DeleteAccessToken removes an opaque access token from Redis and its user tracking.
func (s *RedisTokenStorage) DeleteAccessToken(ctx context.Context, token string) error {
	return s.deleteDynamicAccessToken(ctx, s.accessTokenReference(token))
}

// accessTokenReference selects a stable digest domain for each opaque token class.
func (s *RedisTokenStorage) accessTokenReference(token string) string {
	if isDynamicAccessToken(token) {
		return s.dynamicAccessTokenReference(token)
	}

	return s.redis.GetSecurityManager().IndexDigest("oidc-static-access", token)
}

// dynamicAccessTokenReference hides a dynamic bearer token from Redis keys and indices.
func (s *RedisTokenStorage) dynamicAccessTokenReference(token string) string {
	return s.redis.GetSecurityManager().IndexDigest("oidc-dynamic-access", token)
}

// isDynamicAccessToken identifies the dedicated opaque dynamic-client token namespace.
func isDynamicAccessToken(token string) bool {
	return strings.HasPrefix(token, definitions.OIDCTokenPrefixAccessToken+dcr.ClientIDPrefix)
}

// storeDynamicAccessToken atomically binds opaque access state to the current user revocation epoch.
func (s *RedisTokenStorage) storeDynamicAccessToken(ctx context.Context, reference string, session *OIDCSession, ttl time.Duration) error {
	if session == nil {
		return ErrDynamicTokenRevoked
	}

	return s.storeEpochBoundToken(
		ctx,
		s.dynamicRefreshKey(oidcAccessTokenKeyKind, reference),
		s.dynamicRefreshKey(oidcUserAccessTokensKeyKind, session.UserID),
		reference,
		session,
		ttl,
	)
}

// getDynamicAccessToken validates encrypted access-token state against the user epoch.
func (s *RedisTokenStorage) getDynamicAccessToken(ctx context.Context, reference string) (*OIDCSession, error) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	data, err := s.redis.GetWriteHandle().Get(writeCtx, s.dynamicRefreshKey(oidcAccessTokenKeyKind, reference)).Result()
	if err != nil {
		return nil, err
	}

	session, err := s.decryptSession(data)
	if err != nil {
		return nil, err
	}

	if err := s.validateDynamicUserEpoch(writeCtx, session); err != nil {
		return nil, err
	}

	return session, nil
}

// deleteDynamicAccessToken removes a dynamic access token and its user index entry.
func (s *RedisTokenStorage) deleteDynamicAccessToken(ctx context.Context, reference string) error {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	key := s.dynamicRefreshKey(oidcAccessTokenKeyKind, reference)

	data, err := s.redis.GetWriteHandle().Get(writeCtx, key).Result()
	if stderrors.Is(err, redis.Nil) {
		return nil
	}

	if err != nil {
		return err
	}

	session, err := s.decryptSession(data)
	if err != nil {
		return err
	}

	pipe := s.redis.GetWriteHandle().TxPipeline()
	pipe.Del(writeCtx, key)
	pipe.SRem(writeCtx, s.dynamicRefreshKey(oidcUserAccessTokensKeyKind, session.UserID), reference)
	_, err = pipe.Exec(writeCtx)

	return err
}

// DeleteUserAccessTokens removes all access tokens for a given user from Redis.
func (s *RedisTokenStorage) DeleteUserAccessTokens(ctx context.Context, userID string) error {
	return s.deleteUserDynamicAccessTokens(ctx, userID)
}

// deleteUserDynamicAccessTokens removes the bounded dynamic access-token index for a user.
func (s *RedisTokenStorage) deleteUserDynamicAccessTokens(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	handle := s.redis.GetWriteHandle()
	indexKey := s.dynamicRefreshKey(oidcUserAccessTokensKeyKind, userID)

	references, err := handle.SMembers(writeCtx, indexKey).Result()
	if err != nil && !stderrors.Is(err, redis.Nil) {
		return err
	}

	if len(references) == 0 {
		return nil
	}

	pipe := handle.Pipeline()

	for _, reference := range references {
		pipe.Del(writeCtx, s.dynamicRefreshKey(oidcAccessTokenKeyKind, reference))
	}

	pipe.Del(writeCtx, indexKey)
	_, err = pipe.Exec(writeCtx)

	return err
}

// storeSessionAtKey stores one encrypted OIDC session at a concrete Redis key.
func (s *RedisTokenStorage) storeSessionAtKey(ctx context.Context, key string, session *OIDCSession, ttl time.Duration) error {
	encryptedData, err := s.encryptSession(session)
	if err != nil {
		return err
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	return s.redis.GetWriteHandle().Set(writeCtx, key, encryptedData, ttl).Err()
}

// encryptSession serializes and encrypts one OIDC session.
func (s *RedisTokenStorage) encryptSession(session *OIDCSession) (string, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return "", err
	}

	return s.redis.GetSecurityManager().Encrypt(string(data))
}

// decryptSession decrypts and decodes one OIDC session.
func (s *RedisTokenStorage) decryptSession(data string) (*OIDCSession, error) {
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

// getSessionAtKey retrieves and decrypts one OIDC session from a concrete Redis key.
func (s *RedisTokenStorage) getSessionAtKey(ctx context.Context, key string) (*OIDCSession, error) {
	readCtx, cancel := s.redisReadContext(ctx)
	defer cancel()

	data, err := s.redis.GetReadHandle().Get(readCtx, key).Result()
	if err != nil {
		return nil, err
	}

	return s.decryptSession(data)
}

// deleteKey removes one concrete Redis key through the write handle.
func (s *RedisTokenStorage) deleteKey(ctx context.Context, key string) error {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	return s.redis.GetWriteHandle().Del(writeCtx, key).Err()
}

// storeStaticRefreshToken binds static refresh state to the current user revocation epoch.
func (s *RedisTokenStorage) storeStaticRefreshToken(ctx context.Context, token string, session *OIDCSession, ttl time.Duration) error {
	reference := s.staticRefreshTokenReference(token)

	return s.storeEpochBoundToken(
		ctx,
		s.dynamicRefreshKey(oidcStaticRefreshToken, reference),
		s.dynamicRefreshKey(oidcStaticUserRefreshTokens, session.UserID),
		reference,
		session,
		ttl,
	)
}

// storeEpochBoundToken atomically stores token state only while its user epoch remains current.
func (s *RedisTokenStorage) storeEpochBoundToken(ctx context.Context, key string, indexKey string, reference string, session *OIDCSession, ttl time.Duration) error {
	if session == nil || session.DynamicUserEpoch == "" {
		return ErrDynamicTokenRevoked
	}

	encryptedData, err := s.encryptSession(session)
	if err != nil {
		return err
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	keys := []string{key, indexKey, s.dynamicUserEpochKey(session.UserID)}

	result, err := s.redis.GetWriteHandle().Eval(
		writeCtx,
		dynamicTrackedStoreScript,
		keys,
		encryptedData,
		ttl.Milliseconds(),
		reference,
		session.DynamicUserEpoch,
	).Int64()
	if err != nil {
		return err
	}

	if result != 1 {
		return ErrDynamicTokenRevoked
	}

	return nil
}

// staticRefreshTokenReference hides static bearer credentials from Redis keys and indices.
func (s *RedisTokenStorage) staticRefreshTokenReference(token string) string {
	return s.redis.GetSecurityManager().IndexDigest("oidc-static-refresh", token)
}

// getEpochBoundSession reads and validates token state against the authoritative user epoch.
func (s *RedisTokenStorage) getEpochBoundSession(ctx context.Context, key string) (*OIDCSession, error) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	data, err := s.redis.GetWriteHandle().Get(writeCtx, key).Result()
	if err != nil {
		return nil, err
	}

	session, err := s.decryptSession(data)
	if err != nil {
		return nil, err
	}

	if err := s.validateDynamicUserEpoch(writeCtx, session); err != nil {
		return nil, err
	}

	session.staticRefreshData = data

	return session, nil
}

// DenyJWTAccessToken adds a JWT access token to the denylist in Redis.
// The token is stored with a TTL so it expires automatically when the original token would have expired.
func (s *RedisTokenStorage) DenyJWTAccessToken(ctx context.Context, token string, ttl time.Duration) error {
	if token == "" || ttl <= 0 {
		return nil
	}

	key := s.prefix + fmt.Sprintf("oidc:denied_access_token:%s", token)

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	return s.redis.GetWriteHandle().Set(writeCtx, key, "1", ttl).Err()
}

// IsJWTAccessTokenDenied checks authoritative revocation state without collapsing backend failures into absence.
func (s *RedisTokenStorage) IsJWTAccessTokenDenied(ctx context.Context, token string) (bool, error) {
	key := s.prefix + fmt.Sprintf("oidc:denied_access_token:%s", token)

	readCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	_, err := s.redis.GetWriteHandle().Get(readCtx, key).Result()
	if stderrors.Is(err, redis.Nil) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	return true, nil
}

// FlushUserTokens removes all OIDC access tokens and refresh tokens for a given user.
// It returns a combined error if any of the underlying deletions fail.
func (s *RedisTokenStorage) FlushUserTokens(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}

	epochErr := s.advanceDynamicUserEpoch(ctx, userID)
	if epochErr != nil {
		s.auditor.Record(ctx, dcr.AuditEvent{Operation: dcr.AuditOperationUserRevocation, Outcome: dcr.AuditOutcomeFailed, Reason: "epoch_update_failed"})

		return epochErr
	}

	accessErr := s.deleteUserDynamicAccessTokens(ctx, userID)
	refreshErr := stderrors.Join(s.deleteUserStaticRefreshTokens(ctx, userID), s.deleteUserDynamicRefreshTokens(ctx, userID))

	err := stderrors.Join(accessErr, refreshErr)
	if err != nil {
		s.auditor.Record(ctx, dcr.AuditEvent{Operation: dcr.AuditOperationUserRevocation, Outcome: dcr.AuditOutcomeFailed, Reason: "cleanup_failed"})

		return err
	}

	s.auditor.Record(ctx, dcr.AuditEvent{Operation: dcr.AuditOperationUserRevocation, Outcome: dcr.AuditOutcomeSuccess, Reason: "tokens_flushed"})

	return nil
}

// ListUserSessions returns all active OIDC sessions (via access tokens) for a user.
func (s *RedisTokenStorage) ListUserSessions(ctx context.Context, userID string) (map[string]*OIDCSession, error) {
	references, err := s.userSessionReferences(ctx, userID)
	if err != nil {
		return nil, err
	}

	sessions := make(map[string]*OIDCSession)

	for _, reference := range references {
		session, err := s.userSessionByReference(ctx, reference)
		if err == nil {
			sessions[s.userSessionManagementID(reference)] = session

			continue
		}

		s.removeStaleUserSessionReference(ctx, userID, reference)
	}

	return sessions, nil
}

type userSessionReference struct {
	value string
}

// userSessionReferences reads the epoch-bound opaque access-token index authoritatively.
func (s *RedisTokenStorage) userSessionReferences(ctx context.Context, userID string) ([]userSessionReference, error) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	handle := s.redis.GetWriteHandle()

	dynamic, err := handle.SMembers(writeCtx, s.dynamicRefreshKey(oidcUserAccessTokensKeyKind, userID)).Result()
	if err != nil {
		return nil, err
	}

	references := make([]userSessionReference, 0, len(dynamic))
	for _, value := range dynamic {
		references = append(references, userSessionReference{value: value})
	}

	return references, nil
}

// userSessionByReference loads one management-visible session without bearer exposure.
func (s *RedisTokenStorage) userSessionByReference(ctx context.Context, reference userSessionReference) (*OIDCSession, error) {
	return s.getDynamicAccessToken(ctx, reference.value)
}

// userSessionManagementID derives the stable non-secret identifier exposed by the management API.
func (s *RedisTokenStorage) userSessionManagementID(reference userSessionReference) string {
	sum := sha256.Sum256([]byte("dynamic\x1f" + reference.value))

	return hex.EncodeToString(sum[:])
}

// removeStaleUserSessionReference prunes an index entry after authoritative resolution fails.
func (s *RedisTokenStorage) removeStaleUserSessionReference(ctx context.Context, userID string, reference userSessionReference) {
	indexKey := s.dynamicRefreshKey(oidcUserAccessTokensKeyKind, userID)

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	_ = s.redis.GetWriteHandle().SRem(writeCtx, indexKey, reference.value).Err()
}

// DeleteUserSession removes one session selected through its non-secret management identifier.
func (s *RedisTokenStorage) DeleteUserSession(ctx context.Context, userID string, managementID string) error {
	references, err := s.userSessionReferences(ctx, userID)
	if err != nil {
		return err
	}

	for _, reference := range references {
		if s.userSessionManagementID(reference) != managementID {
			continue
		}

		return s.deleteDynamicAccessToken(ctx, reference.value)
	}

	return redis.Nil
}

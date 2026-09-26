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
	"encoding/json"
	stderrors "errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/idp/clientauth"
	"github.com/croessner/nauthilus/v4/server/idp/dcr"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/redis/go-redis/v9"
)

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
	oidcUserAccessTokensKeyKind  = "access_tokens"
	oidcUserRefreshTokensKeyKind = "refresh_tokens"
	oidcDynamicRefreshConsumed   = "refresh_consumed"
	oidcDynamicRefreshFamily     = "refresh_family"
	oidcDynamicRefreshRevoked    = "refresh_revoked"
	oidcStaticRefreshToken       = "static_refresh_token"
	oidcStaticUserRefreshTokens  = "static_refresh_tokens"
)

// oidcAuthorizationCodeDigestNamespace domain-separates authorization-code key digests.
const oidcAuthorizationCodeDigestNamespace = "oidc-authorization-code"

// oidcDynamicRefreshRevokedTTL bounds how long a revoked refresh family keeps rejecting its tokens.
const oidcDynamicRefreshRevokedTTL = 30 * 24 * time.Hour

// All token scripts below receive only keys of one subject slot (see oidcTokenKeys). Keys that a script
// derives from ARGV prefixes are built from the same subject slot, so Redis Cluster never sees a
// cross-slot access.

const dynamicTrackedStoreScript = `
local epoch = redis.call('GET', KEYS[3]) or '` + oidcSubjectEpochFloor + `'
if epoch ~= ARGV[4] then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('SADD', KEYS[2], ARGV[3])
local current_ttl = redis.call('PTTL', KEYS[2])
if current_ttl < tonumber(ARGV[2]) then redis.call('PEXPIRE', KEYS[2], ARGV[2]) end
return 1
`

const dynamicInitialRefreshStoreScript = `
local epoch = redis.call('GET', KEYS[4]) or '` + oidcSubjectEpochFloor + `'
if epoch ~= ARGV[4] then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('SADD', KEYS[2], ARGV[3])
local current_ttl = redis.call('PTTL', KEYS[2])
if current_ttl < tonumber(ARGV[2]) then redis.call('PEXPIRE', KEYS[2], ARGV[2]) end
redis.call('SET', KEYS[3], ARGV[3], 'PX', ARGV[2])
return 1
`

const dynamicRefreshRotateScript = `
local epoch = redis.call('GET', KEYS[7]) or '` + oidcSubjectEpochFloor + `'
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
if data then return {1, data, redis.call('GET', KEYS[3]) or '` + oidcSubjectEpochFloor + `'} end
local family = redis.call('GET', KEYS[2])
if not family then return {0} end
local active = redis.call('GET', ARGV[1] .. family)
if active then redis.call('DEL', ARGV[2] .. active) end
redis.call('DEL', ARGV[1] .. family)
redis.call('SET', ARGV[3] .. family, '1', 'PX', ARGV[4])
return {2}
`

const staticRefreshConsumeScript = `
local epoch = redis.call('GET', KEYS[3]) or '` + oidcSubjectEpochFloor + `'
if epoch ~= ARGV[2] then return {2} end
local data = redis.call('GET', KEYS[1])
if not data then return {0} end
if data ~= ARGV[3] then return {3} end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
return {1, data}
`

const trackedTokenDeleteScript = `
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
	AccessTokenResources []string `json:"access_token_resources,omitempty"`
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
	keys    oidcTokenKeys
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

	return &RedisTokenStorage{redis: redis, cfg: cfg, auditor: auditor, keys: oidcTokenKeys{prefix: prefix}, prefix: prefix}
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

// authorizationCodeKey returns the single-use code key without embedding the bearer code itself.
// Authorization codes and consent challenges are only referenced by their keyed, domain-separated digest.
func (s *RedisTokenStorage) authorizationCodeKey(code string) string {
	return s.oidcKey("code", s.redis.GetSecurityManager().IndexDigest(oidcAuthorizationCodeDigestNamespace, code))
}

// StoreSession stores an OIDC session with a given code and TTL.
func (s *RedisTokenStorage) StoreSession(ctx context.Context, code string, session *OIDCSession, ttl time.Duration) error {
	return s.storeSessionAtKey(ctx, s.authorizationCodeKey(code), session, ttl)
}

// GetSession retrieves an OIDC session from Redis.
func (s *RedisTokenStorage) GetSession(ctx context.Context, code string) (*OIDCSession, error) {
	return s.getSessionAtKey(ctx, s.authorizationCodeKey(code))
}

// ConsumeSession atomically reads and removes a one-time authorization code.
func (s *RedisTokenStorage) ConsumeSession(ctx context.Context, code string) (*OIDCSession, error) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	data, err := s.redis.GetWriteHandle().GetDel(writeCtx, s.authorizationCodeKey(code)).Result()
	if err != nil {
		return nil, err
	}

	return s.decryptSession(data)
}

// DeleteSession removes an OIDC session from Redis.
func (s *RedisTokenStorage) DeleteSession(ctx context.Context, code string) error {
	return s.deleteKey(ctx, s.authorizationCodeKey(code))
}

// StoreRefreshToken stores a refresh token session in Redis and tracks it for the user.
func (s *RedisTokenStorage) StoreRefreshToken(ctx context.Context, token string, session *OIDCSession, ttl time.Duration) error {
	return s.storeEpochBoundToken(ctx, oidcStaticRefreshToken, oidcStaticUserRefreshTokens, s.staticRefreshTokenReference(token), session, ttl)
}

// GetRefreshToken retrieves authoritative epoch-bound static refresh state.
func (s *RedisTokenStorage) GetRefreshToken(ctx context.Context, token string) (*OIDCSession, error) {
	reference := s.staticRefreshTokenReference(token)

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	owner, err := s.resolveTokenOwner(writeCtx, reference)
	if err != nil {
		return nil, err
	}

	session, data, err := s.loadEpochBoundSession(writeCtx, owner, owner.entry(oidcStaticRefreshToken, reference))
	if err != nil {
		return nil, err
	}

	session.staticRefreshData = data

	return session, nil
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
	owner := s.keys.subject(expected.UserID)

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	keys := []string{
		owner.entry(oidcStaticRefreshToken, reference),
		owner.index(oidcStaticUserRefreshTokens),
		owner.epoch(),
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

	session, err := s.resolveStaticRefreshConsumeResult(result)
	if err != nil {
		return nil, err
	}

	s.deleteTokenLocators(writeCtx, reference)

	return session, nil
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
	owner := s.keys.subject(session.UserID)
	keys := []string{
		owner.entry(oidcRefreshTokenKeyKind, tokenReference),
		owner.index(oidcUserRefreshTokensKeyKind),
		owner.entry(oidcDynamicRefreshFamily, session.RefreshFamilyID),
		owner.epoch(),
	}

	result, err := s.evalWithLocators(
		writeCtx,
		owner,
		ttl,
		[]string{tokenReference},
		dynamicInitialRefreshStoreScript,
		keys,
		encryptedData,
		ttl.Milliseconds(),
		tokenReference,
		session.DynamicUserEpoch,
	)
	if err != nil {
		return err
	}

	if result != 1 {
		s.deleteTokenLocators(writeCtx, tokenReference)

		return ErrDynamicTokenRevoked
	}

	return nil
}

// GetDynamicRefreshToken reads current state from the authoritative handle and revokes reused families.
func (s *RedisTokenStorage) GetDynamicRefreshToken(ctx context.Context, token string) (*OIDCSession, error) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	tokenReference := s.dynamicTokenReference(token)

	owner, err := s.resolveTokenOwner(writeCtx, tokenReference)
	if err != nil {
		return nil, err
	}

	keys := []string{
		owner.entry(oidcRefreshTokenKeyKind, tokenReference),
		owner.entry(oidcDynamicRefreshConsumed, tokenReference),
		owner.epoch(),
	}
	arguments := []any{
		owner.entry(oidcDynamicRefreshFamily, ""),
		owner.entry(oidcRefreshTokenKeyKind, ""),
		owner.entry(oidcDynamicRefreshRevoked, ""),
		oidcDynamicRefreshRevokedTTL.Milliseconds(),
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
		return s.decodeResolvedDynamicRefresh(owner, result)
	case 2:
		s.auditor.Record(ctx, dcr.AuditEvent{Operation: "refresh_replay", Outcome: dcr.AuditOutcomeRevoked, Reason: "ancestor_reuse"})

		return nil, ErrDynamicRefreshTokenReuse
	default:
		return nil, fmt.Errorf("unexpected dynamic refresh resolution status %d", status)
	}
}

// decodeResolvedDynamicRefresh validates an active refresh session against the epoch read by the same script.
func (s *RedisTokenStorage) decodeResolvedDynamicRefresh(owner oidcSubjectKeys, result []any) (*OIDCSession, error) {
	if len(result) != 3 {
		return nil, fmt.Errorf("missing dynamic refresh session")
	}

	data, dataOK := result[1].(string)
	epoch, epochOK := result[2].(string)

	if !dataOK || !epochOK {
		return nil, fmt.Errorf("invalid dynamic refresh session")
	}

	session, err := s.decryptSession(data)
	if err != nil {
		return nil, err
	}

	if err := verifyEpochBoundSession(owner, session, epoch); err != nil {
		return nil, err
	}

	return session, nil
}

// RotateDynamicRefreshToken atomically consumes the current token and installs its successor.
//
// The successor locator is published and the predecessor locator is renewed with the rotation TTL, so
// a replayed predecessor still reaches the consumed marker and triggers family revocation.
func (s *RedisTokenStorage) RotateDynamicRefreshToken(ctx context.Context, oldToken string, newToken string, session *OIDCSession, ttl time.Duration) error {
	encryptedData, err := s.encryptSession(session)
	if err != nil {
		return err
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	oldReference := s.dynamicTokenReference(oldToken)
	newReference := s.dynamicTokenReference(newToken)
	owner := s.keys.subject(session.UserID)
	keys := []string{
		owner.entry(oidcRefreshTokenKeyKind, oldReference),
		owner.entry(oidcRefreshTokenKeyKind, newReference),
		owner.entry(oidcDynamicRefreshConsumed, oldReference),
		owner.index(oidcUserRefreshTokensKeyKind),
		owner.entry(oidcDynamicRefreshFamily, session.RefreshFamilyID),
		owner.entry(oidcDynamicRefreshRevoked, session.RefreshFamilyID),
		owner.epoch(),
	}
	arguments := []any{
		oldReference,
		newReference,
		session.RefreshFamilyID,
		ttl.Milliseconds(),
		encryptedData,
		owner.entry(oidcRefreshTokenKeyKind, ""),
		session.DynamicUserEpoch,
	}

	result, err := s.evalWithLocators(writeCtx, owner, ttl, []string{newReference, oldReference}, dynamicRefreshRotateScript, keys, arguments...)
	if err != nil {
		return err
	}

	if result != 1 {
		s.deleteTokenLocators(writeCtx, newReference)
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

// DynamicUserEpoch reads the authoritative user-wide token revocation epoch.
func (s *RedisTokenStorage) DynamicUserEpoch(ctx context.Context, userID string) (string, error) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	epoch, err := s.redis.GetWriteHandle().Get(writeCtx, s.keys.subject(userID).epoch()).Result()
	if stderrors.Is(err, redis.Nil) {
		return oidcSubjectEpochFloor, nil
	}

	if err != nil {
		return "", err
	}

	return epoch, nil
}

// advanceDynamicUserEpoch invalidates every epoch-bound token minted for an earlier epoch.
// A subject without an epoch key starts at oidcSubjectEpochFloor, so the first revocation yields floor+1.
func (s *RedisTokenStorage) advanceDynamicUserEpoch(ctx context.Context, userID string) error {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	return s.redis.GetWriteHandle().Eval(writeCtx, subjectEpochAdvanceScript, []string{s.keys.subject(userID).epoch()}, oidcSubjectEpochFloor).Err()
}

// verifyEpochBoundSession rejects state outside its subject slot or issued before a subject-wide revocation.
func verifyEpochBoundSession(owner oidcSubjectKeys, session *OIDCSession, currentEpoch string) error {
	if !owner.owns(session) {
		return redis.Nil
	}

	if !isCurrentSubjectEpoch(session.DynamicUserEpoch, currentEpoch) {
		return ErrDynamicTokenRevoked
	}

	return nil
}

// resolveTokenOwner follows a bearer reference locator to the subject slot that holds the token state.
// A locator value that is not a subject digest is treated as absent, so it can never redirect key building.
func (s *RedisTokenStorage) resolveTokenOwner(ctx context.Context, reference string) (oidcSubjectKeys, error) {
	slot, err := s.redis.GetWriteHandle().Get(ctx, s.keys.locator(reference)).Result()
	if err != nil {
		return oidcSubjectKeys{}, err
	}

	if !isHexDigest(slot) {
		return oidcSubjectKeys{}, redis.Nil
	}

	return s.keys.subjectBySlot(slot), nil
}

// loadEpochBoundSession reads token state and its subject epoch in one same-slot round trip.
// It returns the encrypted record as well, so single-use consumers can compare it atomically later.
func (s *RedisTokenStorage) loadEpochBoundSession(ctx context.Context, owner oidcSubjectKeys, key string) (*OIDCSession, string, error) {
	values, err := s.redis.GetWriteHandle().MGet(ctx, key, owner.epoch()).Result()
	if err != nil {
		return nil, "", tokenStateReadError(err)
	}

	if len(values) != 2 {
		return nil, "", fmt.Errorf("unexpected token state read result")
	}

	data, ok := values[0].(string)
	if !ok {
		return nil, "", redis.Nil
	}

	epoch, ok := values[1].(string)
	if !ok {
		epoch = oidcSubjectEpochFloor
	}

	session, err := s.decryptSession(data)
	if err != nil {
		return nil, "", err
	}

	if err := verifyEpochBoundSession(owner, session, epoch); err != nil {
		return nil, "", err
	}

	return session, data, nil
}

// evalWithLocators runs one subject-slot script and publishes bearer locators in the same round trip.
//
// The locators live in their own slots, so they are written through a plain pipeline instead of the
// script. A locator without token state is harmless: a lookup through it finds no record. Callers
// remove locators again when the script rejects the write.
func (s *RedisTokenStorage) evalWithLocators(
	ctx context.Context,
	owner oidcSubjectKeys,
	ttl time.Duration,
	references []string,
	script string,
	keys []string,
	arguments ...any,
) (int64, error) {
	pipe := s.redis.GetWriteHandle().Pipeline()

	for _, reference := range references {
		pipe.Set(ctx, s.keys.locator(reference), owner.slot, ttl)
	}

	result := pipe.Eval(ctx, script, keys, arguments...)

	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}

	return result.Int64()
}

// deleteTokenLocators removes bearer locators on a best-effort basis.
// A surviving locator only points at a subject slot without token state and expires with its TTL.
func (s *RedisTokenStorage) deleteTokenLocators(ctx context.Context, references ...string) {
	if len(references) == 0 {
		return
	}

	pipe := s.redis.GetWriteHandle().Pipeline()

	for _, reference := range references {
		pipe.Del(ctx, s.keys.locator(reference))
	}

	_, _ = pipe.Exec(ctx)
}

// dynamicTokenReference hides bearer credentials from Redis keys and indices.
func (s *RedisTokenStorage) dynamicTokenReference(token string) string {
	return s.redis.GetSecurityManager().IndexDigest("oidc-dynamic-refresh", token)
}

// DeleteRefreshToken removes a refresh token session from Redis and its user tracking.
func (s *RedisTokenStorage) DeleteRefreshToken(ctx context.Context, token string) error {
	return s.deleteLocatedToken(ctx, oidcStaticRefreshToken, oidcStaticUserRefreshTokens, s.staticRefreshTokenReference(token))
}

// DeleteUserRefreshTokens removes all refresh tokens for a given user from Redis.
func (s *RedisTokenStorage) DeleteUserRefreshTokens(ctx context.Context, userID string) error {
	staticErr := s.deleteUserTrackedTokens(ctx, userID, oidcStaticRefreshToken, oidcStaticUserRefreshTokens)
	dynamicErr := s.deleteUserDynamicRefreshTokens(ctx, userID)

	return stderrors.Join(staticErr, dynamicErr)
}

// DeleteDynamicRefreshToken revokes one active dynamic refresh family.
func (s *RedisTokenStorage) DeleteDynamicRefreshToken(ctx context.Context, token string) error {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	tokenReference := s.dynamicTokenReference(token)

	owner, err := s.resolveTokenOwner(writeCtx, tokenReference)
	if err != nil {
		return err
	}

	session, err := s.dynamicRefreshSessionByReference(writeCtx, owner, tokenReference)
	if err != nil {
		return err
	}

	if err := s.revokeDynamicRefreshSession(writeCtx, owner, tokenReference, session); err != nil {
		return err
	}

	s.deleteTokenLocators(writeCtx, tokenReference)

	return nil
}

// deleteUserDynamicRefreshTokens revokes every active DCR refresh family for a user.
func (s *RedisTokenStorage) deleteUserDynamicRefreshTokens(ctx context.Context, userID string) error {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	handle := s.redis.GetWriteHandle()
	owner := s.keys.subject(userID)
	indexKey := owner.index(oidcUserRefreshTokensKeyKind)

	references, err := handle.SMembers(writeCtx, indexKey).Result()
	if err != nil && !stderrors.Is(err, redis.Nil) {
		return err
	}

	var result error

	for _, reference := range references {
		session, getErr := s.dynamicRefreshSessionByReference(writeCtx, owner, reference)
		if stderrors.Is(getErr, redis.Nil) {
			continue
		}

		if getErr != nil {
			result = stderrors.Join(result, getErr)

			continue
		}

		result = stderrors.Join(result, s.revokeDynamicRefreshSession(writeCtx, owner, reference, session))
	}

	result = stderrors.Join(result, handle.Del(writeCtx, indexKey).Err())
	s.deleteTokenLocators(writeCtx, references...)

	return result
}

// dynamicRefreshSessionByReference loads an active dynamic refresh session without bearer material.
func (s *RedisTokenStorage) dynamicRefreshSessionByReference(ctx context.Context, owner oidcSubjectKeys, reference string) (*OIDCSession, error) {
	data, err := s.redis.GetWriteHandle().Get(ctx, owner.entry(oidcRefreshTokenKeyKind, reference)).Result()
	if err != nil {
		return nil, err
	}

	return s.decryptSession(data)
}

// revokeDynamicRefreshSession removes active state and leaves a bounded family marker in one subject slot.
func (s *RedisTokenStorage) revokeDynamicRefreshSession(ctx context.Context, owner oidcSubjectKeys, reference string, session *OIDCSession) error {
	pipe := s.redis.GetWriteHandle().TxPipeline()
	pipe.Del(ctx, owner.entry(oidcRefreshTokenKeyKind, reference))
	pipe.SRem(ctx, owner.index(oidcUserRefreshTokensKeyKind), reference)
	pipe.Del(ctx, owner.entry(oidcDynamicRefreshFamily, session.RefreshFamilyID))
	pipe.Set(ctx, owner.entry(oidcDynamicRefreshRevoked, session.RefreshFamilyID), "1", oidcDynamicRefreshRevokedTTL)
	_, err := pipe.Exec(ctx)

	return err
}

// StoreAccessToken stores an opaque access token in Redis and tracks it for the user.
func (s *RedisTokenStorage) StoreAccessToken(ctx context.Context, token string, session *OIDCSession, ttl time.Duration) error {
	return s.storeEpochBoundToken(ctx, oidcAccessTokenKeyKind, oidcUserAccessTokensKeyKind, s.accessTokenReference(token), session, ttl)
}

// GetAccessToken retrieves an opaque access token session from Redis.
func (s *RedisTokenStorage) GetAccessToken(ctx context.Context, token string) (*OIDCSession, error) {
	return s.getAccessToken(ctx, s.accessTokenReference(token))
}

// GetAccessTokenAuthoritative retrieves an opaque access token from the write handle.
func (s *RedisTokenStorage) GetAccessTokenAuthoritative(ctx context.Context, token string) (*OIDCSession, error) {
	return s.getAccessToken(ctx, s.accessTokenReference(token))
}

// DeleteAccessToken removes an opaque access token from Redis and its user tracking.
func (s *RedisTokenStorage) DeleteAccessToken(ctx context.Context, token string) error {
	return s.deleteLocatedToken(ctx, oidcAccessTokenKeyKind, oidcUserAccessTokensKeyKind, s.accessTokenReference(token))
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

// getAccessToken validates encrypted access-token state against its subject epoch.
func (s *RedisTokenStorage) getAccessToken(ctx context.Context, reference string) (*OIDCSession, error) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	owner, err := s.resolveTokenOwner(writeCtx, reference)
	if err != nil {
		return nil, tokenStateReadError(err)
	}

	session, _, err := s.loadEpochBoundSession(writeCtx, owner, owner.entry(oidcAccessTokenKeyKind, reference))

	return session, err
}

// deleteLocatedToken resolves a bearer reference and removes its record, index entry, and locator.
// An unknown reference is treated as already deleted.
func (s *RedisTokenStorage) deleteLocatedToken(ctx context.Context, recordKind string, indexKind string, reference string) error {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	owner, err := s.resolveTokenOwner(writeCtx, reference)
	if stderrors.Is(err, redis.Nil) {
		return nil
	}

	if err != nil {
		return err
	}

	return s.deleteTrackedToken(writeCtx, owner, recordKind, indexKind, reference)
}

// deleteTrackedToken atomically removes one record with its subject index entry and drops its locator.
func (s *RedisTokenStorage) deleteTrackedToken(ctx context.Context, owner oidcSubjectKeys, recordKind string, indexKind string, reference string) error {
	pipe := s.redis.GetWriteHandle().Pipeline()
	pipe.Eval(ctx, trackedTokenDeleteScript, []string{owner.entry(recordKind, reference), owner.index(indexKind)}, reference)
	pipe.Del(ctx, s.keys.locator(reference))
	_, err := pipe.Exec(ctx)

	return err
}

// DeleteUserAccessTokens removes all access tokens for a given user from Redis.
func (s *RedisTokenStorage) DeleteUserAccessTokens(ctx context.Context, userID string) error {
	return s.deleteUserTrackedTokens(ctx, userID, oidcAccessTokenKeyKind, oidcUserAccessTokensKeyKind)
}

// deleteUserTrackedTokens removes every indexed record of one token class, the index, and the locators.
func (s *RedisTokenStorage) deleteUserTrackedTokens(ctx context.Context, userID string, recordKind string, indexKind string) error {
	if userID == "" {
		return nil
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	handle := s.redis.GetWriteHandle()
	owner := s.keys.subject(userID)
	indexKey := owner.index(indexKind)

	references, err := handle.SMembers(writeCtx, indexKey).Result()
	if err != nil && !stderrors.Is(err, redis.Nil) {
		return err
	}

	if len(references) == 0 {
		return nil
	}

	pipe := handle.Pipeline()

	for _, reference := range references {
		pipe.Del(writeCtx, owner.entry(recordKind, reference))
		pipe.Del(writeCtx, s.keys.locator(reference))
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

// storeEpochBoundToken atomically stores token state only while its subject epoch remains current.
// Record, subject index, and epoch share the subject slot; the bearer locator is written alongside.
func (s *RedisTokenStorage) storeEpochBoundToken(ctx context.Context, recordKind string, indexKind string, reference string, session *OIDCSession, ttl time.Duration) error {
	if session == nil || session.DynamicUserEpoch == "" {
		return ErrDynamicTokenRevoked
	}

	encryptedData, err := s.encryptSession(session)
	if err != nil {
		return err
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	owner := s.keys.subject(session.UserID)
	keys := []string{owner.entry(recordKind, reference), owner.index(indexKind), owner.epoch()}

	result, err := s.evalWithLocators(
		writeCtx,
		owner,
		ttl,
		[]string{reference},
		dynamicTrackedStoreScript,
		keys,
		encryptedData,
		ttl.Milliseconds(),
		reference,
		session.DynamicUserEpoch,
	)
	if err != nil {
		return err
	}

	if result != 1 {
		s.deleteTokenLocators(writeCtx, reference)

		return ErrDynamicTokenRevoked
	}

	return nil
}

// staticRefreshTokenReference hides static bearer credentials from Redis keys and indices.
func (s *RedisTokenStorage) staticRefreshTokenReference(token string) string {
	return s.redis.GetSecurityManager().IndexDigest("oidc-static-refresh", token)
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

	accessErr := s.DeleteUserAccessTokens(ctx, userID)
	refreshErr := s.DeleteUserRefreshTokens(ctx, userID)

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
	owner := s.keys.subject(userID)

	references, err := s.userSessionReferences(ctx, owner)
	if err != nil {
		return nil, err
	}

	sessions := make(map[string]*OIDCSession)

	for _, reference := range references {
		session, err := s.userSessionByReference(ctx, owner, reference)
		if err == nil {
			sessions[s.userSessionManagementID(reference)] = session

			continue
		}

		s.removeStaleUserSessionReference(ctx, owner, reference)
	}

	return sessions, nil
}

type userSessionReference struct {
	value string
}

// userSessionReferences reads the epoch-bound opaque access-token index authoritatively.
func (s *RedisTokenStorage) userSessionReferences(ctx context.Context, owner oidcSubjectKeys) ([]userSessionReference, error) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	values, err := s.redis.GetWriteHandle().SMembers(writeCtx, owner.index(oidcUserAccessTokensKeyKind)).Result()
	if err != nil {
		return nil, err
	}

	references := make([]userSessionReference, 0, len(values))
	for _, value := range values {
		references = append(references, userSessionReference{value: value})
	}

	return references, nil
}

// userSessionByReference loads one management-visible session without bearer exposure.
func (s *RedisTokenStorage) userSessionByReference(ctx context.Context, owner oidcSubjectKeys, reference userSessionReference) (*OIDCSession, error) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	session, _, err := s.loadEpochBoundSession(writeCtx, owner, owner.entry(oidcAccessTokenKeyKind, reference.value))

	return session, err
}

// userSessionManagementID derives the stable non-secret identifier exposed by the management API.
func (s *RedisTokenStorage) userSessionManagementID(reference userSessionReference) string {
	sum := sha256.Sum256([]byte("dynamic\x1f" + reference.value))

	return hex.EncodeToString(sum[:])
}

// removeStaleUserSessionReference prunes an index entry after authoritative resolution fails.
func (s *RedisTokenStorage) removeStaleUserSessionReference(ctx context.Context, owner oidcSubjectKeys, reference userSessionReference) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	_ = s.redis.GetWriteHandle().SRem(writeCtx, owner.index(oidcUserAccessTokensKeyKind), reference.value).Err()
}

// DeleteUserSession removes one session selected through its non-secret management identifier.
func (s *RedisTokenStorage) DeleteUserSession(ctx context.Context, userID string, managementID string) error {
	owner := s.keys.subject(userID)

	references, err := s.userSessionReferences(ctx, owner)
	if err != nil {
		return err
	}

	index := slices.IndexFunc(references, func(reference userSessionReference) bool {
		return s.userSessionManagementID(reference) == managementID
	})
	if index < 0 {
		return redis.Nil
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	return s.deleteTrackedToken(writeCtx, owner, oidcAccessTokenKeyKind, oidcUserAccessTokensKeyKind, references[index].value)
}

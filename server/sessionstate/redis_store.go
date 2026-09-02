// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sessionstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisSchemaVersion  = 1
	defaultRecordTTL    = 10 * time.Minute
	defaultTouchWindow  = 5 * time.Minute
	redisMissingMarker  = "__missing__"
	redisConflictMarker = "__conflict__"
)

const redisCommitScript = `
local current = redis.call('HGET', KEYS[1], 'revision')
local expected = ARGV[1]
if expected == '0' then
  if current then return -1 end
else
  if (not current) or current ~= expected then return -1 end
end
local next_revision = tonumber(expected) + 1
redis.call('HSET', KEYS[1],
  'schema_version', ARGV[2],
  'owner', ARGV[3],
  'revision', tostring(next_revision),
  'payload', ARGV[4],
  'expires_at_ms', ARGV[5],
  'created_at_ms', ARGV[6],
  'idle_expires_at_ms', ARGV[7],
  'absolute_expires_at_ms', ARGV[8],
  'last_touched_at_ms', ARGV[9],
  'revoked', ARGV[10],
  'tombstone', ARGV[11])
redis.call('PEXPIRE', KEYS[1], ARGV[12])
return next_revision
`

const redisDeleteScript = `
local current = redis.call('HGET', KEYS[1], 'revision')
if not current then return 0 end
if current ~= ARGV[1] then return -1 end
redis.call('DEL', KEYS[1])
return 1
`

const redisConsumeScript = `
local current = redis.call('HGET', KEYS[1], 'revision')
if not current then return {'__missing__'} end
if current ~= ARGV[1] then return {'__conflict__'} end
local values = redis.call('HGETALL', KEYS[1])
redis.call('DEL', KEYS[1])
return values
`

const redisIndexedDeleteScript = `
local anchor_current = redis.call('HGET', KEYS[1], 'revision')
local child_current = redis.call('HGET', KEYS[2], 'revision')
if (not anchor_current) or (not child_current) then return -2 end
if anchor_current ~= ARGV[1] or child_current ~= ARGV[13] then return -1 end
local next_revision = tonumber(ARGV[1]) + 1
redis.call('HSET', KEYS[1],
  'schema_version', ARGV[2],
  'owner', ARGV[3],
  'revision', tostring(next_revision),
  'payload', ARGV[4],
  'expires_at_ms', ARGV[5],
  'created_at_ms', ARGV[6],
  'idle_expires_at_ms', ARGV[7],
  'absolute_expires_at_ms', ARGV[8],
  'last_touched_at_ms', ARGV[9],
  'revoked', ARGV[10],
  'tombstone', ARGV[11])
redis.call('PEXPIRE', KEYS[1], ARGV[12])
redis.call('DEL', KEYS[2])
return next_revision
`

const redisIndexedConsumeScript = `
local anchor_current = redis.call('HGET', KEYS[1], 'revision')
local child_current = redis.call('HGET', KEYS[2], 'revision')
if (not anchor_current) or (not child_current) then return {'__missing__'} end
if anchor_current ~= ARGV[1] or child_current ~= ARGV[13] then return {'__conflict__'} end
local values = redis.call('HGETALL', KEYS[2])
local next_revision = tonumber(ARGV[1]) + 1
redis.call('HSET', KEYS[1],
  'schema_version', ARGV[2],
  'owner', ARGV[3],
  'revision', tostring(next_revision),
  'payload', ARGV[4],
  'expires_at_ms', ARGV[5],
  'created_at_ms', ARGV[6],
  'idle_expires_at_ms', ARGV[7],
  'absolute_expires_at_ms', ARGV[8],
  'last_touched_at_ms', ARGV[9],
  'revoked', ARGV[10],
  'tombstone', ARGV[11])
redis.call('PEXPIRE', KEYS[1], ARGV[12])
redis.call('DEL', KEYS[2])
return values
`

const redisTouchScript = `
local revision = redis.call('HGET', KEYS[1], 'revision')
if not revision then return -2 end
if redis.call('HGET', KEYS[1], 'revoked') == '1' then return -3 end
local absolute = tonumber(redis.call('HGET', KEYS[1], 'absolute_expires_at_ms') or '0')
local last_touched = tonumber(redis.call('HGET', KEYS[1], 'last_touched_at_ms') or '0')
local now = tonumber(ARGV[1])
if absolute <= now then
  redis.call('DEL', KEYS[1])
  return -2
end
if last_touched > 0 and now - last_touched < tonumber(ARGV[2]) then return 0 end
local idle_expiry = now + tonumber(ARGV[3])
if idle_expiry > absolute then idle_expiry = absolute end
local next_revision = tonumber(revision) + 1
redis.call('HSET', KEYS[1],
  'revision', tostring(next_revision),
  'last_touched_at_ms', tostring(now),
  'idle_expires_at_ms', tostring(idle_expiry),
  'expires_at_ms', tostring(idle_expiry))
redis.call('PEXPIRE', KEYS[1], tostring(idle_expiry - now))
return 1
`

const redisTransactionScript = `
local width = 12
for index = 1, #KEYS do
  local offset = (index - 1) * width
  local current = redis.call('HGET', KEYS[index], 'revision')
  local expected = ARGV[offset + 1]
  if expected == '0' then
    if current then return -1 end
  else
    if (not current) or current ~= expected then return -1 end
  end
end
local anchor_revision = 0
for index = 1, #KEYS do
  local offset = (index - 1) * width
  local next_revision = tonumber(ARGV[offset + 1]) + 1
  redis.call('HSET', KEYS[index],
    'schema_version', ARGV[offset + 2],
    'owner', ARGV[offset + 3],
    'revision', tostring(next_revision),
    'payload', ARGV[offset + 4],
    'expires_at_ms', ARGV[offset + 5],
    'created_at_ms', ARGV[offset + 6],
    'idle_expires_at_ms', ARGV[offset + 7],
    'absolute_expires_at_ms', ARGV[offset + 8],
    'last_touched_at_ms', ARGV[offset + 9],
    'revoked', ARGV[offset + 10],
    'tombstone', ARGV[offset + 11])
  redis.call('PEXPIRE', KEYS[index], ARGV[offset + 12])
  if index == 1 then anchor_revision = next_revision end
end
return anchor_revision
`

const redisRevokeScript = `
local current = redis.call('HGET', KEYS[1], 'revision')
if not current then return -2 end
if redis.call('HGET', KEYS[1], 'revoked') == '1' then
  if ARGV[3] == '1' then return -1 end
  return tonumber(current)
end
if current ~= ARGV[1] then return -1 end
local next_revision = tonumber(current) + 1
redis.call('HSET', KEYS[1],
  'revision', tostring(next_revision),
  'revoked', '1',
  'tombstone', '1')
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return next_revision
`

// Store errors are stable fail-closed classifications for callers and tests.
var (
	ErrNotFound         = errors.New("session record not found")
	ErrRevisionConflict = errors.New("session record revision conflict")
	ErrParentMissing    = errors.New("session record parent missing")
	ErrBindingMismatch  = errors.New("session record binding mismatch")
	ErrExpired          = errors.New("session record expired")
	ErrRevoked          = errors.New("session record revoked")
	ErrInvalidTTL       = errors.New("session record invalid TTL")
	ErrActiveFlowLimit  = errors.New("session active flow limit reached")
)

const maxActiveProtocolFlows = 16

// RedisStoreConfig defines namespace and write-amortization policy for typed stores.
type RedisStoreConfig struct {
	Prefix        string
	DefaultTTL    time.Duration
	TouchInterval time.Duration
}

// OwnedReference names a typed child key without exposing its raw handle externally.
type OwnedReference struct {
	Owner     Owner
	Reference Reference
}

// RevocationRequest defines a tombstone-first session and child cleanup operation.
type RevocationRequest struct {
	Reference        Reference
	ExpectedRevision Revision
	TombstoneTTL     time.Duration
	Children         []OwnedReference
	RejectRevoked    bool
}

// RedisStores groups separately keyed typed repositories that share one cluster keyspace.
type RedisStores struct {
	Session      *RedisRepository[SessionAnchor]
	OIDC         *RedisRepository[OIDCFlow]
	SAML         *RedisRepository[SAMLFlow]
	SelfService  *RedisRepository[SelfServiceFlow]
	Enrollment   *RedisRepository[EnrollmentRecord]
	StepUp       *RedisRepository[StepUpRecord]
	Ceremony     *RedisRepository[CeremonyRecord]
	TOTPRecovery *RedisRepository[TOTPRecoveryRecord]
	Consent      *RedisRepository[ConsentGrant]
	Logout       *RedisRepository[LogoutIndex]
	keyspace     Keyspace
	client       redis.UniversalClient
	clock        Clock
	touchWindow  time.Duration
}

// RedisRepository persists one typed record family under an exclusive owner namespace.
type RedisRepository[T any] struct {
	client        redis.UniversalClient
	keyspace      Keyspace
	owner         Owner
	clock         Clock
	defaultTTL    time.Duration
	requireParent bool
}

// NewRedisStores creates the complete typed repository set without activating browser paths.
func NewRedisStores(
	client redis.UniversalClient,
	digestSecret []byte,
	clock Clock,
	config RedisStoreConfig,
) (*RedisStores, error) {
	if client == nil {
		return nil, fmt.Errorf("session redis stores: missing client")
	}

	if clock == nil {
		return nil, fmt.Errorf("session redis stores: missing clock")
	}

	keyspace, err := NewKeyspace(config.Prefix, digestSecret)
	if err != nil {
		return nil, err
	}

	defaultTTL, touchWindow := normalizedStoreDurations(config)
	stores := &RedisStores{
		keyspace: keyspace, client: client, clock: clock, touchWindow: touchWindow,
	}
	stores.Session = newRedisRepository[SessionAnchor](client, keyspace, OwnerSessionAnchor, clock, defaultTTL, false)
	stores.OIDC = newRedisRepository[OIDCFlow](client, keyspace, OwnerOIDCFlow, clock, defaultTTL, true)
	stores.SAML = newRedisRepository[SAMLFlow](client, keyspace, OwnerSAMLFlow, clock, defaultTTL, true)
	stores.SelfService = newRedisRepository[SelfServiceFlow](
		client, keyspace, OwnerSelfServiceFlow, clock, defaultTTL, true,
	)
	stores.Enrollment = newRedisRepository[EnrollmentRecord](client, keyspace, OwnerEnrollment, clock, defaultTTL, true)
	stores.StepUp = newRedisRepository[StepUpRecord](client, keyspace, OwnerStepUp, clock, defaultTTL, true)
	stores.Ceremony = newRedisRepository[CeremonyRecord](client, keyspace, OwnerWebAuthnCeremony, clock, defaultTTL, true)
	stores.TOTPRecovery = newRedisRepository[TOTPRecoveryRecord](client, keyspace, OwnerTOTPRecovery, clock, defaultTTL, true)
	stores.Consent = newRedisRepository[ConsentGrant](client, keyspace, OwnerConsent, clock, defaultTTL, false)
	stores.Logout = newRedisRepository[LogoutIndex](client, keyspace, OwnerConsent, clock, defaultTTL, true)

	return stores, nil
}

// normalizedStoreDurations applies safe defaults to repository timing policy.
func normalizedStoreDurations(config RedisStoreConfig) (time.Duration, time.Duration) {
	defaultTTL := config.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = defaultRecordTTL
	}

	touchWindow := config.TouchInterval
	if touchWindow <= 0 {
		touchWindow = defaultTouchWindow
	}

	return defaultTTL, touchWindow
}

// newRedisRepository constructs one typed repository with explicit parent policy.
func newRedisRepository[T any](
	client redis.UniversalClient,
	keyspace Keyspace,
	owner Owner,
	clock Clock,
	defaultTTL time.Duration,
	requireParent bool,
) *RedisRepository[T] {
	return &RedisRepository[T]{
		client: client, keyspace: keyspace, owner: owner, clock: clock, defaultTTL: defaultTTL, requireParent: requireParent,
	}
}

// Load fetches, validates, and decodes one typed record.
func (r *RedisRepository[T]) Load(ctx context.Context, reference Reference) (Versioned[T], error) {
	var empty Versioned[T]

	key, err := r.key(reference)
	if err != nil {
		return empty, err
	}

	if r.requireParent {
		if _, err = r.parentRemainingTTL(ctx, reference.Session); err != nil {
			_ = r.client.Del(ctx, key).Err()

			if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) || errors.Is(err, ErrRevoked) {
				return empty, ErrParentMissing
			}

			return empty, err
		}
	}

	values, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		return empty, fmt.Errorf("session redis load: %w", err)
	}

	if len(values) == 0 {
		return empty, ErrNotFound
	}

	ttl, err := r.client.PTTL(ctx, key).Result()
	if err != nil {
		return empty, fmt.Errorf("session redis load TTL: %w", err)
	}

	if ttl <= 0 {
		_ = r.client.Del(ctx, key).Err()

		return empty, ErrExpired
	}

	return r.decode(values, reference)
}

// Commit atomically creates or compare-and-swap updates one typed record.
func (r *RedisRepository[T]) Commit(ctx context.Context, request CommitRequest[T]) (Revision, error) {
	key, ttl, err := r.commitParameters(ctx, request)
	if err != nil {
		return 0, err
	}

	payload, err := json.Marshal(request.Value)
	if err != nil {
		return 0, fmt.Errorf("session redis commit: encode payload: %w", err)
	}

	metadata := r.commitMetadata(request.Value, ttl)
	arguments := commitArguments(r.owner, request.ExpectedRevision, payload, metadata, ttl)

	result, err := r.client.Eval(ctx, redisCommitScript, []string{key}, arguments...).Int64()
	if err != nil {
		return 0, fmt.Errorf("session redis commit: %w", err)
	}

	if result < 0 {
		return 0, ErrRevisionConflict
	}

	return Revision(result), nil
}

// Delete removes one record only when the expected revision still matches.
func (r *RedisRepository[T]) Delete(ctx context.Context, request DeleteRequest) error {
	key, err := r.key(request.Reference)
	if err != nil {
		return err
	}

	result, err := r.client.Eval(
		ctx,
		redisDeleteScript,
		[]string{key},
		strconv.FormatUint(uint64(request.ExpectedRevision), 10),
	).Int64()
	if err != nil {
		return fmt.Errorf("session redis delete: %w", err)
	}

	if result < 0 {
		return ErrRevisionConflict
	}

	return nil
}

// Consume atomically returns and deletes one record at the expected revision.
// Callers must not expose the value unless this operation succeeds.
func (r *RedisRepository[T]) Consume(ctx context.Context, request DeleteRequest) (Versioned[T], error) {
	var empty Versioned[T]

	key, err := r.key(request.Reference)
	if err != nil {
		return empty, err
	}

	if r.requireParent {
		if _, err = r.parentRemainingTTL(ctx, request.Reference.Session); err != nil {
			_ = r.client.Del(ctx, key).Err()

			if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) || errors.Is(err, ErrRevoked) {
				return empty, ErrParentMissing
			}

			return empty, err
		}
	}

	result, err := r.client.Eval(
		ctx,
		redisConsumeScript,
		[]string{key},
		strconv.FormatUint(uint64(request.ExpectedRevision), 10),
	).Slice()
	if err != nil {
		return empty, fmt.Errorf("session redis consume: %w", err)
	}

	if len(result) == 1 {
		switch fmt.Sprint(result[0]) {
		case redisMissingMarker:
			return empty, ErrNotFound
		case redisConflictMarker:
			return empty, ErrRevisionConflict
		}
	}

	values, err := redisHashResult(result)
	if err != nil {
		return empty, err
	}

	return r.decode(values, request.Reference)
}

func redisHashResult(result []any) (map[string]string, error) {
	if len(result) == 0 || len(result)%2 != 0 {
		return nil, ErrBindingMismatch
	}

	values := make(map[string]string, len(result)/2)
	for index := 0; index < len(result); index += 2 {
		key, keyOK := result[index].(string)
		value, valueOK := result[index+1].(string)

		if !keyOK || !valueOK {
			return nil, ErrBindingMismatch
		}

		values[key] = value
	}

	return values, nil
}

// key validates the repository and derives its non-disclosing Redis key.
func (r *RedisRepository[T]) key(reference Reference) (string, error) {
	if r == nil || r.client == nil || r.clock == nil {
		return "", fmt.Errorf("session redis repository: unavailable")
	}

	return r.keyspace.Key(r.owner, reference)
}

// commitParameters validates binding and caps child TTL to its parent session.
func (r *RedisRepository[T]) commitParameters(
	ctx context.Context,
	request CommitRequest[T],
) (string, time.Duration, error) {
	key, err := r.key(request.Reference)
	if err != nil {
		return "", 0, err
	}

	if err = validateRecordBinding(request.Value, request.Reference); err != nil {
		return "", 0, err
	}

	ttl := request.TTL
	if ttl <= 0 {
		ttl = r.defaultTTL
	}

	if r.owner == OwnerSessionAnchor {
		boundedTTL, ttlErr := r.capAnchorTTL(request.Value, ttl)

		return key, boundedTTL, ttlErr
	}

	if !r.requireParent {
		return key, ttl, nil
	}

	parentTTL, err := r.parentRemainingTTL(ctx, request.Reference.Session)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) || errors.Is(err, ErrRevoked) {
			return "", 0, ErrParentMissing
		}

		return "", 0, err
	}

	if ttl > parentTTL {
		ttl = parentTTL
	}

	if ttl <= 0 {
		return "", 0, ErrInvalidTTL
	}

	return key, ttl, nil
}

// capAnchorTTL validates absolute expiry and restricts the Redis TTL accordingly.
func (r *RedisRepository[T]) capAnchorTTL(value T, ttl time.Duration) (time.Duration, error) {
	anchor, ok := any(value).(SessionAnchor)
	if !ok || !validAnchorTimes(anchor, r.clock.Now()) {
		return 0, ErrInvalidTTL
	}

	remaining := anchor.AbsoluteExpiresAt.Sub(r.clock.Now())
	idleRemaining := anchor.IdleExpiresAt.Sub(r.clock.Now())

	if ttl > remaining {
		ttl = remaining
	}

	if ttl > idleRemaining {
		ttl = idleRemaining
	}

	if ttl <= 0 {
		return 0, ErrInvalidTTL
	}

	return ttl, nil
}

// validAnchorTimes enforces ordered creation, idle, and absolute expiry timestamps.
func validAnchorTimes(anchor SessionAnchor, now time.Time) bool {
	if anchor.CreatedAt.IsZero() || anchor.CreatedAt.After(now) {
		return false
	}

	if !anchor.IdleExpiresAt.After(now) || !anchor.AbsoluteExpiresAt.After(now) {
		return false
	}

	return !anchor.IdleExpiresAt.After(anchor.AbsoluteExpiresAt)
}

type commitMetadata struct {
	expiresAt         time.Time
	createdAt         time.Time
	idleExpiresAt     time.Time
	absoluteExpiresAt time.Time
	lastTouchedAt     time.Time
	revoked           bool
	tombstone         bool
}

// commitMetadata derives common hash fields from a typed value and bounded TTL.
func (r *RedisRepository[T]) commitMetadata(value T, ttl time.Duration) commitMetadata {
	now := r.clock.Now()
	metadata := commitMetadata{
		expiresAt: now.Add(ttl), createdAt: now, idleExpiresAt: now.Add(ttl), absoluteExpiresAt: now.Add(ttl), lastTouchedAt: now,
	}

	if anchor, ok := any(value).(SessionAnchor); ok {
		metadata.createdAt = anchor.CreatedAt
		metadata.idleExpiresAt = anchor.IdleExpiresAt
		metadata.absoluteExpiresAt = anchor.AbsoluteExpiresAt
		metadata.lastTouchedAt = anchor.LastTouchedAt
		metadata.revoked = anchor.Revoked
		metadata.tombstone = anchor.Tombstone

		if metadata.lastTouchedAt.IsZero() {
			metadata.lastTouchedAt = anchor.CreatedAt
		}

		if !metadata.idleExpiresAt.IsZero() && metadata.idleExpiresAt.Before(metadata.expiresAt) {
			metadata.expiresAt = metadata.idleExpiresAt
		}
	}

	return metadata
}

// parentRemainingTTL validates a live anchor and returns its strict remaining lifetime.
func (r *RedisRepository[T]) parentRemainingTTL(ctx context.Context, session Handle) (time.Duration, error) {
	reference := Reference{Session: session, Record: session}

	key, err := r.keyspace.Key(OwnerSessionAnchor, reference)
	if err != nil {
		return 0, err
	}

	values, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("session redis parent: %w", err)
	}

	if len(values) == 0 {
		return 0, ErrNotFound
	}

	if values["revoked"] == "1" || values["tombstone"] == "1" {
		return 0, ErrRevoked
	}

	absoluteExpiry, err := parseRedisTime(values, "absolute_expires_at_ms")
	if err != nil || !absoluteExpiry.After(r.clock.Now()) {
		return 0, ErrExpired
	}

	redisTTL, err := r.client.PTTL(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("session redis parent TTL: %w", err)
	}

	remaining := absoluteExpiry.Sub(r.clock.Now())

	if redisTTL <= 0 {
		return 0, ErrExpired
	}

	if redisTTL < remaining {
		remaining = redisTTL
	}

	return remaining, nil
}

// decode validates Redis metadata before exposing one typed payload.
func (r *RedisRepository[T]) decode(values map[string]string, reference Reference) (Versioned[T], error) {
	var result Versioned[T]
	if len(values) == 0 {
		return result, ErrNotFound
	}

	if values["owner"] != string(r.owner) || values["schema_version"] != strconv.Itoa(redisSchemaVersion) {
		return result, ErrBindingMismatch
	}

	expiresAt, err := parseRedisTime(values, "expires_at_ms")
	if err != nil {
		return result, err
	}

	if !expiresAt.After(r.clock.Now()) {
		return result, ErrExpired
	}

	if values["revoked"] == "1" || values["tombstone"] == "1" {
		return result, ErrRevoked
	}

	revision, err := strconv.ParseUint(values["revision"], 10, 64)
	if err != nil || revision == 0 {
		return result, ErrBindingMismatch
	}

	if err = json.Unmarshal([]byte(values["payload"]), &result.Value); err != nil {
		return result, fmt.Errorf("session redis load: decode payload: %w", err)
	}

	if err = validateRecordBinding(result.Value, reference); err != nil {
		return Versioned[T]{}, err
	}

	result.Revision = Revision(revision)
	normalizeLoadedRecord(&result.Value, result.Revision, expiresAt, values)

	return result, nil
}

// parseRedisTime parses one required millisecond timestamp field.
func parseRedisTime(values map[string]string, field string) (time.Time, error) {
	milliseconds, err := strconv.ParseInt(values[field], 10, 64)
	if err != nil || milliseconds <= 0 {
		return time.Time{}, ErrBindingMismatch
	}

	return time.UnixMilli(milliseconds).UTC(), nil
}

// validateRecordBinding rejects cross-session, cross-record, and wrong-kind values.
func validateRecordBinding[T any](value T, reference Reference) error {
	var (
		recordHandle  Handle
		sessionHandle Handle
	)

	switch typed := any(value).(type) {
	case SessionAnchor:
		recordHandle, sessionHandle = typed.Handle, typed.Handle
	case OIDCFlow:
		recordHandle, sessionHandle = typed.Handle, typed.Session
	case SAMLFlow:
		recordHandle, sessionHandle = typed.Handle, typed.Session
	case SelfServiceFlow:
		recordHandle, sessionHandle = typed.Handle, typed.Session
	case EnrollmentRecord:
		recordHandle, sessionHandle = typed.Handle, typed.Session
	case StepUpRecord:
		recordHandle, sessionHandle = typed.Handle, typed.Session
	case CeremonyRecord:
		recordHandle, sessionHandle = typed.Handle, typed.Session
	case TOTPRecoveryRecord:
		recordHandle, sessionHandle = typed.Handle, typed.Session
	case ConsentGrant:
		if err := validateConsentGrant(typed, reference); err != nil {
			return err
		}

		recordHandle, sessionHandle = typed.Handle, reference.Session
	case LogoutIndex:
		if err := validateLogoutIndex(typed); err != nil {
			return err
		}

		recordHandle, sessionHandle = typed.Handle, typed.Session
	default:
		return ErrBindingMismatch
	}

	if recordHandle != reference.Record || sessionHandle != reference.Session {
		return ErrBindingMismatch
	}

	return nil
}

// normalizeLoadedRecord applies trusted hash metadata to the decoded typed value.
func normalizeLoadedRecord[T any](value *T, revision Revision, expiresAt time.Time, fields map[string]string) {
	switch typed := any(value).(type) {
	case *SessionAnchor:
		typed.Revision, typed.ExpiresAt = revision, expiresAt
		typed.LastTouchedAt, _ = parseRedisTime(fields, "last_touched_at_ms")
		typed.IdleExpiresAt, _ = parseRedisTime(fields, "idle_expires_at_ms")
		typed.AbsoluteExpiresAt, _ = parseRedisTime(fields, "absolute_expires_at_ms")
	case *OIDCFlow:
		typed.Revision, typed.ExpiresAt = revision, expiresAt
	case *SAMLFlow:
		typed.Revision, typed.ExpiresAt = revision, expiresAt
	case *SelfServiceFlow:
		typed.Revision, typed.ExpiresAt = revision, expiresAt
	case *EnrollmentRecord:
		typed.Revision, typed.ExpiresAt = revision, expiresAt
	case *StepUpRecord:
		typed.Revision, typed.ExpiresAt = revision, expiresAt
	case *CeremonyRecord:
		typed.Revision, typed.ExpiresAt = revision, expiresAt
	case *TOTPRecoveryRecord:
		typed.Revision, typed.ExpiresAt = revision, expiresAt
	case *ConsentGrant:
		typed.Revision, typed.ExpiresAt = revision, expiresAt
	case *LogoutIndex:
		typed.Revision, typed.ExpiresAt = revision, expiresAt
	}
}

func validateLogoutIndex(index LogoutIndex) error {
	if strings.TrimSpace(index.IdentityReference) == "" || len(index.IdentityReference) > 512 ||
		strings.TrimSpace(index.Account) == "" || len(index.Account) > 512 {
		return ErrBindingMismatch
	}

	if len(index.OIDCClientIDs) > maxActiveProtocolFlows {
		return ErrActiveFlowLimit
	}

	seen := make(map[string]struct{}, len(index.OIDCClientIDs))
	for _, clientID := range index.OIDCClientIDs {
		clientID = strings.TrimSpace(clientID)
		if clientID == "" || len(clientID) > 512 {
			return ErrBindingMismatch
		}

		if _, duplicate := seen[clientID]; duplicate {
			return ErrBindingMismatch
		}

		seen[clientID] = struct{}{}
	}

	return nil
}

// boolRedisValue encodes booleans without an open-ended textual vocabulary.
func boolRedisValue(value bool) string {
	if value {
		return "1"
	}

	return "0"
}

// TouchSession refreshes idle expiry only after the configured write-amortization window.
func (s *RedisStores) TouchSession(
	ctx context.Context,
	reference Reference,
	idleTTL time.Duration,
) (bool, error) {
	if s == nil || s.client == nil || s.clock == nil || idleTTL <= 0 {
		return false, ErrInvalidTTL
	}

	key, err := s.keyspace.Key(OwnerSessionAnchor, reference)
	if err != nil {
		return false, err
	}

	result, err := s.client.Eval(ctx, redisTouchScript, []string{key},
		strconv.FormatInt(s.clock.Now().UnixMilli(), 10),
		strconv.FormatInt(s.touchWindow.Milliseconds(), 10),
		strconv.FormatInt(idleTTL.Milliseconds(), 10),
	).Int64()
	if err != nil {
		return false, fmt.Errorf("session redis touch: %w", err)
	}

	switch result {
	case -3:
		return false, ErrRevoked
	case -2:
		return false, ErrNotFound
	case 0:
		return false, nil
	default:
		return true, nil
	}
}

type transactionMutation struct {
	key  string
	args []any
}

// Commit atomically applies a revision-checked typed mutation set in one Redis Cluster slot.
func (s *RedisStores) Commit(ctx context.Context, request TransactionRequest) (TransactionReceipt, error) {
	if s == nil || s.Session == nil || request.Session == nil {
		return TransactionReceipt{}, fmt.Errorf("session redis transaction: missing anchor mutation")
	}

	mutations, err := s.transactionMutations(ctx, request)
	if err != nil {
		return TransactionReceipt{}, err
	}

	keys, arguments, err := transactionArguments(mutations)
	if err != nil {
		return TransactionReceipt{}, err
	}

	result, err := s.client.Eval(ctx, redisTransactionScript, keys, arguments...).Int64()
	if err != nil {
		return TransactionReceipt{}, fmt.Errorf("session redis transaction: %w", err)
	}

	if result < 0 {
		return TransactionReceipt{}, ErrRevisionConflict
	}

	return TransactionReceipt{Revision: Revision(result)}, nil
}

// CommitOIDCFlow atomically adds one bounded OIDC index entry and commits its typed child.
func (s *RedisStores) CommitOIDCFlow(ctx context.Context, request CommitRequest[OIDCFlow]) (Revision, error) {
	return commitIndexedFlow(ctx, s, request, appendOIDCIndex, assignOIDCMutation)
}

// CommitSAMLFlow atomically adds one bounded SAML index entry and commits its typed child.
func (s *RedisStores) CommitSAMLFlow(ctx context.Context, request CommitRequest[SAMLFlow]) (Revision, error) {
	return commitIndexedFlow(ctx, s, request, appendSAMLIndex, assignSAMLMutation)
}

// CommitSelfServiceFlow atomically indexes and commits one bounded internal-login flow.
func (s *RedisStores) CommitSelfServiceFlow(
	ctx context.Context,
	request CommitRequest[SelfServiceFlow],
) (Revision, error) {
	return commitIndexedFlow(ctx, s, request, appendSelfServiceIndex, assignSelfServiceMutation)
}

// CommitCeremony atomically indexes and commits one short-lived WebAuthn operation.
func (s *RedisStores) CommitCeremony(ctx context.Context, request CommitRequest[CeremonyRecord]) (Revision, error) {
	return commitIndexedFlow(ctx, s, request, appendCeremonyIndex, assignCeremonyMutation)
}

// CommitEnrollment atomically indexes and commits one required-factor enrollment.
func (s *RedisStores) CommitEnrollment(ctx context.Context, request CommitRequest[EnrollmentRecord]) (Revision, error) {
	return commitIndexedFlow(ctx, s, request, appendEnrollmentIndex, assignEnrollmentMutation)
}

// CommitStepUp atomically indexes and commits one dynamic-assurance operation.
func (s *RedisStores) CommitStepUp(ctx context.Context, request CommitRequest[StepUpRecord]) (Revision, error) {
	return commitIndexedFlow(ctx, s, request, appendStepUpIndex, assignStepUpMutation)
}

// CommitTOTPRecovery atomically indexes and commits one TOTP or recovery operation.
func (s *RedisStores) CommitTOTPRecovery(ctx context.Context, request CommitRequest[TOTPRecoveryRecord]) (Revision, error) {
	return commitIndexedFlow(ctx, s, request, appendTOTPRecoveryIndex, assignTOTPRecoveryMutation)
}

// CommitLogoutIndex atomically indexes and commits the current-v1 browser logout record.
func (s *RedisStores) CommitLogoutIndex(ctx context.Context, request CommitRequest[LogoutIndex]) (Revision, error) {
	return commitIndexedFlow(ctx, s, request, appendLogoutIndex, assignLogoutMutation)
}

func commitIndexedFlow[T any](
	ctx context.Context,
	s *RedisStores,
	request CommitRequest[T],
	appendIndex func(anchor *SessionAnchor, handle Handle) error,
	assignChild func(transaction *TransactionRequest, child CommitRequest[T]),
) (Revision, error) {
	for range 4 {
		anchor, err := s.loadAnchorForChild(ctx, request.Reference)
		if err != nil {
			return 0, err
		}

		if err = reconcileIndexedChildren(ctx, s, &anchor.Value); err != nil {
			return 0, err
		}

		if err = appendIndex(&anchor.Value, request.Reference.Record); err != nil {
			return 0, err
		}

		transaction := TransactionRequest{
			Session: &CommitRequest[SessionAnchor]{
				Reference:        Reference{Session: request.Reference.Session, Record: request.Reference.Session},
				ExpectedRevision: anchor.Revision, Value: anchor.Value, TTL: anchor.Value.ExpiresAt.Sub(s.clock.Now()),
			},
		}
		assignChild(&transaction, request)

		_, err = s.Commit(ctx, transaction)
		if !errors.Is(err, ErrRevisionConflict) {
			if err != nil {
				return 0, err
			}

			return request.ExpectedRevision + 1, nil
		}
	}

	return 0, ErrRevisionConflict
}

// reconcileIndexedChildren drops only missing or expired child references before a new indexed commit.
func reconcileIndexedChildren(ctx context.Context, stores *RedisStores, anchor *SessionAnchor) error {
	if stores == nil || anchor == nil || anchor.Handle == "" {
		return ErrBindingMismatch
	}

	families := []func() error{
		func() error { return reconcileIndexedFamily(ctx, stores.OIDC, anchor.Handle, &anchor.OIDCFlows) },
		func() error { return reconcileIndexedFamily(ctx, stores.SAML, anchor.Handle, &anchor.SAMLFlows) },
		func() error {
			return reconcileIndexedFamily(ctx, stores.SelfService, anchor.Handle, &anchor.SelfServiceFlows)
		},
		func() error {
			return reconcileIndexedFamily(ctx, stores.Enrollment, anchor.Handle, &anchor.Enrollments)
		},
		func() error { return reconcileIndexedFamily(ctx, stores.StepUp, anchor.Handle, &anchor.StepUps) },
		func() error { return reconcileIndexedFamily(ctx, stores.Ceremony, anchor.Handle, &anchor.Ceremonies) },
		func() error {
			return reconcileIndexedFamily(ctx, stores.TOTPRecovery, anchor.Handle, &anchor.TOTPRecovery)
		},
		func() error { return reconcileIndexedFamily(ctx, stores.Logout, anchor.Handle, &anchor.LogoutIndexes) },
	}
	for _, reconcile := range families {
		if err := reconcile(); err != nil {
			return err
		}
	}

	return nil
}

// reconcileIndexedFamily retains live children and fails closed on every error except absence or expiry.
func reconcileIndexedFamily[T any](
	ctx context.Context,
	repository *RedisRepository[T],
	session Handle,
	handles *[]Handle,
) error {
	if repository == nil || handles == nil {
		return ErrBindingMismatch
	}

	retained := make([]Handle, 0, len(*handles))
	for _, handle := range *handles {
		_, err := repository.Load(ctx, Reference{Session: session, Record: handle})
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
			continue
		}

		if err != nil {
			return err
		}

		retained = append(retained, handle)
	}

	*handles = retained

	return nil
}

func appendOIDCIndex(anchor *SessionAnchor, handle Handle) error {
	return appendActiveFlow(&anchor.OIDCFlows, handle)
}

func appendSAMLIndex(anchor *SessionAnchor, handle Handle) error {
	return appendActiveFlow(&anchor.SAMLFlows, handle)
}

// appendSelfServiceIndex binds one internal-login handle to its canonical session.
func appendSelfServiceIndex(anchor *SessionAnchor, handle Handle) error {
	return appendActiveFlow(&anchor.SelfServiceFlows, handle)
}

func appendCeremonyIndex(anchor *SessionAnchor, handle Handle) error {
	return appendActiveFlow(&anchor.Ceremonies, handle)
}

func appendEnrollmentIndex(anchor *SessionAnchor, handle Handle) error {
	return appendActiveFlow(&anchor.Enrollments, handle)
}

func appendStepUpIndex(anchor *SessionAnchor, handle Handle) error {
	return appendActiveFlow(&anchor.StepUps, handle)
}

func appendTOTPRecoveryIndex(anchor *SessionAnchor, handle Handle) error {
	return appendActiveFlow(&anchor.TOTPRecovery, handle)
}

func appendLogoutIndex(anchor *SessionAnchor, handle Handle) error {
	return appendActiveFlow(&anchor.LogoutIndexes, handle)
}

func assignOIDCMutation(transaction *TransactionRequest, child CommitRequest[OIDCFlow]) {
	transaction.OIDC = []CommitRequest[OIDCFlow]{child}
}

func assignSAMLMutation(transaction *TransactionRequest, child CommitRequest[SAMLFlow]) {
	transaction.SAML = []CommitRequest[SAMLFlow]{child}
}

// assignSelfServiceMutation assigns one internal-login mutation to a transaction.
func assignSelfServiceMutation(transaction *TransactionRequest, child CommitRequest[SelfServiceFlow]) {
	transaction.SelfService = []CommitRequest[SelfServiceFlow]{child}
}

func assignCeremonyMutation(transaction *TransactionRequest, child CommitRequest[CeremonyRecord]) {
	transaction.Ceremony = []CommitRequest[CeremonyRecord]{child}
}

func assignEnrollmentMutation(transaction *TransactionRequest, child CommitRequest[EnrollmentRecord]) {
	transaction.Enrollment = []CommitRequest[EnrollmentRecord]{child}
}

func assignStepUpMutation(transaction *TransactionRequest, child CommitRequest[StepUpRecord]) {
	transaction.StepUp = []CommitRequest[StepUpRecord]{child}
}

func assignTOTPRecoveryMutation(transaction *TransactionRequest, child CommitRequest[TOTPRecoveryRecord]) {
	transaction.TOTPRecovery = []CommitRequest[TOTPRecoveryRecord]{child}
}

func assignLogoutMutation(transaction *TransactionRequest, child CommitRequest[LogoutIndex]) {
	transaction.Logout = []CommitRequest[LogoutIndex]{child}
}

func (s *RedisStores) loadAnchorForChild(ctx context.Context, reference Reference) (Versioned[SessionAnchor], error) {
	if reference.Session == "" || reference.Record == "" {
		return Versioned[SessionAnchor]{}, ErrBindingMismatch
	}

	return s.Session.Load(ctx, Reference{Session: reference.Session, Record: reference.Session})
}

func appendActiveFlow(index *[]Handle, handle Handle) error {
	for _, current := range *index {
		if current == handle {
			return nil
		}
	}

	if len(*index) >= maxActiveProtocolFlows {
		return ErrActiveFlowLimit
	}

	*index = append(*index, handle)

	return nil
}

// DeleteOIDCFlow atomically removes one OIDC child and its anchor index entry.
func (s *RedisStores) DeleteOIDCFlow(ctx context.Context, request DeleteRequest) error {
	return s.deleteIndexedFlow(ctx, OwnerOIDCFlow, request, func(anchor *SessionAnchor) {
		anchor.OIDCFlows = removeActiveFlow(anchor.OIDCFlows, request.Reference.Record)
	})
}

// DeleteSAMLFlow atomically removes one SAML child and its anchor index entry.
func (s *RedisStores) DeleteSAMLFlow(ctx context.Context, request DeleteRequest) error {
	return s.deleteIndexedFlow(ctx, OwnerSAMLFlow, request, func(anchor *SessionAnchor) {
		anchor.SAMLFlows = removeActiveFlow(anchor.SAMLFlows, request.Reference.Record)
	})
}

// DeleteSelfServiceFlow atomically removes one internal-login child and its anchor index entry.
func (s *RedisStores) DeleteSelfServiceFlow(ctx context.Context, request DeleteRequest) error {
	return s.deleteIndexedFlow(ctx, OwnerSelfServiceFlow, request, func(anchor *SessionAnchor) {
		anchor.SelfServiceFlows = removeActiveFlow(anchor.SelfServiceFlows, request.Reference.Record)
	})
}

// DeleteEnrollment atomically removes one enrollment child and its anchor index entry.
func (s *RedisStores) DeleteEnrollment(ctx context.Context, request DeleteRequest) error {
	return s.deleteIndexedFlow(ctx, OwnerEnrollment, request, func(anchor *SessionAnchor) {
		anchor.Enrollments = removeActiveFlow(anchor.Enrollments, request.Reference.Record)
	})
}

// DeleteStepUp atomically removes one step-up child and its anchor index entry.
func (s *RedisStores) DeleteStepUp(ctx context.Context, request DeleteRequest) error {
	return s.deleteIndexedFlow(ctx, OwnerStepUp, request, func(anchor *SessionAnchor) {
		anchor.StepUps = removeActiveFlow(anchor.StepUps, request.Reference.Record)
	})
}

// DeleteTOTPRecovery atomically removes one TOTP/recovery child and its anchor index entry.
func (s *RedisStores) DeleteTOTPRecovery(ctx context.Context, request DeleteRequest) error {
	return s.deleteIndexedFlow(ctx, OwnerTOTPRecovery, request, func(anchor *SessionAnchor) {
		anchor.TOTPRecovery = removeActiveFlow(anchor.TOTPRecovery, request.Reference.Record)
	})
}

// DeleteLogoutIndex atomically removes one logout index and its anchor entry.
func (s *RedisStores) DeleteLogoutIndex(ctx context.Context, request DeleteRequest) error {
	return s.deleteIndexedFlow(ctx, OwnerConsent, request, func(anchor *SessionAnchor) {
		anchor.LogoutIndexes = removeActiveFlow(anchor.LogoutIndexes, request.Reference.Record)
	})
}

// ConsumeCeremony atomically removes a ceremony and its bounded anchor index before returning the payload.
func (s *RedisStores) ConsumeCeremony(
	ctx context.Context,
	request DeleteRequest,
) (Versioned[CeremonyRecord], error) {
	return consumeIndexedRecord(ctx, s, s.Ceremony, request, func(anchor *SessionAnchor) {
		anchor.Ceremonies = removeActiveFlow(anchor.Ceremonies, request.Reference.Record)
	})
}

// ConsumeStepUp atomically removes one terminal step-up and its bounded anchor index.
func (s *RedisStores) ConsumeStepUp(
	ctx context.Context,
	request DeleteRequest,
) (Versioned[StepUpRecord], error) {
	return consumeIndexedRecord(ctx, s, s.StepUp, request, func(anchor *SessionAnchor) {
		anchor.StepUps = removeActiveFlow(anchor.StepUps, request.Reference.Record)
	})
}

// ConsumeOIDCFlow atomically removes one OIDC flow and its bounded anchor index before returning the payload.
func (s *RedisStores) ConsumeOIDCFlow(
	ctx context.Context,
	request DeleteRequest,
) (Versioned[OIDCFlow], error) {
	return consumeIndexedRecord(ctx, s, s.OIDC, request, func(anchor *SessionAnchor) {
		anchor.OIDCFlows = removeActiveFlow(anchor.OIDCFlows, request.Reference.Record)
	})
}

// ConsumeSAMLFlow atomically removes one SAML flow and its bounded anchor index before returning the payload.
func (s *RedisStores) ConsumeSAMLFlow(
	ctx context.Context,
	request DeleteRequest,
) (Versioned[SAMLFlow], error) {
	return consumeIndexedRecord(ctx, s, s.SAML, request, func(anchor *SessionAnchor) {
		anchor.SAMLFlows = removeActiveFlow(anchor.SAMLFlows, request.Reference.Record)
	})
}

// ConsumeSelfServiceFlow atomically removes one internal-login flow and its bounded anchor index.
func (s *RedisStores) ConsumeSelfServiceFlow(
	ctx context.Context,
	request DeleteRequest,
) (Versioned[SelfServiceFlow], error) {
	return consumeIndexedRecord(ctx, s, s.SelfService, request, func(anchor *SessionAnchor) {
		anchor.SelfServiceFlows = removeActiveFlow(anchor.SelfServiceFlows, request.Reference.Record)
	})
}

func consumeIndexedRecord[T any](
	ctx context.Context,
	stores *RedisStores,
	repository *RedisRepository[T],
	request DeleteRequest,
	remove func(anchor *SessionAnchor),
) (Versioned[T], error) {
	var empty Versioned[T]

	childKey, err := repository.key(request.Reference)
	if err != nil {
		return empty, err
	}

	for range 4 {
		anchor, loadErr := stores.loadAnchorForChild(ctx, request.Reference)
		if loadErr != nil {
			return empty, loadErr
		}

		remove(&anchor.Value)
		anchorRequest := CommitRequest[SessionAnchor]{
			Reference:        Reference{Session: request.Reference.Session, Record: request.Reference.Session},
			ExpectedRevision: anchor.Revision, Value: anchor.Value, TTL: anchor.Value.ExpiresAt.Sub(stores.clock.Now()),
		}

		mutations := make([]transactionMutation, 0, 1)
		if _, err = appendTransactionMutation(ctx, &mutations, stores.Session, anchorRequest); err != nil {
			return empty, err
		}

		arguments := append(mutations[0].args, strconv.FormatUint(uint64(request.ExpectedRevision), 10))

		result, evalErr := stores.client.Eval(
			ctx, redisIndexedConsumeScript, []string{mutations[0].key, childKey}, arguments...,
		).Slice()
		if evalErr != nil {
			return empty, fmt.Errorf("session redis indexed consume: %w", evalErr)
		}

		if len(result) == 1 {
			switch fmt.Sprint(result[0]) {
			case redisMissingMarker:
				return empty, ErrNotFound
			case redisConflictMarker:
				continue
			}
		}

		values, decodeErr := redisHashResult(result)
		if decodeErr != nil {
			return empty, decodeErr
		}

		return repository.decode(values, request.Reference)
	}

	return empty, ErrRevisionConflict
}

func (s *RedisStores) deleteIndexedFlow(
	ctx context.Context,
	owner Owner,
	request DeleteRequest,
	remove func(anchor *SessionAnchor),
) error {
	childKey, err := s.keyspace.Key(owner, request.Reference)
	if err != nil {
		return err
	}

	for range 4 {
		anchor, loadErr := s.loadAnchorForChild(ctx, request.Reference)
		if loadErr != nil {
			return loadErr
		}

		remove(&anchor.Value)
		anchorRequest := CommitRequest[SessionAnchor]{
			Reference:        Reference{Session: request.Reference.Session, Record: request.Reference.Session},
			ExpectedRevision: anchor.Revision, Value: anchor.Value, TTL: anchor.Value.ExpiresAt.Sub(s.clock.Now()),
		}

		mutations := make([]transactionMutation, 0, 1)
		if _, err = appendTransactionMutation(ctx, &mutations, s.Session, anchorRequest); err != nil {
			return err
		}

		arguments := append(mutations[0].args, strconv.FormatUint(uint64(request.ExpectedRevision), 10))

		result, evalErr := s.client.Eval(
			ctx, redisIndexedDeleteScript, []string{mutations[0].key, childKey}, arguments...,
		).Int64()
		if evalErr != nil {
			return fmt.Errorf("session redis indexed delete: %w", evalErr)
		}

		switch result {
		case -2:
			return ErrNotFound
		case -1:
			continue
		default:
			return nil
		}
	}

	return ErrRevisionConflict
}

func removeActiveFlow(index []Handle, handle Handle) []Handle {
	kept := index[:0]
	for _, current := range index {
		if current != handle {
			kept = append(kept, current)
		}
	}

	return kept
}

// transactionMutations validates and serializes every typed transaction member.
func (s *RedisStores) transactionMutations(
	ctx context.Context,
	request TransactionRequest,
) ([]transactionMutation, error) {
	mutations := make([]transactionMutation, 0, transactionRequestSize(request))

	anchorTTL, err := appendTransactionMutation(ctx, &mutations, s.Session, *request.Session)
	if err != nil {
		return nil, err
	}

	if err = appendTransactionChildMutations(&mutations, s.OIDC, request.OIDC, anchorTTL); err != nil {
		return nil, err
	}

	if err = appendTransactionChildMutations(&mutations, s.SAML, request.SAML, anchorTTL); err != nil {
		return nil, err
	}

	if err = appendTransactionChildMutations(&mutations, s.SelfService, request.SelfService, anchorTTL); err != nil {
		return nil, err
	}

	if err = appendTransactionChildMutations(&mutations, s.Enrollment, request.Enrollment, anchorTTL); err != nil {
		return nil, err
	}

	if err = appendTransactionChildMutations(&mutations, s.StepUp, request.StepUp, anchorTTL); err != nil {
		return nil, err
	}

	if err = appendTransactionChildMutations(&mutations, s.Ceremony, request.Ceremony, anchorTTL); err != nil {
		return nil, err
	}

	if err = appendTransactionChildMutations(&mutations, s.TOTPRecovery, request.TOTPRecovery, anchorTTL); err != nil {
		return nil, err
	}

	if err = appendTransactionChildMutations(&mutations, s.Logout, request.Logout, anchorTTL); err != nil {
		return nil, err
	}

	return mutations, nil
}

// transactionRequestSize returns the bounded mutation capacity needed for one request.
func transactionRequestSize(request TransactionRequest) int {
	return 1 + len(request.OIDC) + len(request.SAML) + len(request.SelfService) + len(request.Enrollment) +
		len(request.StepUp) + len(request.Ceremony) + len(request.TOTPRecovery) + len(request.Logout)
}

// appendTransactionMutations serializes one typed request family.
func appendTransactionChildMutations[T any](
	mutations *[]transactionMutation,
	repository *RedisRepository[T],
	requests []CommitRequest[T],
	parentTTL time.Duration,
) error {
	for _, request := range requests {
		if err := appendTransactionChildMutation(mutations, repository, request, parentTTL); err != nil {
			return err
		}
	}

	return nil
}

// appendTransactionMutation validates and serializes one typed request.
func appendTransactionMutation[T any](
	ctx context.Context,
	mutations *[]transactionMutation,
	repository *RedisRepository[T],
	request CommitRequest[T],
) (time.Duration, error) {
	key, ttl, err := repository.commitParameters(ctx, request)
	if err != nil {
		return 0, err
	}

	if err = appendSerializedTransactionMutation(mutations, repository, request, key, ttl); err != nil {
		return 0, err
	}

	return ttl, nil
}

// appendTransactionChildMutation validates one child against the anchor mutation in the same transaction.
func appendTransactionChildMutation[T any](
	mutations *[]transactionMutation,
	repository *RedisRepository[T],
	request CommitRequest[T],
	parentTTL time.Duration,
) error {
	key, err := repository.key(request.Reference)
	if err != nil {
		return err
	}

	if err = validateRecordBinding(request.Value, request.Reference); err != nil {
		return err
	}

	ttl := request.TTL
	if ttl <= 0 {
		ttl = repository.defaultTTL
	}

	if ttl > parentTTL {
		ttl = parentTTL
	}

	if ttl <= 0 {
		return ErrInvalidTTL
	}

	return appendSerializedTransactionMutation(mutations, repository, request, key, ttl)
}

// appendSerializedTransactionMutation encodes one already validated fixed-width Redis mutation.
func appendSerializedTransactionMutation[T any](
	mutations *[]transactionMutation,
	repository *RedisRepository[T],
	request CommitRequest[T],
	key string,
	ttl time.Duration,
) error {
	payload, err := json.Marshal(request.Value)
	if err != nil {
		return fmt.Errorf("session redis transaction: encode payload: %w", err)
	}

	metadata := repository.commitMetadata(request.Value, ttl)
	*mutations = append(*mutations, transactionMutation{
		key:  key,
		args: commitArguments(repository.owner, request.ExpectedRevision, payload, metadata, ttl),
	})

	return nil
}

// commitArguments returns the fixed-width Lua argument set for one hash mutation.
func commitArguments(
	owner Owner,
	expected Revision,
	payload []byte,
	metadata commitMetadata,
	ttl time.Duration,
) []any {
	return []any{
		strconv.FormatUint(uint64(expected), 10),
		strconv.Itoa(redisSchemaVersion),
		string(owner),
		payload,
		strconv.FormatInt(metadata.expiresAt.UnixMilli(), 10),
		strconv.FormatInt(metadata.createdAt.UnixMilli(), 10),
		strconv.FormatInt(metadata.idleExpiresAt.UnixMilli(), 10),
		strconv.FormatInt(metadata.absoluteExpiresAt.UnixMilli(), 10),
		strconv.FormatInt(metadata.lastTouchedAt.UnixMilli(), 10),
		boolRedisValue(metadata.revoked),
		boolRedisValue(metadata.tombstone),
		strconv.FormatInt(ttl.Milliseconds(), 10),
	}
}

// transactionArguments checks same-slot coordination and flattens Lua inputs.
func transactionArguments(mutations []transactionMutation) ([]string, []any, error) {
	if len(mutations) == 0 {
		return nil, nil, fmt.Errorf("session redis transaction: empty mutation set")
	}

	hashTag := RedisClusterHashTag(mutations[0].key)
	keys := make([]string, 0, len(mutations))

	arguments := make([]any, 0, len(mutations)*12)
	for _, mutation := range mutations {
		if hashTag == "" || RedisClusterHashTag(mutation.key) != hashTag {
			return nil, nil, ErrBindingMismatch
		}

		keys = append(keys, mutation.key)
		arguments = append(arguments, mutation.args...)
	}

	return keys, arguments, nil
}

// RevokeSession writes the anchor tombstone before best-effort idempotent child deletion.
func (s *RedisStores) RevokeSession(ctx context.Context, request RevocationRequest) error {
	if s == nil || s.client == nil || request.TombstoneTTL <= 0 {
		return ErrInvalidTTL
	}

	anchorKey, err := s.keyspace.Key(OwnerSessionAnchor, request.Reference)
	if err != nil {
		return err
	}

	result, err := s.client.Eval(ctx, redisRevokeScript, []string{anchorKey},
		strconv.FormatUint(uint64(request.ExpectedRevision), 10),
		strconv.FormatInt(request.TombstoneTTL.Milliseconds(), 10),
		boolRedisValue(request.RejectRevoked),
	).Int64()
	if err != nil {
		return fmt.Errorf("session redis revoke: %w", err)
	}

	if result == -2 {
		return ErrNotFound
	}

	if result < 0 {
		return ErrRevisionConflict
	}

	childKeys, err := s.revocationChildKeys(request.Reference.Session, request.Children)
	if err != nil {
		return err
	}

	if len(childKeys) == 0 {
		return nil
	}

	if err = s.client.Del(ctx, childKeys...).Err(); err != nil {
		return fmt.Errorf("session redis revoke cleanup: %w", err)
	}

	return nil
}

// revocationChildKeys validates child ownership and derives same-session cleanup keys.
func (s *RedisStores) revocationChildKeys(session Handle, children []OwnedReference) ([]string, error) {
	keys := make([]string, 0, len(children))
	for _, child := range children {
		if child.Reference.Session != session || !isChildOwner(child.Owner) {
			return nil, ErrBindingMismatch
		}

		key, err := s.keyspace.Key(child.Owner, child.Reference)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// isChildOwner restricts cleanup to typed child namespaces.
func isChildOwner(owner Owner) bool {
	switch owner {
	case OwnerOIDCFlow, OwnerSAMLFlow, OwnerSelfServiceFlow, OwnerEnrollment, OwnerStepUp,
		OwnerWebAuthnCeremony, OwnerTOTPRecovery, OwnerConsent:
		return true
	default:
		return false
	}
}

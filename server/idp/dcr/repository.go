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

package dcr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/redis/go-redis/v9"
)

const registrationScript = `
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[5]) then return 4 end
if redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3], 'NX') == false then return 5 end
redis.call('ZADD', KEYS[2], ARGV[4], ARGV[6])
return 1
`

const registrationAttemptScript = `
if tonumber(redis.call('GET', KEYS[1]) or '0') >= tonumber(ARGV[1]) then return 2 end
if tonumber(redis.call('GET', KEYS[2]) or '0') >= tonumber(ARGV[2]) then return 2 end
if tonumber(redis.call('GET', KEYS[3]) or '0') >= tonumber(ARGV[3]) then return 3 end
local source_count = redis.call('INCR', KEYS[1])
if source_count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[4]) end
local source_day_count = redis.call('INCR', KEYS[2])
if source_day_count == 1 then redis.call('PEXPIRE', KEYS[2], 86400000) end
local global_count = redis.call('INCR', KEYS[3])
if global_count == 1 then redis.call('PEXPIRE', KEYS[3], ARGV[5]) end
return 1
`

const touchScript = `
local score = redis.call('ZSCORE', KEYS[2], ARGV[4])
if not score or tonumber(score) <= tonumber(ARGV[1]) then return 0 end
local encoded = redis.call('GET', KEYS[1])
if not encoded then return 0 end
local record = cjson.decode(encoded)
if not record.first_used_at or record.first_used_at == '' then record.first_used_at = ARGV[2] end
record.last_used_at = ARGV[2]
redis.call('SET', KEYS[1], cjson.encode(record), 'KEEPTTL')
redis.call('ZADD', KEYS[2], ARGV[3], ARGV[4])
return 1
`

// Repository stores dynamic clients and always resolves them from the authoritative write handle.
type Repository struct {
	redis     rediscli.Client
	prefix    string
	lifecycle config.OIDCDynamicClientRegistrationLifecycle
	auditor   Auditor
	now       func() time.Time
}

// ReserveAttempt atomically consumes anonymous registration attempt budget.
func (r *Repository) ReserveAttempt(ctx context.Context, sourceHash string, limits config.OIDCDynamicClientRegistrationLimits) error {
	if err := r.CleanupExpired(ctx, 100); err != nil {
		return err
	}

	handle, err := r.writeHandle()
	if err != nil {
		return err
	}

	keys := []string{
		r.registryKey("rate:source:" + sourceHash),
		r.registryKey("rate:source-day:" + sourceHash),
		r.registryKey("rate:global"),
	}
	arguments := []any{
		limits.SourceRegistrations,
		limits.SourceDailyRegistrations,
		limits.GlobalRegistrations,
		limits.SourceWindow.Milliseconds(),
		limits.GlobalWindow.Milliseconds(),
	}

	result, evalErr := handle.Eval(ctx, registrationAttemptScript, keys, arguments...).Int64()
	if evalErr != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, evalErr)
	}

	if result == 1 {
		return nil
	}

	if result == 2 || result == 3 {
		return ErrRateLimited
	}

	return fmt.Errorf("%w: unexpected attempt result %d", ErrUnavailable, result)
}

// CleanupExpired removes a bounded batch of expired active records and creates tombstones.
func (r *Repository) CleanupExpired(ctx context.Context, maximum int64) error {
	if maximum <= 0 {
		return nil
	}

	handle, err := r.writeHandle()
	if err != nil {
		return err
	}

	clientIDs, err := handle.ZRangeByScore(ctx, r.registryKey("active"), &redis.ZRangeBy{
		Min:   "-inf",
		Max:   strconv.FormatInt(r.now().UnixMilli(), 10),
		Count: maximum,
	}).Result()
	if err != nil {
		r.auditor.Record(ctx, AuditEvent{Operation: AuditOperationCleanup, Outcome: AuditOutcomeFailed, Reason: AuditReasonStorageFailure})

		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	for _, clientID := range clientIDs {
		if _, resolveErr := r.Get(ctx, clientID); resolveErr != nil && !errors.Is(resolveErr, ErrNotFound) {
			r.auditor.Record(ctx, AuditEvent{Operation: AuditOperationCleanup, Outcome: AuditOutcomeFailed, Reason: "expiry_failure", ClientID: clientID})

			return resolveErr
		}
	}

	if len(clientIDs) > 0 {
		r.auditor.Record(ctx, AuditEvent{Operation: AuditOperationCleanup, Outcome: AuditOutcomeSuccess, Reason: "expired_batch"})
	}

	return nil
}

// NewRepository creates an authoritative dynamic-client repository.
func NewRepository(client rediscli.Client, prefix string, lifecycle config.OIDCDynamicClientRegistrationLifecycle, auditors ...Auditor) *Repository {
	auditor := Auditor(discardAuditor{})
	if len(auditors) > 0 && auditors[0] != nil {
		auditor = auditors[0]
	}

	return &Repository{redis: client, prefix: prefix, lifecycle: lifecycle, auditor: auditor, now: time.Now}
}

// Register atomically enforces quotas, rate limits, and unique client creation.
func (r *Repository) Register(ctx context.Context, record *DynamicClientRecord, limits config.OIDCDynamicClientRegistrationLimits) error {
	handle, err := r.writeHandle()
	if err != nil {
		return err
	}

	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("%w: encode record: %v", ErrCorrupt, err)
	}

	now := r.now()
	maximumTTL := r.lifecycle.MaximumTTL
	keys := []string{
		r.clientKey(record.ClientID),
		r.registryKey("active"),
	}
	arguments := []any{
		encoded,
		now.UnixMilli(),
		maximumTTL.Milliseconds(),
		now.Add(r.lifecycle.UnusedTTL).UnixMilli(),
		limits.ActiveClients,
		record.ClientID,
	}

	result, evalErr := handle.Eval(ctx, registrationScript, keys, arguments...).Int64()
	if evalErr != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, evalErr)
	}

	switch result {
	case 1:
		return nil
	case 4:
		return ErrQuota
	case 5:
		return errClientIDCollision
	default:
		return fmt.Errorf("%w: unexpected registration result %d", ErrUnavailable, result)
	}
}

// Get resolves a dynamic client through the authoritative Redis handle without extending activity.
func (r *Repository) Get(ctx context.Context, clientID string) (*DynamicClientRecord, error) {
	handle, err := r.writeHandle()
	if err != nil {
		return nil, err
	}

	key := r.clientKey(clientID)

	encoded, err := handle.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	record := &DynamicClientRecord{}
	if err := json.Unmarshal(encoded, record); err != nil || record.ClientID != clientID || record.Profile != ProfileMailClientV1 {
		return nil, ErrCorrupt
	}

	now := r.now()
	if !record.RevokedAt.IsZero() || r.expired(record, now) {
		if err := r.expire(ctx, handle, key, clientID); err != nil {
			r.auditor.Record(ctx, AuditEvent{Operation: AuditOperationExpiry, Outcome: AuditOutcomeFailed, Reason: AuditReasonStorageFailure, ClientID: clientID})

			return nil, err
		}

		r.auditor.Record(ctx, AuditEvent{Operation: AuditOperationExpiry, Outcome: AuditOutcomeSuccess, Reason: "lifecycle_expired", ClientID: clientID})

		return nil, ErrNotFound
	}

	return record, nil
}

// Touch records activity only after a caller has validated a protocol use of the client.
func (r *Repository) Touch(ctx context.Context, clientID string) error {
	record, err := r.Get(ctx, clientID)
	if err != nil {
		return err
	}

	now := r.now()
	activeUntil := now.Add(r.lifecycle.InactivityTTL)
	absoluteExpiry := record.CreatedAt.Add(r.lifecycle.MaximumTTL)

	if activeUntil.After(absoluteExpiry) {
		activeUntil = absoluteExpiry
	}

	handle, err := r.writeHandle()
	if err != nil {
		return err
	}

	result, err := handle.Eval(
		ctx,
		touchScript,
		[]string{r.clientKey(clientID), r.registryKey("active")},
		now.UnixMilli(),
		now.UTC().Format(time.RFC3339Nano),
		activeUntil.UnixMilli(),
		clientID,
	).Int64()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	if result != 1 {
		return ErrNotFound
	}

	return nil
}

// writeHandle returns the sole permitted handle for security-sensitive DCR state.
func (r *Repository) writeHandle() (redis.UniversalClient, error) {
	if r == nil || r.redis == nil || r.redis.GetWriteHandle() == nil {
		return nil, ErrUnavailable
	}

	return r.redis.GetWriteHandle(), nil
}

// expired evaluates unused, inactivity, and absolute profile lifetimes.
func (r *Repository) expired(record *DynamicClientRecord, now time.Time) bool {
	if now.Sub(record.CreatedAt) >= r.lifecycle.MaximumTTL {
		return true
	}

	if record.FirstUsedAt.IsZero() {
		return now.Sub(record.CreatedAt) >= r.lifecycle.UnusedTTL
	}

	return now.Sub(record.LastUsedAt) >= r.lifecycle.InactivityTTL
}

// expire removes active state and leaves a bounded tombstone.
func (r *Repository) expire(ctx context.Context, handle redis.UniversalClient, key string, clientID string) error {
	pipe := handle.TxPipeline()
	pipe.Del(ctx, key)
	pipe.ZRem(ctx, r.registryKey("active"), clientID)
	pipe.Set(ctx, r.registryKey("tombstone:"+clientID), "expired", r.lifecycle.TombstoneTTL)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("%w: expire client: %v", ErrUnavailable, err)
	}

	return nil
}

// clientKey returns the namespaced dynamic-client key.
func (r *Repository) clientKey(clientID string) string {
	return r.registryKey("client:" + clientID)
}

// registryKey pins every atomic registry key to one Redis Cluster hash slot.
func (r *Repository) registryKey(suffix string) string {
	return r.prefix + "oidc:dcr:{registry}:" + suffix
}

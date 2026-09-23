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

// Redis Cluster layout: every dynamic client owns the slot {<client_id>} for its record and tombstone,
// so per-request lookups spread across the cluster. The active-client index and the registration rate
// limits stay in the deliberately global {registry} slot because quota and global rate enforcement need
// one atomic counter. No script or transaction spans both slots; the two sides are kept consistent by
// ordered writes, compensation, and index repair in CleanupExpired.

// registrationScript reserves quota and index membership inside the {registry} slot.
const registrationScript = `
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then return 4 end
if redis.call('ZADD', KEYS[1], 'NX', ARGV[2], ARGV[3]) == 0 then return 5 end
return 1
`

const registrationAttemptScript = `
if tonumber(redis.call('GET', KEYS[1]) or '0') >= tonumber(ARGV[1]) then return 2 end
if tonumber(redis.call('GET', KEYS[2]) or '0') >= tonumber(ARGV[2]) then return 4 end
if tonumber(redis.call('GET', KEYS[3]) or '0') >= tonumber(ARGV[3]) then return 3 end
local source_count = redis.call('INCR', KEYS[1])
if source_count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[4]) end
local source_day_count = redis.call('INCR', KEYS[2])
if source_day_count == 1 then redis.call('PEXPIRE', KEYS[2], 86400000) end
local global_count = redis.call('INCR', KEYS[3])
if global_count == 1 then redis.call('PEXPIRE', KEYS[3], ARGV[5]) end
return 1
`

// touchIndexScript extends index activity only while the registry still considers the client active.
const touchIndexScript = `
local score = redis.call('ZSCORE', KEYS[1], ARGV[3])
if not score or tonumber(score) <= tonumber(ARGV[1]) then return 0 end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[3])
return 1
`

// touchRecordScript rewrites activity timestamps without resurrecting an expired client record.
const touchRecordScript = `
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'KEEPTTL')
return 1
`

const (
	// cleanupBatchSize bounds the expired clients processed after one admitted registration attempt.
	cleanupBatchSize = 100
	// repairSampleSize bounds the random index entries checked for a missing record per cleanup run.
	repairSampleSize = 10
	// repairGracePeriod protects registrations between their index reservation and their record write.
	// Scores come from the clock of the instance that reserved the entry, while the repair compares them
	// with its own clock. The period therefore also absorbs clock skew between instances; a few seconds of
	// write latency alone would need far less.
	repairGracePeriod = 5 * time.Minute
)

// attemptRateLimitCauses maps registrationAttemptScript rejection codes to classified causes.
var attemptRateLimitCauses = map[int64]error{
	2: ErrSourceWindowRateLimited,
	3: ErrGlobalRateLimited,
	4: ErrSourceDailyRateLimited,
}

// Repository stores dynamic clients and always resolves them from the authoritative write handle.
type Repository struct {
	redis     rediscli.Client
	prefix    string
	lifecycle config.OIDCDynamicClientRegistrationLifecycle
	auditor   Auditor
	now       func() time.Time
}

// ReserveAttempt atomically consumes anonymous registration attempt budget.
//
// Expired clients are cleaned up only after the attempt was admitted, so rejected anonymous requests never
// pay for cleanup reads.
func (r *Repository) ReserveAttempt(ctx context.Context, sourceHash string, limits config.OIDCDynamicClientRegistrationLimits) error {
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
		return r.CleanupExpired(ctx, cleanupBatchSize)
	}

	if cause, limited := attemptRateLimitCauses[result]; limited {
		return fmt.Errorf("%w: %w", ErrRateLimited, cause)
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

	clientIDs, err := handle.ZRangeByScore(ctx, r.activeKey(), &redis.ZRangeBy{
		Min:   "-inf",
		Max:   strconv.FormatInt(r.now().UnixMilli(), 10),
		Count: maximum,
	}).Result()
	if err != nil {
		r.auditor.Record(ctx, AuditEvent{Operation: AuditOperationCleanup, Outcome: AuditOutcomeFailed, Reason: AuditReasonStorageFailure})

		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	for _, clientID := range clientIDs {
		if err := r.cleanupClient(ctx, handle, clientID); err != nil {
			r.auditor.Record(ctx, AuditEvent{Operation: AuditOperationCleanup, Outcome: AuditOutcomeFailed, Reason: "expiry_failure", ClientID: clientID})

			return err
		}
	}

	if len(clientIDs) > 0 {
		r.auditor.Record(ctx, AuditEvent{Operation: AuditOperationCleanup, Outcome: AuditOutcomeSuccess, Reason: "expired_batch"})
	}

	return r.repairIndexSample(ctx, handle)
}

// repairIndexSample removes a bounded random sample of index entries whose client record is gone.
//
// Entries are only considered when their score proves that they were not reserved within the last
// repairGracePeriod, so a registration between its index reservation and its record write is never
// touched. Remaining orphans are removed by the regular cleanup once their score is due.
func (r *Repository) repairIndexSample(ctx context.Context, handle redis.UniversalClient) error {
	members, err := handle.ZRandMemberWithScores(ctx, r.activeKey(), repairSampleSize).Result()
	if err != nil {
		return fmt.Errorf("%w: sample client index: %v", ErrUnavailable, err)
	}

	settledBefore := float64(r.now().Add(r.lifecycle.UnusedTTL - repairGracePeriod).UnixMilli())

	for _, member := range members {
		clientID, ok := member.Member.(string)
		if !ok || member.Score >= settledBefore {
			continue
		}

		if err := r.removeOrphanedEntry(ctx, handle, clientID); err != nil {
			return err
		}
	}

	return nil
}

// removeOrphanedEntry drops one index entry after confirming that its client record no longer exists.
func (r *Repository) removeOrphanedEntry(ctx context.Context, handle redis.UniversalClient, clientID string) error {
	exists, err := handle.Exists(ctx, r.clientKey(clientID)).Result()
	if err != nil {
		return fmt.Errorf("%w: check client record: %v", ErrUnavailable, err)
	}

	if exists != 0 {
		return nil
	}

	if err := handle.ZRem(ctx, r.activeKey(), clientID).Err(); err != nil {
		return fmt.Errorf("%w: repair client index: %v", ErrUnavailable, err)
	}

	return nil
}

// cleanupClient expires one due client and repairs index entries whose record no longer exists.
// A still-active client gets its index score realigned with the expiry its record actually carries.
func (r *Repository) cleanupClient(ctx context.Context, handle redis.UniversalClient, clientID string) error {
	record, err := r.Get(ctx, clientID)
	if err == nil {
		score := float64(r.expiresAt(record).UnixMilli())
		if err := handle.ZAddXX(ctx, r.activeKey(), redis.Z{Score: score, Member: clientID}).Err(); err != nil {
			return fmt.Errorf("%w: realign client index: %v", ErrUnavailable, err)
		}

		return nil
	}

	if !errors.Is(err, ErrNotFound) {
		return err
	}

	if err := handle.ZRem(ctx, r.activeKey(), clientID).Err(); err != nil {
		return fmt.Errorf("%w: repair client index: %v", ErrUnavailable, err)
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

// Register enforces quota and index membership atomically in the registry slot, then creates the record.
//
// The registry reservation comes first so a record never exists without quota admission. A failed or
// colliding record write releases the reservation again; a reservation orphaned by a crash is removed by
// CleanupExpired once its unused-client deadline passes.
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

	result, evalErr := handle.Eval(
		ctx,
		registrationScript,
		[]string{r.activeKey()},
		limits.ActiveClients,
		now.Add(r.lifecycle.UnusedTTL).UnixMilli(),
		record.ClientID,
	).Int64()
	if evalErr != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, evalErr)
	}

	switch result {
	case 1:
		return r.createRecord(ctx, handle, record.ClientID, encoded)
	case 4:
		return ErrQuota
	case 5:
		return errClientIDCollision
	default:
		return fmt.Errorf("%w: unexpected registration result %d", ErrUnavailable, result)
	}
}

// createRecord writes a new client record and releases the registry reservation on a collision.
//
// A failed write keeps the reservation because its outcome is unknown: a record written despite a
// client-side timeout stays counted, and a reservation without a record is removed by the index repair.
func (r *Repository) createRecord(ctx context.Context, handle redis.UniversalClient, clientID string, encoded []byte) error {
	created, err := handle.SetNX(ctx, r.clientKey(clientID), encoded, r.lifecycle.MaximumTTL).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	if created {
		return nil
	}

	_ = handle.ZRem(ctx, r.activeKey(), clientID).Err()

	return errClientIDCollision
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
//
// The registry index is extended before the record so a record is only rewritten while the registry
// still considers the client active. An index entry extended for a record that vanished meanwhile is
// repaired by CleanupExpired.
func (r *Repository) Touch(ctx context.Context, clientID string) error {
	record, err := r.Get(ctx, clientID)
	if err != nil {
		return err
	}

	now := r.now()

	encoded, err := encodeTouchedRecord(record, now)
	if err != nil {
		return err
	}

	activeUntil := r.expiresAt(record)

	handle, err := r.writeHandle()
	if err != nil {
		return err
	}

	if err := evalActivity(ctx, handle, touchIndexScript, r.activeKey(), now.UnixMilli(), activeUntil.UnixMilli(), clientID); err != nil {
		return err
	}

	return evalActivity(ctx, handle, touchRecordScript, r.clientKey(clientID), encoded)
}

// evalActivity runs one single-slot activity script and maps a rejected update to ErrNotFound.
func evalActivity(ctx context.Context, handle redis.UniversalClient, script string, key string, arguments ...any) error {
	result, err := handle.Eval(ctx, script, []string{key}, arguments...).Int64()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	if result != 1 {
		return ErrNotFound
	}

	return nil
}

// encodeTouchedRecord updates lifecycle timestamps and preserves integer metadata encoding.
func encodeTouchedRecord(record *DynamicClientRecord, now time.Time) ([]byte, error) {
	if record.FirstUsedAt.IsZero() {
		record.FirstUsedAt = now
	}

	record.LastUsedAt = now

	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("%w: encode touched record: %v", ErrCorrupt, err)
	}

	return encoded, nil
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
	return !now.Before(r.expiresAt(record))
}

// expiresAt returns the earliest of the unused or inactivity deadline and the absolute lifetime.
func (r *Repository) expiresAt(record *DynamicClientRecord) time.Time {
	deadline := record.CreatedAt.Add(r.lifecycle.UnusedTTL)
	if !record.FirstUsedAt.IsZero() {
		deadline = record.LastUsedAt.Add(r.lifecycle.InactivityTTL)
	}

	if absolute := record.CreatedAt.Add(r.lifecycle.MaximumTTL); absolute.Before(deadline) {
		return absolute
	}

	return deadline
}

// expire removes the record with its tombstone in the client slot, then drops the registry entry.
// The record is removed first so the client stops resolving even if the index update fails; such a
// stale index entry is repaired by CleanupExpired, so the index update is best-effort.
func (r *Repository) expire(ctx context.Context, handle redis.UniversalClient, key string, clientID string) error {
	pipe := handle.TxPipeline()
	pipe.Del(ctx, key)
	pipe.Set(ctx, r.tombstoneKey(clientID), "expired", r.lifecycle.TombstoneTTL)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("%w: expire client: %v", ErrUnavailable, err)
	}

	_ = handle.ZRem(ctx, r.activeKey(), clientID).Err()

	return nil
}

// clientKey returns the dynamic-client record key in the client's own hash slot.
func (r *Repository) clientKey(clientID string) string {
	return r.prefix + "oidc:dcr:client:{" + clientID + "}"
}

// tombstoneKey returns the bounded expiry marker that shares the client's hash slot.
func (r *Repository) tombstoneKey(clientID string) string {
	return r.clientKey(clientID) + ":tombstone"
}

// activeKey returns the registry index of active clients ordered by their next expiry check.
//
// The name differs from the index of the former shared-tag layout on purpose: members of that index have no
// readable record any more and must not count against the quota after the hard cut.
func (r *Repository) activeKey() string {
	return r.registryKey("clients")
}

// registryKey pins the global registry index and rate-limit counters to one Redis Cluster hash slot.
func (r *Repository) registryKey(suffix string) string {
	return r.prefix + "oidc:dcr:{registry}:" + suffix
}

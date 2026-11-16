// Copyright (C) 2026 Christian Roessner
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

package bruteforce

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/stats"
	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/redis/go-redis/v9"
)

const (
	// AffectedAccountsMaintenanceInterval is the tick of the background maintenance loop.
	AffectedAccountsMaintenanceInterval = time.Minute

	// affectedAccountsLeaseTTL is shorter than the tick interval so a single instance acquires every tick even
	// when its ticks drift by a few milliseconds; a short overlap between instances is harmless because every
	// step is idempotent and guarded.
	affectedAccountsLeaseTTL = AffectedAccountsMaintenanceInterval * 3 / 4

	// affectedAccountsMaintenanceBatch bounds the members handled by one maintenance step.
	affectedAccountsMaintenanceBatch = 256

	// affectedAccountsHeartbeatTTL is how long the maintenance state survives without a tick. A gap longer
	// than this (cleanup disabled, downgrade, outage) re-arms the lifecycle before anything is removed again.
	affectedAccountsHeartbeatTTL = 10 * AffectedAccountsMaintenanceInterval

	stateFieldArmedAt     = "armed_at"
	stateFieldRearmDone   = "rearm_done"
	stateFieldRearmCursor = "rearm_cursor"
	stateFieldAdoptCursor = "adopt_cursor"
	stateFieldIndexCursor = "index_cursor"

	adoptModeRearm = "gt"
	adoptModeAdopt = "nx"
)

// affectedAccountsExpireScript removes members from S and L only while their deadline in L is still due.
// KEYS: S, L. ARGV: now, member... It runs atomically on the S/L slot and returns the removed members.
var affectedAccountsExpireScript = redis.NewScript(`
local now = tonumber(ARGV[1])
local removed = {}
for i = 2, #ARGV do
  local deadline = redis.call('ZSCORE', KEYS[2], ARGV[i])
  if deadline and tonumber(deadline) <= now then
    redis.call('ZREM', KEYS[2], ARGV[i])
    redis.call('SREM', KEYS[1], ARGV[i])
    removed[#removed + 1] = ARGV[i]
  end
end
return removed
`)

// affectedAccountsAdoptScript writes deadlines only for members that are still in S, so a concurrent flush is
// never undone. KEYS: S, L. ARGV: mode ("nx" adopts, "gt" re-arms), deadline, member... Returns the changes.
var affectedAccountsAdoptScript = redis.NewScript(`
local changed = 0
for i = 3, #ARGV do
  if redis.call('SISMEMBER', KEYS[1], ARGV[i]) == 1 then
    if ARGV[1] == 'gt' then
      changed = changed + redis.call('ZADD', KEYS[2], 'GT', 'CH', ARGV[2], ARGV[i])
    else
      changed = changed + redis.call('ZADD', KEYS[2], 'NX', ARGV[2], ARGV[i])
    end
  end
end
return changed
`)

// errAffectedAccountsStep wraps a maintenance step failure with its step name.
var errAffectedAccountsStep = errors.New("affected-account maintenance step failed")

// AffectedAccountsMaintainer ages out stale affected-account metadata in bounded steps.
//
// It never touches password histories, bans, counters, RWP, reputation, or toleration keys. Only S, I, L and
// its own state are changed, and a member is removed from S only by the guarded expire script.
type AffectedAccountsMaintainer struct {
	redis   rediscli.Client
	logger  *slog.Logger
	now     func() time.Time
	refused atomic.Bool
	batch   int
}

// NewAffectedAccountsMaintainer creates a maintainer for the given Redis client.
func NewAffectedAccountsMaintainer(redisClient rediscli.Client, logger *slog.Logger) *AffectedAccountsMaintainer {
	return &AffectedAccountsMaintainer{redis: redisClient, logger: logger, now: time.Now, batch: affectedAccountsMaintenanceBatch}
}

// RunOnce performs one maintenance tick: it refreshes the size gauges and, when cleanup is enabled and this
// instance holds the tick lease, runs the bounded lifecycle steps.
func (m *AffectedAccountsMaintainer) RunOnce(ctx context.Context, cfg config.File) error {
	keys, err := NewAffectedAccountKeys(cfg.GetServer().GetRedis().GetPrefix())
	if err != nil {
		m.reportRefusal(err)

		return err
	}

	m.refused.Store(false)
	m.updateGauges(ctx, cfg, keys)

	if !cfg.GetBruteForce().IsAffectedAccountsCleanupEnabled() {
		return nil
	}

	acquired, err := m.acquireLease(ctx, cfg, keys)
	if err != nil {
		return m.stepError("lease", err)
	}

	if !acquired {
		return nil
	}

	run := &affectedAccountsRun{
		maintainer: m,
		cfg:        cfg,
		keys:       keys,
		now:        m.now(),
		retention:  AffectedAccountRetention(cfg),
	}

	return run.execute(ctx)
}

// redisCall bounds one Redis call by the configured write timeout and counts its read and write commands.
func redisCall(ctx context.Context, cfg config.File, reads int, writes int) (context.Context, context.CancelFunc) {
	metrics := stats.GetMetrics()

	if reads > 0 {
		metrics.GetRedisReadCounter().Add(float64(reads))
	}

	if writes > 0 {
		metrics.GetRedisWriteCounter().Add(float64(writes))
	}

	return util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
}

// acquireLease takes the tick lease so that normally one instance works per tick.
func (m *AffectedAccountsMaintainer) acquireLease(ctx context.Context, cfg config.File, keys AffectedAccountKeys) (bool, error) {
	dCtx, cancel := redisCall(ctx, cfg, 0, 1)
	defer cancel()

	return m.redis.GetWriteHandle().SetNX(dCtx, keys.Lease, strconv.FormatInt(m.now().UnixNano(), 10), affectedAccountsLeaseTTL).Result()
}

// reportRefusal logs and counts a refused maintenance run once per transition into the refused state.
func (m *AffectedAccountsMaintainer) reportRefusal(err error) {
	if m.refused.Swap(true) {
		return
	}

	affectedAccountsMaintenanceErrors.WithLabelValues("refused").Inc()

	_ = level.Warn(m.logger).Log(
		definitions.LogKeyMsg, "Affected-account maintenance refused: the Redis prefix prevents a same-slot retention key",
		definitions.LogKeyError, err,
	)
}

// updateGauges publishes the cardinalities of S, L and I from the primary; every instance does this per tick.
func (m *AffectedAccountsMaintainer) updateGauges(ctx context.Context, cfg config.File, keys AffectedAccountKeys) {
	var setCard, retentionCard, indexCard *redis.IntCmd

	dCtx, cancel := redisCall(ctx, cfg, 3, 0)
	defer cancel()

	cmds, execErr := m.redis.GetWriteHandle().Pipelined(dCtx, func(pipe redis.Pipeliner) error {
		setCard = pipe.SCard(dCtx, keys.Set)
		retentionCard = pipe.ZCard(dCtx, keys.Retention)
		indexCard = pipe.ZCard(dCtx, keys.Index)

		return nil
	})

	if err := errors.Join(setCard.Err(), retentionCard.Err(), indexCard.Err(), rediscli.UnattributedPipelineError(execErr, cmds)); err != nil {
		_ = m.stepError("gauges", err)

		return
	}

	affectedAccountsMembers.WithLabelValues("set").Set(float64(setCard.Val()))
	affectedAccountsMembers.WithLabelValues("retention").Set(float64(retentionCard.Val()))
	affectedAccountsMembers.WithLabelValues("index").Set(float64(indexCard.Val()))
}

// stepError counts and logs a failed step and returns it wrapped with the step name.
func (m *AffectedAccountsMaintainer) stepError(step string, err error) error {
	affectedAccountsMaintenanceErrors.WithLabelValues(step).Inc()

	_ = level.Error(m.logger).Log(
		definitions.LogKeyMsg, "Affected-account maintenance step failed",
		"step", step,
		definitions.LogKeyError, err,
	)

	return fmt.Errorf("%w: %s: %w", errAffectedAccountsStep, step, err)
}

// affectedAccountsState is the persisted maintenance progress shared by all instances.
type affectedAccountsState struct {
	rearmCursor uint64
	adoptCursor uint64
	indexCursor uint64
	rearmDone   bool
	armed       bool
}

// affectedAccountsRun carries the inputs of one leased maintenance tick.
type affectedAccountsRun struct {
	maintainer *AffectedAccountsMaintainer
	cfg        config.File
	keys       AffectedAccountKeys
	now        time.Time
	retention  time.Duration
}

// handle returns the write handle; all maintenance reads go to the primary to avoid replica lag.
func (r *affectedAccountsRun) handle() redis.UniversalClient {
	return r.maintainer.redis.GetWriteHandle()
}

// execute runs the steps of one tick. Until a full re-arm pass over S has finished after the heartbeat was
// missing, nothing is removed: every member first gets a deadline of at least now + R. The heartbeat is
// refreshed before any step, so failing steps never trigger a re-arm; independent steps run even when another
// step failed, and their errors are joined.
func (r *affectedAccountsRun) execute(ctx context.Context) error {
	if err := r.refreshHeartbeat(ctx); err != nil {
		return r.maintainer.stepError("state", err)
	}

	state, err := r.loadState(ctx)
	if err != nil {
		return r.maintainer.stepError("state", err)
	}

	if !state.rearmDone {
		next, err := r.adoptStep(ctx, state.rearmCursor, adoptModeRearm)
		if err != nil {
			return r.maintainer.stepError("rearm", err)
		}

		state.rearmCursor = next
		state.rearmDone = next == 0

		return r.saveState(ctx, state)
	}

	var errs []error

	if err = r.removeStep(ctx); err != nil {
		errs = append(errs, r.maintainer.stepError("remove", err))
	}

	if next, err := r.adoptStep(ctx, state.adoptCursor, adoptModeAdopt); err != nil {
		errs = append(errs, r.maintainer.stepError("adopt", err))
	} else {
		state.adoptCursor = next
	}

	if next, err := r.indexOrphanStep(ctx, state.indexCursor); err != nil {
		errs = append(errs, r.maintainer.stepError("index", err))
	} else {
		state.indexCursor = next
	}

	return errors.Join(append(errs, r.saveState(ctx, state))...)
}

// refreshHeartbeat extends the TTL of an existing state hash; a missing hash stays missing and arms a new
// generation in loadState.
func (r *affectedAccountsRun) refreshHeartbeat(ctx context.Context) error {
	dCtx, cancel := redisCall(ctx, r.cfg, 0, 1)
	defer cancel()

	return r.handle().Expire(dCtx, r.keys.State, affectedAccountsHeartbeatTTL).Err()
}

// loadState reads the maintenance state; a missing heartbeat arms a new lifecycle generation that starts
// with a re-arm pass.
func (r *affectedAccountsRun) loadState(ctx context.Context) (affectedAccountsState, error) {
	dCtx, cancel := redisCall(ctx, r.cfg, 1, 0)
	defer cancel()

	fields, err := r.handle().HGetAll(dCtx, r.keys.State).Result()
	if err != nil {
		return affectedAccountsState{}, err
	}

	if fields[stateFieldArmedAt] == "" {
		affectedAccountsMaintenanceActions.WithLabelValues("armed").Inc()

		return affectedAccountsState{}, nil
	}

	return affectedAccountsState{
		rearmCursor: parseStateCursor(fields[stateFieldRearmCursor]),
		adoptCursor: parseStateCursor(fields[stateFieldAdoptCursor]),
		indexCursor: parseStateCursor(fields[stateFieldIndexCursor]),
		rearmDone:   fields[stateFieldRearmDone] == "1",
		armed:       true,
	}, nil
}

// parseStateCursor decodes a stored SCAN cursor; an unreadable value restarts the pass from the beginning.
func parseStateCursor(raw string) uint64 {
	cursor, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0
	}

	return cursor
}

// saveState persists progress and refreshes the heartbeat TTL in one write pipeline.
func (r *affectedAccountsRun) saveState(ctx context.Context, state affectedAccountsState) error {
	rearmDone := "0"
	if state.rearmDone {
		rearmDone = "1"
	}

	values := []any{
		stateFieldRearmDone, rearmDone,
		stateFieldRearmCursor, strconv.FormatUint(state.rearmCursor, 10),
		stateFieldAdoptCursor, strconv.FormatUint(state.adoptCursor, 10),
		stateFieldIndexCursor, strconv.FormatUint(state.indexCursor, 10),
	}

	if !state.armed {
		values = append(values, stateFieldArmedAt, strconv.FormatInt(r.now.Unix(), 10))
	}

	var setCmd *redis.IntCmd

	var expireCmd *redis.BoolCmd

	dCtx, cancel := redisCall(ctx, r.cfg, 0, 2)
	defer cancel()

	cmds, execErr := r.handle().Pipelined(dCtx, func(pipe redis.Pipeliner) error {
		setCmd = pipe.HSet(dCtx, r.keys.State, values...)
		expireCmd = pipe.Expire(dCtx, r.keys.State, affectedAccountsHeartbeatTTL)

		return nil
	})

	if err := errors.Join(setCmd.Err(), expireCmd.Err(), rediscli.UnattributedPipelineError(execErr, cmds)); err != nil {
		return r.maintainer.stepError("state", err)
	}

	return nil
}

// removeStep removes due members without password history and extends the deadline of due members that still
// have one. Candidates are bounded by the batch size.
func (r *affectedAccountsRun) removeStep(ctx context.Context) error {
	nowScore := strconv.FormatInt(r.now.Unix(), 10)

	dCtx, cancel := redisCall(ctx, r.cfg, 1, 0)
	defer cancel()

	candidates, err := r.handle().ZRangeByScore(dCtx, r.keys.Retention, &redis.ZRangeBy{
		Min:   "-inf",
		Max:   nowScore,
		Count: int64(r.maintainer.batch),
	}).Result()
	if err != nil || len(candidates) == 0 {
		return err
	}

	removable, extensions, err := r.classifyCandidates(ctx, candidates)
	if err != nil {
		return err
	}

	if err = r.extendDeadlines(ctx, extensions); err != nil {
		return err
	}

	return r.expireMembers(ctx, nowScore, removable)
}

// classifyCandidates reads the history TTL of every candidate from the primary. Members without history are
// removable; members with history get a new deadline at the end of that history.
func (r *affectedAccountsRun) classifyCandidates(ctx context.Context, candidates []string) ([]string, []redis.Z, error) {
	removable := make([]string, 0, len(candidates))
	extensions := make([]redis.Z, 0)
	batches := rediscli.ReadPipelineBatches{
		Client:    r.maintainer.redis,
		Cfg:       r.cfg,
		BatchSize: r.maintainer.batch,
		Primary:   true,
	}

	err := rediscli.RunReadPipelineBatches(ctx, batches, candidates,
		func(ctx context.Context, pipe redis.Pipeliner, account string) *redis.DurationCmd {
			return pipe.PTTL(ctx, GetPWHistIPsRedisKey(account, r.cfg))
		},
		func(account string, cmd *redis.DurationCmd) error {
			ttl := cmd.Val()

			switch {
			case ttl == time.Duration(-2):
				removable = append(removable, account)
			case ttl < 0:
				// A history without TTL is kept and re-checked after another retention period.
				extensions = append(extensions, redis.Z{Score: affectedAccountDeadline(r.now, r.retention), Member: account})
			default:
				extensions = append(extensions, redis.Z{Score: affectedAccountDeadline(r.now, ttl+time.Second), Member: account})
			}

			return nil
		},
	)

	return removable, extensions, err
}

// extendDeadlines moves existing deadlines forward; XX never re-creates an entry for a flushed member.
func (r *affectedAccountsRun) extendDeadlines(ctx context.Context, extensions []redis.Z) error {
	if len(extensions) == 0 {
		return nil
	}

	dCtx, cancel := redisCall(ctx, r.cfg, 0, 1)
	defer cancel()

	changed, err := r.handle().ZAddArgs(dCtx, r.keys.Retention, redis.ZAddArgs{
		XX:      true,
		GT:      true,
		Ch:      true,
		Members: extensions,
	}).Result()
	if err != nil {
		return err
	}

	affectedAccountsMaintenanceActions.WithLabelValues("extended").Add(float64(changed))

	return nil
}

// expireMembers runs the guarded expire script on S and L, then removes the expired members from I and
// restores the index entry of any member a writer re-added in the meantime. A failed index removal leaves
// orphans that the index step repairs.
func (r *affectedAccountsRun) expireMembers(ctx context.Context, nowScore string, removable []string) error {
	if len(removable) == 0 {
		return nil
	}

	args := append([]any{nowScore}, rediscli.StringsToArgs(removable)...)

	dCtx, cancel := redisCall(ctx, r.cfg, 0, 2)
	defer cancel()

	removed, err := affectedAccountsExpireScript.Run(dCtx, r.handle(), []string{r.keys.Set, r.keys.Retention}, args...).StringSlice()
	if err != nil {
		return err
	}

	affectedAccountsMaintenanceActions.WithLabelValues("removed").Add(float64(len(removed)))

	if len(removed) == 0 {
		return nil
	}

	if err = r.handle().ZRem(dCtx, r.keys.Index, rediscli.StringsToArgs(removed)...).Err(); err != nil {
		return err
	}

	return r.restoreReaddedIndexEntries(ctx, removed)
}

// restoreReaddedIndexEntries re-adds index entries for removed members that a concurrent writer put back into S
// between the expire script and the index removal; the score is the restore time of the new episode.
func (r *affectedAccountsRun) restoreReaddedIndexEntries(ctx context.Context, removed []string) error {
	readded, err := r.membersInSet(ctx, removed, true)
	if err != nil || len(readded) == 0 {
		return err
	}

	restored, err := r.addIndexEntries(ctx, readded)
	if err != nil {
		return err
	}

	affectedAccountsMaintenanceActions.WithLabelValues("index_restored").Add(float64(restored))

	return nil
}

// adoptStep scans one bounded slice of S. It gives members deadlines through the guarded adopt script (NX for
// regular adoption, GT for a re-arm pass) and backfills missing index entries. It returns the next cursor.
func (r *affectedAccountsRun) adoptStep(ctx context.Context, cursor uint64, mode string) (uint64, error) {
	dCtx, cancel := redisCall(ctx, r.cfg, 1, 1)
	defer cancel()

	members, next, err := r.handle().SScan(dCtx, r.keys.Set, cursor, "", int64(r.maintainer.batch)).Result()
	if err != nil || len(members) == 0 {
		return next, err
	}

	args := append([]any{mode, affectedAccountDeadline(r.now, r.retention)}, rediscli.StringsToArgs(members)...)

	changed, err := affectedAccountsAdoptScript.Run(dCtx, r.handle(), []string{r.keys.Set, r.keys.Retention}, args...).Int64()
	if err != nil {
		return cursor, err
	}

	action := "adopted"
	if mode == adoptModeRearm {
		action = "rearmed"
	}

	affectedAccountsMaintenanceActions.WithLabelValues(action).Add(float64(changed))

	if err = r.backfillIndex(ctx, members); err != nil {
		return cursor, err
	}

	return next, nil
}

// backfillIndex adds index entries for scanned members that lack one, scored with the repair time. Existing
// first-seen scores are never changed. Members flushed meanwhile are removed again by the orphan check.
func (r *affectedAccountsRun) backfillIndex(ctx context.Context, members []string) error {
	added, err := r.addIndexEntries(ctx, members)
	if err != nil {
		return err
	}

	affectedAccountsMaintenanceActions.WithLabelValues("backfilled").Add(float64(added))

	if added == 0 {
		return nil
	}

	return r.removeIndexOrphans(ctx, members)
}

// addIndexEntries adds members to I with the current time as score, keeping existing first-seen scores (NX).
func (r *affectedAccountsRun) addIndexEntries(ctx context.Context, members []string) (int64, error) {
	entries := make([]redis.Z, len(members))
	for index, member := range members {
		entries[index] = redis.Z{Score: float64(r.now.Unix()), Member: member}
	}

	dCtx, cancel := redisCall(ctx, r.cfg, 0, 1)
	defer cancel()

	return r.handle().ZAddNX(dCtx, r.keys.Index, entries...).Result()
}

// indexOrphanStep scans one bounded slice of I and removes entries without a member in S.
func (r *affectedAccountsRun) indexOrphanStep(ctx context.Context, cursor uint64) (uint64, error) {
	dCtx, cancel := redisCall(ctx, r.cfg, 1, 0)
	defer cancel()

	pairs, next, err := r.handle().ZScan(dCtx, r.keys.Index, cursor, "", int64(r.maintainer.batch)).Result()
	if err != nil {
		return cursor, err
	}

	members := make([]string, 0, len(pairs)/2)
	for index := 0; index < len(pairs); index += 2 {
		members = append(members, pairs[index])
	}

	if err = r.removeIndexOrphans(ctx, members); err != nil {
		return cursor, err
	}

	return next, nil
}

// removeIndexOrphans removes the given members from I when S no longer contains them. The check and the
// removal are not atomic (different slots); a member re-added in between is backfilled on the next pass.
func (r *affectedAccountsRun) removeIndexOrphans(ctx context.Context, members []string) error {
	orphans, err := r.membersInSet(ctx, members, false)
	if err != nil || len(orphans) == 0 {
		return err
	}

	dCtx, cancel := redisCall(ctx, r.cfg, 0, 1)
	defer cancel()

	removed, err := r.handle().ZRem(dCtx, r.keys.Index, rediscli.StringsToArgs(orphans)...).Result()
	if err != nil {
		return err
	}

	affectedAccountsMaintenanceActions.WithLabelValues("index_orphan_removed").Add(float64(removed))

	return nil
}

// membersInSet returns the members whose S membership equals want, checked with one SMISMEMBER.
func (r *affectedAccountsRun) membersInSet(ctx context.Context, members []string, want bool) ([]string, error) {
	if len(members) == 0 {
		return nil, nil
	}

	dCtx, cancel := redisCall(ctx, r.cfg, 1, 0)
	defer cancel()

	isMember, err := r.handle().SMIsMember(dCtx, r.keys.Set, rediscli.StringsToArgs(members)...).Result()
	if err != nil {
		return nil, err
	}

	selected := make([]string, 0)

	for index, present := range isMember {
		if present == want {
			selected = append(selected, members[index])
		}
	}

	return selected, nil
}

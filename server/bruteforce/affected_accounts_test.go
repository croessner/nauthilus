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
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/testing/rediscluster"
	"github.com/croessner/nauthilus/v4/server/testing/redisslot"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
)

// lifecycleFixture drives the affected-account maintenance against miniredis with a controllable clock.
type lifecycleFixture struct {
	*preAuthFixture
	keys       AffectedAccountKeys
	maintainer *AffectedAccountsMaintainer
	now        time.Time
	retention  time.Duration
}

// newLifecycleFixture builds a maintainer with a small batch so bounds are visible in tests.
func newLifecycleFixture(t *testing.T, batch int) *lifecycleFixture {
	t.Helper()

	base := newTriggeredFixture(t, "203.0.113.90")

	keys, err := NewAffectedAccountKeys(base.cfg.GetServer().GetRedis().GetPrefix())
	if err != nil {
		t.Fatalf("lifecycle keys: %v", err)
	}

	fixture := &lifecycleFixture{
		preAuthFixture: base,
		keys:           keys,
		maintainer:     NewAffectedAccountsMaintainer(base.redis, log.GetLogger()),
		now:            time.Now().Truncate(time.Second),
		retention:      AffectedAccountRetention(base.cfg),
	}

	fixture.maintainer.batch = batch
	fixture.maintainer.now = func() time.Time { return fixture.now }

	return fixture
}

// tick runs one maintenance tick; the lease is dropped first because the fixture clock does not move miniredis.
func (f *lifecycleFixture) tick(t *testing.T) error {
	t.Helper()

	f.storage.Del(f.keys.Lease)

	return f.maintainer.RunOnce(t.Context(), f.cfg)
}

// mustTick runs one tick and fails the test on error.
func (f *lifecycleFixture) mustTick(t *testing.T) {
	t.Helper()

	if err := f.tick(t); err != nil {
		t.Fatalf("maintenance tick: %v", err)
	}
}

// historyKey returns the password-history IP set of an account.
func (f *lifecycleFixture) historyKey(account string) string {
	return GetPWHistIPsRedisKey(account, f.cfg)
}

// seedLegacy stores a member the way the previous release did: S and I, but no retention deadline.
func (f *lifecycleFixture) seedLegacy(t *testing.T, account string, withHistory bool) {
	t.Helper()

	if _, err := f.storage.SetAdd(f.keys.Set, account); err != nil {
		t.Fatalf("seed set: %v", err)
	}

	if _, err := f.storage.ZAdd(f.keys.Index, 1000, account); err != nil {
		t.Fatalf("seed index: %v", err)
	}

	if withHistory {
		if _, err := f.storage.SetAdd(f.historyKey(account), "192.0.2.1"); err != nil {
			t.Fatalf("seed history: %v", err)
		}

		f.storage.SetTTL(f.historyKey(account), time.Hour)
	}
}

// state reports whether an account is in S and I and returns its deadline in L (0 when missing).
func (f *lifecycleFixture) state(account string) (bool, bool, float64) {
	ctx := context.Background()
	inSet, _ := f.client.SIsMember(ctx, f.keys.Set, account).Result()
	_, indexErr := f.client.ZScore(ctx, f.keys.Index, account).Result()
	deadline, _ := f.client.ZScore(ctx, f.keys.Retention, account).Result()

	return inSet, indexErr == nil, deadline
}

// rearm runs ticks until the re-arm pass of a new lifecycle generation has finished.
func (f *lifecycleFixture) rearm(t *testing.T) {
	t.Helper()

	for range 100 {
		f.mustTick(t)

		if f.storage.HGet(f.keys.State, stateFieldRearmDone) == "1" {
			return
		}
	}

	t.Fatal("re-arm pass did not finish")
}

// lifecycleAccounts returns n account names.
func lifecycleAccounts(n int) []string {
	accounts := make([]string, n)
	for index := range accounts {
		accounts[index] = fmt.Sprintf("bench%d@example.test", index)
	}

	return accounts
}

func TestAffectedAccountRetentionCoversConfiguredLifetimes(t *testing.T) {
	cases := []struct {
		name string
		edit func(*config.FileSettings)
		want time.Duration
	}{
		{name: "default_floor", edit: func(*config.FileSettings) {}, want: config.DefaultAffectedAccountsRetention},
		{name: "configured_retention", edit: func(s *config.FileSettings) { s.BruteForce.AffectedAccounts.Retention = 72 * time.Hour }, want: 72 * time.Hour},
		{name: "ban_time_plus_periods", edit: func(s *config.FileSettings) {
			s.BruteForce.Buckets = []config.BruteForceRule{{Name: "long", Period: 6 * time.Hour, BanTime: 24 * time.Hour}}
		}, want: 36 * time.Hour},
		{name: "password_history", edit: func(s *config.FileSettings) { s.Server.Redis.NegCacheTTL = 48 * time.Hour }, want: 48 * time.Hour},
		{name: "custom_toleration", edit: func(s *config.FileSettings) {
			s.BruteForce.CustomTolerations = []config.Tolerate{{TolerateTTL: 100 * time.Hour}}
		}, want: 100 * time.Hour},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			settings := &config.FileSettings{
				Server:     &config.ServerSection{Redis: config.Redis{NegCacheTTL: time.Hour}},
				BruteForce: &config.BruteForceSection{Buckets: []config.BruteForceRule{{Name: "b", Period: time.Minute, BanTime: time.Hour}}},
			}

			tc.edit(settings)

			if got := AffectedAccountRetention(settings); got != tc.want {
				t.Fatalf("retention = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestMaintenanceRearmsLegacyMembersBeforeRemovingStaleOnes(t *testing.T) {
	fixture := newLifecycleFixture(t, 4)
	accounts := lifecycleAccounts(10)

	for index, account := range accounts {
		fixture.seedLegacy(t, account, index < 3)
	}

	fixture.rearm(t)

	wantDeadline := affectedAccountDeadline(fixture.now, fixture.retention)
	for _, account := range accounts {
		fixture.assertState(t, account, true, true, func(deadline float64) bool { return deadline == wantDeadline })
	}

	// Just before the deadline nothing is due.
	fixture.now = fixture.now.Add(fixture.retention - time.Minute)
	fixture.mustTick(t)
	fixture.assertSetSize(t, len(accounts), len(accounts))

	// The first due tick removes at most one batch.
	fixture.now = fixture.now.Add(2 * time.Minute)
	fixture.mustTick(t)
	fixture.assertSetSize(t, len(accounts)-4, len(accounts))

	for range 5 {
		fixture.mustTick(t)
	}

	nowScore := float64(fixture.now.Unix())

	for _, account := range accounts[:3] {
		fixture.assertState(t, account, true, true, func(deadline float64) bool { return deadline > nowScore })
	}

	for _, account := range accounts[3:] {
		fixture.assertState(t, account, false, false, func(deadline float64) bool { return deadline == 0 })
	}

	fixture.assertIdempotent(t, 3)
}

// assertState checks set and index membership and validates the retention deadline of one account.
func (f *lifecycleFixture) assertState(t *testing.T, account string, wantSet bool, wantIndex bool, validDeadline func(float64) bool) {
	t.Helper()

	inSet, inIndex, deadline := f.state(account)
	if inSet != wantSet || inIndex != wantIndex || !validDeadline(deadline) {
		t.Fatalf("%s: set=%t index=%t deadline=%v, want set=%t index=%t", account, inSet, inIndex, deadline, wantSet, wantIndex)
	}
}

// assertSetSize checks that the set size lies within [minimum, maximum].
func (f *lifecycleFixture) assertSetSize(t *testing.T, minimum int, maximum int) {
	t.Helper()

	if card, _ := f.storage.SCard(f.keys.Set); card < minimum || card > maximum {
		t.Fatalf("set has %d members, want between %d and %d", card, minimum, maximum)
	}
}

// assertIdempotent runs further ticks and checks that they change nothing but the maintenance state.
func (f *lifecycleFixture) assertIdempotent(t *testing.T, ticks int) {
	t.Helper()

	before := stripState(f.storage.Dump(), f.keys.State)

	for range ticks {
		f.mustTick(t)
	}

	if after := stripState(f.storage.Dump(), f.keys.State); after != before {
		t.Fatalf("repeated ticks changed data:\nbefore %s\nafter %s", before, after)
	}
}

// stripState removes the maintenance state hash, whose cursors move on every tick, from a miniredis dump.
func stripState(dump string, stateKey string) string {
	lines := []string{}
	skip := false

	for _, line := range splitLines(dump) {
		if len(line) > 0 && line[0] != ' ' {
			skip = line == "- "+stateKey
		}

		if !skip {
			lines = append(lines, line)
		}
	}

	return fmt.Sprint(lines)
}

// splitLines splits a dump into lines without importing strings for one call site.
func splitLines(value string) []string {
	lines := []string{}
	start := 0

	for index := range len(value) {
		if value[index] == '\n' {
			lines = append(lines, value[start:index])
			start = index + 1
		}
	}

	return append(lines, value[start:])
}

func TestMaintenanceNeverTouchesSecurityState(t *testing.T) {
	fixture := newLifecycleFixture(t, 256)
	prefix := fixture.cfg.GetServer().GetRedis().GetPrefix()
	security := map[string]string{
		prefix + "bf:ban:192.0.2.0/24":                   "bucket",
		prefix + "bf:cnt:{bucket:192.0.2.0/24}:win:1":    "7",
		prefix + "pw_hist:{gone@example.test:192.0.2.1}": "hash",
		prefix + "bf:tr:{192.0.2.1}":                     "reputation",
	}

	for key, value := range security {
		if err := fixture.storage.Set(key, value); err != nil {
			t.Fatalf("seed security key: %v", err)
		}

		fixture.storage.SetTTL(key, 4*time.Hour)
	}

	fixture.seedLegacy(t, "gone@example.test", false)
	fixture.rearm(t)
	fixture.now = fixture.now.Add(fixture.retention + time.Minute)
	fixture.mustTick(t)

	if inSet, _, _ := fixture.state("gone@example.test"); inSet {
		t.Fatal("stale account was not removed")
	}

	for key, value := range security {
		got, err := fixture.storage.Get(key)
		if err != nil || got != value || fixture.storage.TTL(key) != 4*time.Hour {
			t.Fatalf("security key %s = %q ttl %s (err %v), want untouched", key, got, fixture.storage.TTL(key), err)
		}
	}
}

// scriptHook runs a callback right before a lifecycle script reaches Redis, modelling a concurrent writer.
type scriptHook struct {
	before func(ctx context.Context, cmd redis.Cmder)
	fired  bool
}

// DialHook passes dials through unchanged.
func (h *scriptHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) { return next(ctx, network, addr) }
}

// ProcessHook fires once before the first EVALSHA or EVAL.
func (h *scriptHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if !h.fired && (cmd.Name() == "evalsha" || cmd.Name() == "eval") {
			h.fired = true
			h.before(ctx, cmd)
		}

		return next(ctx, cmd)
	}
}

// ProcessPipelineHook passes pipelines through unchanged.
func (h *scriptHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// seedDue stores an armed, due member without history and an armed maintenance state.
func (f *lifecycleFixture) seedDue(t *testing.T, account string) {
	t.Helper()

	f.seedLegacy(t, account, false)
	f.rearm(t)

	if _, err := f.storage.ZAdd(f.keys.Retention, float64(f.now.Add(-time.Hour).Unix()), account); err != nil {
		t.Fatalf("seed due deadline: %v", err)
	}
}

func TestExpireGuardKeepsAccountRefreshedByConcurrentWriter(t *testing.T) {
	fixture := newLifecycleFixture(t, 16)
	account := "raced@example.test"

	fixture.seedDue(t, account)

	writer := fixture.manager(account).WithRWPDecision(true).(*bucketManagerImpl)
	fixture.client.AddHook(&scriptHook{before: func(context.Context, redis.Cmder) { writer.updateAffectedAccount() }})

	fixture.mustTick(t)

	inSet, inIndex, deadline := fixture.state(account)
	if !inSet || !inIndex || deadline <= float64(fixture.now.Unix()) {
		t.Fatalf("raced account: set=%t index=%t deadline=%v, want kept with the writer's fresh deadline", inSet, inIndex, deadline)
	}
}

func TestFlushDuringMaintenanceIsNeverUndone(t *testing.T) {
	for _, name := range []string{"before_expire", "before_adopt"} {
		t.Run(name, func(t *testing.T) {
			fixture := newLifecycleFixture(t, 16)
			account := "flushed@example.test"

			if name == "before_expire" {
				fixture.seedDue(t, account)
			} else {
				fixture.seedLegacy(t, account, false)
			}

			fixture.client.AddHook(&scriptHook{before: func(ctx context.Context, _ redis.Cmder) {
				// The explicit flush pipeline of the management API.
				_, _ = fixture.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.SRem(ctx, fixture.keys.Set, account)
					pipe.ZRem(ctx, fixture.keys.Retention, account)
					pipe.ZRem(ctx, fixture.keys.Index, account)

					return nil
				})
			}})

			for range 3 {
				fixture.mustTick(t)
			}

			if inSet, inIndex, deadline := fixture.state(account); inSet || inIndex || deadline != 0 {
				t.Fatalf("flushed account resurrected: set=%t index=%t deadline=%v", inSet, inIndex, deadline)
			}
		})
	}
}

func TestMaintenanceRepairsPartialUpdates(t *testing.T) {
	fixture := newLifecycleFixture(t, 16)

	fixture.rearm(t)

	// Writer lost its retention and index commands: S only.
	if _, err := fixture.storage.SetAdd(fixture.keys.Set, "set-only@example.test"); err != nil {
		t.Fatal(err)
	}

	// Lua admin hook reset: I only (SREM without ZREM).
	if _, err := fixture.storage.ZAdd(fixture.keys.Index, 5, "index-only@example.test"); err != nil {
		t.Fatal(err)
	}

	// Writer lost SADD: L only, already due.
	if _, err := fixture.storage.ZAdd(fixture.keys.Retention, float64(fixture.now.Add(-time.Minute).Unix()), "retention-only@example.test"); err != nil {
		t.Fatal(err)
	}

	fixture.mustTick(t)

	if inSet, inIndex, deadline := fixture.state("set-only@example.test"); !inSet || !inIndex || deadline == 0 {
		t.Fatalf("set-only member: set=%t index=%t deadline=%v, want adopted and backfilled", inSet, inIndex, deadline)
	}

	for _, account := range []string{"index-only@example.test", "retention-only@example.test"} {
		if inSet, inIndex, deadline := fixture.state(account); inSet || inIndex || deadline != 0 {
			t.Fatalf("%s: set=%t index=%t deadline=%v, want removed", account, inSet, inIndex, deadline)
		}
	}
}

// indexZRemHook intercepts the first ZREM on the affected-account index: it either fails it, modelling a
// cross-slot partial failure, or runs a callback first, modelling a concurrent writer.
type indexZRemHook struct {
	scriptHook
	before   func()
	indexKey string
	fail     bool
	done     bool
}

// ProcessHook applies the configured behaviour to one ZREM on the index key.
func (h *indexZRemHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if args := cmd.Args(); h.done || cmd.Name() != "zrem" || len(args) < 2 || args[1] != h.indexKey {
			return next(ctx, cmd)
		}

		h.done = true

		if h.before != nil {
			h.before()
		}

		if h.fail {
			cmd.SetErr(errors.New("injected index failure"))

			return cmd.Err()
		}

		return next(ctx, cmd)
	}
}

func TestFailedIndexRemovalAfterExpireIsRepaired(t *testing.T) {
	fixture := newLifecycleFixture(t, 16)
	account := "orphan@example.test"

	fixture.seedDue(t, account)
	fixture.client.AddHook(&indexZRemHook{indexKey: fixture.keys.Index, fail: true})

	errorsBefore := testutil.ToFloat64(affectedAccountsMaintenanceErrors.WithLabelValues("remove"))

	if err := fixture.tick(t); err == nil {
		t.Fatal("expected the injected index failure to fail the tick")
	}

	if got := testutil.ToFloat64(affectedAccountsMaintenanceErrors.WithLabelValues("remove")); got != errorsBefore+1 {
		t.Fatalf("remove errors = %v, want %v", got, errorsBefore+1)
	}

	// The remove step failed after the expire script, but the independent index step of the same tick
	// already repaired the orphan, and the heartbeat stayed fresh (no re-arm).
	if inSet, inIndex, deadline := fixture.state(account); inSet || inIndex || deadline != 0 {
		t.Fatalf("after failed ZREM: set=%t index=%t deadline=%v, want removed everywhere", inSet, inIndex, deadline)
	}

	if fixture.storage.HGet(fixture.keys.State, stateFieldRearmDone) != "1" {
		t.Fatal("a failed step must not trigger a re-arm")
	}
}

func TestWriterReaddBeforeIndexRemovalKeepsIndexEntry(t *testing.T) {
	fixture := newLifecycleFixture(t, 16)
	account := "readded@example.test"

	fixture.seedDue(t, account)

	writer := fixture.manager(account).WithRWPDecision(true).(*bucketManagerImpl)
	fixture.client.AddHook(&indexZRemHook{indexKey: fixture.keys.Index, before: writer.updateAffectedAccount})

	// Run only the remove step: in a full tick the adopt backfill could hide a missing restore for small sets.
	run := &affectedAccountsRun{
		maintainer: fixture.maintainer,
		cfg:        fixture.cfg,
		keys:       fixture.keys,
		now:        fixture.now,
		retention:  fixture.retention,
	}

	if err := run.removeStep(t.Context()); err != nil {
		t.Fatalf("remove step: %v", err)
	}

	// The expire script removed the account, the writer re-added it, and the index entry was restored.
	fixture.assertState(t, account, true, true, func(deadline float64) bool { return deadline > float64(fixture.now.Unix()) })
}

func TestMaintenanceLeaseLetsOneInstanceWorkPerTick(t *testing.T) {
	fixture := newLifecycleFixture(t, 16)
	other := NewAffectedAccountsMaintainer(fixture.redis, log.GetLogger())
	other.now = fixture.maintainer.now

	fixture.seedLegacy(t, "lease@example.test", false)

	if err := fixture.maintainer.RunOnce(t.Context(), fixture.cfg); err != nil {
		t.Fatalf("first instance: %v", err)
	}

	if ttl := fixture.storage.TTL(fixture.keys.Lease); ttl <= 0 || ttl >= AffectedAccountsMaintenanceInterval {
		t.Fatalf("lease TTL = %s, want shorter than the %s tick", ttl, AffectedAccountsMaintenanceInterval)
	}

	// The second instance does not get the lease and changes nothing.
	before := fixture.storage.Dump()

	if err := other.RunOnce(t.Context(), fixture.cfg); err != nil {
		t.Fatalf("second instance: %v", err)
	}

	if after := fixture.storage.Dump(); after != before {
		t.Fatalf("instance without lease changed data:\nbefore %s\nafter %s", before, after)
	}

	// The next tick (one interval later) finds the lease expired.
	fixture.storage.FastForward(AffectedAccountsMaintenanceInterval)

	if acquired, err := other.acquireLease(t.Context(), fixture.cfg, fixture.keys); err != nil || !acquired {
		t.Fatalf("lease after one interval: acquired=%t err=%v", acquired, err)
	}
}

func TestHeartbeatGapRearmsInsteadOfRemovingStaleDeadlines(t *testing.T) {
	fixture := newLifecycleFixture(t, 16)
	account := "gap@example.test"

	// Armed generation with a member whose deadline went stale while writers did not refresh it.
	fixture.seedDue(t, account)

	// No maintenance tick for longer than the heartbeat TTL (cleanup disabled, downgrade, outage).
	fixture.storage.FastForward(affectedAccountsHeartbeatTTL + time.Minute)

	fixture.mustTick(t)

	inSet, _, deadline := fixture.state(account)
	if !inSet || deadline != affectedAccountDeadline(fixture.now, fixture.retention) {
		t.Fatalf("after gap: set=%t deadline=%v, want re-armed to now + R", inSet, deadline)
	}
}

func TestDisabledCleanupKeepsDataButWriterStillRefreshesDeadline(t *testing.T) {
	fixture := newLifecycleFixture(t, 16)
	disabled := false
	fixture.cfg.(*config.FileSettings).BruteForce.AffectedAccounts.CleanupEnabled = &disabled
	account := "disabled@example.test"

	fixture.seedLegacy(t, account, false)
	fixture.mustTick(t)

	if fixture.storage.Exists(fixture.keys.State) || fixture.storage.Exists(fixture.keys.Lease) {
		t.Fatal("disabled cleanup wrote maintenance state")
	}

	fixture.manager(account).WithRWPDecision(true).(*bucketManagerImpl).updateAffectedAccount()

	if _, _, deadline := fixture.state(account); deadline == 0 {
		t.Fatal("writer did not refresh the deadline while cleanup is disabled")
	}
}

func TestMaintenanceRefusesPrefixWithoutSameSlotSibling(t *testing.T) {
	fixture := newLifecycleFixture(t, 16)
	fixture.cfg.(*config.FileSettings).Server.Redis.Prefix = "a}b:"

	refusedBefore := testutil.ToFloat64(affectedAccountsMaintenanceErrors.WithLabelValues("refused"))

	for range 3 {
		if err := fixture.tick(t); !errors.Is(err, rediscli.ErrNoSlotSibling) {
			t.Fatalf("tick error = %v, want ErrNoSlotSibling", err)
		}
	}

	if got := testutil.ToFloat64(affectedAccountsMaintenanceErrors.WithLabelValues("refused")); got != refusedBefore+1 {
		t.Fatalf("refused counter = %v, want one increment for the transition", got)
	}

	if keys := fixture.storage.Keys(); len(keys) != 0 {
		t.Fatalf("refused maintenance wrote keys: %v", keys)
	}
}

func TestRWPOnlyFailureWritesHistoryWithoutAffectedAccount(t *testing.T) {
	fixture := newLifecycleFixture(t, 16)
	account := "rwp@example.test"

	// A false enforce decision means the request is a repeating wrong password.
	fixture.manager(account).WithRWPDecision(false).(*bucketManagerImpl).ProcessPWHist()

	if inSet, inIndex, deadline := fixture.state(account); inSet || inIndex || deadline != 0 {
		t.Fatalf("RWP-only failure: set=%t index=%t deadline=%v, want no affected-account entry", inSet, inIndex, deadline)
	}

	if ok, _ := fixture.storage.SIsMember(fixture.historyKey(account), fixture.clientIP); !ok {
		t.Fatal("RWP-only failure did not record the password-history IP")
	}
}

func TestMaintenanceAgesOutTwelveThousandLegacyMembersInBoundedTicks(t *testing.T) {
	fixture := newLifecycleFixture(t, affectedAccountsMaintenanceBatch)
	accounts := lifecycleAccounts(12000)
	withHistory := 0

	pipe := fixture.client.Pipeline()

	for index, account := range accounts {
		pipe.SAdd(t.Context(), fixture.keys.Set, account)
		pipe.ZAdd(t.Context(), fixture.keys.Index, redis.Z{Score: float64(index), Member: account})

		if index%17 == 0 {
			withHistory++

			pipe.SAdd(t.Context(), fixture.historyKey(account), "192.0.2.7")
			pipe.Expire(t.Context(), fixture.historyKey(account), 2*fixture.retention)
		}
	}

	if _, err := pipe.Exec(t.Context()); err != nil {
		t.Fatalf("seed legacy members: %v", err)
	}

	fixture.rearm(t)
	fixture.now = fixture.now.Add(fixture.retention + time.Minute)

	previous := len(accounts)
	ticks := 0

	for ; ticks < 200; ticks++ {
		fixture.mustTick(t)

		card, _ := fixture.storage.SCard(fixture.keys.Set)
		if previous-card > affectedAccountsMaintenanceBatch {
			t.Fatalf("tick %d removed %d members, want at most %d", ticks, previous-card, affectedAccountsMaintenanceBatch)
		}

		if card == withHistory {
			break
		}

		previous = card
	}

	members, _ := fixture.storage.Members(fixture.keys.Set)
	for _, account := range members {
		if !slices.Contains(accounts, account) || !fixture.storage.Exists(fixture.historyKey(account)) {
			t.Fatalf("remaining member %s has no history", account)
		}
	}

	if card, _ := fixture.storage.SCard(fixture.keys.Set); card != withHistory {
		t.Fatalf("set has %d members after %d ticks, want the %d with history", card, ticks, withHistory)
	}

	t.Logf("removed %d legacy members in %d ticks", len(accounts)-withHistory, ticks+1)
}

func TestLifecycleOnClusterKeepsScriptKeysVerbatimAndSlotLocal(t *testing.T) {
	nodes := rediscluster.NewTwoNode(t)
	guard := redisslot.NewGuard(t, "").Attach(nodes.Cluster)
	cfg := passwordHistoryCommandConfig(0)
	cfg.(*config.FileSettings).Server.Redis.NegCacheTTL = time.Hour
	client := rediscli.NewTestClientForHandle(nodes.Cluster)
	keys := seedClusterLegacyMembers(t, nodes, cfg, 20)

	writer := NewBucketManagerWithDeps(t.Context(), "cluster-guid", "203.0.113.91", BucketManagerDeps{
		Cfg:      cfg,
		Logger:   log.GetLogger(),
		Redis:    client,
		Tolerate: tolerate.NewTolerateWithDeps(cfg, log.GetLogger(), client, 0),
	}).WithAccountName("active@example.test").WithRWPDecision(true).(*bucketManagerImpl)

	now := time.Now().Truncate(time.Second)
	maintainer := NewAffectedAccountsMaintainer(client, log.GetLogger())
	maintainer.now = func() time.Time { return now }

	tick := func() {
		nodes.Node(keys.Lease).Del(keys.Lease)

		if err := maintainer.RunOnce(t.Context(), cfg); err != nil {
			t.Fatalf("cluster tick: %v", err)
		}
	}

	tick() // re-arm

	now = now.Add(AffectedAccountRetention(cfg) + time.Minute)

	writer.updateAffectedAccount()

	// The writer uses the real clock, which is behind the advanced fixture clock; model activity at fixture time.
	if _, err := nodes.Cluster.ZAddGT(t.Context(), keys.Retention, redis.Z{Score: float64(now.Add(time.Hour).Unix()), Member: "active@example.test"}).Result(); err != nil {
		t.Fatal(err)
	}

	tick()

	assertClusterOnlyActiveAccount(t, nodes, keys, "active@example.test")

	if guard.Units() == 0 {
		t.Fatal("slot guard inspected no script")
	}
}

// seedClusterLegacyMembers stores legacy members on the nodes that own S and I and checks the slot layout.
func seedClusterLegacyMembers(t *testing.T, nodes *rediscluster.TwoNode, cfg config.File, count int) AffectedAccountKeys {
	t.Helper()

	keys, err := NewAffectedAccountKeys(cfg.GetServer().GetRedis().GetPrefix())
	if err != nil {
		t.Fatalf("lifecycle keys: %v", err)
	}

	if nodes.Node(keys.Set) != nodes.Node(keys.Retention) || nodes.Node(keys.Set) != nodes.Node(keys.State) {
		t.Fatal("S, L and M are not served by one node")
	}

	for _, account := range lifecycleAccounts(count) {
		if _, err := nodes.Node(keys.Set).SetAdd(keys.Set, account); err != nil {
			t.Fatal(err)
		}

		if _, err := nodes.Node(keys.Index).ZAdd(keys.Index, 1, account); err != nil {
			t.Fatal(err)
		}
	}

	return keys
}

// assertClusterOnlyActiveAccount checks S and I and that no script helper rewrote any key on either node.
func assertClusterOnlyActiveAccount(t *testing.T, nodes *rediscluster.TwoNode, keys AffectedAccountKeys, account string) {
	t.Helper()

	if members, _ := nodes.Node(keys.Set).Members(keys.Set); !slices.Equal(members, []string{account}) {
		t.Fatalf("set members = %v, want only %s", members, account)
	}

	if index, _ := nodes.Node(keys.Index).ZMembers(keys.Index); !slices.Equal(index, []string{account}) {
		t.Fatalf("index members = %v, want only %s", index, account)
	}

	for _, node := range []*miniredis.Miniredis{nodes.Low, nodes.High} {
		for _, key := range node.Keys() {
			if strings.Contains(key, "{nauthilus}") {
				t.Fatalf("a script helper rewrote a key: %s", key)
			}
		}
	}
}

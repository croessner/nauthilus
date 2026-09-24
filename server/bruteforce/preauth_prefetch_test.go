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

package bruteforce

import (
	"context"
	"net"
	"reflect"
	"slices"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/bruteforce/l1"
	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/testing/redisroundtrip"
	"github.com/redis/go-redis/v9"
)

const preAuthTestUser = "user@example.test"

// preAuthFixture wires a bucket manager factory to miniredis with a round-trip recorder.
type preAuthFixture struct {
	storage  *miniredis.Miniredis
	client   *redis.Client
	redis    rediscli.Client
	recorder *redisroundtrip.Recorder
	cfg      config.File
	clientIP string
}

// preAuthOutcome captures every decision the pre-authentication check exposes to its caller.
type preAuthOutcome struct {
	enforce          bool
	rwpError         bool
	withError        bool
	alreadyTriggered bool
	ruleTriggered    bool
	ruleNumber       int
	message          string
	bruteForceName   string
	counters         map[string]uint
	facts            []BucketPolicyFact
}

// newPreAuthFixture starts miniredis, uploads all scripts and attaches the recorder afterwards.
func newPreAuthFixture(t *testing.T, clientIP string) *preAuthFixture {
	t.Helper()

	storage := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: storage.Addr()})

	t.Cleanup(func() { _ = client.Close() })

	cfg := passwordHistoryCommandConfig(0)
	redisClient := rediscli.NewTestClient(client)

	rediscli.ClearScriptCache()

	if err := rediscli.UploadAllScripts(t.Context(), log.GetLogger(), redisClient); err != nil {
		t.Fatalf("upload scripts: %v", err)
	}

	return &preAuthFixture{
		storage:  storage,
		client:   client,
		redis:    redisClient,
		recorder: redisroundtrip.Attach(client),
		cfg:      cfg,
		clientIP: clientIP,
	}
}

// manager creates a request bucket manager; an empty account models an unknown account.
func (f *preAuthFixture) manager(accountName string) *bucketManagerImpl {
	bm := NewBucketManagerWithDeps(context.Background(), "prefetch-guid", f.clientIP, BucketManagerDeps{
		Cfg:      f.cfg,
		Logger:   log.GetLogger(),
		Redis:    f.redis,
		Tolerate: tolerate.NewTolerateWithDeps(f.cfg, log.GetLogger(), f.redis, 0),
	}).
		WithUsername(preAuthTestUser).
		WithProtocol("imap").
		WithPassword(secret.New("wrong-password")).
		WithAccountName(accountName)

	return bm.(*bucketManagerImpl)
}

// rules returns the configured bucket rules of the fixture.
func (f *preAuthFixture) rules() []config.BruteForceRule {
	return f.cfg.GetBruteForceRules()
}

// check mirrors the CheckBruteForce call order and returns every exposed decision.
func (f *preAuthFixture) check(bm *bucketManagerImpl, prefetch bool) preAuthOutcome {
	rules := f.rules()
	bm.PrepareNetcalc(rules)

	if prefetch {
		bm.PrefetchPreAuthState(rules)
	}

	enforce, rwpErr := bm.ShouldEnforceBucketUpdate()
	outcome := preAuthOutcome{enforce: enforce, rwpError: rwpErr != nil}

	if rwpErr != nil {
		return outcome
	}

	var network *net.IPNet

	outcome.withError, outcome.alreadyTriggered, outcome.ruleNumber = bm.CheckRepeatingBruteForcer(rules, &network, &outcome.message)
	if !outcome.withError && !outcome.alreadyTriggered {
		outcome.withError, outcome.ruleTriggered, outcome.ruleNumber = bm.CheckBucketOverLimit(rules, &outcome.message)
	}

	outcome.facts = bm.GetBucketPolicyFacts()
	if len(outcome.facts) == 0 {
		// The core check collects policy facts itself when the cached-ban path skipped the counters.
		outcome.facts, _ = bm.CollectBucketPolicyFacts(rules)
	}

	outcome.bruteForceName = bm.GetBruteForceName()
	outcome.counters = bm.GetBruteForceCounter()

	return outcome
}

// seedFailures stores failed attempts, a committed RWP hash and a positive reputation for the client.
func (f *preAuthFixture) seedFailures(t *testing.T, failures int) {
	t.Helper()

	seed := f.manager(passwordHistoryCommandAccount)
	rules := f.rules()

	for range failures {
		seed.SaveBruteForceBucketCounterToRedis(&rules[0])
	}

	if _, err := seed.CommitRWPSlidingWindow(); err != nil {
		t.Fatalf("seed RWP window: %v", err)
	}

	f.storage.HSet(seed.tolerate().GetReputationKey(f.clientIP), reputationPositiveField, "3")
}

// preAuthPrefetchScenario describes one pre-authentication state with its expected round trips.
type preAuthPrefetchScenario struct {
	name            string
	clientIP        string
	accountName     string
	failures        int
	ban             bool
	wantTrips       [][]string
	sequentialTrips int
	wantOutcome     preAuthOutcome
}

// preAuthPrefetchScenarios covers counting, over-limit, account-less and cached-ban checks.
func preAuthPrefetchScenarios() []preAuthPrefetchScenario {
	return []preAuthPrefetchScenario{
		{
			name:            "known account below limit",
			clientIP:        "198.51.100.10",
			accountName:     passwordHistoryCommandAccount,
			failures:        1,
			wantTrips:       [][]string{{"evalsha", "exists", "hget"}, {"evalsha"}},
			sequentialTrips: 4,
			wantOutcome:     preAuthOutcome{ruleNumber: -1},
		},
		{
			name:            "known account over limit",
			clientIP:        "198.51.100.11",
			accountName:     passwordHistoryCommandAccount,
			failures:        6,
			wantTrips:       [][]string{{"evalsha", "exists", "hget"}, {"evalsha"}},
			sequentialTrips: 4,
			wantOutcome:     preAuthOutcome{ruleTriggered: true},
		},
		{
			name:            "unknown account stays on the read handle without the RWP script",
			clientIP:        "198.51.100.12",
			failures:        1,
			wantTrips:       [][]string{{"exists", "hget"}, {"evalsha"}},
			sequentialTrips: 3,
			wantOutcome:     preAuthOutcome{enforce: true, ruleNumber: -1},
		},
		{
			name:            "cached ban reuses the prefetched ban and reputation reads",
			clientIP:        "198.51.100.13",
			accountName:     passwordHistoryCommandAccount,
			ban:             true,
			wantTrips:       [][]string{{"evalsha", "exists", "hget"}, {"evalsha"}},
			sequentialTrips: 5,
			wantOutcome:     preAuthOutcome{alreadyTriggered: true},
		},
	}
}

func TestPreAuthPrefetchKeepsDecisionsAndHalvesRoundTrips(t *testing.T) {
	for _, tc := range preAuthPrefetchScenarios() {
		t.Run(tc.name, func(t *testing.T) {
			runPreAuthPrefetchScenario(t, tc)
		})
	}
}

// runPreAuthPrefetchScenario compares the sequential and the prefetched check on the same Redis state.
func runPreAuthPrefetchScenario(t *testing.T, tc preAuthPrefetchScenario) {
	t.Helper()

	fixture := newPreAuthFixture(t, tc.clientIP)
	fixture.seedFailures(t, tc.failures)

	if tc.ban {
		if err := fixture.storage.Set(rediscli.GetBruteForceBanKey(passwordHistoryCommandPrefix, tc.clientIP+"/32"), "command-shape"); err != nil {
			t.Fatalf("seed ban: %v", err)
		}
	}

	fixture.recorder.Reset()

	sequential := fixture.check(fixture.manager(tc.accountName), false)
	if got := fixture.recorder.Count(); got != tc.sequentialTrips {
		t.Fatalf("sequential check used %d round trips, want %d: %v", got, tc.sequentialTrips, fixture.recorder.RoundTrips())
	}

	fixture.recorder.Reset()

	prefetched := fixture.check(fixture.manager(tc.accountName), true)
	if trips := fixture.recorder.RoundTrips(); !reflect.DeepEqual(trips, tc.wantTrips) {
		t.Fatalf("prefetched check round trips = %v, want %v", trips, tc.wantTrips)
	}

	if !reflect.DeepEqual(prefetched, sequential) {
		t.Fatalf("prefetched outcome = %+v, want sequential outcome %+v", prefetched, sequential)
	}

	assertPreAuthDecision(t, prefetched, tc.wantOutcome)
}

func TestPreAuthPrefetchSkipsRedisOnL1Block(t *testing.T) {
	fixture := newPreAuthFixture(t, "198.51.100.20")
	bm := fixture.manager(passwordHistoryCommandAccount)
	rules := fixture.rules()

	l1.GetEngine().Set(t.Context(), l1.KeyBurst(bm.bfBurstKey()), l1.Decision{Blocked: true, Rule: rules[0].Name}, 0)
	t.Cleanup(func() {
		l1.GetEngine().Set(context.Background(), l1.KeyBurst(bm.bfBurstKey()), l1.Decision{}, 0)
	})

	bm.PrepareNetcalc(rules)
	bm.PrefetchPreAuthState(rules)

	if got := fixture.recorder.Count(); got != 0 {
		t.Fatalf("L1 block issued %d prefetch round trips, want none", got)
	}

	outcome := fixture.check(bm, false)
	if !outcome.alreadyTriggered || outcome.message != "Brute force attack detected (L1 engine)" {
		t.Fatalf("L1 outcome = %+v, want cached L1 block", outcome)
	}

	// The RWP precheck runs alone; the later policy-fact collection reads bans, reputation and counters
	// exactly like the sequential path does.
	want := [][]string{{"evalsha"}, {"exists"}, {"hget"}, {"evalsha"}}
	if trips := fixture.recorder.RoundTrips(); !reflect.DeepEqual(trips, want) {
		t.Fatalf("L1 block round trips = %v, want %v", trips, want)
	}
}

func TestPreAuthPrefetchRetriesOnlyTheRWPScriptAfterNoScript(t *testing.T) {
	fixture := newPreAuthFixture(t, "198.51.100.30")
	fixture.seedFailures(t, 1)

	want := fixture.check(fixture.manager(passwordHistoryCommandAccount), false)

	if err := fixture.client.ScriptFlush(t.Context()).Err(); err != nil {
		t.Fatalf("flush scripts: %v", err)
	}

	fixture.recorder.Reset()

	bm := fixture.manager(passwordHistoryCommandAccount)
	bm.PrepareNetcalc(fixture.rules())
	bm.PrefetchPreAuthState(fixture.rules())

	trips := fixture.recorder.RoundTrips()
	if len(trips) < 3 || !slices.Equal(trips[0], []string{"evalsha", "exists", "hget"}) ||
		!slices.Equal(trips[len(trips)-1], []string{"evalsha"}) {
		t.Fatalf("NOSCRIPT prefetch round trips = %v, want pipeline, script upload, RWP-only retry", trips)
	}

	for _, trip := range trips[1 : len(trips)-1] {
		if !slices.Equal(trip, []string{"script"}) {
			t.Fatalf("NOSCRIPT prefetch repeated non-script work: %v", trips)
		}
	}

	enforce, err := bm.ShouldEnforceBucketUpdate()
	if err != nil || enforce != want.enforce {
		t.Fatalf("retried RWP verdict = enforce:%t err:%v, want enforce:%t", enforce, err, want.enforce)
	}
}

func TestPreAuthPrefetchKeepsRWPStorageErrorsFailClosed(t *testing.T) {
	fixture := newPreAuthFixture(t, "198.51.100.40")
	bm := fixture.manager(passwordHistoryCommandAccount)
	allowKey, _ := bm.buildRWPKeyAndHash()

	if err := fixture.storage.Set(allowKey, "wrong type"); err != nil {
		t.Fatalf("seed wrong RWP type: %v", err)
	}

	fixture.recorder.Reset()

	outcome := fixture.check(bm, true)
	if !outcome.rwpError {
		t.Fatalf("prefetched RWP storage error outcome = %+v, want an RWP error", outcome)
	}

	if got := fixture.recorder.Count(); got != 1 {
		t.Fatalf("failed prefetch used %d round trips, want 1", got)
	}
}

// assertPreAuthDecision verifies the scenario decision so that the equivalence check compares real verdicts.
func assertPreAuthDecision(t *testing.T, got preAuthOutcome, want preAuthOutcome) {
	t.Helper()

	if got.enforce != want.enforce || got.rwpError || got.withError ||
		got.alreadyTriggered != want.alreadyTriggered || got.ruleTriggered != want.ruleTriggered {
		t.Fatalf("decision = %+v, want enforce:%t already:%t triggered:%t", got, want.enforce, want.alreadyTriggered, want.ruleTriggered)
	}

	if !got.alreadyTriggered && !got.ruleTriggered && got.ruleNumber != want.ruleNumber {
		t.Fatalf("rule number = %d, want %d", got.ruleNumber, want.ruleNumber)
	}
}

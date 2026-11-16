package tolerate

import (
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/redis/go-redis/v9"
)

// tolerationHarness drives a toleration manager against miniredis with a clock that follows the simulated Redis time.
type tolerationHarness struct {
	manager *tolerateImpl
	storage *miniredis.Miniredis
	now     time.Time
}

// newTolerationHarness builds a static-percent manager with the given window over a fresh miniredis.
func newTolerationHarness(t *testing.T, ttl time.Duration, percent uint8) *tolerationHarness {
	t.Helper()

	storage := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: storage.Addr()})

	t.Cleanup(func() { _ = client.Close() })

	cfg := &config.FileSettings{
		Server:     &config.ServerSection{},
		BruteForce: &config.BruteForceSection{TolerateTTL: ttl, ToleratePercent: percent},
	}

	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	config.SetTestFile(cfg)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")
	rediscli.ClearScriptCache()

	harness := &tolerationHarness{storage: storage, now: time.Unix(1_800_000_000, 0)}
	harness.manager = NewTolerateWithDeps(cfg, log.GetLogger(), rediscli.NewTestClient(client), percent).(*tolerateImpl)
	harness.manager.deps.clock = func() time.Time { return harness.now }

	return harness
}

// advance moves the event clock and the Redis expiry clock together.
func (h *tolerationHarness) advance(duration time.Duration) {
	h.now = h.now.Add(duration)
	h.storage.FastForward(duration)
}

// succeed records verified successes for count distinct accounts.
func (h *tolerationHarness) succeed(t *testing.T, ip string, prefix string, count int) {
	t.Helper()

	for index := range count {
		h.manager.SetIPAddress(t.Context(), ip, fmt.Sprintf("%s%d", prefix, index), true)
	}
}

// fail records count failed attempts against one account.
func (h *tolerationHarness) fail(t *testing.T, ip string, account string, count int) {
	t.Helper()

	for range count {
		h.manager.SetIPAddress(t.Context(), ip, account, false)
	}
}

// TestTolerationSingleAccountAttackBehindValidLogins keeps ten valid accounts from opening an unlimited attack on an
// eleventh account behind the same address.
func TestTolerationSingleAccountAttackBehindValidLogins(t *testing.T) {
	harness := newTolerationHarness(t, time.Hour, 20)
	ip := "192.0.2.10"

	harness.succeed(t, ip, "attacker", 10)
	harness.fail(t, ip, "victim", 2)

	if fact := harness.manager.PolicyFact(t.Context(), ip); !fact.Active {
		t.Fatalf("two failures within 20%% of ten accounts must stay tolerated: %+v", fact)
	}

	harness.fail(t, ip, "victim", 1)

	fact := harness.manager.PolicyFact(t.Context(), ip)
	if fact.Active || fact.Negative != 3 {
		t.Fatalf("the third failed attempt on one account must end toleration: %+v", fact)
	}
}

// TestTolerationRepeatedSuccessDoesNotInflateAllowance counts repeated logins of one account once.
func TestTolerationRepeatedSuccessDoesNotInflateAllowance(t *testing.T) {
	harness := newTolerationHarness(t, time.Hour, 50)
	ip := "192.0.2.12"

	for range 100 {
		harness.manager.SetIPAddress(t.Context(), ip, "Attacker", true)
	}

	harness.fail(t, ip, "victim", 1)

	fact := harness.manager.PolicyFact(t.Context(), ip)
	if fact.Positive != 1 || fact.Active {
		t.Fatalf("one account logging in repeatedly must not buy failed attempts: %+v", fact)
	}
}

// TestTolerationSuccessesAgeOutDuringContinuousAttack ages successes out of the window while failures continue.
func TestTolerationSuccessesAgeOutDuringContinuousAttack(t *testing.T) {
	harness := newTolerationHarness(t, 30*time.Minute, 20)
	ip := "192.0.2.11"

	harness.succeed(t, ip, "attacker", 10)

	for range 180 {
		harness.advance(time.Minute)
		harness.fail(t, ip, "victim", 1)
	}

	fact := harness.manager.PolicyFact(t.Context(), ip)
	if fact.Positive != 0 || fact.Negative != 30 || fact.Active {
		t.Fatalf("counters must cover only the last 30 minutes: %+v", fact)
	}
}

// TestTolerationIdleCountersAgeOutOnRead counts only the window at read time, without any write or background refresh,
// so every instance sharing Redis sees the same exact counters.
func TestTolerationIdleCountersAgeOutOnRead(t *testing.T) {
	harness := newTolerationHarness(t, 30*time.Minute, 20)
	ip := "192.0.2.13"

	harness.succeed(t, ip, "user", 10)
	harness.advance(20 * time.Minute)
	harness.succeed(t, ip, "late", 2)
	harness.advance(15 * time.Minute)

	if counters := harness.manager.GetTolerateMap(t.Context(), ip); counters[PositiveField] != 2 {
		t.Fatalf("the read must ignore successes older than the window: %v", counters)
	}

	harness.advance(20 * time.Minute)

	if fact := harness.manager.PolicyFact(t.Context(), ip); fact.Positive != 0 || fact.Active {
		t.Fatalf("an idle address must lose its toleration after the window: %+v", fact)
	}

	if keys := harness.storage.Keys(); len(keys) != 0 {
		t.Fatalf("idle toleration sets must expire with their key: %v", keys)
	}
}

// TestAdaptivePercentMatchesDocumentedScenarios pins the logarithmic scaling used in the documentation examples.
func TestAdaptivePercentMatchesDocumentedScenarios(t *testing.T) {
	defaults := policySettings{minPercent: 10, maxPercent: 50, scale: 1}
	production := policySettings{minPercent: 3, maxPercent: 50, scale: 1}

	for _, testCase := range []struct {
		settings policySettings
		positive int64
		want     uint8
	}{
		{defaults, 1, 16}, {defaults, 5, 25}, {defaults, 50, 44}, {defaults, 100, 50}, {defaults, 500, 50},
		{production, 4, 19}, {production, 5, 21}, {production, 10, 27},
	} {
		if got := adaptivePercent(testCase.positive, testCase.settings); got != testCase.want {
			t.Fatalf("adaptivePercent(%d, %+v) = %d, want %d", testCase.positive, testCase.settings, got, testCase.want)
		}
	}
}

// TestTolerationSaturatedNegativesAreNeverTolerated keeps the retention cap from becoming an allowance.
func TestTolerationSaturatedNegativesAreNeverTolerated(t *testing.T) {
	if tolerationActive(1_000_000, tolerationNegativeCap, tolerationNegativeCap*2) {
		t.Fatal("a saturated negative count must not be tolerated")
	}

	if !tolerationActive(1_000_000, tolerationNegativeCap-1, tolerationNegativeCap*2) {
		t.Fatal("a count below the cap within the allowance must be tolerated")
	}
}

// TestRecordTolerationEventCapsNegativeEvents keeps only the newest negative events once the cap is reached.
func TestRecordTolerationEventCapsNegativeEvents(t *testing.T) {
	harness := newTolerationHarness(t, time.Hour, 20)
	key := harness.manager.getRedisKey("192.0.2.14")
	keys := RedisKeys(harness.manager.deps.cfg.GetServer().GetRedis().GetPrefix(), "192.0.2.14")

	var result any

	for index := range 5 {
		var err error

		result, err = rediscli.ExecuteScript(t.Context(), harness.manager.effectiveRedis(), "RecordTolerationEvent",
			rediscli.LuaScripts["RecordTolerationEvent"], keys, harness.now.Unix()+int64(index), 3600,
			tolerationEventNegative, fmt.Sprintf("event%d", index), 3)
		if err != nil {
			t.Fatalf("record event: %v", err)
		}
	}

	if fmt.Sprint(result) != "[0 3]" {
		t.Fatalf("counters = %v, want [0 3]", result)
	}

	members, err := harness.storage.ZMembers(key + tolerateNegativeFlag)
	if err != nil || len(members) != 3 || members[0] != "event2" {
		t.Fatalf("retained members = %v (%v), want the newest three", members, err)
	}
}

// TestTolerationRedisKeysShareOneClusterSlot pins the key shape that the admin flush deletes.
func TestTolerationRedisKeysShareOneClusterSlot(t *testing.T) {
	keys := RedisKeys("nt:", "2001:db8::/64")
	want := []string{"nt:bf:tr:{2001:db8::/64}:P", "nt:bf:tr:{2001:db8::/64}:N"}

	if fmt.Sprint(keys) != fmt.Sprint(want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
}

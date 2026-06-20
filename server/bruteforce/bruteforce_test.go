// Copyright (C) 2024 Christian Rößner
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

package bruteforce_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/bruteforce"
	"github.com/croessner/nauthilus/v3/server/bruteforce/l1"
	"github.com/croessner/nauthilus/v3/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func mustRuntimeModule(value string) *config.RuntimeModule {
	runtimeModule := config.RuntimeModule{}
	if err := runtimeModule.Set(value); err != nil {
		panic(err)
	}

	return &runtimeModule
}

func mustBackend(value string) *config.Backend {
	backend := config.Backend{}
	if err := backend.Set(value); err != nil {
		panic(err)
	}

	return &backend
}

func initTestConfig() config.File {
	runtimeModule := mustRuntimeModule(definitions.ControlBruteForce)
	backend := mustBackend(definitions.BackendCacheName)

	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())

	testFile := &config.FileSettings{
		Server: &config.ServerSection{
			RuntimeModules: []*config.RuntimeModule{runtimeModule},
			Backends:       []*config.Backend{backend},
			Redis: config.Redis{
				Prefix: "nt_",
			}},
		BruteForce: &config.BruteForceSection{
			Buckets: []config.BruteForceRule{
				{
					Name:           "testbucket",
					Period:         time.Hour,
					CIDR:           32,
					IPv4:           true,
					IPv6:           false,
					FailedRequests: 5,
				}}},
	}
	config.SetTestFile(testFile)
	util.SetDefaultConfigFile(testFile)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	return testFile
}

func setupSubtest(cfg config.File) (redismock.ClientMock, tolerate.Tolerate) {
	rediscli.ClearScriptCache()
	l1.GetEngine().Clear()

	db, mock := redismock.NewClientMock()
	rediscli.NewTestClient(db)

	tol := tolerate.NewTolerateWithDeps(cfg, log.GetLogger(), rediscli.GetClient(), 0)
	tolerate.SetTolerate(tol)

	return mock, tol
}

func mockNoisy(mock redismock.ClientMock) {
	for range 20 {
		mock.Regexp().ExpectHGetAll(".*").SetVal(map[string]string{})
		mock.Regexp().ExpectGet(".*").RedisNil()
		mock.Regexp().ExpectHGet(".*", ".*").RedisNil()
	}
}

func TestBruteForceScenarios(t *testing.T) {
	cfg := initTestConfig()

	for _, tc := range triggeredBruteForceScenarios() {
		t.Run(tc.name, func(t *testing.T) {
			runTriggeredBruteForceScenario(t, cfg, tc)
		})
	}

	t.Run("Scenario 1b: RWP active skips affected accounts", func(t *testing.T) {
		runRWPActiveSkipsAffectedAccountsScenario(t, cfg)
	})

	t.Run("Scenario 2b: Ban write failure does not trigger", func(t *testing.T) {
		runBanWriteFailureScenario(t, cfg)
	})
}

const (
	bruteForceScenarioIP      = "1.2.3.4"
	bruteForceScenarioAccount = "user1"
	bruteForceScenarioPass    = "password123"
)

type triggeredBruteForceScenario struct {
	name           string
	guid           string
	accountName    string
	username       string
	protocol       string
	password       string
	expectAffected bool
}

// triggeredBruteForceScenarios returns the process-brute-force trigger cases.
func triggeredBruteForceScenarios() []triggeredBruteForceScenario {
	return []triggeredBruteForceScenario{
		{
			name:           "Scenario 1: Known user, same password (Brute force triggered)",
			guid:           "scen1",
			accountName:    bruteForceScenarioAccount,
			username:       bruteForceScenarioAccount,
			protocol:       "imap",
			password:       bruteForceScenarioPass,
			expectAffected: true,
		},
		{
			name:           "Scenario 2: Known user, different passwords (Brute force triggered)",
			guid:           "scen2",
			accountName:    bruteForceScenarioAccount,
			password:       "new_password",
			expectAffected: true,
		},
		{
			name:     "Scenario 3: Different users, same password (Brute force)",
			guid:     "scen3",
			username: "user2",
			password: bruteForceScenarioPass,
		},
		{
			name:     "Scenario 4: Different users, different passwords (Brute force)",
			guid:     "scen4",
			username: "user3",
			password: "passX",
		},
	}
}

// runTriggeredBruteForceScenario verifies a triggered brute-force process path.
func runTriggeredBruteForceScenario(t *testing.T, cfg config.File, tc triggeredBruteForceScenario) {
	t.Helper()

	mock, bm := setupScenarioBucketManager(t, cfg, tc)
	expectTriggeredProcessRedis(mock, tc.expectAffected)

	assert.True(t, processScenarioBruteForce(cfg, bm))
}

// setupScenarioBucketManager creates a bucket manager for a scenario case.
func setupScenarioBucketManager(
	t *testing.T,
	cfg config.File,
	tc triggeredBruteForceScenario,
) (redismock.ClientMock, bruteforce.BucketManager) {
	t.Helper()

	mock, tol := setupSubtest(cfg)
	mockNoisy(mock)
	mock.MatchExpectationsInOrder(false)

	bm := bruteforce.NewBucketManagerWithDeps(context.Background(), tc.guid, bruteForceScenarioIP, bruteforce.BucketManagerDeps{
		Cfg:      cfg,
		Logger:   log.GetLogger(),
		Redis:    rediscli.GetClient(),
		Tolerate: tol,
	})

	if tc.accountName != "" {
		bm = bm.WithAccountName(tc.accountName)
	}

	if tc.username != "" {
		bm = bm.WithUsername(tc.username)
	}

	if tc.protocol != "" {
		bm = bm.WithProtocol(tc.protocol)
	}

	return mock, bm.WithPassword(secret.New(tc.password))
}

// expectTriggeredProcessRedis configures Redis expectations for a successful trigger.
func expectTriggeredProcessRedis(mock redismock.ClientMock, expectAffected bool) {
	mock.Regexp().ExpectHGetAll(".*:P").SetVal(map[string]string{"positive": "0"})
	mock.Regexp().ExpectHGetAll(".*:N").SetVal(map[string]string{"negative": "0"})

	if expectAffected {
		mock.Regexp().ExpectSIsMember(".*affected_accounts", bruteForceScenarioAccount).SetVal(false)
		mock.Regexp().ExpectSAdd(".*affected_accounts", bruteForceScenarioAccount).SetVal(int64(1))
	}

	expectSlidingWindowTrigger(mock)
	mock.Regexp().ExpectSetNX(".*bf:ban:.*", "testbucket", 8*time.Hour).SetVal(true)
	mock.Regexp().ExpectZAddNX(".*bf:bans:.*", redis.Z{Score: 0, Member: ""}).SetVal(int64(1))
	mock.Regexp().ExpectPublish(definitions.RedisBFBlocksChannel, ".*").SetVal(1)
	mock.Regexp().ExpectPublish(definitions.RedisBFBlocksChannel, ".*").SetVal(1)
	expectBurstLeaderAndPasswordHistory(mock)
}

// expectSlidingWindowTrigger configures the shared over-limit bucket script result.
func expectSlidingWindowTrigger(mock redismock.ClientMock) {
	mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("sha-sw")
	mock.Regexp().ExpectEvalSha("sha-sw", []string{".*", ".*"}, ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*").
		SetVal([]any{"10", int64(1), "4"})
}

// expectBurstLeaderAndPasswordHistory configures burst gate and password-history writes.
func expectBurstLeaderAndPasswordHistory(mock redismock.ClientMock) {
	mock.ExpectScriptLoad(rediscli.LuaScripts["IncrementAndExpire"]).SetVal("sha-inc")
	mock.Regexp().ExpectEvalSha("sha-inc", []string{".*"}, ".*").SetVal(int64(1))
	mock.Regexp().ExpectEvalSha(".*", []string{".*"}, ".*", ".*", ".*").SetVal(int64(1))
	mock.Regexp().ExpectEvalSha(".*", []string{".*"}, ".*", ".*", ".*").SetVal(int64(1))
}

// processScenarioBruteForce invokes ProcessBruteForce with the default test rule.
func processScenarioBruteForce(cfg config.File, bm bruteforce.BucketManager) bool {
	rule := cfg.GetBruteForceRules()[0]
	_, network, _ := net.ParseCIDR(bruteForceScenarioIP + "/32")

	return bm.ProcessBruteForce(true, false, &rule, network, "attack", func() {})
}

// runRWPActiveSkipsAffectedAccountsScenario verifies PW_HIST without affected-account indexing.
func runRWPActiveSkipsAffectedAccountsScenario(t *testing.T, cfg config.File) {
	t.Helper()

	mock, tol := setupSubtest(cfg)
	bm := bruteforce.NewBucketManagerWithDeps(context.Background(), "scen1b", bruteForceScenarioIP, bruteforce.BucketManagerDeps{
		Cfg:      cfg,
		Logger:   log.GetLogger(),
		Redis:    rediscli.GetClient(),
		Tolerate: tol,
	}).WithAccountName(bruteForceScenarioAccount).WithUsername(bruteForceScenarioAccount).WithProtocol("imap").WithPassword(secret.New(bruteForceScenarioPass)).WithRWPDecision(false)

	mock.MatchExpectationsInOrder(false)
	mock.Regexp().ExpectSIsMember(".*pw_hist_ips.*", bruteForceScenarioIP).SetVal(false)
	mock.Regexp().ExpectSAdd(".*pw_hist_ips.*", bruteForceScenarioIP).SetVal(int64(1))
	mock.Regexp().ExpectExpire(".*pw_hist_ips.*", cfg.GetServer().Redis.NegCacheTTL).SetVal(true)

	bm.ProcessPWHist()

	assert.NoError(t, mock.ExpectationsWereMet())
}

// runBanWriteFailureScenario verifies that failed ban writes do not trigger.
func runBanWriteFailureScenario(t *testing.T, cfg config.File) {
	t.Helper()

	mock, bm := setupScenarioBucketManager(t, cfg, triggeredBruteForceScenario{
		guid:           "scen2b",
		accountName:    bruteForceScenarioAccount,
		password:       "new_password",
		expectAffected: true,
	})
	expectBanWriteFailureRedis(mock)

	assert.False(t, processScenarioBruteForce(cfg, bm))
}

// expectBanWriteFailureRedis configures Redis expectations for a failed ban write.
func expectBanWriteFailureRedis(mock redismock.ClientMock) {
	mock.Regexp().ExpectHGetAll(".*:P").SetVal(map[string]string{"positive": "0"})
	mock.Regexp().ExpectHGetAll(".*:N").SetVal(map[string]string{"negative": "0"})
	mock.Regexp().ExpectSIsMember(".*affected_accounts", bruteForceScenarioAccount).SetVal(false)
	mock.Regexp().ExpectSAdd(".*affected_accounts", bruteForceScenarioAccount).SetVal(int64(1))
	expectSlidingWindowTrigger(mock)
	mock.Regexp().ExpectSetNX(".*bf:ban:.*", "testbucket", 8*time.Hour).SetErr(errors.New("redis write failed"))
	mock.Regexp().ExpectExists(".*bf:ban:.*").SetVal(int64(0))
}

func TestProcessPWHistSkipsWithoutAccountName(t *testing.T) {
	cfg := initTestConfig()
	mock, tol := setupSubtest(cfg)
	mock.MatchExpectationsInOrder(false)

	bm := bruteforce.NewBucketManagerWithDeps(context.Background(), "pw_hist_skip", "1.2.3.4", bruteforce.BucketManagerDeps{
		Cfg:      cfg,
		Logger:   log.GetLogger(),
		Redis:    rediscli.GetClient(),
		Tolerate: tol,
	}).WithUsername("user1").WithProtocol("imap").WithPassword(secret.New("password123"))

	accountName := bm.ProcessPWHist()
	assert.Empty(t, accountName)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestProcessPWHistIndexesNewAffectedAccount(t *testing.T) {
	cfg := initTestConfig()
	mock, tol := setupSubtest(cfg)
	mock.MatchExpectationsInOrder(false)

	const (
		accountName = "user1"
		clientIP    = "1.2.3.4"
	)

	bm := bruteforce.NewBucketManagerWithDeps(context.Background(), "pw_hist_index", clientIP, bruteforce.BucketManagerDeps{
		Cfg:      cfg,
		Logger:   log.GetLogger(),
		Redis:    rediscli.GetClient(),
		Tolerate: tol,
	}).WithAccountName(accountName).WithUsername(accountName).WithProtocol("imap").WithPassword(secret.New("password123")).WithRWPDecision(true)

	prefix := cfg.GetServer().GetRedis().GetPrefix()
	affectedKey := prefix + definitions.RedisAffectedAccountsKey
	accountIndexKey := rediscli.GetAffectedAccountsIndexKey(prefix)
	pwHistKey := bruteforce.GetPWHistIPsRedisKey(accountName, cfg)

	mock.ExpectSIsMember(affectedKey, accountName).SetVal(false)
	mock.ExpectSAdd(affectedKey, accountName).SetVal(1)
	mock.CustomMatch(func(_ []any, actual []any) error {
		if len(actual) != 5 {
			return fmt.Errorf("unexpected zadd args: %v", actual)
		}

		if actual[1] != accountIndexKey || actual[2] != "nx" || actual[4] != accountName {
			return fmt.Errorf("unexpected affected-account index zadd: %v", actual)
		}

		return nil
	}).ExpectZAddNX(accountIndexKey, redis.Z{Score: 0, Member: accountName}).SetVal(1)
	mock.ExpectSIsMember(pwHistKey, clientIP).SetVal(false)
	mock.ExpectSAdd(pwHistKey, clientIP).SetVal(1)
	mock.ExpectExpire(pwHistKey, cfg.GetServer().Redis.NegCacheTTL).SetVal(true)

	assert.Equal(t, accountName, bm.ProcessPWHist())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBruteForceLogic(t *testing.T) {
	cfg := initTestConfig()

	t.Run("IP already identified as brute forcer", func(t *testing.T) {
		assertAlreadyIdentifiedBruteForcer(t, cfg)
	})

	t.Run("IP over the limit", func(t *testing.T) {
		assertIPOverLimit(t, cfg)
	})
}

const bruteForceLogicIP = "192.168.1.1"

// assertAlreadyIdentifiedBruteForcer verifies cached ban-key detection.
func assertAlreadyIdentifiedBruteForcer(t *testing.T, cfg config.File) {
	t.Helper()

	mock, bm := setupLogicBucketManager(cfg)
	prefix := cfg.GetServer().GetRedis().GetPrefix()
	banKey := rediscli.GetBruteForceBanKey(prefix, bruteForceLogicIP+"/32")
	mock.ExpectExists(banKey).SetVal(1)

	network := &net.IPNet{}

	var message string

	withError, alreadyTriggered, ruleNumber := bm.CheckRepeatingBruteForcer(cfg.GetBruteForceRules(), &network, &message)

	assert.False(t, withError)
	assert.True(t, alreadyTriggered)
	assert.Equal(t, 0, ruleNumber)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// assertIPOverLimit verifies bucket counter over-limit policy facts.
func assertIPOverLimit(t *testing.T, cfg config.File) {
	t.Helper()

	mock, bm := setupLogicBucketManager(cfg)
	rules := cfg.GetBruteForceRules()
	rule := &rules[0]
	_, network, _ := net.ParseCIDR(bruteForceLogicIP + "/32")
	currentKey, prevKey, _ := bm.GetSlidingWindowKeys(rule, network)

	mock.MatchExpectationsInOrder(false)
	mock.Regexp().ExpectHGet(".*", "positive").RedisNil()
	mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("sha1")
	mock.Regexp().ExpectEvalSha("sha1", []string{currentKey, prevKey}, ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*").
		SetVal([]any{"15", int64(1), "4"})

	var message string

	withError, ruleTriggered, _ := bm.CheckBucketOverLimit(rules, &message)

	assert.False(t, withError)
	assert.True(t, ruleTriggered)
	assertBucketPolicyFactsOverLimit(t, bm.GetBucketPolicyFacts())
	assert.NoError(t, mock.ExpectationsWereMet())
}

// setupLogicBucketManager creates a bucket manager for core logic tests.
func setupLogicBucketManager(cfg config.File) (redismock.ClientMock, bruteforce.BucketManager) {
	mock, tol := setupSubtest(cfg)
	bm := bruteforce.NewBucketManagerWithDeps(context.Background(), "test", bruteForceLogicIP, bruteforce.BucketManagerDeps{
		Cfg:      cfg,
		Logger:   log.GetLogger(),
		Redis:    rediscli.GetClient(),
		Tolerate: tol,
	})

	return mock, bm
}

// assertBucketPolicyFactsOverLimit verifies the stored over-limit facts.
func assertBucketPolicyFactsOverLimit(t *testing.T, facts []bruteforce.BucketPolicyFact) {
	t.Helper()

	if assert.Len(t, facts, 1) {
		assert.True(t, facts[0].Matched)
		assert.Equal(t, "testbucket", facts[0].Name)
		assert.Equal(t, float64(15), facts[0].Count)
		assert.Equal(t, float64(4), facts[0].EffectiveLimit)
		assert.True(t, facts[0].OverLimit)
		assert.True(t, facts[0].Repeating)
	}
}

func TestBruteForceFilters(t *testing.T) {
	t.Run("Bucket key includes protocol and OIDC when filters configured", func(t *testing.T) {
		runtimeModule := mustRuntimeModule(definitions.ControlBruteForce)
		testFileFilters := &config.FileSettings{
			Server: &config.ServerSection{
				RuntimeModules: []*config.RuntimeModule{runtimeModule},
				Redis:          config.Redis{Prefix: "nt_"},
			},
			BruteForce: &config.BruteForceSection{
				Buckets: []config.BruteForceRule{
					{
						Name:             "filtered",
						Period:           time.Hour,
						CIDR:             24,
						IPv4:             true,
						IPv6:             false,
						FailedRequests:   5,
						FilterByProtocol: []string{"imap"},
						FilterByOIDCCID:  []string{"cid123"},
					},
				},
			},
		}

		bm := bruteforce.NewBucketManagerWithDeps(context.Background(), "test", "10.0.1.2", bruteforce.BucketManagerDeps{Cfg: testFileFilters, Logger: log.GetLogger(), Redis: rediscli.GetClient()}).
			WithProtocol("imap").
			WithOIDCCID("cid123")

		rule := testFileFilters.GetBruteForceRules()[0]
		key := bm.GetBruteForceBucketRedisKey(&rule)

		expected := "nt_bf:{10.0.1.0/24|p=imap|oidc=cid123}:3600:24:5:4:10.0.1.0/24:imap:oidc:cid123"
		assert.Equal(t, expected, key)
	})
}

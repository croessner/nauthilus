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
	"net"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/bruteforce/l1"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func initTestConfig() config.File {
	feature := config.Feature{}
	feature.Set("brute_force")
	backend := config.Backend{}
	backend.Set("cache")

	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	testFile := &config.FileSettings{
		Server: &config.ServerSection{
			Features: []*config.Feature{&feature},
			Backends: []*config.Backend{&backend},
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
	for i := 0; i < 20; i++ {
		mock.Regexp().ExpectHGetAll(".*").SetVal(map[string]string{})
		mock.Regexp().ExpectGet(".*").RedisNil()
	}
}

func TestBruteForceScenarios(t *testing.T) {
	cfg := initTestConfig()
	const attackerIP = "1.2.3.4"
	const accountName = "user1"
	const password = "password123"
	hashedPW := util.GetHash(util.PreparePassword(password))

	t.Run("Scenario 1: Known user, same password (RWP protection)", func(t *testing.T) {
		mock, tol := setupSubtest(cfg)
		mockNoisy(mock)
		bm := bruteforce.NewBucketManagerWithDeps(context.Background(), "scen1", attackerIP, bruteforce.BucketManagerDeps{
			Cfg:      cfg,
			Logger:   log.GetLogger(),
			Redis:    rediscli.GetClient(),
			Tolerate: tol,
		}).WithAccountName(accountName).WithPassword(password)

		mock.MatchExpectationsInOrder(false)

		mock.ExpectScriptLoad(rediscli.LuaScripts["RWPAllowSet"]).SetVal("sha-rwp")
		mock.Regexp().ExpectEvalSha("sha-rwp", []string{".*"}, ".*", ".*", hashedPW).SetVal(int64(1))

		mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("sha-sw")
		mock.Regexp().ExpectEvalSha("sha-sw", []string{".*", ".*", ".*"}, ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*").
			SetVal([]interface{}{"0", int64(0), "4"})

		rule := cfg.GetBruteForceRules()[0]
		_, network, _ := net.ParseCIDR(attackerIP + "/32")
		triggered := bm.ProcessBruteForce(true, false, &rule, network, "attack", func() {})

		assert.False(t, triggered)
	})

	t.Run("Scenario 2: Known user, different passwords (Brute force triggered)", func(t *testing.T) {
		mock, tol := setupSubtest(cfg)
		mockNoisy(mock)
		bm := bruteforce.NewBucketManagerWithDeps(context.Background(), "scen2", attackerIP, bruteforce.BucketManagerDeps{
			Cfg:      cfg,
			Logger:   log.GetLogger(),
			Redis:    rediscli.GetClient(),
			Tolerate: tol,
		}).WithAccountName(accountName).WithPassword("new_password")

		mock.MatchExpectationsInOrder(false)

		mock.ExpectScriptLoad(rediscli.LuaScripts["RWPAllowSet"]).SetVal("sha-rwp")
		mock.Regexp().ExpectEvalSha("sha-rwp", []string{".*"}, ".*", ".*", ".*").SetVal(int64(0))

		mock.Regexp().ExpectHGetAll(".*:P").SetVal(map[string]string{"positive": "0"})
		mock.Regexp().ExpectHGetAll(".*:N").SetVal(map[string]string{"negative": "0"})

		// Check if account is in affected-accounts
		mock.Regexp().ExpectSIsMember(".*affected_accounts", accountName).SetVal(false)
		mock.Regexp().ExpectSAdd(".*affected_accounts", accountName).SetVal(int64(1))

		mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("sha-sw")
		mock.Regexp().ExpectEvalSha("sha-sw", []string{".*", ".*", ".*"}, ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*").
			SetVal([]interface{}{"10", int64(1), "4"})

		mock.Regexp().ExpectHSet(".*bruteforce:.*", attackerIP+"/32", "testbucket").SetVal(int64(1))

		// Verifiziere globale Sperre via Pub/Sub
		mock.Regexp().ExpectPublish(definitions.RedisBFBlocksChannel, ".*").SetVal(1)
		mock.Regexp().ExpectPublish(definitions.RedisBFBlocksChannel, ".*").SetVal(1)

		mock.ExpectScriptLoad(rediscli.LuaScripts["IncrementAndExpire"]).SetVal("sha-inc")
		mock.Regexp().ExpectEvalSha("sha-inc", []string{".*"}, ".*").SetVal(int64(1))

		// New password history Set logic
		mock.Regexp().ExpectEvalSha(".*", []string{".*"}, ".*", ".*", ".*").SetVal(int64(1))
		mock.Regexp().ExpectEvalSha(".*", []string{".*"}, ".*", ".*", ".*").SetVal(int64(1))

		rule := cfg.GetBruteForceRules()[0]
		_, network, _ := net.ParseCIDR(attackerIP + "/32")
		triggered := bm.ProcessBruteForce(true, false, &rule, network, "attack", func() {})

		assert.True(t, triggered)
	})

	t.Run("Scenario 3: Different users, same password (Brute force)", func(t *testing.T) {
		mock, tol := setupSubtest(cfg)
		mockNoisy(mock)
		bm := bruteforce.NewBucketManagerWithDeps(context.Background(), "scen3", attackerIP, bruteforce.BucketManagerDeps{
			Cfg:      cfg,
			Logger:   log.GetLogger(),
			Redis:    rediscli.GetClient(),
			Tolerate: tol,
		}).WithUsername("user2").WithPassword(password)

		mock.MatchExpectationsInOrder(false)

		mock.ExpectScriptLoad(rediscli.LuaScripts["RWPAllowSet"]).SetVal("sha-rwp")
		mock.Regexp().ExpectEvalSha("sha-rwp", []string{".*"}, ".*", ".*", hashedPW).SetVal(int64(0))
		mock.Regexp().ExpectHGetAll(".*:P").SetVal(map[string]string{"positive": "0"})
		mock.Regexp().ExpectHGetAll(".*:N").SetVal(map[string]string{"negative": "0"})
		mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("sha-sw")
		mock.Regexp().ExpectEvalSha("sha-sw", []string{".*", ".*", ".*"}, ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*").
			SetVal([]interface{}{"10", int64(1), "4"})
		mock.Regexp().ExpectHSet(".*", attackerIP+"/32", "testbucket").SetVal(int64(1))
		mock.Regexp().ExpectPublish(definitions.RedisBFBlocksChannel, ".*").SetVal(1)
		mock.Regexp().ExpectPublish(definitions.RedisBFBlocksChannel, ".*").SetVal(1)
		mock.ExpectScriptLoad(rediscli.LuaScripts["IncrementAndExpire"]).SetVal("sha-inc")
		mock.Regexp().ExpectEvalSha("sha-inc", []string{".*"}, ".*").SetVal(int64(1))

		// New password history Set logic
		mock.Regexp().ExpectEvalSha(".*", []string{".*"}, ".*", ".*", ".*").SetVal(int64(1))
		mock.Regexp().ExpectEvalSha(".*", []string{".*"}, ".*", ".*", ".*").SetVal(int64(1))

		rule := cfg.GetBruteForceRules()[0]
		_, network, _ := net.ParseCIDR(attackerIP + "/32")
		triggered := bm.ProcessBruteForce(true, false, &rule, network, "attack", func() {})

		assert.True(t, triggered)
	})

	t.Run("Scenario 4: Different users, different passwords (Brute force)", func(t *testing.T) {
		mock, tol := setupSubtest(cfg)
		mockNoisy(mock)
		bm := bruteforce.NewBucketManagerWithDeps(context.Background(), "scen4", attackerIP, bruteforce.BucketManagerDeps{
			Cfg:      cfg,
			Logger:   log.GetLogger(),
			Redis:    rediscli.GetClient(),
			Tolerate: tol,
		}).WithUsername("user3").WithPassword("passX")

		mock.MatchExpectationsInOrder(false)

		mock.ExpectScriptLoad(rediscli.LuaScripts["RWPAllowSet"]).SetVal("sha-rwp")
		mock.Regexp().ExpectEvalSha("sha-rwp", []string{".*"}, ".*", ".*", ".*").SetVal(int64(0))
		mock.Regexp().ExpectHGetAll(".*:P").SetVal(map[string]string{"positive": "0"})
		mock.Regexp().ExpectHGetAll(".*:N").SetVal(map[string]string{"negative": "0"})
		mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("sha-sw")
		mock.Regexp().ExpectEvalSha("sha-sw", []string{".*", ".*", ".*"}, ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*").
			SetVal([]interface{}{"10", int64(1), "4"})
		mock.Regexp().ExpectHSet(".*", attackerIP+"/32", "testbucket").SetVal(int64(1))
		mock.Regexp().ExpectPublish(definitions.RedisBFBlocksChannel, ".*").SetVal(1)
		mock.Regexp().ExpectPublish(definitions.RedisBFBlocksChannel, ".*").SetVal(1)
		mock.ExpectScriptLoad(rediscli.LuaScripts["IncrementAndExpire"]).SetVal("sha-inc")
		mock.Regexp().ExpectEvalSha("sha-inc", []string{".*"}, ".*").SetVal(int64(1))

		// New password history Set logic
		mock.Regexp().ExpectEvalSha(".*", []string{".*"}, ".*", ".*", ".*").SetVal(int64(1))
		mock.Regexp().ExpectEvalSha(".*", []string{".*"}, ".*", ".*", ".*").SetVal(int64(1))

		rule := cfg.GetBruteForceRules()[0]
		_, network, _ := net.ParseCIDR(attackerIP + "/32")
		triggered := bm.ProcessBruteForce(true, false, &rule, network, "attack", func() {})

		assert.True(t, triggered)
	})
}

func TestBruteForceLogic(t *testing.T) {
	cfg := initTestConfig()
	const testIP = "192.168.1.1"

	t.Run("IP already identified as brute forcer", func(t *testing.T) {
		mock, tol := setupSubtest(cfg)
		bm := bruteforce.NewBucketManagerWithDeps(context.Background(), "test", testIP, bruteforce.BucketManagerDeps{
			Cfg:      cfg,
			Logger:   log.GetLogger(),
			Redis:    rediscli.GetClient(),
			Tolerate: tol,
		})
		prefix := cfg.GetServer().GetRedis().GetPrefix()

		shardKey := rediscli.GetBruteForceHashKey(prefix, testIP+"/32")
		mock.ExpectHMGet(shardKey, testIP+"/32").SetVal([]interface{}{"testbucket"})

		network := &net.IPNet{}
		var message string
		withError, alreadyTriggered, ruleNumber := bm.CheckRepeatingBruteForcer(cfg.GetBruteForceRules(), &network, &message)

		assert.False(t, withError)
		assert.True(t, alreadyTriggered)
		assert.Equal(t, 0, ruleNumber)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("IP over the limit", func(t *testing.T) {
		mock, tol := setupSubtest(cfg)
		bm := bruteforce.NewBucketManagerWithDeps(context.Background(), "test", testIP, bruteforce.BucketManagerDeps{
			Cfg:      cfg,
			Logger:   log.GetLogger(),
			Redis:    rediscli.GetClient(),
			Tolerate: tol,
		})

		rules := cfg.GetBruteForceRules()
		rule := &rules[0]
		_, network, _ := net.ParseCIDR(testIP + "/32")
		currentKey, prevKey, _ := bm.GetSlidingWindowKeys(rule, network)

		mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("sha1")
		mock.Regexp().ExpectEvalSha("sha1", []string{currentKey, prevKey, ".*"}, ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*").
			SetVal([]interface{}{"15", int64(1), "4"})

		var message string
		withError, ruleTriggered, _ := bm.CheckBucketOverLimit(rules, &message)

		assert.False(t, withError)
		assert.True(t, ruleTriggered)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestBruteForceFilters(t *testing.T) {
	t.Run("Bucket key includes protocol and OIDC when filters configured", func(t *testing.T) {
		feature := config.Feature{}
		feature.Set("brute_force")
		testFileFilters := &config.FileSettings{
			Server: &config.ServerSection{
				Features: []*config.Feature{&feature},
				Redis:    config.Redis{Prefix: "nt_"},
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

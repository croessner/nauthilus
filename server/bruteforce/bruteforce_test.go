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
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestBruteForceLogic(t *testing.T) {
	db, mock := redismock.NewClientMock()
	rediscli.NewTestClient(db)

	feature := config.Feature{}
	feature.Set("brute_force")

	backend := config.Backend{}
	backend.Set("cache")

	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	config.SetTestFile(&config.FileSettings{
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
					CIDR:           16,
					IPv4:           true,
					IPv6:           false,
					FailedRequests: 10,
				}}},
	})

	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	t.Run("IP already identified as brute forcer", func(t *testing.T) {
		bm := bruteforce.NewBucketManager(context.Background(), "test", "192.168.1.1")
		testNetwork := "192.168.0.0/16"

		mock.ExpectHMGet(
			config.GetFile().GetServer().GetRedis().GetPrefix()+definitions.RedisBruteForceHashKey,
			testNetwork).SetVal([]interface{}{"testbucket"})

		network := &net.IPNet{}

		var message string

		withError, alreadyTriggered, ruleNumber := bm.CheckRepeatingBruteForcer(
			config.GetFile().GetBruteForceRules(), &network, &message)

		assert.False(t, withError, "No error should occur")
		assert.True(t, alreadyTriggered, "The rule should already be triggered")
		assert.Equal(t, "Brute force attack detected (cached result)", message)
		assert.Equal(t, 0, ruleNumber, "The first rule should be triggered")

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("IP not identified as brute forcer", func(t *testing.T) {
		bm := bruteforce.NewBucketManager(context.Background(), "test", "192.168.1.1")
		testNetwork := "192.168.0.0/16"

		mock.ExpectHMGet(
			config.GetFile().GetServer().GetRedis().GetPrefix()+definitions.RedisBruteForceHashKey,
			testNetwork).SetVal([]interface{}{nil})

		network := &net.IPNet{}

		var message string

		withError, alreadyTriggered, ruleNumber := bm.CheckRepeatingBruteForcer(
			config.GetFile().GetBruteForceRules(), &network, &message)

		assert.False(t, withError, "No error should occur")
		assert.False(t, alreadyTriggered, "The rule should not be triggered")
		assert.Empty(t, message, "The message should remain empty")
		assert.Equal(t, 0, ruleNumber, "The rule index should be 0")

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("IP not over the limit", func(t *testing.T) {
		bm := bruteforce.NewBucketManager(context.Background(), "test", "192.168.1.1")

		rule := config.GetFile().GetBruteForceRules()[0]
		mock.ExpectGet(bm.GetBruteForceBucketRedisKey(&rule)).SetVal("5")

		var message string

		withError, ruleTriggered, ruleNumber := bm.CheckBucketOverLimit(
			config.GetFile().GetBruteForceRules(), &message)

		assert.False(t, withError, "No error should occur")
		assert.False(t, ruleTriggered, "The rule should not be triggered")
		assert.Empty(t, message, "The message should remain empty")
		assert.Equal(t, 0, ruleNumber, "The rule index should remain 0")

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("IP over the limit", func(t *testing.T) {
		bm := bruteforce.NewBucketManager(context.Background(), "test", "192.168.1.1")

		rule := config.GetFile().GetBruteForceRules()[0]
		mock.ExpectGet(bm.GetBruteForceBucketRedisKey(&rule)).SetVal("15")

		var message string

		withError, ruleTriggered, ruleNumber := bm.CheckBucketOverLimit(
			config.GetFile().GetBruteForceRules(), &message)

		assert.False(t, withError, "No error should occur")
		assert.True(t, ruleTriggered, "The rule should be triggered")
		assert.NotEmpty(t, message, "The message should not be empty")
		assert.Contains(t, message, "Brute force attack detected", "The message should indicate a brute force attack is detected")
		assert.Equal(t, 0, ruleNumber, "The first rule should be triggered")

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("No brute force, repeating wrong password", func(t *testing.T) {
		const password = "<PASSWORD>"
		const accountName = "testaccount"
		const testIPAddress = "192.168.1.1"

		// Arguments passed to Lua gate (must match production):
		// ARGV[1]=hashedPW, ARGV[2]=ttlSec (neg cache TTL), ARGV[3]=maxFields
		hashedPW := util.GetHash(util.PreparePassword(password))

		bm := bruteforce.NewBucketManager(context.Background(), "test", testIPAddress).
			WithUsername("testuser").
			WithPassword(password).
			WithAccountName(accountName)

		// Account-scoped PW_HIST contains the counter for this password
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "100"})

		// Totals: use only new PW_HIST_TOTAL counters (legacy fallback removed)
		mock.ExpectGet(
			config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + fmt.Sprintf(":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress),
		).SetVal("100")
		mock.ExpectGet(
			config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + fmt.Sprintf(":{%s}:%s", testIPAddress, testIPAddress),
		).RedisNil()

		// Bucket with account information - defer (LoadAllPasswordHistories)
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "101"})

		// Bucket without account information - defer (LoadAllPasswordHistories)
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":{%s}:%s", testIPAddress, testIPAddress)).
			SetVal(map[string]string{hashedPW: "101"})

		// Order of Lua gate executions is not semantically relevant; allow any order
		mock.MatchExpectationsInOrder(false)

		_, network, _ := net.ParseCIDR("192.168.0.0/16")
		message := "test message"
		rule := config.GetFile().GetBruteForceRules()[0]

		var (
			featureName     string
			bruteForceName  string
			loginAttempts   uint
			passwordHistory *bruteforce.PasswordHistory
		)

		triggered := bm.ProcessBruteForce(true, false, &rule, network, message, func() {
			featureName = bm.GetFeatureName()
			bruteForceName = bm.GetBruteForceName()
			loginAttempts = bm.GetLoginAttempts()
			passwordHistory = bm.GetPasswordHistory()
		})

		assert.False(t, triggered, "Result should not trigger an action")
		assert.Equal(t, "", featureName, "The feature name should be empty")
		assert.Equal(t, "", bruteForceName, "The brute force name should be empty")
		assert.Equal(t, uint(101), loginAttempts, "The login attempts should be 101")
		assert.NotNil(t, passwordHistory, "The password history should not be nil")

		if passwordHistory != nil {
			if value, okay := (*passwordHistory)[hashedPW]; okay {
				assert.Equal(t, uint(101), value, "The password history should contain the correct value")
			} else {
				assert.Fail(t, "The password history should contain the correct value")
			}

			assert.Equal(t, 1, len(*passwordHistory), "The password history should only contain one entry")
		}

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("No brute force, repeating wrong password with both totals present", func(t *testing.T) {
		const password = "<PASSWORD>"
		const accountName = "testaccount"
		const testIPAddress = "192.168.1.1"

		hashedPW := util.GetHash(util.PreparePassword(password))

		bm := bruteforce.NewBucketManager(context.Background(), "test", testIPAddress).
			WithUsername("testuser").
			WithPassword(password).
			WithAccountName(accountName)

		// Account-scoped PW_HIST contains the counter for this password
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "100"})

		// Totals: both present and equal to counter
		mock.ExpectGet(
			config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + fmt.Sprintf(":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress),
		).SetVal("100")
		mock.ExpectGet(
			config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + fmt.Sprintf(":{%s}:%s", testIPAddress, testIPAddress),
		).SetVal("100")

		// Bucket with account information - defer (LoadAllPasswordHistories)
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "101"})

		// Bucket without account information - defer (LoadAllPasswordHistories)
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":{%s}:%s", testIPAddress, testIPAddress)).
			SetVal(map[string]string{hashedPW: "101"})

		mock.MatchExpectationsInOrder(true)

		_, network, _ := net.ParseCIDR("192.168.0.0/16")
		message := "test message"
		rule := config.GetFile().GetBruteForceRules()[0]

		var (
			featureName     string
			bruteForceName  string
			loginAttempts   uint
			passwordHistory *bruteforce.PasswordHistory
		)

		triggered := bm.ProcessBruteForce(true, false, &rule, network, message, func() {
			featureName = bm.GetFeatureName()
			bruteForceName = bm.GetBruteForceName()
			loginAttempts = bm.GetLoginAttempts()
			passwordHistory = bm.GetPasswordHistory()
		})

		assert.False(t, triggered, "Result should not trigger an action")
		assert.Equal(t, "", featureName, "The feature name should be empty")
		assert.Equal(t, "", bruteForceName, "The brute force name should be empty")
		assert.Equal(t, uint(101), loginAttempts, "The login attempts should be 101")
		assert.NotNil(t, passwordHistory, "The password history should not be nil")

		if passwordHistory != nil {
			if value, okay := (*passwordHistory)[hashedPW]; okay {
				assert.Equal(t, uint(101), value, "The password history should contain the correct value")
			} else {
				assert.Fail(t, "The password history should contain the correct value")
			}

			assert.Equal(t, 1, len(*passwordHistory), "The password history should only contain one entry")
		}

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Brute force enforced", func(t *testing.T) {
		const password = "<PASSWORD>"
		const accountName = "testaccount"
		const testIPAddress = "192.168.1.1"

		hashedPW := util.GetHash(util.PreparePassword(password))

		bm := bruteforce.NewBucketManager(context.Background(), "test", testIPAddress).
			WithUsername("testuser").
			WithPassword(password).
			WithAccountName(accountName)

		// Account-scoped PW_HIST contains the counter for this password
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "100"})

		// Totals indicate not repeating: use max(total_account, total_ip) > counter
		mock.ExpectGet(
			config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + fmt.Sprintf(":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress),
		).SetVal("100")
		mock.ExpectGet(
			config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + fmt.Sprintf(":{%s}:%s", testIPAddress, testIPAddress),
		).SetVal("101")

		// Affected accounts aren't set
		mock.ExpectSIsMember(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix()+definitions.RedisAffectedAccountsKey, accountName).
			RedisNil()

		// Affected account added
		mock.ExpectSAdd(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix()+definitions.RedisAffectedAccountsKey, accountName).
			SetVal(1)

		rule := config.GetFile().GetBruteForceRules()[0]
		_, network, _ := net.ParseCIDR("192.168.0.0/16")

		// Add IP address to a pre-result map
		mock.ExpectHSet(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix()+definitions.RedisBruteForceHashKey, network.String(), rule.Name).
			SetVal(1)

		// Bucket with account informtion - defer
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "101"})

		// Bucket without account informtion - defer
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":{%s}:%s", testIPAddress, testIPAddress)).
			SetVal(map[string]string{
				hashedPW:    "101",
				"otherHash": "1",
			})

		mock.MatchExpectationsInOrder(true)

		message := "test message"

		var (
			featureName     string
			bruteForceName  string
			loginAttempts   uint
			passwordHistory *bruteforce.PasswordHistory
		)

		triggered := bm.ProcessBruteForce(true, false, &rule, network, message, func() {
			featureName = bm.GetFeatureName()
			bruteForceName = bm.GetBruteForceName()
			loginAttempts = bm.GetLoginAttempts()
			passwordHistory = bm.GetPasswordHistory()
		})

		assert.True(t, triggered, "Result should trigger an action")
		assert.Equal(t, "brute_force", featureName, "The feature name should not be empty")
		assert.Equal(t, "testbucket", bruteForceName, "The brute force name should not be empty")
		assert.Equal(t, uint(101), loginAttempts, "The login attempts should be 101")
		assert.NotNil(t, passwordHistory, "The password history should not be nil")

		if passwordHistory != nil {
			if value, okay := (*passwordHistory)[hashedPW]; okay {
				assert.Equal(t, uint(101), value, "The password history should contain the correct value")
			} else {
				assert.Fail(t, "The password history should contain the correct value")
			}

			assert.Equal(t, 2, len(*passwordHistory), "The password history should contain two entries")
		}

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Brute force with 10% toleration", func(t *testing.T) {
		const password = "<PASSWORD>"
		const accountName = "testaccount"
		const testIPAddress = "192.168.1.1"

		tolerate.GetTolerate().SetCustomToleration(testIPAddress, 10, time.Hour)

		hashedPW := util.GetHash(util.PreparePassword(password))

		bm := bruteforce.NewBucketManager(context.Background(), "test", testIPAddress).
			WithUsername("testuser").
			WithPassword(password).
			WithAccountName(accountName)

		// Account-scoped PW_HIST contains the counter for this password
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "100"})

		// Totals: repeating true (sum == counter)
		mock.ExpectGet(
			config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + fmt.Sprintf(":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress),
		).SetVal("100")
		mock.ExpectGet(
			config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + fmt.Sprintf(":{%s}:%s", testIPAddress, testIPAddress),
		).RedisNil()

		// No TR counters expected in this branch because repeating-wrong-password skips further brute-force computation

		// Bucket with account information - defer
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "101"})

		// Bucket without account information - defer
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":{%s}:%s", testIPAddress, testIPAddress)).
			SetVal(map[string]string{
				hashedPW:    "101",
				"otherHash": "1",
			})

		mock.MatchExpectationsInOrder(true)

		rule := config.GetFile().GetBruteForceRules()[0]
		_, network, _ := net.ParseCIDR("192.168.0.0/16")
		message := "test message"

		var (
			featureName     string
			bruteForceName  string
			loginAttempts   uint
			passwordHistory *bruteforce.PasswordHistory
		)

		triggered := bm.ProcessBruteForce(true, false, &rule, network, message, func() {
			featureName = bm.GetFeatureName()
			bruteForceName = bm.GetBruteForceName()
			loginAttempts = bm.GetLoginAttempts()
			passwordHistory = bm.GetPasswordHistory()
		})

		assert.False(t, triggered, "Result should not trigger an action")
		assert.Equal(t, "", featureName, "The feature name should be empty")
		assert.Equal(t, "", bruteForceName, "The brute force name should be empty")
		assert.Equal(t, uint(101), loginAttempts, "The login attempts should be 101")
		assert.NotNil(t, passwordHistory, "The password history should not be nil")

		if passwordHistory != nil {
			if value, okay := (*passwordHistory)[hashedPW]; okay {
				assert.Equal(t, uint(101), value, "The password history should contain the correct value")
			} else {
				assert.Fail(t, "The password history should contain the correct value")
			}

			assert.Equal(t, 2, len(*passwordHistory), "The password history should contain two entries")
		}

		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestBruteForceFilters(t *testing.T) {
	db, mock := redismock.NewClientMock()
	rediscli.NewTestClient(db)

	feature := config.Feature{}
	feature.Set("brute_force")

	backend := config.Backend{}
	backend.Set("cache")

	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	config.SetTestFile(&config.FileSettings{
		Server: &config.ServerSection{
			Features: []*config.Feature{&feature},
			Backends: []*config.Backend{&backend},
			Redis: config.Redis{
				Prefix: "nt_",
			}},
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
	})

	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	t.Run("Bucket key includes protocol and OIDC when filters configured and context provided", func(t *testing.T) {
		bm := bruteforce.NewBucketManager(context.Background(), "test", "10.0.1.2").
			WithProtocol("imap").
			WithOIDCCID("cid123")

		rule := config.GetFile().GetBruteForceRules()[0]
		key := bm.GetBruteForceBucketRedisKey(&rule)

		// Expected network for 10.0.1.2/24 is 10.0.1.0/24
		expected := config.GetFile().GetServer().GetRedis().GetPrefix() +
			"bf:{10.0.1.0/24|p=imap|oidc=cid123}:" + fmt.Sprintf("%.0f:%d:%d:%s:%s:%s:oidc:%s",
			rule.Period.Seconds(), rule.CIDR, rule.FailedRequests, "4", "10.0.1.0/24", "imap", "cid123")

		assert.Equal(t, expected, key, "Key should include protocol and OIDC parts when filters match and context is provided")
	})

	t.Run("Bucket key reconstructs filters from Redis metadata when context missing", func(t *testing.T) {
		bm := bruteforce.NewBucketManager(context.Background(), "test", "10.0.1.2")
		rule := config.GetFile().GetBruteForceRules()[0]

		// loadPWHistFiltersIfMissing will try IP-specific meta first
		metaKeyIP := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistMetaKey + ":" + "10.0.1.2"
		mock.ExpectHGetAll(metaKeyIP).SetVal(map[string]string{
			"protocol": "imap",
			"oidc_cid": "cid123",
		})

		key := bm.GetBruteForceBucketRedisKey(&rule)

		expected := config.GetFile().GetServer().GetRedis().GetPrefix() +
			"bf:{10.0.1.0/24|p=imap|oidc=cid123}:" + fmt.Sprintf("%.0f:%d:%d:%s:%s:%s:oidc:%s",
			rule.Period.Seconds(), rule.CIDR, rule.FailedRequests, "4", "10.0.1.0/24", "imap", "cid123")

		assert.Equal(t, expected, key, "Key should reconstruct protocol and OIDC parts from PW_HIST_META")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("CheckRepeatingBruteForcer respects protocol filter and uses cached pre-result", func(t *testing.T) {
		bm := bruteforce.NewBucketManager(context.Background(), "test", "10.0.1.2").WithProtocol("imap")
		rule := config.GetFile().GetBruteForceRules()[0]

		// Pre-result (cache) lookup uses BRUTEFORCE hash with the matching network key
		_, network, _ := net.ParseCIDR("10.0.1.0/24")
		mock.ExpectHMGet(
			config.GetFile().GetServer().GetRedis().GetPrefix()+definitions.RedisBruteForceHashKey,
			network.String(),
		).SetVal([]interface{}{rule.Name})

		var message string
		var netPtr *net.IPNet

		withError, alreadyTriggered, ruleNumber := bm.CheckRepeatingBruteForcer(
			[]config.BruteForceRule{rule}, &netPtr, &message)

		assert.False(t, withError)
		assert.True(t, alreadyTriggered)
		assert.Equal(t, 0, ruleNumber)
		assert.Contains(t, message, "cached result")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestBruteForceFiltersNonMatching(t *testing.T) {
	db, mock := redismock.NewClientMock()
	rediscli.NewTestClient(db)

	feature := config.Feature{}
	feature.Set("brute_force")

	backend := config.Backend{}
	backend.Set("cache")

	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	config.SetTestFile(&config.FileSettings{
		Server: &config.ServerSection{
			Features: []*config.Feature{&feature},
			Backends: []*config.Backend{&backend},
			Redis: config.Redis{
				Prefix: "nt_",
			}},
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
				},
			},
		},
	})

	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	t.Run("Key should not include non-matching protocol and rule should not match", func(t *testing.T) {
		bm := bruteforce.NewBucketManager(context.Background(), "test", "10.0.1.2").
			WithProtocol("smtp") // not in FilterByProtocol

		rule := config.GetFile().GetBruteForceRules()[0]

		key := bm.GetBruteForceBucketRedisKey(&rule)
		// No protocol suffix because it does not match rule filter
		expected := config.GetFile().GetServer().GetRedis().GetPrefix() +
			"bf:{10.0.1.0/24}:" + fmt.Sprintf("%.0f:%d:%d:%s:%s",
			rule.Period.Seconds(), rule.CIDR, rule.FailedRequests, "4", "10.0.1.0/24")
		assert.Equal(t, expected, key)

		var msg string
		withErr, triggered, rn := bm.CheckBucketOverLimit([]config.BruteForceRule{rule}, &msg)
		assert.False(t, withErr)
		assert.False(t, triggered)
		assert.Equal(t, 0, rn) // iterated 0th rule but skipped, not triggered
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestSaveFailedPasswordCounterTotals(t *testing.T) {
	db, mock := redismock.NewClientMock()
	rediscli.NewTestClient(db)

	feature := config.Feature{}
	feature.Set("brute_force")

	backend := config.Backend{}
	backend.Set("cache")

	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	config.SetTestFile(&config.FileSettings{
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
					CIDR:           16,
					IPv4:           true,
					IPv6:           false,
					FailedRequests: 10,
				},
			},
		},
	})

	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	t.Run("Write path increments total counters for both scopes", func(t *testing.T) {
		const password = "<PASSWORD>"
		const accountName = "testaccount"
		const testIPAddress = "192.168.1.1"

		bm := bruteforce.NewBucketManager(context.Background(), "test", testIPAddress).
			WithUsername("testuser").
			WithPassword(password).
			WithAccountName(accountName)

		// SaveFailedPasswordCounterInRedis uses Lua gate; upload script and assert subsequent EvalSha calls.
		mock.ExpectScriptLoad(bruteforce.PwHistGateScript).SetVal("shaPwGate2")
		// Expect account+IP scoped totals update
		// Arguments passed to Lua gate (must match production):
		// ARGV[1]=hashedPW, ARGV[2]=ttlSec (neg cache TTL), ARGV[3]=maxFields
		hashedPwTotals := util.GetHash(util.PreparePassword(password))
		mock.ExpectEvalSha("shaPwGate2", []string{
			config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress),
			config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + fmt.Sprintf(":{%s:%s}:%s:%s", accountName, testIPAddress, accountName, testIPAddress),
		}, hashedPwTotals, int64(0), int64(definitions.MaxPasswordHistoryEntries)).SetVal(int64(1))
		// Expect IP-only scoped totals update
		mock.ExpectEvalSha("shaPwGate2", []string{
			config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(":{%s}:%s", testIPAddress, testIPAddress),
			config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + fmt.Sprintf(":{%s}:%s", testIPAddress, testIPAddress),
		}, hashedPwTotals, int64(0), int64(definitions.MaxPasswordHistoryEntries)).SetVal(int64(1))

		// Order is not important here
		mock.MatchExpectationsInOrder(false)

		// Execute the write path directly
		bm.SaveFailedPasswordCounterInRedis()

		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

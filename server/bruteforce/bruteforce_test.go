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

func TestCheckRepeatingBruteForcer(t *testing.T) {
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

	log.SetupLogging(definitions.LogLevelNone, false, false, "test")

	t.Run("IP already identified as brute forcer", func(t *testing.T) {
		bm := bruteforce.NewBucketManager(context.Background(), "test", "192.168.1.1")
		testNetwork := "192.168.0.0/16"

		mock.ExpectHGet(
			config.GetFile().GetServer().GetRedis().GetPrefix()+definitions.RedisBruteForceHashKey,
			testNetwork).SetVal("testbucket")

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

		mock.ExpectHGet(
			config.GetFile().GetServer().GetRedis().GetPrefix()+definitions.RedisBruteForceHashKey,
			testNetwork).RedisNil()

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

		network := &net.IPNet{}

		var message string

		withError, ruleTriggered, ruleNumber := bm.CheckBucketOverLimit(
			config.GetFile().GetBruteForceRules(), &network, &message)

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

		network := &net.IPNet{}

		var message string

		withError, ruleTriggered, ruleNumber := bm.CheckBucketOverLimit(
			config.GetFile().GetBruteForceRules(), &network, &message)

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

		hashedPW := util.GetHash(util.PreparePassword(password))

		bm := bruteforce.NewBucketManager(context.Background(), "test", testIPAddress).
			WithUsername("testuser").
			WithPassword(password).
			WithAccountName(accountName)

		// Bucket with account informtion
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":%s:%s", accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "100"})

		// Bucket without account informtion
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":%s", testIPAddress)).
			SetVal(map[string]string{hashedPW: "100"})

		// Bucket with account informtion - defer
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":%s:%s", accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "101"})

		// Bucket without account informtion - defer
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":%s", testIPAddress)).
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

		// Bucket with account informtion
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":%s:%s", accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "100"})

		// Bucket without account informtion
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":%s", testIPAddress)).
			SetVal(map[string]string{
				hashedPW:    "100",
				"otherHash": "1",
			})

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
				":%s:%s", accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "101"})

		// Bucket without account informtion - defer
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":%s", testIPAddress)).
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

		// Bucket with account informtion
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":%s:%s", accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "100"})

		// Bucket without account informtion
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":%s", testIPAddress)).
			SetVal(map[string]string{
				hashedPW:    "100",
				"otherHash": "1",
			})

		// Get the current map with negative and positive counters
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + ":bf:TR:" + testIPAddress).
			SetVal(map[string]string{
				"positive": "100",
				"negative": "5",
			})

		// Bucket with account informtion - defer
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":%s:%s", accountName, testIPAddress)).
			SetVal(map[string]string{hashedPW: "101"})

		// Bucket without account informtion - defer
		mock.ExpectHGetAll(
			config.GetFile().
				GetServer().
				GetRedis().
				GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(
				":%s", testIPAddress)).
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

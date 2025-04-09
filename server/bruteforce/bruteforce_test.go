package bruteforce_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestCheckRepeatingBruteForcer(t *testing.T) {
	db, mock := redismock.NewClientMock()
	rediscli.NewTestClient(db)

	bruteForceFeature := config.Feature{}
	bruteForceFeature.Set("brute_force")

	config.SetTestFile(&config.FileSettings{
		Server: &config.ServerSection{
			Features: []*config.Feature{&bruteForceFeature},
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

	bm := bruteforce.NewBucketManager(context.Background(), "test", "192.168.1.1")

	t.Run("IP already identified as brute forcer", func(t *testing.T) {
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
}

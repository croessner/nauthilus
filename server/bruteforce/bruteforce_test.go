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
	// Initialize the Redis mock
	db, mock := redismock.NewClientMock()
	rediscli.NewTestClient(db)

	config.SetTestFile(&config.FileSettings{
		Server: &config.ServerSection{
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
		// Network to simulate in Redis map
		testNetwork := "192.168.0.0/16"

		// Redis mock: Hash key exists with a valid bucket name
		mock.ExpectHGet("nt_"+definitions.RedisBruteForceHashKey, testNetwork).SetVal("testbucket")

		// Prepare the network object for the function
		network := &net.IPNet{}

		var message string

		withError, alreadyTriggered, ruleNumber := bm.CheckRepeatingBruteForcer(
			config.GetFile().GetBruteForceRules(), &network, &message)

		// Assertions
		assert.False(t, withError, "No error should occur")
		assert.True(t, alreadyTriggered, "The rule should already be triggered")
		assert.Equal(t, "Brute force attack detected (cached result)", message)
		assert.Equal(t, 0, ruleNumber, "The first rule should be triggered")

		// Verify the Redis mock expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("IP not identified as brute forcer", func(t *testing.T) {
		// Network to simulate in Redis map
		testNetwork := "192.168.0.0/16"

		// Redis mock: No value exists for the network in the hash map
		mock.ExpectHGet("nt_"+definitions.RedisBruteForceHashKey, testNetwork).RedisNil()

		// Prepare the network object for the function
		network := &net.IPNet{}

		var message string

		withError, alreadyTriggered, ruleNumber := bm.CheckRepeatingBruteForcer(
			config.GetFile().GetBruteForceRules(), &network, &message)

		// Assertions
		assert.False(t, withError, "No error should occur")
		assert.False(t, alreadyTriggered, "The rule should not be triggered")
		assert.Empty(t, message, "The message should remain empty")
		assert.Equal(t, 0, ruleNumber, "The rule index should be 0")

		// Verify the Redis mock expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

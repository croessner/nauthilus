package tolerate

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/redis/go-redis/v9"
)

var (
	tolerate     Tolerate
	initTolerate sync.Once
)

// Tolerate represents an interface for managing IP-based tolerance mechanisms for authentication attempts.
type Tolerate interface {
	// SetContext updates the context for the Tolerate instance.
	SetContext(ctx context.Context)

	// SetIPAddress tracks and updates authentication behavior for a given IP address.
	SetIPAddress(ipAddress string, username string, authenticated bool)

	// IsTolerated checks if an IP address is within the allowed tolerance based on past interactions.
	IsTolerated(ipAddress string) bool
}

type tolerateImpl struct {
	ctx          context.Context
	pctTolerated uint8
	mu           sync.Mutex
}

// SetContext updates the context for the tolerateImpl instance in a thread-safe manner.
func (t *tolerateImpl) SetContext(ctx context.Context) {
	t.mu.Lock()

	defer t.mu.Unlock()

	t.ctx = ctx
}

// SetIPAddress increments the Redis hash counter for the specified IP address based on authentication status.
// It sets a TTL for the hash key to manage the expiration of the tolerance data.
func (t *tolerateImpl) SetIPAddress(ipAddress string, username string, authenticated bool) {
	tolerateTTL := config.GetFile().GetBruteForce().GetTolerateTTL()
	if tolerateTTL == 0 {
		return
	}

	redisKey := t.getRedisKey(ipAddress)
	now := time.Now().Unix()

	flag := ":P"
	if !authenticated {
		flag = ":N"
	}

	stats.GetMetrics().GetRedisWriteCounter().Inc()
	_, err := rediscli.GetClient().GetWriteHandle().ZAdd(
		t.ctx,
		redisKey+flag,
		redis.Z{
			Score: float64(now), Member: strings.ToLower(username),
		}).Result()
	if err != nil {
		t.logRedisError(ipAddress, err)

		return
	}

	removed := int64(0)

	stats.GetMetrics().GetRedisWriteCounter().Inc()
	removed, err = rediscli.GetClient().GetWriteHandle().ZRemRangeByScore(
		t.ctx,
		redisKey+flag,
		"-inf",
		strconv.FormatInt(now-int64(tolerateTTL), 10),
	).Result()
	if err != nil {
		t.logRedisError(ipAddress, err)

		return
	}

	if removed > 0 {
		t.logDbgRemovedRecords(removed)
	}

	stats.GetMetrics().GetRedisReadCounter().Inc()
	positive, err := rediscli.GetClient().GetReadHandle().ZCount(t.ctx, redisKey+":P", "-inf", "+inf").Uint64()
	if err != nil {
		t.logRedisError(ipAddress, err)

		return
	}

	stats.GetMetrics().GetRedisWriteCounter().Inc()
	if err = rediscli.GetClient().GetWriteHandle().Expire(t.ctx, redisKey+":P", tolerateTTL).Err(); err != nil {
		t.logRedisError(ipAddress, err)

		return
	}

	stats.GetMetrics().GetRedisReadCounter().Inc()
	negative, err := rediscli.GetClient().GetReadHandle().ZCount(t.ctx, redisKey+":N", "-inf", "+inf").Uint64()
	if err != nil {
		t.logRedisError(ipAddress, err)

		return
	}

	stats.GetMetrics().GetRedisWriteCounter().Inc()
	if err = rediscli.GetClient().GetWriteHandle().Expire(t.ctx, redisKey+":N", tolerateTTL).Err(); err != nil {
		t.logRedisError(ipAddress, err)

		return
	}

	stats.GetMetrics().GetRedisWriteCounter().Inc()
	if err = rediscli.GetClient().GetWriteHandle().HSet(t.ctx, t.getRedisKey(ipAddress), "positive", strconv.FormatUint(positive, 10)).Err(); err != nil {
		t.logRedisError(ipAddress, err)

		return
	}

	stats.GetMetrics().GetRedisWriteCounter().Inc()
	if err = rediscli.GetClient().GetWriteHandle().HSet(t.ctx, t.getRedisKey(ipAddress), "negative", strconv.FormatUint(negative, 10)).Err(); err != nil {
		t.logRedisError(ipAddress, err)

		return
	}

	stats.GetMetrics().GetRedisWriteCounter().Inc()
	if err = rediscli.GetClient().GetWriteHandle().Expire(t.ctx, t.getRedisKey(ipAddress), tolerateTTL).Err(); err != nil {
		t.logRedisError(ipAddress, err)

		return
	}
}

// IsTolerated checks if the specified IP address is tolerated based on positive and negative interaction thresholds.
func (t *tolerateImpl) IsTolerated(ipAddress string) bool {
	var (
		okay     bool
		positive uint
		negative uint
	)

	if config.GetFile().GetBruteForce().GetTolerateTTL() == 0 {
		return false
	}

	ipMap := t.getMap(ipAddress)

	if positive, okay = ipMap[ipAddress]; !okay {
		positive = 0
	}

	if positive == 0 {
		return false
	}

	if negative, okay = ipMap[ipAddress]; !okay {
		negative = 0
	}

	maxNegative := (uint(t.pctTolerated) * positive) / 100

	t.logDbgTolerate(
		ipAddress,
		positive,
		negative,
		maxNegative,
		t.pctTolerated,
	)

	return negative <= maxNegative
}

var _ Tolerate = (*tolerateImpl)(nil)

// getRedisKey constructs a Redis key using the configured prefix and the given IP address.
func (t *tolerateImpl) getRedisKey(ipAddress string) string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + ":bf:TR:" + ipAddress
}

// getMap retrieves a map of string keys to unsigned integer values from Redis using the specified IP address as a key.
// It fetches all entries from a Redis hash, converts the values to unsigned integers, and handles retrieval/parsing errors.
func (t *tolerateImpl) getMap(ipAddress string) map[string]uint {
	var (
		counter uint64
		err     error
		result  map[string]string
	)

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	ipMap := make(map[string]uint)

	result, err = rediscli.GetClient().GetReadHandle().HGetAll(t.ctx, t.getRedisKey(ipAddress)).Result()

	if err != nil {
		return ipMap
	}

	for k, v := range result {
		counter, err = strconv.ParseUint(v, 10, 32)
		if err != nil {
			continue
		}

		ipMap[k] = uint(counter)
	}

	return ipMap
}

// logDbgTolerate logs debug information about tolerance evaluation, including interaction counts and thresholds.
func (t *tolerateImpl) logDbgTolerate(address string, positive uint, negative uint, maxNegatives uint, tolerated uint8) {
	util.DebugModule(
		definitions.DbgTolerate,
		definitions.LogKeyClientIP, address,
		"positives", positive,
		"negatives", negative,
		"max_negatives", maxNegatives,
		"tolerated", tolerated,
	)
}

// logDbgRemovedRecords logs the count of removed records for debugging purposes in the tolerate module.
func (t *tolerateImpl) logDbgRemovedRecords(removed int64) {
	util.DebugModule(
		definitions.DbgTolerate,
		"removed", removed,
	)
}

// logRedisError logs a Redis error and the associated client IP address as a warning-level log entry.
func (t *tolerateImpl) logRedisError(ipAddress string, err error) {
	level.Warn(log.Logger).Log(
		definitions.LogKeyClientIP, ipAddress,
		definitions.LogKeyMsg, err,
	)
}

// GetTolerate initializes and returns a singleton instance of Tolerate with the configured tolerance percentage.
func GetTolerate() Tolerate {
	initTolerate.Do(func() {
		tolerate = NewTolerate(config.GetFile().GetBruteForce().GetToleratePercent())
	})

	return tolerate
}

// NewTolerate creates a new Tolerate implementation with a specified percentage tolerance for negative actions.
func NewTolerate(pctTolerated uint8) Tolerate {
	tolerate = &tolerateImpl{ctx: context.TODO(), pctTolerated: pctTolerated, mu: sync.Mutex{}}

	return tolerate
}

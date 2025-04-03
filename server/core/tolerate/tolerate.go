package tolerate

import (
	"context"
	"net"
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

var (
	cleaner     *houseKeeper
	initCleaner sync.Once
)

// houseKeeper manages a collection of IP addresses and ensures thread-safe operations.
type houseKeeper struct {
	ctx        context.Context
	ipMap      map[string]struct{}
	mu         sync.Mutex
	ipAddressC chan string
}

// getIPsToClean retrieves a list of all IP addresses currently stored in the houseKeeper's ipMap in a thread-safe manner.
func (c *houseKeeper) getIPsToClean() []string {
	c.mu.Lock()

	defer c.mu.Unlock()

	var ips []string

	for ip := range c.ipMap {
		ips = append(ips, ip)
	}

	return ips
}

// setIPAddress adds the specified IP address to the ipMap in a thread-safe manner.
func (c *houseKeeper) setIPAddress(ipAddress string) {
	c.ipAddressC <- ipAddress
}

// removeIPAddress removes the specified IP address from the ipMap in a thread-safe manner.
func (c *houseKeeper) removeIPAddress(ipAddress string) {
	c.mu.Lock()

	defer c.mu.Unlock()

	delete(c.ipMap, ipAddress)
}

// getHouseKeeper initializes and returns a singleton instance of houseKeeper in a thread-safe manner.
func getHouseKeeper(ctx context.Context) *houseKeeper {
	initCleaner.Do(func() {
		cleaner = newHouseKeeper(ctx)
	})

	return cleaner
}

// newHouseKeeper initializes and returns a new instance of houseKeeper with a given context and an empty IP map.
func newHouseKeeper(ctx context.Context) *houseKeeper {
	maxConcurrentRequests := config.GetFile().GetServer().GetMaxConcurrentRequests()
	if maxConcurrentRequests == 0 {
		maxConcurrentRequests = 1000
	}

	keeper := &houseKeeper{
		ctx:        ctx,
		ipMap:      make(map[string]struct{}),
		ipAddressC: make(chan string, maxConcurrentRequests),
	}

	go keeper.runIPWorker()

	return keeper
}

// runIPWorker processes IP addresses from the channel and adds them to the ipMap in a thread-safe manner.
func (c *houseKeeper) runIPWorker() {
	for ip := range c.ipAddressC {
		c.mu.Lock()

		c.ipMap[ip] = struct{}{}

		c.mu.Unlock()
	}
}

// Tolerate represents an interface for managing IP-based tolerance mechanisms for authentication attempts.
type Tolerate interface {
	// SetContext updates the context for the Tolerate instance.
	SetContext(ctx context.Context)

	// SetCustomTolerations sets the custom toleration configurations for IP-based authentication tolerances.
	SetCustomTolerations(tolerations []config.Tolerate)

	// StartHouseKeeping initiates a periodic housekeeping routine to clean up expired IP tolerance data in Redis storage.
	StartHouseKeeping()

	// SetIPAddress tracks and updates authentication behavior for a given IP address.
	SetIPAddress(ipAddress string, username string, authenticated bool)

	// IsTolerated checks if an IP address is within the allowed tolerance based on past interactions.
	IsTolerated(ipAddress string) bool
}

type tolerateImpl struct {
	ctx             context.Context
	pctTolerated    uint8
	customTolerates []config.Tolerate
	mu              sync.Mutex
}

// SetContext updates the context for the tolerateImpl instance in a thread-safe manner.
func (t *tolerateImpl) SetContext(ctx context.Context) {
	t.mu.Lock()

	defer t.mu.Unlock()

	t.ctx = ctx
}

// SetCustomTolerations sets the custom toleration configurations in a thread-safe manner. It replaces existing values.
func (t *tolerateImpl) SetCustomTolerations(tolerations []config.Tolerate) {
	if tolerations == nil {
		return
	}

	t.mu.Lock()

	defer t.mu.Unlock()

	t.customTolerates = tolerations
}

// SetIPAddress increments the Redis hash counter for the specified IP address based on authentication status.
// It sets a TTL for the hash key to manage the expiration of the tolerance data.
func (t *tolerateImpl) SetIPAddress(ipAddress string, username string, authenticated bool) {
	if strings.TrimSpace(ipAddress) == "" {
		return
	}

	getHouseKeeper(t.ctx).setIPAddress(ipAddress)

	tolerateTTL := config.GetFile().GetBruteForce().GetTolerateTTL()

	for _, customTolerate := range t.customTolerates {
		if !t.findIP(customTolerate.IPAddress, ipAddress) {
			continue
		}

		tolerateTTL = customTolerate.TolerateTTL

		break
	}

	if tolerateTTL == 0 {
		return
	}

	redisKey := t.getRedisKey(ipAddress)
	now := time.Now().Unix()

	flag := ":P"
	label := "positive"

	if !authenticated {
		flag = ":N"
		label = "negative"
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

	stats.GetMetrics().GetRedisReadCounter().Inc()
	positive, err := rediscli.GetClient().GetReadHandle().ZCount(t.ctx, redisKey+flag, "-inf", "+inf").Uint64()
	if err != nil {
		t.logRedisError(ipAddress, err)

		return
	}

	stats.GetMetrics().GetRedisWriteCounter().Inc()
	if err = rediscli.GetClient().GetWriteHandle().Expire(t.ctx, redisKey+flag, tolerateTTL).Err(); err != nil {
		t.logRedisError(ipAddress, err)

		return
	}

	stats.GetMetrics().GetRedisWriteCounter().Inc()
	if err = rediscli.GetClient().GetWriteHandle().HSet(t.ctx, t.getRedisKey(ipAddress), label, strconv.FormatUint(positive, 10)).Err(); err != nil {
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
		positive int64
		negative int64
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

	pctTolerated := t.pctTolerated
	for _, customToleration := range t.customTolerates {
		if !t.findIP(customToleration.IPAddress, ipAddress) {
			continue
		}

		pctTolerated = customToleration.ToleratePercent

		break
	}

	maxNegative := (int64(pctTolerated) * positive) / 100

	t.logDbgTolerate(
		ipAddress,
		positive,
		negative,
		maxNegative,
		t.pctTolerated,
	)

	return negative <= maxNegative
}

// StartHouseKeeping initiates a periodic cleanup process to remove expired tolerance data for IP addresses from Redis.
func (t *tolerateImpl) StartHouseKeeping() {
	var err error

	ticker := time.NewTicker(time.Second * 60)

	defer ticker.Stop()

	for range ticker.C {
		now := time.Now().Unix()
		removed := int64(0)

		for _, ipAddress := range getHouseKeeper(t.ctx).getIPsToClean() {
			redisKey := t.getRedisKey(ipAddress)
			tolerateTTL := config.GetFile().GetBruteForce().GetTolerateTTL()

			for _, customTolerate := range t.customTolerates {
				if !t.findIP(customTolerate.IPAddress, ipAddress) {
					continue
				}

				tolerateTTL = customTolerate.TolerateTTL

				break
			}

			for _, flag := range []string{":P", ":N"} {
				keysExists := rediscli.GetClient().GetReadHandle().Exists(t.ctx, redisKey+flag).Val()
				if keysExists == 0 {
					getHouseKeeper(t.ctx).removeIPAddress(ipAddress)

					continue
				}

				stats.GetMetrics().GetRedisWriteCounter().Inc()
				removed, err = rediscli.GetClient().GetWriteHandle().ZRemRangeByScore(
					t.ctx,
					redisKey+flag,
					"-inf",
					strconv.FormatInt(now-int64(tolerateTTL), 10),
				).Result()
				if err != nil {
					t.logRedisError(ipAddress, err)

					break
				}

				if removed > 0 {
					t.logDbgRemovedRecords(removed)
				}
			}
		}
	}
}

var _ Tolerate = (*tolerateImpl)(nil)

// getRedisKey constructs a Redis key using the configured prefix and the given IP address.
func (t *tolerateImpl) getRedisKey(ipAddress string) string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + ":bf:TR:" + ipAddress
}

// getMap retrieves a map of string keys to unsigned integer values from Redis using the specified IP address as a key.
// It fetches all entries from a Redis hash, converts the values to unsigned integers, and handles retrieval/parsing errors.
func (t *tolerateImpl) getMap(ipAddress string) map[string]int64 {
	var (
		counter int64
		err     error
		result  map[string]string
	)

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	ipMap := make(map[string]int64)

	result, err = rediscli.GetClient().GetReadHandle().HGetAll(t.ctx, t.getRedisKey(ipAddress)).Result()

	if err != nil {
		return ipMap
	}

	for k, v := range result {
		counter, err = strconv.ParseInt(v, 10, 64)
		if err != nil {
			continue
		}

		ipMap[k] = counter
	}

	return ipMap
}

// logDbgTolerate logs debug information about tolerance evaluation, including interaction counts and thresholds.
func (t *tolerateImpl) logDbgTolerate(address string, positive int64, negative int64, maxNegatives int64, tolerated uint8) {
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

// findIP checks if the provided IP address or network contains or matches the specified IP address.
func (t *tolerateImpl) findIP(ipOrNet, ipAddress string) bool {
	cmpAddress := net.ParseIP(ipAddress)
	if cmpAddress == nil {
		return false
	}

	address := net.ParseIP(ipOrNet)
	if address != nil {
		if address.Equal(cmpAddress) {
			return true
		}

		return false
	}

	_, network, err := net.ParseCIDR(ipOrNet)
	if err != nil {
		return false
	}

	if network.Contains(cmpAddress) {
		return true
	}

	return false
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
	tolerate = &tolerateImpl{
		ctx:             context.TODO(),
		pctTolerated:    pctTolerated,
		customTolerates: config.GetFile().GetBruteForce().GetCustomTolerations(),
		mu:              sync.Mutex{}}

	return tolerate
}

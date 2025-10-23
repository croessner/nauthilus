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

package tolerate

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/ipscoper"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
)

var (
	tolerate     Tolerate
	initTolerate sync.Once
)

var (
	cleaner     *houseKeeper
	initCleaner sync.Once
)

// Shared IP scoper for tolerations context
var tolScoper = ipscoper.NewIPScoper()

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
	// SetCustomTolerations sets the custom toleration configurations for IP-based authentication tolerances.
	SetCustomTolerations(tolerations []config.Tolerate)

	// SetCustomToleration configures toleration settings for the specified IP address with a percentage and Time-to-Live duration.
	SetCustomToleration(ipAddress string, pctTolerated uint8, tolerateTTL time.Duration)

	// DeleteCustomToleration removes the toleration configuration for the specified IP address from the system.
	DeleteCustomToleration(ipAddress string)

	// GetCustomTolerations retrieves the list of configured IP-based toleration settings, including percentage and TTL.
	GetCustomTolerations() []config.Tolerate

	// StartHouseKeeping initiates a periodic housekeeping routine to clean up expired IP tolerance data in Redis storage.
	StartHouseKeeping(ctx context.Context)

	// SetIPAddress tracks and updates authentication behavior for a given IP address.
	SetIPAddress(ctx context.Context, ipAddress string, username string, authenticated bool)

	// IsTolerated checks if an IP address is within the allowed tolerance based on past interactions.
	IsTolerated(ctx context.Context, ipAddress string) bool

	// GetTolerateMap retrieves a map containing toleration data as key-value pairs for a specific IP address.
	GetTolerateMap(ctx context.Context, ipAddress string) map[string]int64
}

type tolerateImpl struct {
	houseKeeperContext context.Context
	pctTolerated       uint8
	customTolerates    []config.Tolerate
	mu                 sync.Mutex
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

// SetCustomToleration updates toleration settings for a specific IP address with provided percentage and TTL in a thread-safe manner.
func (t *tolerateImpl) SetCustomToleration(ipAddress string, pctTolerated uint8, tolerateTTL time.Duration) {
	if strings.TrimSpace(ipAddress) == "" {
		return
	}

	t.mu.Lock()

	toleration := config.Tolerate{
		IPAddress:       ipAddress,
		ToleratePercent: pctTolerated,
		TolerateTTL:     tolerateTTL,
	}

	newTolerations := make([]config.Tolerate, 0)

	if len(t.customTolerates) == 0 {
		newTolerations = append(newTolerations, toleration)
	}

	for index, currentToleration := range t.customTolerates {
		if currentToleration.IPAddress != toleration.IPAddress {
			newTolerations = append(newTolerations, currentToleration)

			continue
		}

		newTolerations = append(newTolerations, toleration)
		newTolerations = append(newTolerations, t.customTolerates[index+1:]...)

		break
	}

	t.mu.Unlock()

	t.SetCustomTolerations(newTolerations)
}

// DeleteCustomToleration removes a toleration entry for a given IP address from the custom tolerations in a thread-safe manner.
func (t *tolerateImpl) DeleteCustomToleration(ipAddress string) {
	if strings.TrimSpace(ipAddress) == "" {
		return
	}

	t.mu.Lock()

	newTolerations := make([]config.Tolerate, 0)

	for _, currentToleration := range t.customTolerates {
		if currentToleration.IPAddress != ipAddress {
			newTolerations = append(newTolerations, currentToleration)

			continue
		}
	}

	t.mu.Unlock()

	t.SetCustomTolerations(newTolerations)
}

// GetCustomTolerations retrieves the current list of custom toleration configurations in a thread-safe manner.
func (t *tolerateImpl) GetCustomTolerations() []config.Tolerate {
	t.mu.Lock()

	defer t.mu.Unlock()

	return t.customTolerates
}

// SetIPAddress increments the Redis hash counter for the specified IP address based on authentication status.
// It sets a TTL for the hash key to manage the expiration of the tolerance data.
func (t *tolerateImpl) SetIPAddress(ctx context.Context, ipAddress string, username string, authenticated bool) {
	if strings.TrimSpace(ipAddress) == "" {
		return
	}

	// Track scoped identifier in housekeeping to avoid per-/128 duplicates for IPv6
	scoped := tolScoper.Scope(ipscoper.ScopeTolerations, ipAddress)
	t.getHouseKeeper().setIPAddress(scoped)

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

	// Use Lua script to add to sorted set, count elements, and set expirations atomically
	result, err := rediscli.ExecuteScript(
		ctx,
		"ZAddCountAndExpire",
		rediscli.LuaScripts["ZAddCountAndExpire"],
		[]string{redisKey + flag, t.getRedisKey(ipAddress)},
		float64(now),
		strings.ToLower(username),
		label,
		int(tolerateTTL.Seconds()),
	)

	if err != nil {
		t.logRedisError(ipAddress, err)

		return
	}

	// Log the result for debugging if needed
	util.DebugModule(definitions.DbgTolerate,
		definitions.LogKeyMsg, fmt.Sprintf("ZAddCountAndExpire result: %v", result),
		"ip", ipAddress,
		"username", username,
		"authenticated", authenticated,
	)
}

// IsTolerated checks if the specified IP address is tolerated based on positive and negative interaction thresholds.
func (t *tolerateImpl) IsTolerated(ctx context.Context, ipAddress string) bool {
	var (
		okay     bool
		positive int64
		negative int64
	)

	tolerateTTL := config.GetFile().GetBruteForce().GetTolerateTTL()
	pctTolerated := t.pctTolerated
	adaptiveToleration := config.GetFile().GetBruteForce().GetAdaptiveToleration()
	minToleratePercent := config.GetFile().GetBruteForce().GetMinToleratePercent()
	maxToleratePercent := config.GetFile().GetBruteForce().GetMaxToleratePercent()
	scaleFactor := config.GetFile().GetBruteForce().GetScaleFactor()

	// Check for custom tolerations for this IP
	for _, customTolerate := range t.customTolerates {
		if !t.findIP(customTolerate.IPAddress, ipAddress) {
			continue
		}

		tolerateTTL = customTolerate.TolerateTTL
		pctTolerated = customTolerate.ToleratePercent

		// If custom toleration has adaptive settings, use them
		if customTolerate.AdaptiveToleration {
			adaptiveToleration = true

			if customTolerate.MinToleratePercent > 0 {
				minToleratePercent = customTolerate.MinToleratePercent
			}

			if customTolerate.MaxToleratePercent > 0 {
				maxToleratePercent = customTolerate.MaxToleratePercent
			}

			if customTolerate.ScaleFactor > 0 {
				scaleFactor = customTolerate.ScaleFactor
			}
		} else {
			// If custom toleration explicitly disables adaptive, respect that
			adaptiveToleration = false
		}

		break
	}

	if tolerateTTL == 0 {
		return false
	}

	redisKey := t.getRedisKey(ipAddress)

	// If adaptive toleration is enabled, use the Lua script to calculate
	if adaptiveToleration {
		adaptiveEnabled := 1

		// Execute the adaptive toleration calculation script
		stats.GetMetrics().GetRedisReadCounter().Inc()
		result, err := rediscli.ExecuteScript(
			ctx,
			"CalculateAdaptiveToleration",
			rediscli.LuaScripts["CalculateAdaptiveToleration"],
			[]string{redisKey},
			minToleratePercent,
			maxToleratePercent,
			scaleFactor,
			pctTolerated,
			adaptiveEnabled,
		)

		if err != nil {
			t.logRedisError(ipAddress, err)
			// Fall back to standard calculation if script fails
		} else {
			if arr, ok := result.([]any); ok {
				resultArray := make([]int64, len(arr))

				for i, v := range arr {
					if n, ok := v.(int64); ok {
						resultArray[i] = n
					} else {
						resultArray[i] = 0
					}
				}

				if len(resultArray) == 5 {
					calculatedPct := resultArray[0]
					maxNegative := resultArray[1]
					positive = resultArray[2]
					negative = resultArray[3]
					adaptiveUsed := resultArray[4]

					adaptiveStr := "static"
					if adaptiveUsed == 1 {
						adaptiveStr = "adaptive"
					}

					// If there are no positives, do not tolerate
					if positive == 0 {
						t.logDbgTolerate(ipAddress, positive, negative, 0, uint8(calculatedPct), adaptiveStr)

						return false
					}

					t.logDbgTolerate(
						ipAddress,
						positive,
						negative,
						maxNegative,
						uint8(calculatedPct),
						adaptiveStr,
					)

					return negative <= maxNegative
				}
			}
		}
	}

	// Fall back to standard calculation if adaptive is disabled or script failed
	ipMap := t.GetTolerateMap(ctx, ipAddress)

	if positive, okay = ipMap["positive"]; !okay {
		positive = 0
	}

	if positive == 0 {
		return false
	}

	if negative, okay = ipMap["negative"]; !okay {
		negative = 0
	}

	maxNegative := (int64(pctTolerated) * positive) / 100

	t.logDbgTolerate(
		ipAddress,
		positive,
		negative,
		maxNegative,
		pctTolerated,
		"static",
	)

	return negative <= maxNegative
}

// StartHouseKeeping initiates a periodic cleanup process to remove expired tolerance data for IP addresses from Redis.
func (t *tolerateImpl) StartHouseKeeping(ctx context.Context) {
	t.houseKeeperContext = ctx

	var err error

	ticker := time.NewTicker(time.Second * 60)

	defer ticker.Stop()

	for range ticker.C {
		now := time.Now().Unix()
		removed := int64(0)

		for _, ipAddress := range t.getHouseKeeper().getIPsToClean() {
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
				keysExists := rediscli.GetClient().GetReadHandle().Exists(t.houseKeeperContext, redisKey+flag).Val()
				if keysExists == 0 {
					t.getHouseKeeper().removeIPAddress(ipAddress)

					continue
				}

				stats.GetMetrics().GetRedisWriteCounter().Inc()
				removed, err = rediscli.GetClient().GetWriteHandle().ZRemRangeByScore(
					t.houseKeeperContext,
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

// GetTolerateMap retrieves a map of toleration data from Redis for the specified IP address.
func (t *tolerateImpl) GetTolerateMap(ctx context.Context, ipAddress string) map[string]int64 {
	var (
		counter int64
		err     error
		result  map[string]string
	)

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	ipMap := make(map[string]int64)

	result, err = rediscli.GetClient().GetReadHandle().HGetAll(ctx, t.getRedisKey(ipAddress)).Result()
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

var _ Tolerate = (*tolerateImpl)(nil)

// getHouseKeeper initializes and returns a singleton instance of houseKeeper in a thread-safe manner.
func (t *tolerateImpl) getHouseKeeper() *houseKeeper {
	initCleaner.Do(func() {
		cleaner = newHouseKeeper(t.houseKeeperContext)
	})

	return cleaner
}

// getRedisKey constructs a Redis key using the configured prefix and the given IP address.
func (t *tolerateImpl) getRedisKey(ipAddress string) string {
	// Apply tolerations scoping (e.g., IPv6 /CIDR) so all components use consistent keys
	scoped := tolScoper.Scope(ipscoper.ScopeTolerations, ipAddress)
	return config.GetFile().GetServer().GetRedis().GetPrefix() + "bf:TR:" + scoped
}

// logDbgTolerate logs debug information about tolerance evaluation, including interaction counts and thresholds.
func (t *tolerateImpl) logDbgTolerate(address string, positive int64, negative int64, maxNegatives int64, tolerated uint8, mode string) {
	util.DebugModule(
		definitions.DbgTolerate,
		definitions.LogKeyClientIP, address,
		"positives", positive,
		"negatives", negative,
		"max_negatives", maxNegatives,
		"tolerated", tolerated,
		"mode", mode,
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
		tolerate = newTolerate(config.GetFile().GetBruteForce().GetToleratePercent())
	})

	return tolerate
}

// newTolerate creates a new Tolerate implementation with a specified percentage tolerance for negative actions.
func newTolerate(pctTolerated uint8) Tolerate {
	tolerate = &tolerateImpl{
		pctTolerated:    pctTolerated,
		customTolerates: config.GetFile().GetBruteForce().GetCustomTolerations(),
		mu:              sync.Mutex{},
	}

	return tolerate
}

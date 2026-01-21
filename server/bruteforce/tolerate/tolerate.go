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
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/bruteforce/l1"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/ipscoper"
	"github.com/croessner/nauthilus/server/log/level"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/svcctx"
	"github.com/croessner/nauthilus/server/util"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/singleflight"
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
func newHouseKeeper(ctx context.Context, cfg config.File) *houseKeeper {
	maxConcurrentRequests := cfg.GetServer().GetMaxConcurrentRequests()
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

	// GetReputationKey returns the Redis key used for reputation data for the given IP address.
	GetReputationKey(ipAddress string) string
}

type tolerateDeps struct {
	cfg    config.File
	logger *slog.Logger
	redis  rediscli.Client
}

type tolerateImpl struct {
	houseKeeperContext context.Context
	pctTolerated       uint8
	customTolerates    []config.Tolerate
	mu                 sync.Mutex
	// sg dedupliziert parallele identische Redis-Script-Aufrufe pro IP (logikgleich, weniger RTT)
	sg singleflight.Group

	deps tolerateDeps
}

func (t *tolerateImpl) effectiveCfg() config.File {
	return t.deps.cfg
}

func (t *tolerateImpl) effectiveLogger() *slog.Logger {
	return t.deps.logger
}

func (t *tolerateImpl) effectiveRedis() rediscli.Client {
	return t.deps.redis
}

func (t *tolerateImpl) SetCustomTolerations(tolerations []config.Tolerate) {
	// Trace configuration update (service-scoped)
	tr := monittrace.New("nauthilus/tolerate")
	ctx, sp := tr.Start(svcctx.Get(), "tolerate.set_custom",
		attribute.Int("count", func() int {
			if tolerations == nil {
				return 0
			}

			return len(tolerations)
		}()),
	)

	_ = ctx

	defer sp.End()

	if tolerations == nil {
		return
	}

	t.mu.Lock()

	defer t.mu.Unlock()

	t.customTolerates = tolerations
}

func (t *tolerateImpl) SetCustomToleration(ipAddress string, pctTolerated uint8, tolerateTTL time.Duration) {
	tr := monittrace.New("nauthilus/tolerate")
	ctx, sp := tr.Start(svcctx.Get(), "tolerate.set_one",
		attribute.String("ip_address", ipAddress),
		attribute.Int("tolerated_pct", int(pctTolerated)),
		attribute.String("ttl", tolerateTTL.String()),
	)

	_ = ctx

	defer sp.End()

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

func (t *tolerateImpl) DeleteCustomToleration(ipAddress string) {
	tr := monittrace.New("nauthilus/tolerate")
	ctx, sp := tr.Start(svcctx.Get(), "tolerate.delete",
		attribute.String("ip_address", ipAddress),
	)

	_ = ctx

	defer sp.End()

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

func (t *tolerateImpl) GetCustomTolerations() []config.Tolerate {
	t.mu.Lock()

	defer t.mu.Unlock()

	return t.customTolerates
}

func (t *tolerateImpl) SetIPAddress(ctx context.Context, ipAddress string, username string, authenticated bool) {
	tr := monittrace.New("nauthilus/tolerate")
	sctx, sp := tr.Start(ctx, "tolerate.set_ip",
		attribute.String("ip_address", ipAddress),
		attribute.String("username", username),
		attribute.Bool("authenticated", authenticated),
	)

	defer sp.End()

	if strings.TrimSpace(ipAddress) == "" {
		return
	}

	// Track scoped identifier in housekeeping to avoid per-/128 duplicates for IPv6
	scoped := tolScoper.WithCfg(t.deps.cfg).Scope(ipscoper.ScopeTolerations, ipAddress)
	t.getHouseKeeper().setIPAddress(scoped)

	tolerateTTL := t.deps.cfg.GetBruteForce().GetTolerateTTL()

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
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(sctx, t.deps.cfg)

	result, err := rediscli.ExecuteScript(
		dCtx,
		t.effectiveRedis(),
		"ZAddCountAndExpire",
		rediscli.LuaScripts["ZAddCountAndExpire"],
		[]string{redisKey + flag, t.getRedisKey(ipAddress)},
		float64(now),
		strings.ToLower(username),
		label,
		int(tolerateTTL.Seconds()),
	)

	cancel()

	if err != nil {
		t.logRedisError(t.deps.logger, ipAddress, err)

		return
	}

	// Log the result for debugging if needed
	util.DebugModuleWithCfg(sctx, t.deps.cfg, t.deps.logger, definitions.DbgTolerate,
		definitions.LogKeyMsg, fmt.Sprintf("ZAddCountAndExpire result: %v", result),
		"ip", ipAddress,
		"username", username,
	)
}

// IsTolerated checks if the specified IP address is tolerated based on positive and negative interaction thresholds.
func (t *tolerateImpl) IsTolerated(ctx context.Context, ipAddress string) bool {
	tr := monittrace.New("nauthilus/tolerate")
	tctx, tsp := tr.Start(ctx, "tolerate.is_tolerated",
		attribute.String("ip_address", ipAddress),
	)
	defer tsp.End()

	var (
		okay     bool
		positive int64
		negative int64
	)

	tolerateTTL := t.deps.cfg.GetBruteForce().GetTolerateTTL()
	pctTolerated := t.pctTolerated
	adaptiveToleration := t.deps.cfg.GetBruteForce().GetAdaptiveToleration()
	minToleratePercent := t.deps.cfg.GetBruteForce().GetMinToleratePercent()
	maxToleratePercent := t.deps.cfg.GetBruteForce().GetMaxToleratePercent()
	scaleFactor := t.deps.cfg.GetBruteForce().GetScaleFactor()

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

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, t.deps.cfg)
		resultAny, err, _ := t.sg.Do("tol:"+redisKey, func() (any, error) {
			defer cancel()

			return rediscli.ExecuteScript(
				dCtx,
				t.effectiveRedis(),
				"CalculateAdaptiveToleration",
				rediscli.LuaScripts["CalculateAdaptiveToleration"],
				[]string{redisKey},
				minToleratePercent,
				maxToleratePercent,
				scaleFactor,
				pctTolerated,
				adaptiveEnabled,
			)
		})

		result := resultAny

		if err != nil {
			t.logRedisError(t.deps.logger, ipAddress, err)
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
						t.logDbgTolerate(ctx, ipAddress, positive, negative, 0, uint8(calculatedPct), adaptiveStr)

						return false
					}

					// Store in L1 cache
					l1.GetEngine().SetReputation(ctx, l1.KeyReputation(ipAddress), l1.L1Reputation{
						Positive: positive,
						Negative: negative,
					}, 0)

					t.logDbgTolerate(
						ctx,
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
	ipMap := t.GetTolerateMap(tctx, ipAddress)

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
		ctx,
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
	tr := monittrace.New("nauthilus/tolerate")
	_, hsp := tr.Start(ctx, "tolerate.housekeeping")

	defer hsp.End()

	t.houseKeeperContext = ctx

	var err error

	ticker := time.NewTicker(time.Second * 60)

	defer ticker.Stop()

	for range ticker.C {
		now := time.Now().Unix()
		removed := int64(0)

		for _, ipAddress := range t.getHouseKeeper().getIPsToClean() {
			redisKey := t.getRedisKey(ipAddress)
			tolerateTTL := t.deps.cfg.GetBruteForce().GetTolerateTTL()

			for _, customTolerate := range t.customTolerates {
				if !t.findIP(customTolerate.IPAddress, ipAddress) {
					continue
				}

				tolerateTTL = customTolerate.TolerateTTL

				break
			}

			for _, flag := range []string{":P", ":N"} {
				// Check if key exists with a read-deadline context
				stats.GetMetrics().GetRedisReadCounter().Inc()

				dCtxRead, cancelRead := util.GetCtxWithDeadlineRedisRead(t.houseKeeperContext, t.deps.cfg)
				keysExists := t.deps.redis.GetReadHandle().Exists(dCtxRead, redisKey+flag).Val()
				cancelRead()

				if keysExists == 0 {
					t.getHouseKeeper().removeIPAddress(ipAddress)

					continue
				}

				// Remove old entries with a write-deadline context
				stats.GetMetrics().GetRedisWriteCounter().Inc()

				dCtxWrite, cancelWrite := util.GetCtxWithDeadlineRedisWrite(t.houseKeeperContext, t.deps.cfg)
				removed, err = t.deps.redis.GetWriteHandle().ZRemRangeByScore(
					dCtxWrite,
					redisKey+flag,
					"-inf",
					strconv.FormatInt(now-int64(tolerateTTL.Seconds()), 10),
				).Result()
				cancelWrite()

				if err != nil {
					t.logRedisError(t.deps.logger, ipAddress, err)

					break
				}

				if removed > 0 {
					t.logDbgRemovedRecords(t.houseKeeperContext, removed)
				}
			}
		}
	}
}

// GetTolerateMap retrieves a map of toleration data from Redis for the specified IP address.
func (t *tolerateImpl) GetTolerateMap(ctx context.Context, ipAddress string) map[string]int64 {
	tr := monittrace.New("nauthilus/tolerate")
	gctx, gsp := tr.Start(ctx, "tolerate.get_map",
		attribute.String("ip_address", ipAddress),
	)

	defer gsp.End()

	var (
		counter int64
		err     error
		result  map[string]string
	)

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	ipMap := make(map[string]int64)

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(gctx, t.deps.cfg)

	result, err = t.deps.redis.GetReadHandle().HGetAll(dCtx, t.getRedisKey(ipAddress)).Result()

	cancel()

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

func (t *tolerateImpl) GetReputationKey(ipAddress string) string {
	return t.getRedisKey(ipAddress)
}

var _ Tolerate = (*tolerateImpl)(nil)

// getHouseKeeper initializes and returns a singleton instance of houseKeeper in a thread-safe manner.
func (t *tolerateImpl) getHouseKeeper() *houseKeeper {
	initCleaner.Do(func() {
		cleaner = newHouseKeeper(t.houseKeeperContext, t.deps.cfg)
	})

	return cleaner
}

// getRedisKey constructs a Redis key using the configured prefix and the given IP address.
func (t *tolerateImpl) getRedisKey(ipAddress string) string {
	cfg := t.deps.cfg
	scoped := tolScoper.WithCfg(cfg).Scope(ipscoper.ScopeTolerations, ipAddress)

	return cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisBFTolerationPrefix + "{" + scoped + "}"
}

// logDbgTolerate logs debug information about tolerance evaluation, including interaction counts and thresholds.
func (t *tolerateImpl) logDbgTolerate(ctx context.Context, address string, positive int64, negative int64, maxNegatives int64, tolerated uint8, mode string) {
	util.DebugModuleWithCfg(ctx, t.deps.cfg, t.deps.logger,
		definitions.DbgTolerate,
		definitions.LogKeyClientIP, address,
		"positives", positive,
		"negatives", negative,
		"max_negatives", maxNegatives,
		"tolerated", tolerated,
		"mode", mode,
	)
}

func (t *tolerateImpl) logDbgRemovedRecords(ctx context.Context, removed int64) {
	util.DebugModuleWithCfg(ctx, t.deps.cfg, t.deps.logger,
		definitions.DbgTolerate,
		"removed", removed,
	)
}

// logRedisError logs a Redis error and the associated client IP address as a warning-level log entry.
func (t *tolerateImpl) logRedisError(logger *slog.Logger, ipAddress string, err error) {
	level.Warn(logger).Log(
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

func NewTolerateWithDeps(cfg config.File, logger *slog.Logger, redis rediscli.Client, pctTolerated uint8) Tolerate {
	t := &tolerateImpl{
		pctTolerated:    pctTolerated,
		customTolerates: cfg.GetBruteForce().GetCustomTolerations(),
		mu:              sync.Mutex{},
		deps: tolerateDeps{
			cfg:    cfg,
			logger: logger,
			redis:  redis,
		},
	}

	return t
}

func SetTolerate(t Tolerate) {
	tolerate = t
}

func GetTolerate() Tolerate {
	return tolerate
}

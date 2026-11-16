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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/ipscoper"
	"github.com/croessner/nauthilus/v4/server/log/level"
	monittrace "github.com/croessner/nauthilus/v4/server/monitoring/trace"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/stats"
	"github.com/croessner/nauthilus/v4/server/svcctx"
	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/singleflight"
)

var tolerate Tolerate

const (
	tolerateAdaptiveMode = "adaptive"
	tolerateDisabledMode = "disabled"
	tolerateNegativeFlag = ":N"
	toleratePositiveFlag = ":P"
	tolerateStaticMode   = "static"

	// tolerationNegativeCap bounds the retained failed-attempt events per scoped address. A count at the cap is
	// saturated and never tolerated, so the bound cannot turn into an unlimited allowance for large proxies.
	tolerationNegativeCap = 10000

	tolerationEventPositive = PositiveField
	tolerationEventNegative = NegativeField
)

const (
	// PositiveField names the windowed count of distinct accounts with a verified success. It also scales the
	// brute-force bucket limits.
	PositiveField = "positive"

	// NegativeField names the windowed count of counted failed attempts.
	NegativeField = "negative"
)

// RedisKey returns the toleration key base of an already scoped identifier. The braces keep both sorted sets in one
// Redis Cluster slot.
func RedisKey(prefix string, scoped string) string {
	return prefix + definitions.RedisBFTolerationPrefix + "{" + scoped + "}"
}

// RedisKeys returns the positive and negative sorted-set keys of an already scoped identifier.
func RedisKeys(prefix string, scoped string) []string {
	key := RedisKey(prefix, scoped)

	return []string{key + toleratePositiveFlag, key + tolerateNegativeFlag}
}

// WindowQuery names one windowed toleration count: the sorted set and the exclusive lower score bound for ZCOUNT.
type WindowQuery struct {
	Key string
	Min string
}

// Valid reports whether the query names a counter; tolerations disabled for an address yield an invalid query.
func (q WindowQuery) Valid() bool {
	return q.Key != ""
}

// windowCounts holds the windowed toleration counters of one address.
type windowCounts struct {
	positive int64
	negative int64
}

// Shared IP scoper for tolerations context
var tolScoper = ipscoper.NewIPScoper()

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

	// SetIPAddress records one verified authentication outcome for a given IP address.
	SetIPAddress(ctx context.Context, ipAddress string, username string, authenticated bool)

	// IsTolerated checks if an IP address is within the allowed tolerance based on past interactions.
	IsTolerated(ctx context.Context, ipAddress string) bool

	// PolicyFact returns the policy-visible toleration state for the IP address.
	PolicyFact(ctx context.Context, ipAddress string) PolicyFact

	// GetTolerateMap returns the windowed positive and negative counters of an IP address.
	GetTolerateMap(ctx context.Context, ipAddress string) map[string]int64

	// PositiveWindow returns the ZCOUNT query of distinct successful accounts that scales the bucket limits.
	PositiveWindow(ipAddress string) WindowQuery
}

// PolicyFact is the request-local policy view of one toleration calculation.
type PolicyFact struct {
	TTL             time.Duration
	Mode            string
	Positive        int64
	Negative        int64
	MaxNegative     int64
	Percent         uint8
	Active          bool
	Custom          bool
	SuppressedBlock bool
}

type policySettings struct {
	ttl        time.Duration
	scale      float64
	percent    uint8
	minPercent uint8
	maxPercent uint8
	adaptive   bool
	custom     bool
}

type tolerateDeps struct {
	cfg    config.File
	logger *slog.Logger
	redis  rediscli.Client
	clock  func() time.Time
}

type tolerateImpl struct {
	customTolerates []config.Tolerate
	pctTolerated    uint8
	mu              sync.Mutex
	// sg deduplicates concurrent identical counter reads per address.
	sg singleflight.Group

	deps tolerateDeps
}

func (t *tolerateImpl) effectiveRedis() rediscli.Client {
	return t.deps.redis
}

// now returns the event and window clock; tests inject one that follows a simulated Redis clock.
func (t *tolerateImpl) now() time.Time {
	if t.deps.clock != nil {
		return t.deps.clock()
	}

	return time.Now()
}

// SetCustomTolerations replaces the list with a manager-owned copy.
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

	t.customTolerates = slices.Clone(tolerations)
}

// SetCustomToleration atomically inserts or replaces one address-specific tolerance.
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

	defer t.mu.Unlock()

	for index := range t.customTolerates {
		if t.customTolerates[index].IPAddress == ipAddress {
			t.customTolerates[index] = toleration
			return
		}
	}

	t.customTolerates = append(t.customTolerates, toleration)
}

// DeleteCustomToleration removes one address without racing concurrent updates.
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

	t.customTolerates = newTolerations
	t.mu.Unlock()
}

// GetCustomTolerations returns an independent snapshot safe to read after releasing the lock.
func (t *tolerateImpl) GetCustomTolerations() []config.Tolerate {
	t.mu.Lock()

	defer t.mu.Unlock()

	return slices.Clone(t.customTolerates)
}

// SetIPAddress records one verified authentication outcome in the windowed toleration sets of the address.
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

	tolerateTTL := t.tolerateTTLForIP(ipAddress)
	if tolerateTTL == 0 {
		return
	}

	event, member := tolerationEvent(username, authenticated)

	result, err := t.recordTolerationEvent(sctx, ipAddress, event, member, tolerateTTL)
	if err != nil {
		t.logRedisError(t.deps.logger, ipAddress, err)

		return
	}

	// Log the result for debugging if needed
	util.DebugModuleWithCfg(sctx, t.deps.cfg, t.deps.logger, definitions.DbgTolerate,
		definitions.LogKeyMsg, fmt.Sprintf("RecordTolerationEvent result: %v", result),
		"ip", ipAddress,
		"username", username,
	)
}

// tolerationEvent maps one credential outcome onto its event kind and sorted-set member. A success is keyed by the
// account, so repeated logins of one account count once and cannot inflate the allowance. A failure gets a unique
// member, so every failed attempt counts regardless of the attacked account.
func tolerationEvent(username string, authenticated bool) (string, string) {
	if authenticated {
		return tolerationEventPositive, strings.ToLower(username)
	}

	return tolerationEventNegative, uniqueTolerationMember()
}

// uniqueTolerationMember returns a sorted-set member that no other failed attempt shares.
func uniqueTolerationMember() string {
	var random [8]byte

	_, _ = rand.Read(random[:])

	return strconv.FormatInt(time.Now().UnixNano(), 36) + ":" + hex.EncodeToString(random[:])
}

// tolerateTTLForIP resolves the configured toleration TTL for an IP address.
func (t *tolerateImpl) tolerateTTLForIP(ipAddress string) time.Duration {
	tolerateTTL := t.deps.cfg.GetBruteForce().GetTolerateTTL()

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, customTolerate := range t.customTolerates {
		if !t.findIP(customTolerate.IPAddress, ipAddress) {
			continue
		}

		return customTolerate.TolerateTTL
	}

	return tolerateTTL
}

// recordTolerationEvent adds one event and purges both windowed sorted sets of one address via Lua.
func (t *tolerateImpl) recordTolerationEvent(
	ctx context.Context,
	ipAddress string,
	event string,
	member string,
	tolerateTTL time.Duration,
) (any, error) {
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, t.deps.cfg)
	defer cancel()

	return rediscli.ExecuteScript(
		dCtx,
		t.effectiveRedis(),
		"RecordTolerationEvent",
		rediscli.LuaScripts["RecordTolerationEvent"],
		RedisKeys(t.deps.cfg.GetServer().GetRedis().GetPrefix(), t.scopedAddress(ipAddress)),
		t.now().Unix(),
		windowSeconds(tolerateTTL),
		event,
		member,
		tolerationNegativeCap,
	)
}

// tolerationActive reports whether the windowed counters allow suppressing a block. A saturated negative count is
// never tolerated, because the cap hides how many failures really happened.
func tolerationActive(positive int64, negative int64, maxNegative int64) bool {
	return positive > 0 && negative < tolerationNegativeCap && negative <= maxNegative
}

// IsTolerated checks if the specified IP address is tolerated based on positive and negative interaction thresholds.
func (t *tolerateImpl) IsTolerated(ctx context.Context, ipAddress string) bool {
	return t.PolicyFact(ctx, ipAddress).Active
}

// PolicyFact returns the policy-visible toleration state for the specified IP address.
func (t *tolerateImpl) PolicyFact(ctx context.Context, ipAddress string) (fact PolicyFact) {
	tr := monittrace.New("nauthilus/tolerate")

	tctx, tsp := tr.Start(ctx, "tolerate.is_tolerated",
		attribute.String("ip_address", ipAddress),
	)
	defer tsp.End()

	// Registered after tsp.End so it runs first and can still decorate the span.
	defer func() {
		stats.GetMetrics().GetTolerationDecisionsTotal().WithLabelValues(fact.Mode).Inc()

		// A disabled toleration carries a configured percentage that was never
		// applied; observing it would skew the distribution.
		if fact.Mode != tolerateDisabledMode {
			stats.GetMetrics().GetTolerationPercent().Observe(float64(fact.Percent))
		}

		tsp.SetAttributes(
			attribute.String("toleration.mode", fact.Mode),
			attribute.Bool("toleration.active", fact.Active),
			attribute.Bool("toleration.custom", fact.Custom),
			attribute.Int64("toleration.percent", int64(fact.Percent)),
			attribute.Int64("toleration.positive", fact.Positive),
			attribute.Int64("toleration.negative", fact.Negative),
		)
	}()

	settings := t.policySettingsForIP(ipAddress)
	fact = PolicyFact{
		TTL:     settings.ttl,
		Mode:    tolerateDisabledMode,
		Percent: settings.percent,
		Custom:  settings.custom,
	}

	if settings.ttl == 0 {
		return fact
	}

	counts, err := t.sharedWindowCounts(tctx, ipAddress, settings.ttl)
	if err != nil {
		t.logRedisError(t.deps.logger, ipAddress, err)

		fact.Mode = tolerateStaticMode

		return fact
	}

	fact = policyFactFromCounts(settings, counts)
	t.logDbgTolerate(tctx, ipAddress, fact.Positive, fact.Negative, fact.MaxNegative, fact.Percent, fact.Mode)

	return fact
}

// policySettingsForIP resolves the global or matching custom toleration settings of an address.
func (t *tolerateImpl) policySettingsForIP(ipAddress string) policySettings {
	bruteForce := t.deps.cfg.GetBruteForce()
	settings := policySettings{
		ttl:        bruteForce.GetTolerateTTL(),
		scale:      bruteForce.GetScaleFactor(),
		percent:    t.pctTolerated,
		minPercent: bruteForce.GetMinToleratePercent(),
		maxPercent: bruteForce.GetMaxToleratePercent(),
		adaptive:   bruteForce.GetAdaptiveToleration(),
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, customTolerate := range t.customTolerates {
		if !t.findIP(customTolerate.IPAddress, ipAddress) {
			continue
		}

		settings.ttl = customTolerate.TolerateTTL
		settings.percent = customTolerate.ToleratePercent
		settings.custom = true
		settings.adaptive = customTolerate.AdaptiveToleration

		if customTolerate.AdaptiveToleration {
			settings.minPercent = customTolerate.GetMinToleratePercent()
			settings.maxPercent = customTolerate.GetMaxToleratePercent()
			settings.scale = customTolerate.GetScaleFactor()
		}

		break
	}

	return settings
}

// policyFactFromCounts applies the static or adaptive percentage to the windowed counters. Adaptive scaling needs at
// least one successful account; without one the static percentage is reported.
func policyFactFromCounts(settings policySettings, counts windowCounts) PolicyFact {
	percent := settings.percent
	mode := tolerateStaticMode

	if settings.adaptive && counts.positive > 0 {
		percent = adaptivePercent(counts.positive, settings)
		mode = tolerateAdaptiveMode
	}

	maxNegative := (int64(percent) * counts.positive) / 100

	return PolicyFact{
		TTL:         settings.ttl,
		Mode:        mode,
		Positive:    counts.positive,
		Negative:    counts.negative,
		MaxNegative: maxNegative,
		Percent:     percent,
		Active:      tolerationActive(counts.positive, counts.negative, maxNegative),
		Custom:      settings.custom,
	}
}

// adaptivePercent scales the toleration percentage logarithmically between the configured bounds. It mirrors the
// bucket-limit scaling in the SlidingWindowCounter script, so both decisions use the same percentage.
func adaptivePercent(positive int64, settings policySettings) uint8 {
	minPercent := float64(settings.minPercent)
	maxPercent := float64(settings.maxPercent)
	factor := math.Min(1, math.Log(float64(positive+1))/math.Log(100)*settings.scale)
	percent := math.Floor(minPercent + (maxPercent-minPercent)*factor)

	return uint8(math.Max(minPercent, math.Min(maxPercent, percent)))
}

// GetTolerateMap returns the windowed positive and negative counters of an address. It is empty when tolerations are
// disabled for the address or the counters cannot be read.
func (t *tolerateImpl) GetTolerateMap(ctx context.Context, ipAddress string) map[string]int64 {
	tr := monittrace.New("nauthilus/tolerate")
	gctx, gsp := tr.Start(ctx, "tolerate.get_map",
		attribute.String("ip_address", ipAddress),
	)

	defer gsp.End()

	ipMap := make(map[string]int64)

	tolerateTTL := t.tolerateTTLForIP(ipAddress)
	if tolerateTTL == 0 {
		return ipMap
	}

	counts, err := t.sharedWindowCounts(gctx, ipAddress, tolerateTTL)
	if err != nil {
		t.logRedisError(t.deps.logger, ipAddress, err)

		return ipMap
	}

	ipMap[PositiveField] = counts.positive
	ipMap[NegativeField] = counts.negative

	return ipMap
}

// PositiveWindow returns the ZCOUNT query of distinct successful accounts within the address's toleration window.
func (t *tolerateImpl) PositiveWindow(ipAddress string) WindowQuery {
	tolerateTTL := t.tolerateTTLForIP(ipAddress)
	if tolerateTTL == 0 {
		return WindowQuery{}
	}

	return WindowQuery{Key: t.getRedisKey(ipAddress) + toleratePositiveFlag, Min: t.windowMin(tolerateTTL)}
}

// sharedWindowCounts deduplicates concurrent counter reads of one address.
func (t *tolerateImpl) sharedWindowCounts(ctx context.Context, ipAddress string, tolerateTTL time.Duration) (windowCounts, error) {
	minScore := t.windowMin(tolerateTTL)
	key := t.getRedisKey(ipAddress)

	result, err, _ := t.sg.Do("tol:"+key+":"+minScore, func() (any, error) {
		return t.windowCounts(ctx, key, minScore)
	})
	if err != nil {
		return windowCounts{}, err
	}

	counts, _ := result.(windowCounts)

	return counts, nil
}

// windowCounts counts both sorted sets of one address within the window in a single read pipeline. Counting on read
// keeps every instance exact without background refreshes; expired members are purged by the next write or expire
// with their key.
func (t *tolerateImpl) windowCounts(ctx context.Context, key string, minScore string) (windowCounts, error) {
	stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, t.deps.cfg)
	defer cancel()

	var positive, negative *redis.IntCmd

	_, err := t.deps.redis.GetReadHandle().Pipelined(dCtx, func(pipe redis.Pipeliner) error {
		positive = pipe.ZCount(dCtx, key+toleratePositiveFlag, minScore, "+inf")
		negative = pipe.ZCount(dCtx, key+tolerateNegativeFlag, minScore, "+inf")

		return nil
	})
	if err != nil {
		return windowCounts{}, err
	}

	return windowCounts{positive: positive.Val(), negative: negative.Val()}, nil
}

// windowMin returns the exclusive ZCOUNT lower bound of the window; it matches the purge cutoff of the write script.
func (t *tolerateImpl) windowMin(tolerateTTL time.Duration) string {
	return "(" + strconv.FormatInt(t.now().Unix()-windowSeconds(tolerateTTL), 10)
}

// windowSeconds converts a toleration TTL into whole window seconds, at least one.
func windowSeconds(tolerateTTL time.Duration) int64 {
	return max(int64(1), int64(tolerateTTL.Seconds()))
}

var _ Tolerate = (*tolerateImpl)(nil)

// getRedisKey constructs a Redis key using the configured prefix and the given IP address.
func (t *tolerateImpl) getRedisKey(ipAddress string) string {
	return RedisKey(t.deps.cfg.GetServer().GetRedis().GetPrefix(), t.scopedAddress(ipAddress))
}

// scopedAddress returns the toleration-scoped identifier of a raw client address.
func (t *tolerateImpl) scopedAddress(ipAddress string) string {
	return tolScoper.WithCfg(t.deps.cfg).Scope(ipscoper.ScopeTolerations, ipAddress)
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
		return address.Equal(cmpAddress)
	}

	_, network, err := net.ParseCIDR(ipOrNet)
	if err != nil {
		return false
	}

	return network.Contains(cmpAddress)
}

// NewTolerateWithDeps constructs a manager with its own mutable tolerance snapshot.
func NewTolerateWithDeps(cfg config.File, logger *slog.Logger, redis rediscli.Client, pctTolerated uint8) Tolerate {
	t := &tolerateImpl{
		pctTolerated:    pctTolerated,
		customTolerates: slices.Clone(cfg.GetBruteForce().GetCustomTolerations()),
		mu:              sync.Mutex{},
		deps: tolerateDeps{
			cfg:    cfg,
			logger: logger,
			redis:  redis,
		},
	}

	return t
}

// SetTolerate provides the exported SetTolerate function.
func SetTolerate(t Tolerate) {
	tolerate = t
}

// GetTolerate provides the exported GetTolerate function.
func GetTolerate() Tolerate {
	return tolerate
}

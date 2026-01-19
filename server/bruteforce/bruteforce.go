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

package bruteforce

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	errors2 "errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/ipscoper"
	"github.com/croessner/nauthilus/server/localcache"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/dspinhirne/netaddr-go"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/singleflight"
)

// containsString reports whether s is present in the slice.
// Kept unexported and simple to avoid allocations and stay DRY for common membership checks.
func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}

	return false
}

// PwHistGateScript is a Lua script that atomically updates password history counters.
// It enforces a maximum number of fields in the password-history hash to avoid
// unbounded growth and reduces client/server round-trips to a single EVAL call.
//
// KEYS:
//
//	[1] = password-history hash key (HINCRBY + EXPIRE)
//	[2] = optional total counter key (INCR + EXPIRE) – may be omitted
//
// ARGV:
//
//	[1] = field (password hash)
//	[2] = ttl seconds
//	[3] = max fields allowed in the hash
//
// Returns:
//
//	1 if the operation was performed (under limit), 0 if max fields reached (no-op)
const PwHistGateScript = `
local field = ARGV[1]
local ttl = tonumber(ARGV[2])
local max_fields = tonumber(ARGV[3])

if redis.call('HLEN', KEYS[1]) >= max_fields then
  return 0
end

redis.call('HINCRBY', KEYS[1], field, 1)
redis.call('EXPIRE', KEYS[1], ttl)

if #KEYS > 1 and KEYS[2] and KEYS[2] ~= '' then
  redis.call('INCR', KEYS[2])
  redis.call('EXPIRE', KEYS[2], ttl)
end

return 1
`

// microDecision captures a short-lived decision result for the same semantic request key.
type microDecision struct {
	Block bool
	Rule  string
}

var (
	microCacheOnce sync.Once
	microCache     *localcache.Cache
)

func getMicroCache() *localcache.Cache {
	microCacheOnce.Do(func() {
		// Always-on micro cache with fixed conservative TTL (flagless standard)
		ttl := 300 * time.Millisecond
		microCache = localcache.NewCache(ttl, ttl)
	})

	return microCache
}

// bruteForceBucketCounter represents a cache mechanism to handle brute force attack mitigation using brute force buckets.
type bruteForceBucketCounter uint

// PasswordHistory is a map of hashed passwords with their failure counter.
type PasswordHistory map[string]uint

// BucketManager defines an interface for managing brute force and password history buckets in a system.
type BucketManager interface {
	// GetLoginAttempts returns the number of login attempts monitored by the bucket manager as an unsigned integer.
	GetLoginAttempts() uint

	// GetPasswordsAccountSeen returns the number of accounts for which passwords have been tracked or seen.
	GetPasswordsAccountSeen() uint

	// GetPasswordsTotalSeen retrieves the total number of unique passwords encountered across all accounts.
	GetPasswordsTotalSeen() uint

	// GetFeatureName returns the name "brute_force" if the system triggered.
	GetFeatureName() string

	// GetBruteForceName retrieves the name associated with the specific brute force bucket that triggered.
	GetBruteForceName() string

	// GetBruteForceCounter returns a map containing brute force detection counters associated with specific criteria or keys.
	GetBruteForceCounter() map[string]uint

	// GetBruteForceBucketRedisKey generates and returns the Redis key for tracking the brute force bucket associated with the given rule.
	GetBruteForceBucketRedisKey(rule *config.BruteForceRule) (key string)

	// GetPasswordHistory retrieves the password history as a mapping of hashed passwords with their associated failure counters.
	GetPasswordHistory() *PasswordHistory

	// WithUsername sets the username for the bucket manager, typically for tracking or processing account-specific data.
	WithUsername(username string) BucketManager

	// WithPassword sets the password for the current bucket manager instance.
	WithPassword(password string) BucketManager

	// WithAccountName sets the account name for the BucketManager instance and returns the updated BucketManager.
	WithAccountName(accountName string) BucketManager

	// WithProtocol sets the protocol for the BucketManager instance and returns the updated BucketManager.
	WithProtocol(protocol string) BucketManager

	// WithOIDCCID sets the OIDC Client ID for the BucketManager instance and returns the updated BucketManager.
	WithOIDCCID(oidcCID string) BucketManager

	// LoadAllPasswordHistories retrieves all recorded password history entries for further processing or analysis.
	LoadAllPasswordHistories()

	// CheckRepeatingBruteForcer evaluates if a repeating brute force attack is occurring based on the provided rules and IP network.
	// It returns whether processing should abort, if a rule is already triggered, and the index of the triggered rule.
	CheckRepeatingBruteForcer(rules []config.BruteForceRule, network **net.IPNet, message *string) (withError bool, alreadyTriggered bool, ruleNumber int)

	// CheckBucketOverLimit checks if any brute force rule is violated based on request data, updating the message if necessary.
	// It returns whether an error occurred, if a rule was triggered, and the rule number that was triggered (if any).
	CheckBucketOverLimit(rules []config.BruteForceRule, message *string) (withError bool, ruleTriggered bool, ruleNumber int)

	// ProcessBruteForce processes and evaluates whether a brute force rule should trigger an action based on given parameters.
	// It returns true if the brute force condition for the specified rule is met and properly handled, false otherwise.
	ProcessBruteForce(ruleTriggered, alreadyTriggered bool, rule *config.BruteForceRule, network *net.IPNet, message string, setter func()) bool

	// ProcessPWHist processes the password history for a user and returns the associated account name.
	ProcessPWHist() (accountName string)

	// SaveBruteForceBucketCounterToRedis stores the current brute force bucket counter in Redis for the given rule.
	SaveBruteForceBucketCounterToRedis(rule *config.BruteForceRule)

	// SaveFailedPasswordCounterInRedis updates the Redis counter for failed password attempts for a specific user or session.
	SaveFailedPasswordCounterInRedis()

	// DeleteIPBruteForceRedis removes the Redis key associated with a brute force rule for a specific IP address.
	DeleteIPBruteForceRedis(rule *config.BruteForceRule, ruleName string) (removedKey string, err error)

	// IsIPAddressBlocked checks if an IP address is blocked due to triggering brute force rules and returns related buckets.
	IsIPAddressBlocked() (buckets []string, found bool)

	// PrepareNetcalc precomputes parsed IP, IP family and unique CIDR networks for active rules.
	// It is idempotent and safe to call multiple times.
	PrepareNetcalc(rules []config.BruteForceRule)
}

type bucketManagerImpl struct {
	ctx context.Context

	deps BucketManagerDeps

	bruteForceCounter map[string]uint
	passwordHistory   *PasswordHistory

	guid               string
	username           string
	password           string
	clientIP           string
	accountName        string
	bruteForceName     string
	featureName        string
	protocol           string
	oidcCID            string
	additionalFeatures map[string]any

	// ip scoper used to normalize addresses per feature context (e.g., RWP IPv6 CIDR)
	scoper ipscoper.IPScoper

	// Precalc fields (computed once per request)
	parsedIP net.IP

	netByCIDR map[uint]*net.IPNet // CIDR -> network

	loginAttempts        uint
	passwordsAccountSeen uint
	passwordsTotalSeen   uint

	// request-context flags
	alreadyTriggered bool

	ipIsV4        bool
	ipIsV6        bool
	ipv6Validated bool
}

func (bm *bucketManagerImpl) cfg() config.File {
	return bm.deps.Cfg
}

func (bm *bucketManagerImpl) logger() *slog.Logger {
	return bm.deps.Logger
}

func (bm *bucketManagerImpl) redis() rediscli.Client {
	return bm.deps.Redis
}

func (bm *bucketManagerImpl) tolerate() tolerate.Tolerate {
	return bm.deps.Tolerate
}

// sgBurst entdoppelt parallele identische Burst-Gate-Anfragen (gleicher Burst-Key) ohne Logikänderung.
var sgBurst singleflight.Group

// GetLoginAttempts retrieves the current number of login attempts made for the given bucket manager instance.
func (bm *bucketManagerImpl) GetLoginAttempts() uint {
	return bm.loginAttempts
}

// GetPasswordsAccountSeen returns the number of accounts for which passwords have been seen in the bucket manager.
func (bm *bucketManagerImpl) GetPasswordsAccountSeen() uint {
	return bm.passwordsAccountSeen
}

// GetPasswordsTotalSeen returns the total number of passwords seen by the bucket manager.
func (bm *bucketManagerImpl) GetPasswordsTotalSeen() uint {
	return bm.passwordsTotalSeen
}

// GetFeatureName returns the name of the feature managed by the bucketManagerImpl.
func (bm *bucketManagerImpl) GetFeatureName() string {
	return bm.featureName
}

// GetBruteForceName retrieves the BruteForceName associated with the bucketManagerImpl instance.
func (bm *bucketManagerImpl) GetBruteForceName() string {
	return bm.bruteForceName
}

// GetBruteForceCounter retrieves the brute force counter map, tracking attempts by their respective identifiers.
func (bm *bucketManagerImpl) GetBruteForceCounter() map[string]uint {
	return bm.bruteForceCounter
}

// GetPasswordHistory returns the PasswordHistory, which is a map of hashed passwords and their respective failure counters.
func (bm *bucketManagerImpl) GetPasswordHistory() *PasswordHistory {
	return bm.passwordHistory
}

// GetBruteForceBucketRedisKey generates a Redis key for brute force protection based on the given rule configuration.
func (bm *bucketManagerImpl) GetBruteForceBucketRedisKey(rule *config.BruteForceRule) (key string) {
	// Try to reconstruct filters from PW_HIST metadata if they are missing
	bm.loadPWHistFiltersIfMissing()
	logger := bm.logger()

	network, err := bm.getNetwork(rule)
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to get network for brute force rule",
			definitions.LogKeyError, err,
		)

		return
	}

	return bm.getBruteForceBucketRedisKeyWithNetwork(rule, network)
}

func (bm *bucketManagerImpl) getBruteForceBucketRedisKeyWithNetwork(rule *config.BruteForceRule, network *net.IPNet) (key string) {
	if rule == nil {
		return ""
	}

	if network == nil {
		return ""
	}

	ipProto := ""
	if rule.IPv4 {
		ipProto = "4"
	} else if rule.IPv6 {
		ipProto = "6"
	}

	protocolPart := ""
	if len(rule.GetFilterByProtocol()) > 0 && bm.protocol != "" {
		if containsString(rule.FilterByProtocol, bm.protocol) {
			protocolPart = bm.protocol
		}
	}

	oidcCIDPart := ""
	if len(rule.GetFilterByOIDCCID()) > 0 && bm.oidcCID != "" {
		if containsString(rule.FilterByOIDCCID, bm.oidcCID) {
			oidcCIDPart = bm.oidcCID
		}
	}

	netStr := network.String()

	// Redis Cluster: use a bucket-specific hash-tag so that keys are distributed across the cluster,
	// while still keeping the key name (including the network) stable/readable.
	//
	// NOTE: We intentionally do NOT try to force all bucket-counter keys into one slot. Reads are
	// performed via pipelined GETs to avoid CROSSSLOT issues.
	var hashTag strings.Builder

	hashTag.WriteString(netStr)

	if protocolPart != "" {
		hashTag.WriteString("|p=")
		hashTag.WriteString(protocolPart)
	}

	if oidcCIDPart != "" {
		hashTag.WriteString("|oidc=")
		hashTag.WriteString(oidcCIDPart)
	}

	periodSeconds := int64(math.Round(rule.Period.Seconds()))
	periodPart := strconv.FormatInt(periodSeconds, 10)
	cidrPart := strconv.FormatUint(uint64(rule.CIDR), 10)
	failedPart := strconv.FormatUint(uint64(rule.FailedRequests), 10)

	cfg := bm.cfg()

	var sb strings.Builder

	sb.WriteString(cfg.GetServer().GetRedis().GetPrefix())
	sb.WriteString("bf:{")
	sb.WriteString(hashTag.String())
	sb.WriteString("}:")
	sb.WriteString(periodPart)
	sb.WriteByte(':')
	sb.WriteString(cidrPart)
	sb.WriteByte(':')
	sb.WriteString(failedPart)
	sb.WriteByte(':')
	sb.WriteString(ipProto)
	sb.WriteByte(':')
	sb.WriteString(netStr)

	// Append protocol part with a separator if it exists
	if protocolPart != "" {
		sb.WriteByte(':')
		sb.WriteString(protocolPart)
	}

	// Append OIDC Client ID part with a separator if it exists
	if oidcCIDPart != "" {
		sb.WriteString(":oidc:")
		sb.WriteString(oidcCIDPart)
	}

	key = sb.String()

	logBruteForceRuleRedisKeyDebug(bm, rule, network, key)

	return key
}

// WithUsername sets the username for the bucketManager instance.
func (bm *bucketManagerImpl) WithUsername(username string) BucketManager {
	bm.username = username

	return bm
}

// WithPassword sets the password for the bucketManager instance.
func (bm *bucketManagerImpl) WithPassword(password string) BucketManager {
	bm.password = password

	return bm
}

// WithAccountName sets the account name for the bucket manager and returns the modified BucketManager instance.
func (bm *bucketManagerImpl) WithAccountName(accountName string) BucketManager {
	bm.accountName = accountName

	return bm
}

// WithProtocol sets the protocol for the bucket manager and returns the modified BucketManager instance.
func (bm *bucketManagerImpl) WithProtocol(protocol string) BucketManager {
	bm.protocol = protocol

	return bm
}

// WithOIDCCID sets the OIDC Client ID for the bucket manager and returns the modified BucketManager instance.
func (bm *bucketManagerImpl) WithOIDCCID(oidcCID string) BucketManager {
	bm.oidcCID = oidcCID

	return bm
}

// LoadAllPasswordHistories loads and processes password history data for the current user and overall accounts from Redis.
func (bm *bucketManagerImpl) LoadAllPasswordHistories() {
	if !bm.cfg().HasFeature(definitions.FeatureBruteForce) {
		return
	}

	// 1) Load account-scoped password history first (may be slightly stale)
	if key := bm.getPasswordHistoryRedisHashKey(true); key != "" {
		bm.loadPasswordHistoryFromRedis(key)
	}

	// 2) Read total counters (account-scoped and IP-only) for observability and test expectations
	//    Even if not strictly required for logic, these counters are useful and inexpensive.
	if key := bm.getPasswordHistoryTotalRedisKey(true); key != "" {
		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
		_, _ = bm.redis().GetReadHandle().Get(dCtx, key).Result()
		cancel()
	}

	if key := bm.getPasswordHistoryTotalRedisKey(false); key != "" {
		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
		_, _ = bm.redis().GetReadHandle().Get(dCtx, key).Result()
		cancel()
	}

	// 3) Refresh account-scoped history again to capture the very latest counters
	if key := bm.getPasswordHistoryRedisHashKey(true); key != "" {
		bm.loadPasswordHistoryFromRedis(key)
	}

	// 4) Apply per-account metrics (loginAttempts = current hash count if present)
	if bm.passwordHistory != nil {
		passwordHash := util.GetHash(util.PreparePassword(bm.password))
		if counter, foundPassword := (*bm.passwordHistory)[passwordHash]; foundPassword {
			bm.loginAttempts = counter
		}

		bm.passwordsAccountSeen = uint(len(*bm.passwordHistory))
	}

	// 5) Load IP-only (overall) password history and apply total metric
	if key := bm.getPasswordHistoryRedisHashKey(false); key != "" {
		bm.loadPasswordHistoryFromRedis(key)
	}

	if bm.passwordHistory != nil {
		bm.passwordsTotalSeen = uint(len(*bm.passwordHistory))
	}
}

// CheckRepeatingBruteForcer checks a set of brute force rules against a given network and updates the message if triggered.
// Returns whether an error occurred, if a rule was already triggered, and the triggering rule index.
func (bm *bucketManagerImpl) CheckRepeatingBruteForcer(rules []config.BruteForceRule, network **net.IPNet, message *string) (withError bool, alreadyTriggered bool, ruleNumber int) {
	tr := monittrace.New("nauthilus/bruteforce")
	ctx, sp := tr.Start(bm.ctx, "auth.bruteforce.repeating_check",
		attribute.String("protocol", bm.protocol),
		attribute.String("oidc_cid", bm.oidcCID),
		attribute.Int("rules.total", len(rules)),
	)
	defer sp.End()

	ipFamily := "unknown"
	switch {
	case bm.parsedIP != nil && bm.parsedIP.To4() != nil:
		ipFamily = "ipv4"
	case bm.parsedIP != nil && bm.parsedIP.To16() != nil:
		ipFamily = "ipv6"
	}

	sp.SetAttributes(attribute.String("ip_family", ipFamily))

	// Micro-cache fast path: reuse a very recent decision for identical semantic request key.
	_, msp := tr.Start(bm.ctx, "auth.bruteforce.repeating_check.micro_cache_emtpy")
	if c := getMicroCache(); c != nil {
		if v, ok := c.Get("bfdec:" + bm.bfBurstKey()); ok {
			if md, ok2 := v.(microDecision); ok2 && md.Block {
				sp.SetAttributes(attribute.Bool("micro_cache.hit", true))

				// find rule index by name to keep downstream behavior intact
				for i := range rules {
					if rules[i].Name == md.Rule {
						if n, nErr := bm.getNetwork(&rules[i]); nErr == nil {
							if n != nil {
								*network = n
							}
						}

						bm.bruteForceName = md.Rule
						*message = "Brute force attack detected (micro-cache)"
						stats.GetMetrics().GetBruteForceCacheHitsTotal().WithLabelValues("micro").Inc()
						sp.SetAttributes(
							attribute.Bool("triggered", true),
							attribute.String("rule", md.Rule),
							attribute.Int("rule.index", i),
						)

						return false, true, i
					}
				}
			}
		}
	}
	msp.End()

	sp.SetAttributes(attribute.Bool("micro_cache.hit", false))

	// Ensure protocol/OIDC context is present when checking rules
	_, lhsp := tr.Start(bm.ctx, "auth.bruteforce.repeating_check.load_pw_hist_filters_if_empty")
	bm.loadPWHistFiltersIfMissing()
	lhsp.End()

	// Ensure IP/net precalc is available even if the caller didn't run PrepareNetcalc.
	if bm.parsedIP == nil {
		bm.PrepareNetcalc(rules)

		// Update family info after PrepareNetcalc populated bm.parsedIP.
		switch {
		case bm.parsedIP != nil && bm.parsedIP.To4() != nil:
			ipFamily = "ipv4"
		case bm.parsedIP != nil && bm.parsedIP.To16() != nil:
			ipFamily = "ipv6"
		default:
			ipFamily = "unknown"
		}
		sp.SetAttributes(attribute.String("ip_family", ipFamily))
	}

	var (
		ruleName string
	)

	logger := bm.logger()

	matchedAnyRule := false

	// Batch pre-result lookup via HMGET for all matching networks
	// Collect candidate fields (network strings) preserving rule order
	type cand struct {
		idx   int
		field string
	}
	candidates := make([]cand, 0, len(rules))

	// Gather candidates
	*network = nil

	_, gatherSpan := tr.Start(ctx, "auth.bruteforce.repeating_check.gather_candidates")
	defer gatherSpan.End()

	for i := range rules {
		if !rules[i].MatchesContext(bm.protocol, bm.oidcCID, bm.parsedIP) {
			continue
		}

		n, nErr := bm.getNetwork(&rules[i])
		if nErr != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Failed to get network for brute force rule",
				definitions.LogKeyError, nErr,
			)

			return true, false, i
		}

		// Only consider this rule matched if it yields a valid network for the client IP
		if n == nil {
			continue
		}

		matchedAnyRule = true
		candidates = append(candidates, cand{idx: i, field: n.String()})
	}

	gatherSpan.SetAttributes(
		attribute.Bool("rules.matched_any", matchedAnyRule),
		attribute.Int("candidates.total", len(candidates)),
	)

	// If we have candidates, issue a pipeline of HMGETs to find the first hit across shards
	if len(candidates) > 0 {
		fields := make([]string, len(candidates))
		for i, c := range candidates {
			fields[i] = c.field
		}

		cmds, errPipe := bm.pipelineHMGetFields(fields, "pipeline_hmget_preresult")
		if errPipe != nil && !errors2.Is(errPipe, redis.Nil) {
			// Fail-open: treat as no pre-result
			level.Warn(logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, fmt.Sprintf("Pipeline HMGET pre-result failed: %v", errPipe))
		} else {
			for i, cmd := range cmds {
				vals, err := cmd.Result()
				if err != nil || len(vals) == 0 || vals[0] == nil {
					continue
				}

				// non-empty string indicates a hit
				if s, ok := vals[0].(string); ok && s != "" {
					// choose the first hit by rule order
					alreadyTriggered = true
					ruleName = s
					bm.bruteForceName = s
					*message = "Brute force attack detected (cached result)"

					stats.GetMetrics().GetBruteForceRejected().WithLabelValues(ruleName).Inc()

					ruleNumber = candidates[i].idx

					// also set the resolved network for downstream logging
					if _, nnet, e := net.ParseCIDR(candidates[i].field); e == nil {
						*network = nnet
					}

					sp.SetAttributes(
						attribute.Bool("triggered", true),
						attribute.String("rule", ruleName),
						attribute.Int("rule.index", ruleNumber),
					)

					return false, alreadyTriggered, ruleNumber
				}
			}
		}
	}

	// If no HMGET hit, fall through to no pre-result

	// Log a warning if no rules matched
	if !matchedAnyRule {
		level.Warn(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyBruteForce, "No matching brute force buckets found",
			"protocol", bm.protocol,
			"client_ip", bm.clientIP)
		sp.SetAttributes(attribute.Bool("rules.matched_any", false))
	}

	sp.SetAttributes(
		attribute.Bool("triggered", alreadyTriggered),
		attribute.Int("candidates.total", len(candidates)),
		attribute.Bool("rules.matched_any", matchedAnyRule),
	)

	return withError, alreadyTriggered, ruleNumber
}

// CheckBucketOverLimit evaluates brute force rules for a given network to detect potential brute force attacks.
// Returns flags indicating errors, if a rule was triggered, and the index of the rule that triggered the detection.
func (bm *bucketManagerImpl) CheckBucketOverLimit(rules []config.BruteForceRule, message *string) (withError bool, ruleTriggered bool, ruleNumber int) {
	tr := monittrace.New("nauthilus/bruteforce")
	ctx, sp := tr.Start(bm.ctx, "auth.bruteforce.bucket_over_limit",
		attribute.String("protocol", bm.protocol),
		attribute.String("oidc_cid", bm.oidcCID),
		attribute.Int("rules.total", len(rules)),
	)
	defer sp.End()

	// Ensure protocol/OIDC context is present when checking rules
	bm.loadPWHistFiltersIfMissing()

	// Ensure IP/net precalc is available even if the caller didn't run PrepareNetcalc.
	if bm.parsedIP == nil || bm.netByCIDR == nil {
		bm.PrepareNetcalc(rules)
	}

	ipFamily := "unknown"
	switch {
	case bm.parsedIP != nil && bm.parsedIP.To4() != nil:
		ipFamily = "ipv4"
	case bm.parsedIP != nil && bm.parsedIP.To16() != nil:
		ipFamily = "ipv6"
	}

	sp.SetAttributes(attribute.String("ip_family", ipFamily))

	matchedAnyRule := false

	// Phase 2: batch load all candidate counters with one MGET
	type bkcand struct {
		idx int
		key string
	}
	cands := make([]bkcand, 0, len(rules))

	_, gatherSpan := tr.Start(ctx, "auth.bruteforce.bucket_over_limit.gather_candidates")

	logger := bm.logger()

	for i := range rules {
		if !rules[i].MatchesContext(bm.protocol, bm.oidcCID, bm.parsedIP) {
			continue
		}

		// Skip, where the current IP address does not match the current rule
		n, nErr := bm.getNetwork(&rules[i])
		if nErr != nil {
			gatherSpan.End()

			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Failed to get network for brute force rule",
				definitions.LogKeyError, nErr,
			)

			return true, false, i
		}

		// Only consider this rule matched if it yields a valid network for the client IP
		if n == nil {
			continue
		}

		matchedAnyRule = true
		// Prepare key for this rule (avoid calling getNetwork twice)
		key := bm.getBruteForceBucketRedisKeyWithNetwork(&rules[i], n)
		if key != "" {
			cands = append(cands, bkcand{idx: i, key: key})
		}
	}

	gatherSpan.SetAttributes(
		attribute.Bool("rules.matched_any", matchedAnyRule),
		attribute.Int("candidates.total", len(cands)),
	)
	gatherSpan.End()

	if len(cands) > 0 {
		keys := make([]string, 0, len(cands))
		for _, c := range cands {
			keys = append(keys, c.key)
		}

		// Redis Cluster: multi-key reads (MGET) require all keys in the same hash slot.
		// Bucket keys are intentionally distributed (hash-tag is bucket-specific), therefore read via
		// a pipeline of GETs.
		defer stats.GetMetrics().GetRedisReadCounter().Inc()
		stats.GetMetrics().GetRedisRoundtripsTotal().WithLabelValues("pipeline_get_bucket_counter").Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
		pipe := bm.redis().GetReadHandle().Pipeline()
		cmds := make([]*redis.StringCmd, 0, len(keys))

		for _, k := range keys {
			cmds = append(cmds, pipe.Get(dCtx, k))
		}

		_, errP := pipe.Exec(dCtx)

		cancel()

		if errP != nil && !errors2.Is(errP, redis.Nil) {
			level.Warn(logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, fmt.Sprintf("Pipeline GET bucket counters failed: %v", errP))
		}

		if bm.bruteForceCounter == nil {
			bm.bruteForceCounter = make(map[string]uint)
		}

		for i, cmd := range cmds {
			v := uint(0)
			if cmd != nil {
				if err := cmd.Err(); err == nil {
					if n, perr := strconv.ParseUint(cmd.Val(), 10, 64); perr == nil {
						v = uint(n)
					}
				} else if !errors2.Is(err, redis.Nil) {
					level.Warn(logger).Log(
						definitions.LogKeyGUID, bm.guid,
						definitions.LogKeyMsg, "GET bucket counter failed",
						"key", keys[i],
						definitions.LogKeyError, err,
					)
				}
			}

			name := rules[cands[i].idx].Name
			bm.bruteForceCounter[name] = v
		}

		// Evaluate in rule order using filled counters
		for _, c := range cands {
			r := &rules[c.idx]
			if bm.bruteForceCounter[r.Name]+1 >= r.FailedRequests {
				ruleTriggered = true
				*message = "Brute force attack detected"

				stats.GetMetrics().GetBruteForceRejected().WithLabelValues(r.Name).Inc()

				ruleNumber = c.idx

				sp.SetAttributes(
					attribute.Bool("triggered", true),
					attribute.String("rule", r.Name),
					attribute.Int("rule.index", ruleNumber),
				)

				return withError, ruleTriggered, ruleNumber
			}
		}
	}

	// Log a warning if no rules matched
	if !matchedAnyRule {
		level.Warn(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyBruteForce, "No matching brute force buckets found",
			"protocol", bm.protocol,
			"client_ip", bm.clientIP)
	}

	sp.SetAttributes(
		attribute.Bool("triggered", ruleTriggered),
		attribute.Bool("rules.matched_any", matchedAnyRule),
		attribute.Int("candidates.total", len(cands)),
	)

	return withError, ruleTriggered, ruleNumber
}

// bfBurstKey builds a short, privacy-safe Redis key for burst gating by hashing
// salient request properties to collapse parallel identical attempts.
func (bm *bucketManagerImpl) bfBurstKey() string {
	// Build a strict semantic key: protocol|userOrAccount|scopedIP|oidcCID
	user := bm.username
	if user == "" && bm.accountName != "" {
		user = bm.accountName
	}

	// Scope IP if scoper configured (e.g., to /64 for IPv6)
	scoped := bm.clientIP
	if bm.scoper != nil {
		scoped = bm.scoper.Scope(ipscoper.ScopeRepeatingWrongPassword, bm.clientIP)
	}

	proto := bm.protocol
	if proto == "" {
		proto = "-"
	}

	var sb strings.Builder

	sb.WriteString(proto)
	sb.WriteByte('\x00')
	sb.WriteString(user)
	sb.WriteByte('\x00')
	sb.WriteString(scoped)
	sb.WriteByte('\x00')
	sb.WriteString(bm.oidcCID)

	base := sb.String()
	sum := sha1.Sum([]byte(base))
	h := hex.EncodeToString(sum[:])

	return bm.cfg().GetServer().GetRedis().GetPrefix() + definitions.RedisBFBurstPrefix + h
}

// burstLeaderGate returns true for the first caller within the small window; false for followers.
func (bm *bucketManagerImpl) burstLeaderGate(ctx context.Context) bool {
	// Ensure at least 1s because the Lua uses EXPIRE seconds
	ttl := time.Second
	argTTL := strconv.FormatInt(int64(ttl.Seconds()), 10)
	key := bm.bfBurstKey()

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, bm.cfg())

	// Dedupliziere identische parallele Script-Aufrufe pro Burst-Key
	resAny, err, _ := sgBurst.Do("burst:"+key, func() (any, error) {
		defer cancel()

		// Redis LUA roundtrip for burst gate
		stats.GetMetrics().GetRedisRoundtripsTotal().WithLabelValues("lua_increment_and_expire").Inc()

		return rediscli.ExecuteScript(dCtx, bm.redis(), "IncrementAndExpire", rediscli.LuaScripts["IncrementAndExpire"], []string{key}, argTTL)
	})

	res := resAny

	if err != nil {
		// Fail-open: better to overcount than miss, and avoid blocking auth
		level.Warn(bm.logger()).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, fmt.Sprintf("Burst gate script error: %v", err))

		return true
	}

	if v, ok := res.(int64); ok && v == 1 {
		return true
	}

	// Follower path; count as cache hit of kind burstLeader
	stats.GetMetrics().GetBruteForceCacheHitsTotal().WithLabelValues("burstLeader").Inc()

	return false
}

// ProcessBruteForce evaluates and handles brute force detection logic, deciding whether further actions are necessary.
func (bm *bucketManagerImpl) ProcessBruteForce(ruleTriggered, alreadyTriggered bool, rule *config.BruteForceRule, network *net.IPNet, message string, setter func()) bool {
	if rule == nil {
		return false
	}

	tr := monittrace.New("nauthilus/bruteforce")
	ctx, sp := tr.Start(bm.ctx, "auth.bruteforce.process",
		attribute.String("protocol", bm.protocol),
		attribute.String("oidc_cid", bm.oidcCID),
		attribute.Bool("rule_triggered", ruleTriggered),
		attribute.Bool("already_triggered", alreadyTriggered),
	)
	defer sp.End()

	// Propagate span context to all downstream operations inside this method.
	prevCtx := bm.ctx
	bm.ctx = ctx
	defer func() {
		bm.ctx = prevCtx
	}()

	ipFamily := "unknown"
	switch {
	case bm.parsedIP != nil && bm.parsedIP.To4() != nil:
		ipFamily = "ipv4"
	case bm.parsedIP != nil && bm.parsedIP.To16() != nil:
		ipFamily = "ipv6"
	}

	sp.SetAttributes(
		attribute.String("ip_family", ipFamily),
	)

	logger := bm.logger()

	if alreadyTriggered || ruleTriggered {
		sp.SetAttributes(attribute.String("rule", rule.Name))

		var useCache bool

		// capture context flag for downstream operations (e.g., PW_HIST behavior)
		bm.alreadyTriggered = alreadyTriggered

		// Ensure the brute-force counter for this rule is loaded for downstream consumers (e.g., Lua/ClickHouse)
		bm.loadBruteForceBucketCounter(rule)

		defer setter()
		defer bm.LoadAllPasswordHistories()

		logBucketRuleDebug(bm, network, rule)

		for _, backendType := range bm.cfg().GetServer().GetBackends() {
			if backendType.Get() == definitions.BackendCache {
				useCache = true

				break
			}
		}

		// Decide whether to enforce brute-force computation or treat as repeating-wrong-password
		// even if the bucket rule matched. This reduces false positives and write amplification.
		if useCache {
			if needEnforce, err := bm.checkEnforceBruteForceComputation(); err != nil {
				level.Error(logger).Log(
					definitions.LogKeyGUID, bm.guid,
					definitions.LogKeyMsg, "Failed to check enforcement of brute force computation",
					definitions.LogKeyError, err,
				)

				return false
			} else if !needEnforce {
				// Repeating wrong password (or similar) detected: skip brute-force enforcement.
				// We still learn the user's IP for later unlock operations, but do not mark the account as affected.
				bm.ProcessPWHist()
				stats.GetMetrics().GetBruteForceHits().WithLabelValues(rule.Name).Inc()

				return false
			}
		}

		if !alreadyTriggered {
			if tol := bm.tolerate(); tol != nil && tol.IsTolerated(bm.ctx, bm.clientIP) {
				level.Info(bm.logger()).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, "IP address is tolerated")

				return false
			}
		}

		if alreadyTriggered {
			// The HMGET pre-result path sets bm.bruteForceName when a cached hit occurs.
			if bm.bruteForceName == "" {
				bm.bruteForceName = fmt.Sprintf("%s,guessed", rule.Name)
			}
		} else {
			bm.bruteForceName = rule.Name
		}

		bm.updateAffectedAccount()

		if ruleTriggered {
			bm.setPreResultBruteForceRedis(rule)
		}

		// For pre-blocked requests, authentication will not run and thus
		// processCacheUserLoginFail will not increment counters. Ensure we
		// count this failed attempt exactly once here, but deduplicate bursts.
		if bm.burstLeaderGate(bm.ctx) {
			bm.SaveFailedPasswordCounterInRedis()
			level.Info(logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyLeadership, "bf_burst_leader")
		} else {
			level.Info(logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyLeadership, "bf_burst_follower")
		}

		logBucketMatchingRule(bm, network, rule, message)

		bm.featureName = definitions.FeatureBruteForce

		// Store micro decision for a very short time to absorb bursts (read-path only)
		if c := getMicroCache(); c != nil {
			// Use value copy to avoid races
			dec := microDecision{Block: true, Rule: bm.bruteForceName}
			// Use cache default TTL
			c.Set("bfdec:"+bm.bfBurstKey(), dec, 0)
		}

		sp.SetAttributes(attribute.Bool("triggered", true))

		return true
	}

	// Also cache negative decision (allow) to avoid immediate redundant HMGET/MGET for identical attempts
	if c := getMicroCache(); c != nil {
		dec := microDecision{Block: false, Rule: ""}
		c.Set("bfdec:"+bm.bfBurstKey(), dec, 0)
	}

	sp.SetAttributes(attribute.Bool("triggered", false))

	return false
}

// ProcessPWHist processes and records the client IP for password history, ensuring data persistence, logging, and error handling.
func (bm *bucketManagerImpl) ProcessPWHist() (accountName string) {
	var (
		alreadyLearned bool
		err            error
	)

	if bm.clientIP == "" {
		return
	}

	if bm.accountName == "" {
		return
	}

	key := GetPWHistIPsRedisKey(bm.accountName, bm.cfg())

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())

	cfg := bm.cfg()
	logger := bm.logger()

	alreadyLearned, err = bm.redis().GetReadHandle().SIsMember(dCtx, key, bm.clientIP).Result()

	if err != nil {
		if !errors2.Is(err, redis.Nil) {
			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Failed to check if IP address is already in PW_HIST_IPS set",
				definitions.LogKeyError, err,
			)
			cancel()

			return
		}
	}

	cancel()

	if alreadyLearned {
		// IP address already stored
		return
	}

	// Use pipelining for write operations to reduce network round trips
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	dCtx, cancel = util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())
	defer cancel()

	_, err = rediscli.ExecuteWritePipeline(dCtx, bm.redis(), func(pipe redis.Pipeliner) error {
		// 1) store IP in PW_HIST_IPS set
		pipe.SAdd(dCtx, key, bm.clientIP)
		pipe.Expire(dCtx, key, bm.cfg().GetServer().Redis.NegCacheTTL)

		// 2) persist optional filters for this IP so a later request can reconstruct them
		fields := make(map[string]any)
		if bm.protocol != "" {
			fields["protocol"] = bm.protocol
		}

		if bm.oidcCID != "" {
			fields["oidc_cid"] = bm.oidcCID
		}

		if len(fields) > 0 {
			// 2a) Persist under the IP-specific meta key
			metaKeyIP := cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistMetaKey + ":" + bm.clientIP
			pipe.HSet(dCtx, metaKeyIP, fields)
			pipe.Expire(dCtx, metaKeyIP, bm.cfg().GetServer().Redis.NegCacheTTL)

			// 2b) Also persist under network-based meta keys for all matching brute-force rules
			for i := range cfg.GetBruteForceRules() {
				rule := cfg.GetBruteForceRules()[i]
				// Reuse bm.getNetwork to respect IPv4/IPv6 flags and CIDR
				if network, err := bm.getNetwork(&rule); err == nil && network != nil {
					metaKeyNet := cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistMetaKey + ":" + network.String()
					pipe.HSet(dCtx, metaKeyNet, fields)
					pipe.Expire(dCtx, metaKeyNet, cfg.GetServer().Redis.NegCacheTTL)
				}
			}
		}

		return nil
	})

	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to store IP address in PW_HIST_IPS set",
			definitions.LogKeyError, err,
		)
	}

	return
}

// SaveBruteForceBucketCounterToRedis saves the brute force bucket counter to Redis using the provided rule configuration.
// It increments the counter and sets an expiration time for the Redis key if the conditions are met.
// Logs errors encountered during Redis operations and updates Redis write metrics.
func (bm *bucketManagerImpl) SaveBruteForceBucketCounterToRedis(rule *config.BruteForceRule) {
	if key := bm.GetBruteForceBucketRedisKey(rule); key != "" {
		util.DebugModuleWithCfg(bm.ctx, bm.cfg(), bm.logger(), definitions.DbgBf, definitions.LogKeyGUID, bm.guid, "store_key", key)

		// Use pipelining for write operations to reduce network round trips
		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())
		defer cancel()

		_, err := rediscli.ExecuteWritePipeline(dCtx, bm.redis(), func(pipe redis.Pipeliner) error {
			// Only increment the counter if this is not the rule that triggered
			if bm.bruteForceName != rule.Name {
				pipe.Incr(dCtx, key)
			}

			// Always set the expiration time
			pipe.Expire(dCtx, key, rule.Period)

			return nil
		})

		if err != nil {
			level.Error(bm.logger()).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Failed to increment brute force bucket counter",
				definitions.LogKeyError, err,
			)
		}
	}
}

// SaveFailedPasswordCounterInRedis increments and persists failed password attempts in Redis for brute force protection.
func (bm *bucketManagerImpl) SaveFailedPasswordCounterInRedis() {
	if !bm.cfg().HasFeature(definitions.FeatureBruteForce) {
		return
	}

	var keys []string

	if bm.clientIP == "" {
		return
	}

	logger := bm.logger()

	if bm.password == "" {
		// Skip processing if password is empty
		level.Debug(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Skipping SaveFailedPasswordCounterInRedis: password is empty",
		)

		return
	}

	keys = append(keys, bm.getPasswordHistoryRedisHashKey(true))
	keys = append(keys, bm.getPasswordHistoryRedisHashKey(false))

	passwordHash := util.GetHash(util.PreparePassword(bm.password))

	for index := range keys {
		util.DebugModuleWithCfg(bm.ctx, bm.cfg(), bm.logger(), definitions.DbgBf, definitions.LogKeyGUID, bm.guid, "incr_key", keys[index])

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())

		// Prepare KEYS and ARGV for the Lua gate.
		totalKey := bm.getPasswordHistoryTotalRedisKey(index == 0)
		luaKeys := []string{keys[index]}
		if totalKey != "" {
			luaKeys = append(luaKeys, totalKey)
		}

		ttlSec := int64(bm.cfg().GetServer().GetRedis().GetNegCacheTTL().Seconds())
		maxFields := int64(bm.cfg().GetServer().GetMaxPasswordHistoryEntries())

		// Execute via central script helper to support EvalSha + auto-upload. Tests use ExpectEval.
		res, err := rediscli.ExecuteScript(dCtx, bm.redis(), "PwHistGate", PwHistGateScript, luaKeys, passwordHash, ttlSec, maxFields)

		cancel()

		// Count as a single Redis write round-trip
		stats.GetMetrics().GetRedisWriteCounter().Add(1)

		if err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Failed to update failed password counter via Lua",
				definitions.LogKeyError, err,
			)

			return
		}

		// Script returns 1 (updated) or 0 (limit reached)
		updated := false
		switch v := res.(type) {
		case int64:
			updated = v == 1
		case string:
			if v == "1" {
				updated = true
			}
		}

		if !updated {
			level.Info(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Too many password hashes for this account",
			)
		} else {
			util.DebugModuleWithCfg(bm.ctx, bm.cfg(), bm.logger(),
				definitions.DbgBf,
				definitions.LogKeyGUID, bm.guid,
				"key", keys[index],
				definitions.LogKeyMsg, "Increased",
			)
		}
	}
}

// DeleteIPBruteForceRedis removes an IP-based brute force entry from Redis based on the provided rule and rule name.
// It returns the removed Redis key if successful or an empty string otherwise.
// Parameters: `rule` specifies the brute force rule, `ruleName` determines the entry to delete or all if set to "*".
// It handles Redis hash key operations and logs errors encountered during the deletion process.
// Returns: The key of the removed entry and an error, if any occurs.
func (bm *bucketManagerImpl) DeleteIPBruteForceRedis(rule *config.BruteForceRule, ruleName string) (string, error) {
	var removedKey string

	cfg := bm.cfg()
	logger := bm.logger()
	redisClient := bm.redis()

	prefix := cfg.GetServer().GetRedis().GetPrefix()

	// If the rule has FilterByProtocol specified, we need to check if the current protocol matches
	if len(rule.FilterByProtocol) > 0 && bm.protocol != "" {
		protocolMatched := false
		for _, p := range rule.GetFilterByProtocol() {
			if p == bm.protocol {
				protocolMatched = true

				break
			}
		}

		if !protocolMatched {
			// Skip this rule if the protocol doesn't match
			return "", nil
		}
	}

	// If the rule has FilterByOIDCCID specified, we need to check if the current OIDC Client ID matches
	if len(rule.GetFilterByOIDCCID()) > 0 && bm.oidcCID != "" {
		oidcCIDMatched := false
		for _, cid := range rule.FilterByOIDCCID {
			if cid == bm.oidcCID {
				oidcCIDMatched = true

				break
			}
		}

		if !oidcCIDMatched {
			// Skip this rule if the OIDC Client ID doesn't match
			return "", nil
		}
	}

	// Resolve network and check current stored value via HMGET (no HGET)
	network, err := bm.getNetwork(rule)
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to get network for brute force rule",
			definitions.LogKeyError, err,
		)

		return "", err
	}
	if network == nil {
		return removedKey, nil
	}

	key := rediscli.GetBruteForceHashKey(prefix, network.String())

	// Read current value with HMGET
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtxR, cancelR := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
	vals, err := redisClient.GetReadHandle().HMGet(dCtxR, key, network.String()).Result()
	cancelR()

	if err != nil {
		return "", err
	}

	current := ""
	if len(vals) > 0 && vals[0] != nil {
		if s, ok := vals[0].(string); ok {
			current = s
		}
	}

	if current == ruleName || ruleName == "*" {
		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())
		defer cancel()

		if removed, err := redisClient.GetWriteHandle().HDel(dCtx, key, network.String()).Result(); err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Failed to delete brute force entry",
				definitions.LogKeyError, err,
			)
		} else if removed > 0 {
			removedKey = key
		}

		return removedKey, nil
	}

	return removedKey, nil
}

// IsIPAddressBlocked determines if the client's IP address is blocked based on brute force rules.
// It returns a list of bucket names where the IP is detected and a boolean indicating if any blocks are found.
func (bm *bucketManagerImpl) IsIPAddressBlocked() (buckets []string, found bool) {
	if bm.clientIP == "" {
		return nil, false
	}

	buckets = make([]string, 0)
	rules := bm.cfg().GetBruteForce().Buckets

	// Build candidate fields and batch HMGET
	type fieldRef struct {
		name, field string
	}

	logger := bm.logger()

	refs := make([]fieldRef, 0, len(rules))
	for i := range rules {
		n, err := bm.getNetwork(&rules[i])
		if err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Failed to get network for brute force rule",
				definitions.LogKeyError, err,
			)

			continue
		}

		if n == nil {
			continue
		}

		refs = append(refs, fieldRef{name: rules[i].Name, field: n.String()})
	}

	if len(refs) == 0 {
		return buckets, false
	}

	fields := make([]string, len(refs))
	for i, r := range refs {
		fields[i] = r.field
	}

	cmds, err := bm.pipelineHMGetFields(fields, "pipeline_hmget_is_blocked")

	if err != nil && !errors2.Is(err, redis.Nil) {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed pipeline HMGET in IsIPAddressBlocked",
			definitions.LogKeyError, err,
		)

		return buckets, false
	}

	for i, cmd := range cmds {
		vals, err := cmd.Result()
		if err != nil || len(vals) == 0 || vals[0] == nil {
			continue
		}

		if s, ok := vals[0].(string); ok && s == refs[i].name {
			buckets = append(buckets, refs[i].name)
		}
	}

	return buckets, len(buckets) > 0
}

func (bm *bucketManagerImpl) pipelineHMGetFields(fields []string, metricLabel string) ([]*redis.SliceCmd, error) {
	if len(fields) == 0 {
		return nil, nil
	}

	prefix := bm.cfg().GetServer().GetRedis().GetPrefix()

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	if metricLabel != "" {
		stats.GetMetrics().GetRedisRoundtripsTotal().WithLabelValues(metricLabel).Inc()
	}

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
	defer cancel()

	pipe := bm.redis().GetReadHandle().Pipeline()
	cmds := make([]*redis.SliceCmd, len(fields))

	for i, f := range fields {
		shardKey := rediscli.GetBruteForceHashKey(prefix, f)
		cmds[i] = pipe.HMGet(dCtx, shardKey, f)
	}

	_, err := pipe.Exec(dCtx)

	return cmds, err
}

var _ BucketManager = (*bucketManagerImpl)(nil)

// loadPWHistFiltersIfMissing tries to restore protocol and OIDC Client ID from Redis metadata
// for the current client IP or its network buckets, but only if those fields are currently empty.
// PW_HIST-based flows may not carry protocol/OIDC context, and we must not lose the original
// bucket filter dimensions. Buckets are CIDR-based, so also consult network-scoped meta keys.
func (bm *bucketManagerImpl) loadPWHistFiltersIfMissing() {
	// If both values are already present, nothing to do
	if bm == nil || (bm.protocol != "" && bm.oidcCID != "") {
		return
	}

	cfg := bm.cfg()
	if cfg == nil {
		return
	}

	logger := bm.logger()
	redisClient := bm.redis()

	if redisClient == nil {
		return
	}

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, cfg)
	defer cancel()

	readOnce := func(key string) map[string]string {
		stats.GetMetrics().GetRedisReadCounter().Inc()

		vals, err := redisClient.GetReadHandle().HGetAll(dCtx, key).Result()
		if err != nil {
			if !errors2.Is(err, redis.Nil) {
				level.Error(logger).Log(
					definitions.LogKeyGUID, bm.guid,
					definitions.LogKeyMsg, "Failed to get protocol/OIDC Client ID from Redis metadata",
					definitions.LogKeyError, err,
				)
			}

			return nil
		}

		if len(vals) == 0 {
			return nil
		}

		return vals
	}

	// 1) Try IP-specific meta
	ipKey := cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistMetaKey + ":" + bm.clientIP
	if vals := readOnce(ipKey); vals != nil {
		if bm.protocol == "" {
			if p, ok := vals["protocol"]; ok {
				bm.protocol = p
			}
		}

		if bm.oidcCID == "" {
			if c, ok := vals["oidc_cid"]; ok {
				bm.oidcCID = c
			}
		}
	}

	// 2) If still missing, try network-scoped meta for any rule matching this IP
	if bm.protocol == "" || bm.oidcCID == "" {
		for i := range cfg.GetBruteForceRules() {
			rule := cfg.GetBruteForceRules()[i]
			if network, err := bm.getNetwork(&rule); err == nil && network != nil {
				netKey := cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistMetaKey + ":" + network.String()
				if vals := readOnce(netKey); vals != nil {
					if bm.protocol == "" {
						if p, ok := vals["protocol"]; ok {
							bm.protocol = p
						}
					}

					if bm.oidcCID == "" {
						if c, ok := vals["oidc_cid"]; ok {
							bm.oidcCID = c
						}
					}
				}
			}

			if bm.protocol != "" && bm.oidcCID != "" {
				break
			}
		}
	}
}

// isRepeatingWrongPassword implements the RWP allowance logic.
// It returns true if the current wrong password should be tolerated (i.e., buckets should NOT be increased),
// based on allowing up to N distinct wrong password hashes within a rolling window. Repeats of already seen
// hashes are always tolerated within the window.
func (bm *bucketManagerImpl) isRepeatingWrongPassword() (repeating bool, err error) {
	logger := bm.logger()

	if bm.password == "" {
		level.Debug(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Skipping isRepeatingWrongPassword: password is empty",
		)

		return false, nil
	}

	passwordHash := util.GetHash(util.PreparePassword(bm.password))

	// Build scope (IP scoping may reduce IPv6 precision) and account identifier
	scoped := bm.clientIP
	if bm.scoper != nil {
		scoped = bm.scoper.Scope(ipscoper.ScopeRepeatingWrongPassword, bm.clientIP)
	}

	acct := bm.accountName
	if acct == "" {
		acct = bm.username
	}

	cfg := bm.cfg()

	threshold := cfg.GetBruteForce().GetRWPAllowedUniqueHashes()
	if threshold < 1 {
		threshold = 1
	}

	ttl := cfg.GetBruteForce().GetRWPWindow()
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	prefix := cfg.GetServer().GetRedis().GetPrefix()
	var sb strings.Builder

	sb.WriteString(prefix)
	sb.WriteString("bf:rwp:allow:")
	sb.WriteString(scoped)
	sb.WriteByte(':')
	sb.WriteString(acct)

	allowKey := sb.String()

	// Atomically check/add using Lua script
	argThreshold := strconv.FormatUint(uint64(threshold), 10)
	argTTL := strconv.FormatInt(int64(ttl.Seconds()), 10)

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
	res, execErr := rediscli.ExecuteScript(
		dCtx,
		bm.redis(),
		"RWPAllowSet",
		rediscli.LuaScripts["RWPAllowSet"],
		[]string{allowKey},
		argThreshold, argTTL, passwordHash,
	)
	cancel()

	if execErr != nil {
		// Fallback heuristic: use PW_HIST_TOTAL counters vs. current hash counter.
		// If totals equal the current hash count, treat as repeating within window.
		level.Warn(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, fmt.Sprintf("RWPAllowSet script error, using totals fallback: %v", execErr),
		)

		// Read account-scoped hash map to get current counter
		acctKey := bm.getPasswordHistoryRedisHashKey(true)
		if acctKey == "" {
			return false, nil
		}

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel = util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
		m, _ := bm.redis().GetReadHandle().HGetAll(dCtx, acctKey).Result()
		cancel()

		cnt := 0
		if s, ok := m[passwordHash]; ok {
			if v, err := strconv.Atoi(s); err == nil {
				cnt = v
			}
		}

		// Read totals
		acctTotKey := bm.getPasswordHistoryTotalRedisKey(true)
		ipTotKey := bm.getPasswordHistoryTotalRedisKey(false)

		var acctTot, ipTot int

		getKey := func(keyName string, value int) int {
			stats.GetMetrics().GetRedisReadCounter().Inc()

			dCtx, cancel = util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
			if s, err := bm.redis().GetReadHandle().Get(dCtx, keyName).Result(); err == nil {
				if v, e := strconv.Atoi(s); e == nil {
					value = v
				}
			}

			cancel()

			return value
		}

		if acctTotKey != "" {
			acctTot = getKey(acctTotKey, acctTot)
		}

		if ipTotKey != "" {
			ipTot = getKey(ipTotKey, ipTot)
		}

		if cnt > 0 && acctTot == cnt && (ipTot == 0 || ipTot == cnt) {
			return true, nil
		}

		return false, nil
	}

	if v, ok := res.(int64); ok && v == 1 {
		// Allowance applies
		userForLog := bm.username
		if userForLog == "" {
			userForLog = bm.accountName
		}

		level.Info(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyBruteForce, "RWP allowance active",
			definitions.LogKeyUsername, userForLog,
			definitions.LogKeyClientIP, bm.clientIP,
			"allowed_unique_hashes", threshold,
		)

		return true, nil
	}

	return false, nil
}

// checkEnforceBruteForceComputation determines if brute force computation must be enforced based on user and password state.
// It returns true if enforcement is needed, or false if not, along with any errors encountered during evaluation.
func (bm *bucketManagerImpl) checkEnforceBruteForceComputation() (bool, error) {
	var (
		repeating bool
		err       error
	)

	cfg := bm.cfg()
	logger := bm.logger()

	/*
		- If a user exists, then check its UCN
		  - If UCN exists, then check for repeating wrong password, else abort the request.
		⇒ Consequences of repeating wrong passwords: buckets won't be increased.

		- If the user is unknown, enforce the brute forcing computation.
		⇒ Consequences are increased buckets.

		- On any error that might occur, abort the current request.
		⇒ Consequences are non-increased buckets.
	*/

	if bm.accountName == "" {
		return true, err
	}

	if repeating, err = bm.isRepeatingWrongPassword(); err != nil {
		return false, err
	} else if repeating {
		return false, nil
	} else if bm.passwordHistory == nil {
		// Known account but no negative history yet.
		// If cold-start grace is DISABLED, we ENFORCE immediately (so complex rules can trigger/fill).
		if !cfg.GetBruteForce().GetColdStartGraceEnabled() {
			return true, nil
		}

		// Cold-start grace is ENABLED: perform a one-time grace and learn the IP; subsequent attempts within TTL enforce.
		// Build keys and perform an atomic cold-start + seed in Redis using preloaded Lua script
		scoped := bm.clientIP
		if bm.scoper != nil {
			scoped = bm.scoper.Scope(ipscoper.ScopeRepeatingWrongPassword, bm.clientIP)
		}

		prefix := cfg.GetServer().GetRedis().GetPrefix()
		coldKey := prefix + "bf:cold:" + scoped

		// Seed is per (ip-scope, account/username, password-hash)
		acct := bm.accountName
		if acct == "" {
			acct = bm.username
		}

		pwHash := util.GetHash(util.PreparePassword(bm.password))
		var sb strings.Builder

		sb.WriteString(prefix)
		sb.WriteString("bf:seed:")
		sb.WriteString(scoped)
		sb.WriteByte(':')
		sb.WriteString(acct)
		sb.WriteByte(':')
		sb.WriteString(pwHash)

		seedKey := sb.String()
		ttl := cfg.GetBruteForce().GetColdStartGraceTTL()
		argTTL := strconv.FormatInt(int64(ttl.Seconds()), 10)

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())
		res, err := rediscli.ExecuteScript(
			dCtx,
			bm.redis(),
			"ColdStartGraceSeed",
			rediscli.LuaScripts["ColdStartGraceSeed"],
			[]string{coldKey, seedKey},
			argTTL,
		)
		cancel()

		if err != nil {
			level.Warn(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, fmt.Sprintf("Cold-start grace ExecuteScript error: %v", err),
			)
			bm.ProcessPWHist()

			return false, nil
		}

		// res==int64(1) means grace (first observation)
		if v, ok := res.(int64); ok && v == 1 {
			level.Info(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Cold-start grace: not enforcing and learning IP",
				definitions.LogKeyUsername, bm.username,
				definitions.LogKeyClientIP, bm.clientIP,
			)
			bm.ProcessPWHist()

			return false, nil
		}

		// Subsequent observation within TTL: enforce computation so complex rules can fill/trigger.
		return true, nil
	}

	return true, nil
}

// getNetwork parses the client IP and generates a network object based on the provided brute force rule configuration.
// Returns the network object if valid, or an error if the IP address is incorrect or fails parsing.
func (bm *bucketManagerImpl) getNetwork(rule *config.BruteForceRule) (network *net.IPNet, err error) {
	// Fast path: use precalculated IP and networks if available
	var ipAddress net.IP

	if bm.parsedIP != nil {
		ipAddress = bm.parsedIP
	} else {
		ipAddress = net.ParseIP(bm.clientIP)
		bm.parsedIP = ipAddress
	}

	if ipAddress == nil {
		return nil, fmt.Errorf("%s '%s'", errors.ErrWrongIPAddress, bm.clientIP)
	}

	bits := 0
	if bm.ipIsV4 || (!bm.ipIsV6 && ipAddress.To4() != nil) {
		bm.ipIsV4 = true
		bm.ipIsV6 = false

		if !rule.IPv4 {
			return nil, nil
		}

		ipAddress = ipAddress.To4()
		bits = 32
	} else if bm.ipIsV6 || ipAddress.To16() != nil {
		bm.ipIsV6 = true
		bm.ipIsV4 = false

		if !rule.IPv6 {
			return nil, nil
		}

		if !bm.ipv6Validated {
			_, err = netaddr.ParseIPv6(bm.clientIP)
			if err != nil {
				return nil, err
			}

			bm.ipv6Validated = true
		}

		ipAddress = ipAddress.To16()
		bits = 128
	}

	// Lookup or compute network for this CIDR
	if bm.netByCIDR != nil {
		if n, ok := bm.netByCIDR[rule.CIDR]; ok && n != nil {
			return n, nil
		}
	}

	mask := net.CIDRMask(int(rule.CIDR), bits)
	if mask == nil {
		return nil, fmt.Errorf("invalid CIDR %d for client IP '%s'", rule.CIDR, bm.clientIP)
	}

	network = &net.IPNet{IP: ipAddress.Mask(mask), Mask: mask}

	if bm.netByCIDR != nil {
		bm.netByCIDR[rule.CIDR] = network
	}

	return network, nil
}

// PrepareNetcalc precomputes parsed IP, family and unique CIDR networks for the provided rules.
// This does not change decision logic; it only caches values for reuse within the request.
func (bm *bucketManagerImpl) PrepareNetcalc(rules []config.BruteForceRule) {
	if bm == nil || bm.deps.Cfg == nil {
		return
	}

	tr := monittrace.New("nauthilus/auth")
	_, span := tr.Start(bm.ctx, "bm.preparenetcalc")
	defer span.End()

	// Initialize the cache map if it does not exist
	if bm.netByCIDR == nil {
		bm.netByCIDR = make(map[uint]*net.IPNet, 8)
	}

	// Parse the client IP string into a netip.Addr (zero-allocation)
	addr, err := netip.ParseAddr(bm.clientIP)
	if err != nil {
		return
	}

	// Update family flags based on the parsed address
	bm.ipIsV4 = addr.Is4()
	bm.ipIsV6 = addr.Is6()

	// Maintain backward compatibility for fields requiring net.IP
	if bm.parsedIP == nil {
		bm.parsedIP = addr.AsSlice()
	}

	// netip.ParseAddr already strictly validates the address, including IPv6
	if bm.ipIsV6 && !bm.ipv6Validated {
		bm.ipv6Validated = true
	}

	// Precompute unique CIDR networks used by rules applicable to the detected family
	for _, r := range rules {
		// Filter rules by IP family
		if (bm.ipIsV4 && !r.IPv4) || (bm.ipIsV6 && !r.IPv6) {
			continue
		}

		// Skip if this CIDR has already been computed
		if _, ok := bm.netByCIDR[r.CIDR]; ok {
			continue
		}

		// Create a prefix and mask the address to get the network part
		if prefix, err := addr.Prefix(int(r.CIDR)); err == nil {
			masked := prefix.Masked().Addr()

			// Convert back to *net.IPNet for compatibility with existing business logic
			ip := net.IP(masked.AsSlice())
			mask := net.CIDRMask(int(r.CIDR), addr.BitLen())
			bm.netByCIDR[r.CIDR] = &net.IPNet{IP: ip, Mask: mask}
		}
	}
}

func (bm *bucketManagerImpl) getPasswordHistoryBaseRedisKey(baseKey string, withUsername bool) string {
	// Normalize the IP for the repeating-wrong-password context (may apply IPv6 CIDR scoping)
	scoped := bm.clientIP
	if bm.scoper != nil {
		scoped = bm.scoper.Scope(ipscoper.ScopeRepeatingWrongPassword, bm.clientIP)
	}

	cfg := bm.cfg()
	logger := bm.logger()

	if withUsername {
		// Prefer explicit accountName; if absent, optionally fall back to username.
		accountName := bm.accountName
		if accountName == "" {
			// Respect config to reduce PW_HIST on cached-blocks
			if cfg.GetBruteForce().GetPWHistKnownAccountsOnlyOnAlreadyTriggered() && bm.alreadyTriggered {
				level.Debug(logger).Log(
					definitions.LogKeyGUID, bm.guid,
					definitions.LogKeyMsg, "Skipping account-scoped PW_HIST for unknown account on cached block",
				)

				return ""
			}

			if bm.username == "" {
				level.Debug(logger).Log(
					definitions.LogKeyGUID, bm.guid,
					definitions.LogKeyMsg, "Skipping getPasswordHistoryBaseRedisKey: no accountName or username",
				)

				return ""
			}

			accountName = bm.username
		}

		var sbHashTag strings.Builder

		sbHashTag.WriteString(accountName)
		sbHashTag.WriteByte(':')
		sbHashTag.WriteString(scoped)

		hashTag := sbHashTag.String()

		var sb strings.Builder

		sb.WriteString(cfg.GetServer().GetRedis().GetPrefix())
		sb.WriteString(baseKey)
		sb.WriteString(":{")
		sb.WriteString(hashTag)
		sb.WriteString("}:")
		sb.WriteString(accountName)
		sb.WriteByte(':')
		sb.WriteString(scoped)

		return sb.String()
	}

	hashTag := scoped
	var sb strings.Builder

	sb.WriteString(cfg.GetServer().GetRedis().GetPrefix())
	sb.WriteString(baseKey)
	sb.WriteString(":{")
	sb.WriteString(hashTag)
	sb.WriteString("}:")
	sb.WriteString(scoped)

	return sb.String()
}

// getPasswordHistoryRedisHashKey generates the Redis hash key for password history storage based on username and client IP.
func (bm *bucketManagerImpl) getPasswordHistoryRedisHashKey(withUsername bool) (key string) {
	key = bm.getPasswordHistoryBaseRedisKey(definitions.RedisPwHashKey, withUsername)
	if key == "" {
		return ""
	}

	util.DebugModuleWithCfg(
		bm.ctx,
		bm.cfg(),
		bm.logger(),
		definitions.DbgBf,
		definitions.LogKeyGUID, bm.guid,
		definitions.LogKeyClientIP, bm.clientIP,
		"key", key,
	)

	return
}

// getPasswordHistoryTotalRedisKey generates the Redis key for the total counter for password history.
func (bm *bucketManagerImpl) getPasswordHistoryTotalRedisKey(withUsername bool) (key string) {
	key = bm.getPasswordHistoryBaseRedisKey(definitions.RedisPwHistTotalKey, withUsername)
	if key == "" {
		return ""
	}

	util.DebugModuleWithCfg(
		bm.ctx,
		bm.cfg(),
		bm.logger(),
		definitions.DbgBf,
		definitions.LogKeyGUID, bm.guid,
		"total_key", key,
	)

	return
}

// checkTooManyPasswordHashes checks if the number of password hashes for a given Redis key exceeds the configured limit.
func (bm *bucketManagerImpl) checkTooManyPasswordHashes(key string) bool {
	var length int64
	var err error

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
	defer cancel()

	if length, err = bm.redis().GetReadHandle().HLen(dCtx, key).Result(); err != nil {
		if !errors2.Is(err, redis.Nil) {
			level.Error(bm.logger()).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Error checking HLen",
				definitions.LogKeyError, err,
			)
		}

		return true
	}

	if length > int64(bm.cfg().GetServer().GetMaxPasswordHistoryEntries()) {
		return true
	}

	return false
}

// loadPasswordHistoryFromRedis loads the password history from a Redis hash table using the provided key.
// Updates the passwordHistory of the bucketManagerImpl instance. Logs errors if encountered during the process.
func (bm *bucketManagerImpl) loadPasswordHistoryFromRedis(key string) {
	if key == "" {
		return
	}

	util.DebugModuleWithCfg(bm.ctx, bm.cfg(), bm.logger(), definitions.DbgBf, definitions.LogKeyGUID, bm.guid, "load_key", key)

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
	defer cancel()

	var passwordHistory map[string]string
	var err error

	logger := bm.logger()

	if passwordHistory, err = bm.redis().GetReadHandle().HGetAll(dCtx, key).Result(); err != nil {
		if !errors2.Is(err, redis.Nil) {
			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Error loading password history from Redis",
				definitions.LogKeyError, err,
			)
		}

		return
	}

	var counterInt int

	if bm.passwordHistory == nil {
		bm.passwordHistory = new(PasswordHistory)
		*bm.passwordHistory = make(PasswordHistory)
	}

	for passwordHash, counter := range passwordHistory {
		if counterInt, err = strconv.Atoi(counter); err != nil {
			if !errors2.Is(err, redis.Nil) {
				level.Error(logger).Log(
					definitions.LogKeyGUID, bm.guid,
					definitions.LogKeyMsg, "Error parsing password history counter",
					definitions.LogKeyError, err,
				)
			}

			return
		}

		(*bm.passwordHistory)[passwordHash] = uint(counterInt)
	}
}

// loadBruteForceBucketCounter loads a brute force bucket counter for the specified rule if the feature is enabled.
// It retrieves the bucket counter from Redis, logs the operation, and updates the in-memory counter mapping for the rule.
func (bm *bucketManagerImpl) loadBruteForceBucketCounter(rule *config.BruteForceRule) {
	if !bm.cfg().HasFeature(definitions.FeatureBruteForce) {
		return
	}

	bucketCounter := new(bruteForceBucketCounter)

	if key := bm.GetBruteForceBucketRedisKey(rule); key != "" {
		util.DebugModuleWithCfg(bm.ctx, bm.cfg(), bm.logger(), definitions.DbgBf, definitions.LogKeyGUID, bm.guid, "load_key", key)

		if err := loadBruteForceBucketCounterFromRedis(bm.ctx, bm.cfg(), bm.logger(), bm.redis(), key, bucketCounter); err != nil {
			return
		}
	}

	if bm.bruteForceCounter == nil {
		bm.bruteForceCounter = make(map[string]uint)
	}

	bm.bruteForceCounter[rule.Name] = uint(*bucketCounter)
}

// setPreResultBruteForceRedis stores a brute force rule in Redis under a hashed key, handling network resolution and errors.
func (bm *bucketManagerImpl) setPreResultBruteForceRedis(rule *config.BruteForceRule) {
	prefix := bm.cfg().GetServer().GetRedis().GetPrefix()
	logger := bm.logger()

	network, err := bm.getNetwork(rule)
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Error getting network for brute force rule",
			definitions.LogKeyError, err,
		)
	} else {
		key := rediscli.GetBruteForceHashKey(prefix, network.String())

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())
		defer cancel()

		if err = bm.redis().GetWriteHandle().HSet(dCtx, key, network.String(), bm.bruteForceName).Err(); err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Error setting brute force rule in Redis",
				definitions.LogKeyError, err,
			)
		}
	}
}

// updateAffectedAccount processes a blocked account by checking its existence in Redis and adding it if not present.
// It increments Redis read and write counters and logs errors encountered during the operations.
func (bm *bucketManagerImpl) updateAffectedAccount() {
	if bm.accountName == "" {
		return
	}

	key := bm.cfg().GetServer().GetRedis().GetPrefix() + definitions.RedisAffectedAccountsKey
	logger := bm.logger()

	// First check if the account is already a member
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())

	isMember, err := bm.redis().GetReadHandle().SIsMember(dCtx, key, bm.accountName).Result()
	if err != nil {
		if !errors2.Is(err, redis.Nil) {
			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Error checking if account is already a member of the affected accounts set",
				definitions.LogKeyError, err,
			)
			cancel()

			return
		}
	}

	cancel()

	// If we already know it's a member, we can skip the write operation
	if isMember {
		return
	}

	// Add the account to the set
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	dCtx, cancel = util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())
	defer cancel()

	if err := bm.redis().GetWriteHandle().SAdd(dCtx, key, bm.accountName).Err(); err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Error adding account to the affected accounts set",
			definitions.LogKeyError, err,
		)
	}
}

// BucketManagerDeps bundles optional dependencies for BucketManager.
//
// If a field is nil, the BucketManager falls back to the legacy global singletons
// to preserve backward-compatible behavior.
type BucketManagerDeps struct {
	Cfg      config.File
	Logger   *slog.Logger
	Redis    rediscli.Client
	Tolerate tolerate.Tolerate
}

// NewBucketManagerWithDeps creates a new BucketManager instance that prefers injected
// dependencies over legacy globals.
func NewBucketManagerWithDeps(ctx context.Context, guid, clientIP string, deps BucketManagerDeps) BucketManager {
	return &bucketManagerImpl{
		ctx:      ctx,
		deps:     deps,
		guid:     guid,
		clientIP: clientIP,
		scoper:   ipscoper.NewIPScoper().WithCfg(deps.Cfg),
	}
}

// GetPWHistIPsRedisKey generates the Redis key for storing password history associated with IPs for a specific account.
func GetPWHistIPsRedisKey(accountName string, cfg config.File) string {
	key := cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistIPsKey + ":" + accountName

	return key
}

// logBucketRuleDebug logs debug information for a brute force rule, including client IP, rule details, and request counts.
func logBucketRuleDebug(bm *bucketManagerImpl, network *net.IPNet, rule *config.BruteForceRule) {
	util.DebugModuleWithCfg(bm.ctx, bm.cfg(), bm.logger(), definitions.DbgBf,
		definitions.LogKeyGUID, bm.guid,
		"limit", rule.FailedRequests,
		definitions.LogKeyClientIP, bm.clientIP,
		"rule_network", fmt.Sprintf("%v", network),
		"rule", rule.Name,
		"counter", bm.bruteForceCounter[rule.Name],
	)
}

// logBucketMatchingRule logs information about a triggered brute force rule, including rule details and client session data.
func logBucketMatchingRule(bm *bucketManagerImpl, network *net.IPNet, rule *config.BruteForceRule, message string) {
	level.Info(bm.logger()).Log(
		definitions.LogKeyGUID, bm.guid,
		definitions.LogKeyBruteForce, message,
		definitions.LogKeyUsername, bm.username,
		definitions.LogKeyClientIP, bm.clientIP,
		"rule_network", fmt.Sprintf("%v", network),
		"rule", rule.Name,
	)
}

// logBruteForceRuleRedisKeyDebug logs debugging information related to brute force rule configuration and Redis key generation.
// It logs details such as rule properties, client IP, session ID, network info, and the generated Redis key.
func logBruteForceRuleRedisKeyDebug(bm *bucketManagerImpl, rule *config.BruteForceRule, network *net.IPNet, key string) {
	util.DebugModuleWithCfg(
		bm.ctx,
		bm.cfg(),
		bm.logger(),
		definitions.DbgBf,
		definitions.LogKeyGUID, bm.guid,
		definitions.LogKeyClientIP, bm.clientIP,
		"rule", rule.Name,
		"period", rule.Period,
		"cidr", rule.CIDR,
		"ipv4", rule.IPv4,
		"ipv6", rule.IPv6,
		"failed_requests", rule.FailedRequests,
		"rule_network", fmt.Sprintf("%v", network),
		"key", key,
	)
}

// loadBruteForceBucketCounterFromRedis retrieves and unmarshals a BruteForceBucketCounter from Redis by the provided key.
// It ensures metrics tracking for Redis read operations and logs errors if Redis operations or unmarshalling fail.
func loadBruteForceBucketCounterFromRedis(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, key string, bucketCounter *bruteForceBucketCounter) (err error) {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	// Count Redis roundtrip for bucket counter GET
	stats.GetMetrics().GetRedisRoundtripsTotal().WithLabelValues("get_bucket_counter").Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
	defer cancel()

	val, err := redisClient.GetReadHandle().Get(dCtx, key).Result()
	if err != nil {
		if errors2.Is(err, redis.Nil) {
			// treat missing as zero
			*bucketCounter = 0

			return nil
		}

		level.Error(logger).Log(
			definitions.LogKeyMsg, "Error loading brute force bucket counter from Redis",
			definitions.LogKeyError, err,
		)

		return err
	}

	// Parse integer value; invalid -> zero
	if n, perr := strconv.ParseUint(val, 10, 64); perr == nil {
		*bucketCounter = bruteForceBucketCounter(n)
	} else {
		*bucketCounter = 0
	}

	return nil
}

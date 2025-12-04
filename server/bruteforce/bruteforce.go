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
	"net"
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
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/dspinhirne/netaddr-go"
	"github.com/redis/go-redis/v9"
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
		// Always-on micro cache with fixed conservative TTL (phase 7: flagless standard)
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

	loginAttempts        uint
	passwordsAccountSeen uint
	passwordsTotalSeen   uint

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

	// request-context flags
	alreadyTriggered bool

	// ip scoper used to normalize addresses per feature context (e.g., RWP IPv6 CIDR)
	scoper ipscoper.IPScoper

	// Precalc fields (computed once per request)
	parsedIP  net.IP
	ipIsV4    bool
	ipIsV6    bool
	netByCIDR map[uint]*net.IPNet // CIDR -> network
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
	var ipProto string
	var protocolPart string
	var oidcCIDPart string

	network, err := bm.getNetwork(rule)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to get network for brute force rule",
			definitions.LogKeyError, err,
		)

		return
	}

	if network == nil {
		return
	}

	if rule.IPv4 {
		ipProto = "4"
	} else if rule.IPv6 {
		ipProto = "6"
	}

	// Add protocol information to the key if the rule has FilterByProtocol specified
	if len(rule.GetFilterByProtocol()) > 0 && bm.protocol != "" {
		// Check if the current protocol is in the FilterByProtocol list
		protocolMatched := false
		for _, p := range rule.FilterByProtocol {
			if p == bm.protocol {
				protocolMatched = true

				break
			}
		}

		if protocolMatched {
			protocolPart = bm.protocol
		}
	}

	// Add OIDC Client ID information to the key if the rule has FilterByOIDCCID specified
	if len(rule.GetFilterByOIDCCID()) > 0 && bm.oidcCID != "" {
		// Check if the current OIDC Client ID is in the FilterByOIDCCID list
		oidcCIDMatched := false
		for _, cid := range rule.FilterByOIDCCID {
			if cid == bm.oidcCID {
				oidcCIDMatched = true

				break
			}
		}

		if oidcCIDMatched {
			oidcCIDPart = bm.oidcCID
		}
	}

	key = config.GetFile().GetServer().GetRedis().GetPrefix() + "bf:" + fmt.Sprintf(
		"%.0f:%d:%d:%s:%s", rule.Period.Seconds(), rule.CIDR, rule.FailedRequests, ipProto, network.String())

	// Append protocol part with a separator if it exists
	if protocolPart != "" {
		key += ":" + protocolPart
	}

	// Append OIDC Client ID part with a separator if it exists
	if oidcCIDPart != "" {
		key += ":oidc:" + oidcCIDPart
	}

	logBruteForceRuleRedisKeyDebug(bm, rule, network, key)

	return
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
	if !config.GetFile().HasFeature(definitions.FeatureBruteForce) {
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

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx)
		_, _ = rediscli.GetClient().GetReadHandle().Get(dCtx, key).Result()
		cancel()
	}

	if key := bm.getPasswordHistoryTotalRedisKey(false); key != "" {
		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx)
		_, _ = rediscli.GetClient().GetReadHandle().Get(dCtx, key).Result()
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
	// Micro-cache fast path: reuse a very recent decision for identical semantic request key.
	if c := getMicroCache(); c != nil {
		if v, ok := c.Get("bfdec:" + bm.bfBurstKey()); ok {
			if md, ok2 := v.(microDecision); ok2 && md.Block {
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

						return false, true, i
					}
				}
			}
		}
	}

	// Ensure protocol/OIDC context is present when checking rules
	bm.loadPWHistFiltersIfMissing()

	var (
		ruleName string
	)

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
	for i := range rules {
		// Protocol filter
		if len(rules[i].FilterByProtocol) > 0 && bm.protocol != "" {
			matched := false
			for _, p := range rules[i].FilterByProtocol {
				if p == bm.protocol {
					matched = true

					break
				}
			}

			if !matched {
				continue
			}
		}

		// OIDC filter
		if len(rules[i].FilterByOIDCCID) > 0 && bm.oidcCID != "" {
			matched := false
			for _, cid := range rules[i].FilterByOIDCCID {
				if cid == bm.oidcCID {
					matched = true

					break
				}
			}

			if !matched {
				continue
			}
		}

		n, nErr := bm.getNetwork(&rules[i])
		if nErr != nil {
			level.Error(log.Logger).Log(
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

	// If we have candidates, issue a single HMGET to find the first hit
	if len(candidates) > 0 {
		key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisBruteForceHashKey

		fields := make([]string, 0, len(candidates))
		for _, c := range candidates {
			fields = append(fields, c.field)
		}

		// metrics
		defer stats.GetMetrics().GetRedisReadCounter().Inc()
		stats.GetMetrics().GetRedisRoundtripsTotal().WithLabelValues("hmget_preresult").Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx)
		vals, errHM := rediscli.GetClient().GetReadHandle().HMGet(dCtx, key, fields...).Result()
		cancel()

		if errHM != nil {
			// Fail-open: treat as no pre-result
			level.Warn(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, fmt.Sprintf("HMGET pre-result failed: %v", errHM))
		} else {
			for i, v := range vals {
				if v == nil {
					continue
				}

				// non-empty string indicates a hit
				if s, ok := v.(string); ok && s != "" {
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

					return false, alreadyTriggered, ruleNumber
				}
			}
		}
	}

	// If no HMGET hit, fall through to no pre-result

	// Log a warning if no rules matched
	if !matchedAnyRule {
		level.Warn(log.Logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyBruteForce, "No matching brute force buckets found",
			"protocol", bm.protocol,
			"client_ip", bm.clientIP)
	}

	return withError, alreadyTriggered, ruleNumber
}

// CheckBucketOverLimit evaluates brute force rules for a given network to detect potential brute force attacks.
// Returns flags indicating errors, if a rule was triggered, and the index of the rule that triggered the detection.
func (bm *bucketManagerImpl) CheckBucketOverLimit(rules []config.BruteForceRule, message *string) (withError bool, ruleTriggered bool, ruleNumber int) {
	// Ensure protocol/OIDC context is present when checking rules
	bm.loadPWHistFiltersIfMissing()

	matchedAnyRule := false

	// Phase 2: batch load all candidate counters with one MGET
	type bkcand struct {
		idx int
		key string
	}
	cands := make([]bkcand, 0, len(rules))

	for i := range rules {
		// Skip if the rule has FilterByProtocol specified and the current protocol is not in the list
		if len(rules[i].FilterByProtocol) > 0 && bm.protocol != "" {
			if !containsString(rules[i].FilterByProtocol, bm.protocol) {
				continue
			}
		}

		// Skip if the rule has FilterByOIDCCID specified and the current OIDC Client ID is not in the list
		if len(rules[i].FilterByOIDCCID) > 0 && bm.oidcCID != "" {
			if !containsString(rules[i].FilterByOIDCCID, bm.oidcCID) {
				continue
			}
		}

		// Skip, where the current IP address does not match the current rule
		n, nErr := bm.getNetwork(&rules[i])
		if nErr != nil {
			level.Error(log.Logger).Log(
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
		// Prepare key for this rule
		key := bm.GetBruteForceBucketRedisKey(&rules[i])
		if key != "" {
			cands = append(cands, bkcand{idx: i, key: key})
		}
	}

	if len(cands) > 0 {
		keys := make([]string, 0, len(cands))
		for _, c := range cands {
			keys = append(keys, c.key)
		}

		// Always use MGET, even for a single candidate
		// metrics
		defer stats.GetMetrics().GetRedisReadCounter().Inc()
		stats.GetMetrics().GetRedisRoundtripsTotal().WithLabelValues("mget_bucket_counter").Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx)
		vals, errM := rediscli.GetClient().GetReadHandle().MGet(dCtx, keys...).Result()
		cancel()
		if errM != nil {
			level.Warn(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, fmt.Sprintf("MGET bucket counters failed: %v", errM))
		} else {
			if bm.bruteForceCounter == nil {
				bm.bruteForceCounter = make(map[string]uint)
			}

			for i, raw := range vals {
				v := uint(0)
				if raw != nil {
					switch t := raw.(type) {
					case string:
						if n, perr := strconv.ParseUint(t, 10, 64); perr == nil {
							v = uint(n)
						}
					case []byte:
						if n, perr := strconv.ParseUint(string(t), 10, 64); perr == nil {
							v = uint(n)
						}
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

					return withError, ruleTriggered, ruleNumber
				}
			}
		}
	}

	// Log a warning if no rules matched
	if !matchedAnyRule {
		level.Warn(log.Logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyBruteForce, "No matching brute force buckets found",
			"protocol", bm.protocol,
			"client_ip", bm.clientIP)
	}

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

	base := proto + "\x00" + user + "\x00" + scoped + "\x00" + bm.oidcCID
	sum := sha1.Sum([]byte(base))
	h := hex.EncodeToString(sum[:])

	return config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisBFBurstPrefix + h
}

// burstLeaderGate returns true for the first caller within the small window; false for followers.
func (bm *bucketManagerImpl) burstLeaderGate(ctx context.Context) bool {
	// Ensure at least 1s because the Lua uses EXPIRE seconds
	ttl := time.Second
	argTTL := strconv.FormatInt(int64(ttl.Seconds()), 10)
	key := bm.bfBurstKey()

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)

	// Dedupliziere identische parallele Script-Aufrufe pro Burst-Key
	resAny, err, _ := sgBurst.Do("burst:"+key, func() (any, error) {
		defer cancel()

		// Redis LUA roundtrip for burst gate
		stats.GetMetrics().GetRedisRoundtripsTotal().WithLabelValues("lua_increment_and_expire").Inc()

		return rediscli.ExecuteScript(dCtx, "IncrementAndExpire", rediscli.LuaScripts["IncrementAndExpire"], []string{key}, argTTL)
	})

	res := resAny

	if err != nil {
		// Fail-open: better to overcount than miss, and avoid blocking auth
		level.Warn(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, fmt.Sprintf("Burst gate script error: %v", err))

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
	if alreadyTriggered || ruleTriggered {
		var useCache bool

		// capture context flag for downstream operations (e.g., PW_HIST behavior)
		bm.alreadyTriggered = alreadyTriggered

		// Ensure the brute-force counter for this rule is loaded for downstream consumers (e.g., Lua/ClickHouse)
		bm.loadBruteForceBucketCounter(rule)

		defer setter()
		defer bm.LoadAllPasswordHistories()

		logBucketRuleDebug(bm, network, rule)

		for _, backendType := range config.GetFile().GetServer().GetBackends() {
			if backendType.Get() == definitions.BackendCache {
				useCache = true

				break
			}
		}

		// Decide whether to enforce brute-force computation or treat as repeating-wrong-password
		// even if the bucket rule matched. This reduces false positives and write amplification.
		if useCache {
			if needEnforce, err := bm.checkEnforceBruteForceComputation(); err != nil {
				level.Error(log.Logger).Log(
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
			if tolerate.GetTolerate().IsTolerated(bm.ctx, bm.clientIP) {
				level.Info(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, "IP address is tolerated")

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
			level.Info(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyLeadership, "bf_burst_leader")
		} else {
			level.Info(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyLeadership, "bf_burst_follower")
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

		return true
	}

	// Also cache negative decision (allow) to avoid immediate redundant HMGET/MGET for identical attempts
	if c := getMicroCache(); c != nil {
		dec := microDecision{Block: false, Rule: ""}
		c.Set("bfdec:"+bm.bfBurstKey(), dec, 0)
	}

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

	key := GetPWHistIPsRedisKey(bm.accountName)

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx)

	alreadyLearned, err = rediscli.GetClient().GetReadHandle().SIsMember(dCtx, key, bm.clientIP).Result()
	if err != nil {
		if !errors2.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(
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

	dCtx, cancel = util.GetCtxWithDeadlineRedisWrite(bm.ctx)
	defer cancel()

	_, err = rediscli.ExecuteWritePipeline(dCtx, func(pipe redis.Pipeliner) error {
		// 1) store IP in PW_HIST_IPS set
		pipe.SAdd(dCtx, key, bm.clientIP)
		pipe.Expire(dCtx, key, config.GetFile().GetServer().Redis.NegCacheTTL)

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
			metaKeyIP := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistMetaKey + ":" + bm.clientIP
			pipe.HSet(dCtx, metaKeyIP, fields)
			pipe.Expire(dCtx, metaKeyIP, config.GetFile().GetServer().Redis.NegCacheTTL)

			// 2b) Also persist under network-based meta keys for all matching brute-force rules
			for i := range config.GetFile().GetBruteForceRules() {
				rule := config.GetFile().GetBruteForceRules()[i]
				// Reuse bm.getNetwork to respect IPv4/IPv6 flags and CIDR
				if network, err := bm.getNetwork(&rule); err == nil && network != nil {
					metaKeyNet := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistMetaKey + ":" + network.String()
					pipe.HSet(dCtx, metaKeyNet, fields)
					pipe.Expire(dCtx, metaKeyNet, config.GetFile().GetServer().Redis.NegCacheTTL)
				}
			}
		}

		return nil
	})

	if err != nil {
		level.Error(log.Logger).Log(
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
		util.DebugModule(definitions.DbgBf, definitions.LogKeyGUID, bm.guid, "store_key", key)

		// Use pipelining for write operations to reduce network round trips
		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx)
		defer cancel()

		_, err := rediscli.ExecuteWritePipeline(dCtx, func(pipe redis.Pipeliner) error {
			// Only increment the counter if this is not the rule that triggered
			if bm.bruteForceName != rule.Name {
				pipe.Incr(dCtx, key)
			}

			// Always set the expiration time
			pipe.Expire(dCtx, key, rule.Period)

			return nil
		})

		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Failed to increment brute force bucket counter",
				definitions.LogKeyError, err,
			)
		}
	}
}

// SaveFailedPasswordCounterInRedis increments and persists failed password attempts in Redis for brute force protection.
func (bm *bucketManagerImpl) SaveFailedPasswordCounterInRedis() {
	if !config.GetFile().HasFeature(definitions.FeatureBruteForce) {
		return
	}

	var keys []string

	if bm.clientIP == "" {
		return
	}

	if bm.password == "" {
		// Skip processing if password is empty
		level.Debug(log.Logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Skipping SaveFailedPasswordCounterInRedis: password is empty",
		)

		return
	}

	keys = append(keys, bm.getPasswordHistoryRedisHashKey(true))
	keys = append(keys, bm.getPasswordHistoryRedisHashKey(false))

	passwordHash := util.GetHash(util.PreparePassword(bm.password))

	for index := range keys {
		util.DebugModule(definitions.DbgBf, definitions.LogKeyGUID, bm.guid, "incr_key", keys[index])

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx)

		// Prepare KEYS and ARGV for the Lua gate.
		totalKey := bm.getPasswordHistoryTotalRedisKey(index == 0)
		luaKeys := []string{keys[index]}
		if totalKey != "" {
			luaKeys = append(luaKeys, totalKey)
		}

		ttlSec := int64(config.GetFile().GetServer().GetRedis().GetNegCacheTTL().Seconds())
		maxFields := int64(config.GetFile().GetServer().GetMaxPasswordHistoryEntries())

		// Execute via central script helper to support EvalSha + auto-upload. Tests use ExpectEval.
		res, err := rediscli.ExecuteScript(dCtx, "PwHistGate", PwHistGateScript, luaKeys, passwordHash, ttlSec, maxFields)

		cancel()

		// Count as a single Redis write round-trip
		stats.GetMetrics().GetRedisWriteCounter().Add(1)

		if err != nil {
			level.Error(log.Logger).Log(
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
			level.Info(log.Logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Too many password hashes for this account",
			)
		} else {
			util.DebugModule(
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

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisBruteForceHashKey

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
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to get network for brute force rule",
			definitions.LogKeyError, err,
		)

		return "", err
	}
	if network == nil {
		return removedKey, nil
	}

	// Read current value with HMGET
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtxR, cancelR := util.GetCtxWithDeadlineRedisRead(bm.ctx)
	vals, err := rediscli.GetClient().GetReadHandle().HMGet(dCtxR, key, network.String()).Result()
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

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx)
		defer cancel()

		if removed, err := rediscli.GetClient().GetWriteHandle().HDel(dCtx, key, network.String()).Result(); err != nil {
			level.Error(log.Logger).Log(
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
	rules := config.GetFile().GetBruteForce().Buckets

	// Build candidate fields and batch HMGET
	type fieldRef struct {
		name, field string
	}

	refs := make([]fieldRef, 0, len(rules))
	for i := range rules {
		n, err := bm.getNetwork(&rules[i])
		if err != nil {
			level.Error(log.Logger).Log(
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

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisBruteForceHashKey
	fields := make([]string, 0, len(refs))
	for _, r := range refs {
		fields = append(fields, r.field)
	}

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx)
	vals, err := rediscli.GetClient().GetReadHandle().HMGet(dCtx, key, fields...).Result()
	cancel()

	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed HMGET in IsIPAddressBlocked",
			definitions.LogKeyError, err,
		)

		return buckets, false
	}

	for i, v := range vals {
		if v == nil {
			continue
		}

		if s, ok := v.(string); ok && s == refs[i].name {
			buckets = append(buckets, refs[i].name)
		}
	}

	return buckets, len(buckets) > 0
}

var _ BucketManager = (*bucketManagerImpl)(nil)

// loadPWHistFiltersIfMissing tries to restore protocol and OIDC Client ID from Redis metadata
// for the current client IP or its network buckets, but only if those fields are currently empty.
// PW_HIST-based flows may not carry protocol/OIDC context, and we must not lose the original
// bucket filter dimensions. Buckets are CIDR-based, so also consult network-scoped meta keys.
func (bm *bucketManagerImpl) loadPWHistFiltersIfMissing() {
	// If both values are already present, nothing to do
	if bm.protocol != "" && bm.oidcCID != "" {
		return
	}

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx)
	defer cancel()

	readOnce := func(key string) map[string]string {
		stats.GetMetrics().GetRedisReadCounter().Inc()

		vals, err := rediscli.GetClient().GetReadHandle().HGetAll(dCtx, key).Result()
		if err != nil {
			if !errors2.Is(err, redis.Nil) {
				level.Error(log.Logger).Log(
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
	ipKey := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistMetaKey + ":" + bm.clientIP
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
		for i := range config.GetFile().GetBruteForceRules() {
			rule := config.GetFile().GetBruteForceRules()[i]
			if network, err := bm.getNetwork(&rule); err == nil && network != nil {
				netKey := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistMetaKey + ":" + network.String()
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
	if bm.password == "" {
		level.Debug(log.Logger).Log(
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

	cfg := config.GetFile().GetBruteForce()
	threshold := cfg.GetRWPAllowedUniqueHashes()
	if threshold < 1 {
		threshold = 1
	}

	ttl := cfg.GetRWPWindow()
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	prefix := config.GetFile().GetServer().GetRedis().GetPrefix()
	allowKey := prefix + "bf:rwp:allow:" + scoped + ":" + acct

	// Atomically check/add using Lua script
	argThreshold := strconv.FormatUint(uint64(threshold), 10)
	argTTL := strconv.FormatInt(int64(ttl.Seconds()), 10)

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx)
	res, execErr := rediscli.ExecuteScript(
		dCtx,
		"RWPAllowSet",
		rediscli.LuaScripts["RWPAllowSet"],
		[]string{allowKey},
		argThreshold, argTTL, passwordHash,
	)
	cancel()

	if execErr != nil {
		// Fallback heuristic: use PW_HIST_TOTAL counters vs. current hash counter.
		// If totals equal the current hash count, treat as repeating within window.
		level.Warn(log.Logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, fmt.Sprintf("RWPAllowSet script error, using totals fallback: %v", execErr),
		)

		// Read account-scoped hash map to get current counter
		acctKey := bm.getPasswordHistoryRedisHashKey(true)
		if acctKey == "" {
			return false, nil
		}

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel = util.GetCtxWithDeadlineRedisRead(bm.ctx)
		m, _ := rediscli.GetClient().GetReadHandle().HGetAll(dCtx, acctKey).Result()
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

			dCtx, cancel = util.GetCtxWithDeadlineRedisRead(bm.ctx)
			if s, err := rediscli.GetClient().GetReadHandle().Get(dCtx, keyName).Result(); err == nil {
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

		level.Info(log.Logger).Log(
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
	} else {
		if repeating, err = bm.isRepeatingWrongPassword(); err != nil {
			return false, err
		} else if repeating {
			return false, nil
		} else if bm.passwordHistory == nil {
			// Known account but no negative history yet.
			// If cold-start grace is DISABLED, we ENFORCE immediately (so complex rules can trigger/fill).
			if !config.GetFile().GetBruteForce().GetColdStartGraceEnabled() {
				return true, nil
			}

			// Cold-start grace is ENABLED: perform a one-time grace and learn the IP; subsequent attempts within TTL enforce.
			// Build keys and perform an atomic cold-start + seed in Redis using preloaded Lua script
			scoped := bm.clientIP
			if bm.scoper != nil {
				scoped = bm.scoper.Scope(ipscoper.ScopeRepeatingWrongPassword, bm.clientIP)
			}

			prefix := config.GetFile().GetServer().GetRedis().GetPrefix()
			coldKey := prefix + "bf:cold:" + scoped

			// Seed is per (ip-scope, account/username, password-hash)
			acct := bm.accountName
			if acct == "" {
				acct = bm.username
			}

			pwHash := util.GetHash(util.PreparePassword(bm.password))
			seedKey := prefix + "bf:seed:" + scoped + ":" + acct + ":" + pwHash
			ttl := config.GetFile().GetBruteForce().GetColdStartGraceTTL()
			argTTL := strconv.FormatInt(int64(ttl.Seconds()), 10)

			dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx)
			res, err := rediscli.ExecuteScript(
				dCtx,
				"ColdStartGraceSeed",
				rediscli.LuaScripts["ColdStartGraceSeed"],
				[]string{coldKey, seedKey},
				argTTL,
			)
			cancel()

			if err != nil {
				level.Warn(log.Logger).Log(
					definitions.LogKeyGUID, bm.guid,
					definitions.LogKeyMsg, fmt.Sprintf("Cold-start grace ExecuteScript error: %v", err),
				)
				bm.ProcessPWHist()

				return false, nil
			}

			// res==int64(1) means grace (first observation)
			if v, ok := res.(int64); ok && v == 1 {
				level.Info(log.Logger).Log(
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

	if strings.Contains(ipAddress.String(), ":") {
		_, err = netaddr.ParseIPv6(bm.clientIP)
		if err != nil {
			return nil, err
		}
	}

	if bm.ipIsV4 || (!bm.ipIsV6 && ipAddress.To4() != nil) {
		bm.ipIsV4 = true
		if !rule.IPv4 {
			return nil, nil
		}
	} else if bm.ipIsV6 || ipAddress.To16() != nil {
		bm.ipIsV6 = true
		if !rule.IPv6 {
			return nil, nil
		}
	}

	// Lookup or compute network for this CIDR
	if bm.netByCIDR != nil {
		if n, ok := bm.netByCIDR[rule.CIDR]; ok && n != nil {
			return n, nil
		}
	}

	_, network, err = net.ParseCIDR(fmt.Sprintf("%s/%d", bm.clientIP, rule.CIDR))
	if err != nil {
		return nil, err
	}

	if bm.netByCIDR != nil {
		bm.netByCIDR[rule.CIDR] = network
	}

	return network, nil
}

// PrepareNetcalc precomputes parsed IP, family and unique CIDR networks for the provided rules.
// This does not change decision logic; it only caches values for reuse within the request.
func (bm *bucketManagerImpl) PrepareNetcalc(rules []config.BruteForceRule) {
	if bm.netByCIDR == nil {
		bm.netByCIDR = make(map[uint]*net.IPNet, 8)
	}

	if bm.parsedIP == nil {
		bm.parsedIP = net.ParseIP(bm.clientIP)
	}

	// Determine family bits
	if bm.parsedIP != nil {
		if bm.parsedIP.To4() != nil {
			bm.ipIsV4 = true
			bm.ipIsV6 = false
		} else if bm.parsedIP.To16() != nil {
			bm.ipIsV6 = true
			bm.ipIsV4 = false
		}
	}

	// Precompute unique CIDR networks used by rules applicable to the detected family
	for _, r := range rules {
		if bm.ipIsV4 && !r.IPv4 {
			continue
		}

		if bm.ipIsV6 && !r.IPv6 {
			continue
		}

		if _, ok := bm.netByCIDR[r.CIDR]; ok {
			continue
		}

		if _, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", bm.clientIP, r.CIDR)); err == nil && n != nil {
			bm.netByCIDR[r.CIDR] = n
		}
	}
}

// getPasswordHistoryRedisHashKey generates the Redis hash key for password history storage based on username and client IP.
func (bm *bucketManagerImpl) getPasswordHistoryRedisHashKey(withUsername bool) (key string) {
	// Normalize the IP for the repeating-wrong-password context (may apply IPv6 CIDR scoping)
	scoped := bm.clientIP
	if bm.scoper != nil {
		scoped = bm.scoper.Scope(ipscoper.ScopeRepeatingWrongPassword, bm.clientIP)
	}

	if withUsername {
		// Prefer explicit accountName; if absent, optionally fall back to username.
		accountName := bm.accountName
		if accountName == "" {
			// If configured and this is a cached-block (alreadyTriggered), do not create
			// per-username PW_HIST entries for unknown accounts to reduce key footprint.
			if config.GetFile().GetBruteForce().GetPWHistKnownAccountsOnlyOnAlreadyTriggered() && bm.alreadyTriggered {
				level.Debug(log.Logger).Log(
					definitions.LogKeyGUID, bm.guid,
					definitions.LogKeyMsg, "Skipping account-scoped PW_HIST for unknown account on cached block",
				)

				return ""
			}

			if bm.username == "" {
				// Skip if neither account nor username is available
				level.Debug(log.Logger).Log(
					definitions.LogKeyGUID, bm.guid,
					definitions.LogKeyMsg, "Skipping getPasswordHistoryRedisHashKey: no accountName or username",
				)

				return ""
			}

			accountName = bm.username
		}

		key = config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(":%s:%s", accountName, scoped)
	} else {
		key = config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHashKey + ":" + scoped
	}

	util.DebugModule(
		definitions.DbgBf,
		definitions.LogKeyGUID, bm.guid,
		definitions.LogKeyClientIP, bm.clientIP,
		"key", key,
	)

	return
}

// getPasswordHistoryTotalRedisKey generates the Redis key for the total counter for password history.
func (bm *bucketManagerImpl) getPasswordHistoryTotalRedisKey(withUsername bool) (key string) {
	// Normalize the IP for the repeating-wrong-password context (may apply IPv6 CIDR scoping)
	scoped := bm.clientIP
	if bm.scoper != nil {
		scoped = bm.scoper.Scope(ipscoper.ScopeRepeatingWrongPassword, bm.clientIP)
	}

	if withUsername {
		// Prefer explicit accountName; if absent, optionally fall back to username.
		accountName := bm.accountName
		if accountName == "" {
			// Respect config to reduce PW_HIST on cached-blocks
			if config.GetFile().GetBruteForce().GetPWHistKnownAccountsOnlyOnAlreadyTriggered() && bm.alreadyTriggered {
				level.Debug(log.Logger).Log(
					definitions.LogKeyGUID, bm.guid,
					definitions.LogKeyMsg, "Skipping account-scoped PW_HIST total for unknown account on cached block",
				)

				return ""
			}

			if bm.username == "" {
				level.Debug(log.Logger).Log(
					definitions.LogKeyGUID, bm.guid,
					definitions.LogKeyMsg, "Skipping getPasswordHistoryTotalRedisKey: no accountName or username",
				)

				return ""
			}

			accountName = bm.username
		}

		key = config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + fmt.Sprintf(":%s:%s", accountName, scoped)
	} else {
		key = config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + ":" + scoped
	}

	util.DebugModule(
		definitions.DbgBf,
		definitions.LogKeyGUID, bm.guid,
		definitions.LogKeyClientIP, bm.clientIP,
		"total_key", key,
	)

	return
}

// checkTooManyPasswordHashes checks if the number of password hashes for a given Redis key exceeds the configured limit.
func (bm *bucketManagerImpl) checkTooManyPasswordHashes(key string) bool {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx)
	defer cancel()

	if length, err := rediscli.GetClient().GetReadHandle().HLen(dCtx, key).Result(); err != nil {
		if !errors2.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Error checking HLen",
				definitions.LogKeyError, err,
			)
		}

		return true
	} else {
		if length > int64(config.GetFile().GetServer().GetMaxPasswordHistoryEntries()) {
			return true
		}
	}

	return false
}

// loadPasswordHistoryFromRedis loads the password history from a Redis hash table using the provided key.
// Updates the passwordHistory of the bucketManagerImpl instance. Logs errors if encountered during the process.
func (bm *bucketManagerImpl) loadPasswordHistoryFromRedis(key string) {
	if key == "" {
		return
	}

	util.DebugModule(definitions.DbgBf, definitions.LogKeyGUID, bm.guid, "load_key", key)

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx)
	defer cancel()

	if passwordHistory, err := rediscli.GetClient().GetReadHandle().HGetAll(dCtx, key).Result(); err != nil {
		if !errors2.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Error loading password history from Redis",
				definitions.LogKeyError, err,
			)
		}

		return
	} else {
		var counterInt int

		if bm.passwordHistory == nil {
			bm.passwordHistory = new(PasswordHistory)
			*bm.passwordHistory = make(PasswordHistory)
		}

		for passwordHash, counter := range passwordHistory {
			if counterInt, err = strconv.Atoi(counter); err != nil {
				if !errors2.Is(err, redis.Nil) {
					level.Error(log.Logger).Log(
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
}

// loadBruteForceBucketCounter loads a brute force bucket counter for the specified rule if the feature is enabled.
// It retrieves the bucket counter from Redis, logs the operation, and updates the in-memory counter mapping for the rule.
func (bm *bucketManagerImpl) loadBruteForceBucketCounter(rule *config.BruteForceRule) {
	if !config.GetFile().HasFeature(definitions.FeatureBruteForce) {
		return
	}

	bucketCounter := new(bruteForceBucketCounter)

	if key := bm.GetBruteForceBucketRedisKey(rule); key != "" {
		util.DebugModule(definitions.DbgBf, definitions.LogKeyGUID, bm.guid, "load_key", key)

		if err := loadBruteForceBucketCounterFromRedis(bm.ctx, key, bucketCounter); err != nil {
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
	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisBruteForceHashKey

	network, err := bm.getNetwork(rule)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Error getting network for brute force rule",
			definitions.LogKeyError, err,
		)
	} else {
		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx)
		defer cancel()

		if err = rediscli.GetClient().GetWriteHandle().HSet(dCtx, key, network.String(), bm.bruteForceName).Err(); err != nil {
			level.Error(log.Logger).Log(
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

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisAffectedAccountsKey

	// First check if the account is already a member
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx)

	isMember, err := rediscli.GetClient().GetReadHandle().SIsMember(dCtx, key, bm.accountName).Result()
	if err != nil {
		if !errors2.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(
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

	dCtx, cancel = util.GetCtxWithDeadlineRedisWrite(bm.ctx)
	defer cancel()

	if err := rediscli.GetClient().GetWriteHandle().SAdd(dCtx, key, bm.accountName).Err(); err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Error adding account to the affected accounts set",
			definitions.LogKeyError, err,
		)
	}
}

// NewBucketManager creates and returns a new instance of BucketManager with the provided context, GUID, and client IP.
func NewBucketManager(ctx context.Context, guid, clientIP string) BucketManager {
	return &bucketManagerImpl{
		ctx:      ctx,
		guid:     guid,
		clientIP: clientIP,
		scoper:   ipscoper.NewIPScoper(),
	}
}

// GetPWHistIPsRedisKey generates the Redis key for storing password history associated with IPs for a specific account.
func GetPWHistIPsRedisKey(accountName string) string {
	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistIPsKey + ":" + accountName

	return key
}

// logBucketRuleDebug logs debug information for a brute force rule, including client IP, rule details, and request counts.
func logBucketRuleDebug(bm *bucketManagerImpl, network *net.IPNet, rule *config.BruteForceRule) {
	util.DebugModule(definitions.DbgBf,
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
	level.Info(log.Logger).Log(
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
	util.DebugModule(
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
func loadBruteForceBucketCounterFromRedis(ctx context.Context, key string, bucketCounter *bruteForceBucketCounter) (err error) {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	// Count Redis roundtrip for bucket counter GET
	stats.GetMetrics().GetRedisRoundtripsTotal().WithLabelValues("get_bucket_counter").Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx)
	defer cancel()

	val, err := rediscli.GetClient().GetReadHandle().Get(dCtx, key).Result()
	if err != nil {
		if errors2.Is(err, redis.Nil) {
			// treat missing as zero
			*bucketCounter = 0

			return nil
		}

		level.Error(log.Logger).Log(
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

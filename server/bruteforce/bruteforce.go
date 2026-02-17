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
	"time"

	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/bruteforce/l1"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/ipscoper"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/dspinhirne/netaddr-go"
	jsoniter "github.com/json-iterator/go"
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

// BlockMessage is the payload for Pub/Sub global synchronization.
type BlockMessage struct {
	Key   string `json:"key"`
	Rule  string `json:"rule"`
	Block bool   `json:"block"`
}

// UpdateL1Cache updates the local L1 decision engine with a global decision.
func UpdateL1Cache(ctx context.Context, key string, block bool, rule string) {
	l1.GetEngine().Set(ctx, key, l1.L1Decision{Blocked: block, Rule: rule}, 0)
}

// BroadcastBlock sends a block event to all Nauthilus instances via Redis Pub/Sub.
func BroadcastBlock(ctx context.Context, redisClient rediscli.Client, cfg config.File, key string, rule string) {
	msg := BlockMessage{
		Key:   key,
		Rule:  rule,
		Block: true,
	}

	payload, err := jsoniter.ConfigFastest.Marshal(msg)
	if err != nil {
		return
	}

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
	defer cancel()

	redisClient.GetWriteHandle().Publish(dCtx, definitions.RedisBFBlocksChannel, payload)
}

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

	// GetBucketKeys returns all Redis keys associated with a brute force rule (e.g. for flushing).
	GetBucketKeys(rule *config.BruteForceRule) []string

	// GetSlidingWindowKeys returns the current and previous window keys for a rule.
	GetSlidingWindowKeys(rule *config.BruteForceRule, network *net.IPNet) (currentKey, prevKey string, weight float64)

	// WithUsername sets the username for the bucket manager, typically for tracking or processing account-specific data.
	WithUsername(username string) BucketManager

	// WithPassword sets the password for the current bucket manager instance.
	WithPassword(password secret.Value) BucketManager

	// WithAccountName sets the account name for the BucketManager instance and returns the updated BucketManager.
	WithAccountName(accountName string) BucketManager

	// WithProtocol sets the protocol for the BucketManager instance and returns the updated BucketManager.
	WithProtocol(protocol string) BucketManager

	// WithOIDCCID sets the OIDC Client ID for the BucketManager instance and returns the updated BucketManager.
	WithOIDCCID(oidcCID string) BucketManager

	// WithRWPDecision sets the RWP enforcement decision (true=enforce, false=RWP active).
	WithRWPDecision(enforce bool) BucketManager

	// LoadAllPasswordHistories retrieves password history metrics (counts and existence) for the current account and IP.
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

	// ShouldEnforceBucketUpdate determines whether brute force bucket counters should be increased.
	// It returns true if enforcement is needed (i.e., the password is NOT a repeating wrong password),
	// or false if the request should be tolerated (RWP detected).
	ShouldEnforceBucketUpdate() (bool, error)
}

type bucketManagerImpl struct {
	deps                 BucketManagerDeps
	ctx                  context.Context
	scoper               ipscoper.IPScoper
	parsedIP             net.IP
	guid                 string
	username             string
	password             secret.Value
	clientIP             string
	accountName          string
	bruteForceName       string
	featureName          string
	protocol             string
	oidcCID              string
	bruteForceCounter    map[string]uint
	netByCIDR            map[uint]*net.IPNet
	loginAttempts        uint
	passwordsAccountSeen uint
	passwordsTotalSeen   uint
	alreadyTriggered     bool
	ipIsV4               bool
	ipIsV6               bool
	ipv6Validated        bool
	rwpDecision          *bool
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

// WithRWPDecision sets the cached RWP enforcement decision (true=enforce, false=RWP active).
func (bm *bucketManagerImpl) WithRWPDecision(enforce bool) BucketManager {
	bm.rwpDecision = &enforce

	return bm
}

// GetBruteForceCounter retrieves the brute force counter map, tracking attempts by their respective identifiers.
func (bm *bucketManagerImpl) GetBruteForceCounter() map[string]uint {
	return bm.bruteForceCounter
}

// GetBruteForceBucketRedisKey generates a Redis base key for a brute force rule.
func (bm *bucketManagerImpl) GetBruteForceBucketRedisKey(rule *config.BruteForceRule) (key string) {
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

	key = bm.getBruteForceBucketBaseKey(rule, network)

	logBruteForceRuleRedisKeyDebug(bm, rule, network, key)

	return key
}

// GetBucketKeys returns all Redis keys (current and previous window) for a rule.
func (bm *bucketManagerImpl) GetBucketKeys(rule *config.BruteForceRule) []string {
	network, err := bm.getNetwork(rule)
	if err != nil || network == nil {
		return nil
	}

	cur, prev, _ := bm.getSlidingWindowKeys(rule, network)

	return []string{cur, prev}
}

func (bm *bucketManagerImpl) GetSlidingWindowKeys(rule *config.BruteForceRule, network *net.IPNet) (currentKey, prevKey string, weight float64) {
	return bm.getSlidingWindowKeys(rule, network)
}

func (bm *bucketManagerImpl) getSlidingWindowKeys(rule *config.BruteForceRule, network *net.IPNet) (currentKey, prevKey string, weight float64) {
	if rule == nil || network == nil {
		return
	}

	baseKey := bm.getBruteForceBucketBaseKey(rule, network)
	period := int64(math.Round(rule.Period.Seconds()))

	if period <= 0 {
		period = 1
	}

	now := time.Now().Unix()
	currentWindow := now / period
	prevWindow := currentWindow - 1

	currentKey = fmt.Sprintf("%s:win:%d", baseKey, currentWindow)
	prevKey = fmt.Sprintf("%s:win:%d", baseKey, prevWindow)

	weight = 1.0 - (float64(now%period) / float64(period))

	return
}

func (bm *bucketManagerImpl) getBruteForceBucketBaseKey(rule *config.BruteForceRule, network *net.IPNet) string {
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

	return sb.String()
}

func (bm *bucketManagerImpl) WithUsername(username string) BucketManager {
	bm.username = username

	return bm
}

// WithPassword sets the password for the bucketManager instance.
func (bm *bucketManagerImpl) WithPassword(password secret.Value) BucketManager {
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

// LoadAllPasswordHistories loads and processes password history metrics (counts) and checks for current password presence.
func (bm *bucketManagerImpl) LoadAllPasswordHistories() {
	if !bm.cfg().HasFeature(definitions.FeatureBruteForce) {
		return
	}

	tr := monittrace.New("nauthilus/bruteforce")
	_, sp := tr.Start(bm.ctx, "bruteforce.load_all_password_histories",
		attribute.String("username", bm.username),
		attribute.String("client_ip", bm.clientIP),
	)
	defer sp.End()

	// 1) Load account-scoped password history metrics
	bm.passwordsAccountSeen = bm.loadPasswordHistoryCount(true)

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

	// 3) Check if current password was already seen for this account
	if key := bm.getPasswordHistoryRedisSetKey(true); key != "" && !bm.password.IsZero() {
		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		var passwordHash string
		bm.password.WithString(func(value string) {
			if value != "" {
				passwordHash = util.GetHash(util.PreparePassword(value))
			}
		})

		if passwordHash == "" {
			return
		}

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
		if isMember, err := bm.redis().GetReadHandle().SIsMember(dCtx, key, passwordHash).Result(); err == nil && isMember {
			bm.loginAttempts = 1
		}
		cancel()
	}

	// 4) Load IP-only (overall) password history metrics
	bm.passwordsTotalSeen = bm.loadPasswordHistoryCount(false)
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

	sp.SetAttributes(attribute.String("ip_family", ipFamily))

	// Ensure IP/net precalc is available for L1 engine check
	bm.PrepareNetcalc(rules)

	// L1 Decision Engine fast path: reuse a very recent decision for identical semantic request key.
	_, msp := tr.Start(bm.ctx, "auth.bruteforce.repeating_check.l1_engine")
	dec, ok := l1.GetEngine().Get(bm.ctx, l1.KeyBurst(bm.bfBurstKey()))
	if !ok {
		// Try network-based L1 check if available
		for i := range rules {
			if n, nErr := bm.getNetwork(&rules[i]); nErr == nil && n != nil {
				if d, okNet := l1.GetEngine().Get(bm.ctx, l1.KeyNetwork(n.String())); okNet && d.Blocked {
					dec = d
					ok = true
					break
				}
			}
		}
	}

	if ok && dec.Blocked {
		sp.SetAttributes(attribute.Bool("micro_cache.hit", true))

		// find rule index by name to keep downstream behavior intact
		for i := range rules {
			if rules[i].Name == dec.Rule {
				if n, nErr := bm.getNetwork(&rules[i]); nErr == nil {
					if n != nil {
						*network = n
					}
				}

				bm.bruteForceName = dec.Rule
				*message = "Brute force attack detected (L1 engine)"
				stats.GetMetrics().GetBruteForceCacheHitsTotal().WithLabelValues("micro").Inc()
				sp.SetAttributes(
					attribute.Bool("triggered", true),
					attribute.String("rule", dec.Rule),
					attribute.Int("rule.index", i),
				)

				return false, true, i
			}
		}
	}
	msp.End()

	sp.SetAttributes(attribute.Bool("micro_cache.hit", false))

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

	// If we have candidates, issue a pipeline of EXISTS on ban keys to find the first hit
	if len(candidates) > 0 {
		fields := make([]string, len(candidates))
		for i, c := range candidates {
			fields[i] = c.field
		}

		cmds, errPipe := bm.pipelineExistsBanKeys(bm.ctx, fields, "pipeline_exists_ban_preresult")
		if errPipe != nil && !errors2.Is(errPipe, redis.Nil) {
			// Fail-open: treat as no pre-result
			level.Warn(logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, fmt.Sprintf("Pipeline EXISTS ban-key failed: %v", errPipe))
		} else {
			for i, cmd := range cmds {
				exists, err := cmd.Result()
				if err != nil || exists == 0 {
					continue
				}

				// Ban key exists — this network is currently banned.
				alreadyTriggered = true
				ruleName = rules[candidates[i].idx].Name
				bm.bruteForceName = ruleName
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

	// If no EXISTS hit, fall through to no pre-result

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

	// Propagate span context to all downstream operations inside this method.
	prevCtx := bm.ctx
	bm.ctx = ctx
	defer func() {
		bm.ctx = prevCtx
	}()

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
		idx     int
		network *net.IPNet
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
		cands = append(cands, bkcand{idx: i, network: n})
	}

	gatherSpan.SetAttributes(
		attribute.Bool("rules.matched_any", matchedAnyRule),
		attribute.Int("candidates.total", len(cands)),
	)
	gatherSpan.End()

	if len(cands) > 0 {
		scriptSHA, errUpload := rediscli.UploadScript(bm.ctx, bm.redis(), "SlidingWindowCounter", rediscli.LuaScripts["SlidingWindowCounter"])
		if errUpload != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Failed to upload SlidingWindowCounter script",
				definitions.LogKeyError, errUpload,
			)

			return true, false, -1
		}

		// Reputation key for the client IP and adaptive scaling configuration
		_, adaptiveEnabled, minPct, maxPct, scaleFactor, staticPct, positive := bm.getAdaptiveScalingConfig()

		// Redis Cluster: we use a pipeline to execute the script for each candidate.
		defer stats.GetMetrics().GetRedisReadCounter().Inc()
		stats.GetMetrics().GetRedisRoundtripsTotal().WithLabelValues("pipeline_eval_bucket_counter").Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
		pipe := bm.redis().GetReadHandle().Pipeline()
		cmds := make([]*redis.Cmd, 0, len(cands))

		for _, c := range cands {
			rule := &rules[c.idx]
			currentKey, prevKey, weight := bm.getSlidingWindowKeys(rule, c.network)
			ttl := int64(math.Round(rule.Period.Seconds() * 2))
			// We check if (total + 1) > FailedRequests to match legacy behavior
			// Or we just pass the limit and adjust the script/call.
			// Let's pass (limit - 1) as the limit to the script if we want to block the Nth attempt.
			limit := int64(rule.FailedRequests) - 1

			// rwp_floor = 0: read-only check path must never modify counters
			cmds = append(cmds, pipe.EvalSha(dCtx, scriptSHA, []string{currentKey, prevKey},
				0, weight, ttl, limit,
				adaptiveEnabled, minPct, maxPct, scaleFactor, staticPct, positive, 0))
		}

		_, errP := pipe.Exec(dCtx)

		cancel()

		if errP != nil && !errors2.Is(errP, redis.Nil) {
			level.Warn(logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, fmt.Sprintf("Pipeline EVAL bucket counters failed: %v", errP))
		}

		if bm.bruteForceCounter == nil {
			bm.bruteForceCounter = make(map[string]uint)
		}

		for i, cmd := range cmds {
			res, err := cmd.Result()
			if err != nil {
				continue
			}

			if resParts, ok := res.([]interface{}); ok && len(resParts) >= 2 {
				totalStr, _ := resParts[0].(string)
				exceeded, _ := resParts[1].(int64)

				totalFloat, _ := strconv.ParseFloat(totalStr, 64)
				total := uint(math.Round(totalFloat))

				name := rules[cands[i].idx].Name
				bm.bruteForceCounter[name] = total

				if exceeded == 1 {
					ruleTriggered = true
					ruleNumber = cands[i].idx
					bm.bruteForceName = name
					*message = "Brute force attack detected"

					stats.GetMetrics().GetBruteForceRejected().WithLabelValues(bm.bruteForceName).Inc()

					effectiveLimit := ""
					if len(resParts) >= 3 {
						effectiveLimit, _ = resParts[2].(string)
					}

					sp.SetAttributes(
						attribute.Bool("triggered", true),
						attribute.String("rule", bm.bruteForceName),
						attribute.Int("rule.index", ruleNumber),
						attribute.Int64("count", int64(total)),
						attribute.String("effective_limit", effectiveLimit),
					)

					return false, true, ruleNumber
				}
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

		// capture context flag for downstream operations (e.g., PW_HIST behavior)
		bm.alreadyTriggered = alreadyTriggered

		// Ensure the brute-force counter for this rule is loaded for downstream consumers (e.g., Lua/ClickHouse)
		bm.loadBruteForceBucketCounter(rule)

		defer setter()
		defer bm.LoadAllPasswordHistories()

		logBucketRuleDebug(bm, network, rule)

		// RWP allowance is handled during early checks and bucket updates. Once a rule is triggered,
		// we always enforce here to ensure ban keys and indices are written consistently.

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
			banActive, err := bm.setPreResultBruteForceRedis(rule)
			if err != nil || !banActive {
				return false
			}

			// Broadcast both the user-specific burst block and the network-wide block
			BroadcastBlock(bm.ctx, bm.redis(), bm.cfg(), l1.KeyBurst(bm.bfBurstKey()), bm.bruteForceName)
			if network != nil {
				BroadcastBlock(bm.ctx, bm.redis(), bm.cfg(), l1.KeyNetwork(network.String()), bm.bruteForceName)
			}
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

		// Store L1 decision for a very short time to absorb bursts (read-path only)
		l1.GetEngine().Set(bm.ctx, l1.KeyBurst(bm.bfBurstKey()), l1.L1Decision{Blocked: true, Rule: bm.bruteForceName}, 0)

		sp.SetAttributes(attribute.Bool("triggered", true))

		return true
	}

	// Also cache negative decision (allow) to avoid immediate redundant HMGET/MGET for identical attempts
	l1.GetEngine().Set(bm.ctx, l1.KeyBurst(bm.bfBurstKey()), l1.L1Decision{Blocked: false, Rule: ""}, 0)

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

	accountName = bm.resolveAccountNameForHistory()
	if accountName == "" {
		return
	}

	bm.updateAffectedAccount()

	key := GetPWHistIPsRedisKey(accountName, bm.cfg())

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())

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
	currentKey, prevKey, weight, ok := bm.prepareSlidingWindow(rule)
	if !ok {
		return
	}

	util.DebugModuleWithCfg(bm.ctx, bm.cfg(), bm.logger(), definitions.DbgBf, definitions.LogKeyGUID, bm.guid, "store_key", currentKey)

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())
	defer cancel()

	// Reputation key for the client IP and adaptive scaling configuration
	_, adaptiveEnabled, minPct, maxPct, scaleFactor, staticPct, positive := bm.getAdaptiveScalingConfig()

	// Only increment if not already triggered by this rule
	increment := 0
	if bm.bruteForceName != rule.Name {
		increment = 1
	}

	ttl := int64(math.Round(rule.Period.Seconds() * 2))
	limit := int64(rule.FailedRequests) - 1

	// Determine RWP catch-up floor: when the bucket counter is below the RWP threshold,
	// the Lua script will bring it up before the normal increment to compensate for
	// attempts that were tolerated during the RWP grace period.
	rwpFloor := 0
	if increment > 0 {
		if bfCfg := bm.cfg().GetBruteForce(); bfCfg != nil {
			rwpFloor = int(bfCfg.GetRWPAllowedUniqueHashes())
		}
	}

	// Limit is not needed for Save in terms of triggering here, but we pass it anyway
	// to maintain script logic.
	_, err := rediscli.ExecuteScript(dCtx, bm.redis(), "SlidingWindowCounter", rediscli.LuaScripts["SlidingWindowCounter"],
		[]string{currentKey, prevKey},
		increment, weight, ttl, limit,
		adaptiveEnabled, minPct, maxPct, scaleFactor, staticPct, positive, rwpFloor)

	stats.GetMetrics().GetRedisWriteCounter().Inc()

	if err != nil {
		level.Error(bm.logger()).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to update brute force bucket via Lua",
			definitions.LogKeyError, err,
		)
	}
}

// SaveFailedPasswordCounterInRedis adds the failed password hash to a Redis set for brute force protection.
func (bm *bucketManagerImpl) SaveFailedPasswordCounterInRedis() {
	if !bm.cfg().HasFeature(definitions.FeatureBruteForce) {
		return
	}

	if bm.clientIP == "" {
		return
	}

	logger := bm.logger()

	if bm.password.IsZero() {
		level.Debug(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Skipping SaveFailedPasswordCounterInRedis: password is empty",
		)

		return
	}

	var passwordHash string
	bm.password.WithString(func(value string) {
		if value != "" {
			passwordHash = util.GetHash(util.PreparePassword(value))
		}
	})
	if passwordHash == "" {
		return
	}
	ttl := bm.cfg().GetServer().GetRedis().GetNegCacheTTL()
	maxEntries := bm.cfg().GetServer().GetMaxPasswordHistoryEntries()

	// Keys for set-based history (with and without username)
	keys := []string{
		bm.getPasswordHistoryRedisSetKey(true),
		bm.getPasswordHistoryRedisSetKey(false),
	}

	for _, key := range keys {
		if key == "" {
			continue
		}

		util.DebugModuleWithCfg(bm.ctx, bm.cfg(), bm.logger(), definitions.DbgBf, definitions.LogKeyGUID, bm.guid, "set_key", key)

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())
		// We use a simple script to add to set and expire, but also respect maxEntries if possible.
		// Since it's now a Set, we don't track counters per password, just existence.
		res, err := rediscli.ExecuteScript(dCtx, bm.redis(), "AddToSetAndExpireLimit", rediscli.LuaScripts["AddToSetAndExpireLimit"], []string{key}, passwordHash, strconv.FormatInt(int64(ttl.Seconds()), 10), strconv.Itoa(int(maxEntries)))
		cancel()

		stats.GetMetrics().GetRedisWriteCounter().Add(1)

		if err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Failed to update failed password set via Lua",
				definitions.LogKeyError, err,
			)

			return
		}

		if val, ok := res.(int64); ok && val == 0 {
			level.Info(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Too many password hashes for this account (set limit reached)",
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
	redisClient := bm.redis()
	logger := bm.logger()

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

	// Resolve network
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

	networkStr := network.String()
	banKey := rediscli.GetBruteForceBanKey(prefix, networkStr)

	// Read current ban value (bucket name) to verify match
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtxR, cancelR := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
	current, err := redisClient.GetReadHandle().Get(dCtxR, banKey).Result()
	cancelR()

	if err != nil && !errors2.Is(err, redis.Nil) {
		return "", err
	}

	// Delete if the stored bucket matches the requested rule name, or if wildcard "*" is used.
	if current == ruleName || ruleName == "*" {
		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())
		defer cancel()

		if removed, delErr := redisClient.GetWriteHandle().Del(dCtx, banKey).Result(); delErr != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Failed to delete brute force ban key",
				definitions.LogKeyError, delErr,
			)
		} else if removed > 0 {
			removedKey = banKey

			// Remove from ZSET ban index
			bm.removeBanFromIndex(dCtx, prefix, networkStr, logger)
		}

		return removedKey, nil
	}

	return removedKey, nil
}

// removeBanFromIndex removes a network from the sharded ZSET ban index.
func (bm *bucketManagerImpl) removeBanFromIndex(ctx context.Context, prefix, networkStr string, logger *slog.Logger) {
	shard := rediscli.GetBanIndexShard(networkStr)
	shardKey := rediscli.GetBruteForceBanIndexShardKey(prefix, shard)

	if err := bm.redis().GetWriteHandle().ZRem(ctx, shardKey, networkStr).Err(); err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Error removing network from ban index ZSET",
			definitions.LogKeyError, err,
		)
	}
}

// IsIPAddressBlocked determines if the client's IP address is blocked based on brute force rules.
// It returns a list of bucket names where the IP is detected and a boolean indicating if any blocks are found.
func (bm *bucketManagerImpl) IsIPAddressBlocked() (buckets []string, found bool) {
	if bm.clientIP == "" {
		return nil, false
	}

	tr := monittrace.New("nauthilus/bruteforce")
	ctx, sp := tr.Start(bm.ctx, "bruteforce.is_ip_blocked", attribute.String("client_ip", bm.clientIP))
	defer sp.End()

	buckets = make([]string, 0)
	rules := bm.cfg().GetBruteForce().Buckets

	// Build candidate networks and batch EXISTS on ban keys
	type fieldRef struct {
		name, network string
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

		refs = append(refs, fieldRef{name: rules[i].Name, network: n.String()})
	}

	if len(refs) == 0 {
		return buckets, false
	}

	networks := make([]string, len(refs))

	for i, r := range refs {
		networks[i] = r.network
	}

	cmds, err := bm.pipelineExistsBanKeys(ctx, networks, "pipeline_exists_ban_is_blocked")

	if err != nil && !errors2.Is(err, redis.Nil) {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed pipeline EXISTS in IsIPAddressBlocked",
			definitions.LogKeyError, err,
		)

		return buckets, false
	}

	for i, cmd := range cmds {
		exists, err := cmd.Result()
		if err != nil || exists == 0 {
			continue
		}

		buckets = append(buckets, refs[i].name)
	}

	sp.SetAttributes(attribute.Int("blocked_buckets_count", len(buckets)))

	return buckets, len(buckets) > 0
}

// pipelineExistsBanKeys checks existence of ban keys for the given networks via a Redis pipeline.
// Returns one BoolCmd per network indicating whether an active ban exists.
func (bm *bucketManagerImpl) pipelineExistsBanKeys(ctx context.Context, networks []string, metricLabel string) ([]*redis.IntCmd, error) {
	if len(networks) == 0 {
		return nil, nil
	}

	prefix := bm.cfg().GetServer().GetRedis().GetPrefix()

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	if metricLabel != "" {
		stats.GetMetrics().GetRedisRoundtripsTotal().WithLabelValues(metricLabel).Inc()
	}

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, bm.cfg())
	defer cancel()

	pipe := bm.redis().GetReadHandle().Pipeline()
	cmds := make([]*redis.IntCmd, len(networks))

	for i, n := range networks {
		banKey := rediscli.GetBruteForceBanKey(prefix, n)
		cmds[i] = pipe.Exists(dCtx, banKey)
	}

	_, err := pipe.Exec(dCtx)

	return cmds, err
}

var _ BucketManager = (*bucketManagerImpl)(nil)

// ShouldEnforceBucketUpdate determines whether brute force bucket counters should be increased.
// It delegates to the internal checkEnforceBruteForceComputation logic which evaluates RWP.
func (bm *bucketManagerImpl) ShouldEnforceBucketUpdate() (bool, error) {
	enforce, err := bm.checkEnforceBruteForceComputation()
	if err != nil {
		return false, err
	}

	bm.rwpDecision = &enforce

	return enforce, nil
}

// isRepeatingWrongPassword implements the RWP allowance logic.
// It returns true if the current wrong password should be tolerated (i.e., buckets should NOT be increased),
// based on allowing up to N distinct wrong password hashes within a rolling window. Repeats of already seen
// hashes are always tolerated within the window.
func (bm *bucketManagerImpl) isRepeatingWrongPassword() (repeating bool, err error) {
	logger := bm.logger()

	if bm.password.IsZero() {
		level.Debug(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Skipping isRepeatingWrongPassword: password is empty",
		)

		return false, nil
	}

	var passwordHash string
	bm.password.WithString(func(value string) {
		if value != "" {
			passwordHash = util.GetHash(util.PreparePassword(value))
		}
	})
	if passwordHash == "" {
		return false, nil
	}

	// Build scope (IP scoping may reduce IPv6 precision) and account identifier
	scoped := bm.clientIP
	if bm.scoper != nil {
		scoped = bm.scoper.Scope(ipscoper.ScopeRepeatingWrongPassword, bm.clientIP)
	}

	acct := ""
	if bm.username != "" {
		acct = accountcache.GetAccountMappingField(bm.username, bm.protocol, bm.oidcCID)
	}
	if acct == "" {
		acct = bm.accountName
	}
	if acct == "" {
		return false, nil
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
	sb.WriteString(definitions.RedisBFRWPAllowPrefix)
	sb.WriteString(scoped)
	sb.WriteByte(':')
	sb.WriteString(acct)

	allowKey := sb.String()

	// Atomically check/add using Lua script
	argThreshold := strconv.FormatUint(uint64(threshold), 10)
	argTTL := strconv.FormatInt(int64(ttl.Seconds()), 10)
	argNow := strconv.FormatInt(time.Now().Unix(), 10)

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
	res, execErr := rediscli.ExecuteScript(
		dCtx,
		bm.redis(),
		"RWPSlidingWindow",
		rediscli.LuaScripts["RWPSlidingWindow"],
		[]string{allowKey},
		passwordHash, argNow, argTTL, argThreshold,
	)
	cancel()

	if execErr != nil {
		// Fallback heuristic: use PW_HIST_TOTAL counters vs. current hash counter.
		// If totals equal the current hash count, treat as repeating within window.
		level.Warn(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, fmt.Sprintf("RWPSlidingWindow script error, using totals fallback: %v", execErr),
		)

		// Read account-scoped hash map to get current counter
		acctKey := bm.getPasswordHistoryRedisSetKey(true)
		if acctKey == "" {
			return false, nil
		}

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel = util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
		isMember, _ := bm.redis().GetReadHandle().SIsMember(dCtx, acctKey, passwordHash).Result()
		cancel()

		if isMember {
			return true, nil
		}

		// Read totals (fallback if SISMEMBER failed or for older consistency checks)
		// We no longer track per-password counters in hashes, so we just return false (not repeating)
		// if SISMEMBER (checked above) returned false. The totals are kept for observability elsewhere.
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
	/*
		- If a user exists (known account), then check for repeating wrong password.
		  - If it is a repeating wrong password, then skip increasing buckets.
		- Otherwise, or if the user is unknown, enforce the brute forcing computation (increase buckets).

		- On any error that might occur during these checks, do NOT increase buckets (fail safe).
	*/

	if bm.accountName == "" {
		return true, nil
	}

	repeating, err := bm.isRepeatingWrongPassword()
	if err != nil {
		return false, err
	}

	if repeating {
		return false, nil
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

	// Populate parsedIP for internal use
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

			// Store in netByCIDR using the standard library net.IPNet format
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

	if withUsername {
		accountName := bm.resolveAccountNameForHistory()
		if accountName == "" {
			return ""
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

// getPasswordHistoryRedisSetKey generates the Redis set key for password history storage based on username and client IP.
func (bm *bucketManagerImpl) getPasswordHistoryRedisSetKey(withUsername bool) (key string) {
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

// loadBruteForceBucketCounter loads a brute force bucket counter for the specified rule if the feature is enabled.
// It retrieves the bucket counter from Redis, logs the operation, and updates the in-memory counter mapping for the rule.
func (bm *bucketManagerImpl) loadBruteForceBucketCounter(rule *config.BruteForceRule) {
	tr := monittrace.New("nauthilus/bruteforce")
	ctx, sp := tr.Start(bm.ctx, "bruteforce.load_bucket_counter", attribute.String("rule", rule.Name))
	defer sp.End()

	currentKey, prevKey, weight, ok := bm.prepareSlidingWindow(rule)
	if !ok {
		return
	}

	util.DebugModuleWithCfg(ctx, bm.cfg(), bm.logger(), definitions.DbgBf, definitions.LogKeyGUID, bm.guid, "load_key", currentKey)

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, bm.cfg())
	defer cancel()

	// Reputation key for the client IP and adaptive scaling configuration
	_, adaptiveEnabled, minPct, maxPct, scaleFactor, staticPct, positive := bm.getAdaptiveScalingConfig()

	ttl := int64(math.Round(rule.Period.Seconds() * 2))
	limit := int64(rule.FailedRequests) - 1

	res, err := rediscli.ExecuteScript(dCtx, bm.redis(), "SlidingWindowCounter", rediscli.LuaScripts["SlidingWindowCounter"],
		[]string{currentKey, prevKey},
		0, weight, ttl, limit,
		adaptiveEnabled, minPct, maxPct, scaleFactor, staticPct, positive)

	stats.GetMetrics().GetRedisReadCounter().Inc()

	if err != nil {
		level.Error(bm.logger()).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to load brute force bucket via Lua",
			definitions.LogKeyError, err,
		)

		return
	}

	total := uint(0)
	if resParts, ok := res.([]interface{}); ok && len(resParts) > 0 {
		if totalStr, ok := resParts[0].(string); ok {
			totalFloat, _ := strconv.ParseFloat(totalStr, 64)
			total = uint(math.Round(totalFloat))
		}
	}

	sp.SetAttributes(attribute.Int64("total", int64(total)))

	if bm.bruteForceCounter == nil {
		bm.bruteForceCounter = make(map[string]uint)
	}

	bm.bruteForceCounter[rule.Name] = total
}

// setPreResultBruteForceRedis stores a brute force ban in Redis as a dedicated per-network key with TTL.
// It uses SET NX EX to avoid race conditions in multi-instance deployments and maintains a sharded ZSET index.
// It returns whether a ban is active (created or already present) and any error encountered.
func (bm *bucketManagerImpl) setPreResultBruteForceRedis(rule *config.BruteForceRule) (bool, error) {
	tr := monittrace.New("nauthilus/bruteforce")
	ctx, sp := tr.Start(bm.ctx, "bruteforce.set_pre_result", attribute.String("rule", rule.Name))
	defer sp.End()

	prefix := bm.cfg().GetServer().GetRedis().GetPrefix()
	logger := bm.logger()

	network, err := bm.getNetwork(rule)
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Error getting network for brute force rule",
			definitions.LogKeyError, err,
		)

		return false, err
	}

	networkStr := network.String()
	banKey := rediscli.GetBruteForceBanKey(prefix, networkStr)
	banTTL := rule.GetBanTime()

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, bm.cfg())
	defer cancel()

	// SET NX EX: only set if no active ban exists for this network (multi-instance safe).
	set, err := bm.redis().GetWriteHandle().SetNX(dCtx, banKey, bm.bruteForceName, banTTL).Result()
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Error setting brute force ban key in Redis",
			definitions.LogKeyError, err,
		)

		// Verify whether the ban key exists despite the write error.
		stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtxR, cancelR := util.GetCtxWithDeadlineRedisRead(ctx, bm.cfg())
		defer cancelR()

		exists, existsErr := bm.redis().GetReadHandle().Exists(dCtxR, banKey).Result()
		if existsErr != nil && !errors2.Is(existsErr, redis.Nil) {
			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Error verifying brute force ban key in Redis",
				definitions.LogKeyError, existsErr,
			)
		}

		if existsErr == nil && exists > 0 {
			return true, nil
		}

		return false, err
	}

	if !set {
		// Ban already exists — nothing to do.
		return true, nil
	}

	// Best-effort: add network to sharded ZSET index.
	bm.addBanToIndex(dCtx, prefix, networkStr, logger)

	return true, nil
}

// addBanToIndex adds a network to the sharded ZSET ban index (best-effort, not atomic with the ban key).
func (bm *bucketManagerImpl) addBanToIndex(ctx context.Context, prefix, networkStr string, logger *slog.Logger) {
	shard := rediscli.GetBanIndexShard(networkStr)
	shardKey := rediscli.GetBruteForceBanIndexShardKey(prefix, shard)
	score := float64(time.Now().Unix())

	if err := bm.redis().GetWriteHandle().ZAddNX(ctx, shardKey, redis.Z{Score: score, Member: networkStr}).Err(); err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Error adding network to ban index ZSET",
			definitions.LogKeyError, err,
		)
	}
}

// updateAffectedAccount processes a blocked account by checking its existence in Redis and adding it if not present.
// It increments Redis read and write counters and logs errors encountered during the operations.
func (bm *bucketManagerImpl) updateAffectedAccount() {
	accountName := bm.resolveAccountNameForHistory()
	if accountName == "" {
		return
	}

	tr := monittrace.New("nauthilus/bruteforce")
	ctx, sp := tr.Start(bm.ctx, "bruteforce.update_affected_account", attribute.String("account", accountName))
	defer sp.End()

	key := bm.cfg().GetServer().GetRedis().GetPrefix() + definitions.RedisAffectedAccountsKey
	logger := bm.logger()

	rwpActive, err := bm.isRWPActive()
	if err != nil {
		level.Warn(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to evaluate RWP decision for affected accounts",
			definitions.LogKeyError, err,
		)

		return
	}

	if rwpActive {
		return
	}

	// First check if the account is already a member
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, bm.cfg())

	isMember, err := bm.redis().GetReadHandle().SIsMember(dCtx, key, accountName).Result()
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

	dCtx, cancel = util.GetCtxWithDeadlineRedisWrite(ctx, bm.cfg())
	defer cancel()

	if err := bm.redis().GetWriteHandle().SAdd(dCtx, key, accountName).Err(); err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Error adding account to the affected accounts set",
			definitions.LogKeyError, err,
		)
	}
}

func (bm *bucketManagerImpl) isRWPActive() (bool, error) {
	if bm.rwpDecision != nil {
		return !*bm.rwpDecision, nil
	}

	enforce, err := bm.checkEnforceBruteForceComputation()
	if err != nil {
		return false, err
	}

	bm.rwpDecision = &enforce

	return !enforce, nil
}

func (bm *bucketManagerImpl) resolveAccountNameForHistory() string {
	accountName := bm.accountName
	if accountName != "" {
		return accountName
	}

	cfg := bm.cfg()
	logger := bm.logger()

	if cfg.GetBruteForce().GetPWHistKnownAccountsOnlyOnAlreadyTriggered() && bm.alreadyTriggered {
		level.Debug(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Skipping account-scoped PW_HIST for unknown account on cached block",
		)

		return ""
	}

	level.Debug(logger).Log(
		definitions.LogKeyGUID, bm.guid,
		definitions.LogKeyMsg, "Skipping account-scoped history: no accountName",
	)

	return ""
}

func (bm *bucketManagerImpl) loadPasswordHistoryCount(isAccountScoped bool) uint {
	if key := bm.getPasswordHistoryRedisSetKey(isAccountScoped); key != "" {
		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
		defer cancel()

		if count, err := bm.redis().GetReadHandle().SCard(dCtx, key).Result(); err == nil {
			return uint(count)
		}
	}

	return 0
}

func (bm *bucketManagerImpl) getAdaptiveScalingConfig() (repKey string, adaptiveEnabled int, minPct, maxPct uint8, scaleFactor float64, staticPct uint8, positive int64) {
	if bm.tolerate() != nil {
		repKey = bm.tolerate().GetReputationKey(bm.clientIP)

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
		defer cancel()

		if val, err := bm.redis().GetReadHandle().HGet(dCtx, repKey, "positive").Int64(); err == nil {
			positive = val
		}
	}

	bfCfg := bm.cfg().GetBruteForce()
	scaleFactor = 1.0

	if bfCfg != nil {
		if bfCfg.GetAdaptiveToleration() {
			adaptiveEnabled = 1
		}

		minPct = bfCfg.GetMinToleratePercent()
		maxPct = bfCfg.GetMaxToleratePercent()
		scaleFactor = bfCfg.GetScaleFactor()
		staticPct = bfCfg.GetToleratePercent()
	}

	return
}

func (bm *bucketManagerImpl) prepareSlidingWindow(rule *config.BruteForceRule) (currentKey, prevKey string, weight float64, ok bool) {
	if !bm.cfg().HasFeature(definitions.FeatureBruteForce) {
		return
	}

	network, err := bm.getNetwork(rule)
	if err != nil {
		level.Error(bm.logger()).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to get network for brute force rule",
			definitions.LogKeyError, err,
		)

		return
	}

	currentKey, prevKey, weight = bm.getSlidingWindowKeys(rule, network)
	if currentKey == "" {
		return
	}

	ok = true

	return
}

// BucketManagerDeps bundles dependencies for BucketManager.
type BucketManagerDeps struct {
	Cfg      config.File
	Logger   *slog.Logger
	Redis    rediscli.Client
	Tolerate tolerate.Tolerate
}

// NewBucketManagerWithDeps creates a new BucketManager instance.
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

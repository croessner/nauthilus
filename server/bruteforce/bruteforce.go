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

// Package bruteforce provides bruteforce functionality.
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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/bruteforce/l1"
	"github.com/croessner/nauthilus/v3/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
	internalpasswordhash "github.com/croessner/nauthilus/v3/server/internal/passwordhash"
	"github.com/croessner/nauthilus/v3/server/ipscoper"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"

	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/dspinhirne/netaddr-go"
	jsoniter "github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/singleflight"
)

const (
	ipFamilyIPv4    = "ipv4"
	ipFamilyIPv6    = "ipv6"
	ipFamilyUnknown = "unknown"
)

// containsString reports whether s is present in the slice.
// Kept unexported and simple to avoid allocations and stay DRY for common membership checks.
func containsString(ss []string, s string) bool {
	return slices.Contains(ss, s)
}

// BlockMessage is the payload for Pub/Sub global synchronization.
type BlockMessage struct {
	Key   string `json:"key"`
	Rule  string `json:"rule"`
	Block bool   `json:"block"`
}

// UpdateL1Cache updates the local L1 decision engine with a global decision.
func UpdateL1Cache(ctx context.Context, key string, block bool, rule string) {
	l1.GetEngine().Set(ctx, key, l1.Decision{Blocked: block, Rule: rule}, 0)
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

	// GetEnvironmentName returns the name "brute_force" if the system triggered.
	GetEnvironmentName() string

	// GetBruteForceName retrieves the name associated with the specific brute force bucket that triggered.
	GetBruteForceName() string

	// GetBruteForceCounter returns a map containing brute force detection counters associated with specific criteria or keys.
	GetBruteForceCounter() map[string]uint

	// GetBucketPolicyFacts returns the last collected policy facts for configured brute-force buckets.
	GetBucketPolicyFacts() []BucketPolicyFact

	// GetTolerationPolicyFact returns the last collected toleration policy fact.
	GetTolerationPolicyFact() tolerate.PolicyFact

	// CollectBucketPolicyFacts reads current bucket state for policy evaluation without modifying counters.
	CollectBucketPolicyFacts(rules []config.BruteForceRule) ([]BucketPolicyFact, error)

	// GetBruteForceBucketRedisKey generates and returns the Redis key for tracking the brute force bucket associated with the given rule.
	GetBruteForceBucketRedisKey(rule *config.BruteForceRule) (key string)

	// GetBruteForceBanRedisKey returns the Redis ban key and normalized network for a rule.
	GetBruteForceBanRedisKey(rule *config.BruteForceRule) (key string, network string, err error)

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

	// CommitRWPSlidingWindow writes the current password hash into the RWP sliding window in Redis.
	// This must only be called after confirming that the rejection was due to a genuine authentication
	// failure, not a environment-based rejection (e.g., RBL) where the password was never verified.
	CommitRWPSlidingWindow()
}

// BucketPolicyFact is the read-only policy view of one configured brute-force bucket.
type BucketPolicyFact struct {
	Name           string
	ClientNet      string
	Count          float64
	Limit          float64
	EffectiveLimit float64
	Remaining      float64
	Ratio          float64
	Period         time.Duration
	BanTime        time.Duration
	CIDR           uint
	Matched        bool
	OverLimit      bool
	AlreadyBanned  bool
	Repeating      bool
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
	environmentName      string
	protocol             string
	oidcCID              string
	bruteForceCounter    map[string]uint
	bucketPolicyFacts    []BucketPolicyFact
	tolerationPolicyFact tolerate.PolicyFact
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

// sgBurst deduplicates parallel identical burst-gate requests for the same burst key.
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

// GetEnvironmentName returns the name of the environment control managed by the bucketManagerImpl.
func (bm *bucketManagerImpl) GetEnvironmentName() string {
	return bm.environmentName
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

// GetBucketPolicyFacts returns a copy of the last collected brute-force bucket policy facts.
func (bm *bucketManagerImpl) GetBucketPolicyFacts() []BucketPolicyFact {
	if bm == nil || len(bm.bucketPolicyFacts) == 0 {
		return nil
	}

	return append([]BucketPolicyFact(nil), bm.bucketPolicyFacts...)
}

// GetTolerationPolicyFact returns the last collected toleration policy fact.
func (bm *bucketManagerImpl) GetTolerationPolicyFact() tolerate.PolicyFact {
	if bm == nil {
		return tolerate.PolicyFact{}
	}

	return bm.tolerationPolicyFact
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

// GetBruteForceBanRedisKey returns the Redis ban key and normalized network for a rule.
func (bm *bucketManagerImpl) GetBruteForceBanRedisKey(rule *config.BruteForceRule) (key string, network string, err error) {
	if rule == nil {
		return "", "", nil
	}

	resolvedNetwork, err := bm.getNetwork(rule)
	if err != nil {
		return "", "", err
	}

	if resolvedNetwork == nil {
		return "", "", nil
	}

	network = resolvedNetwork.String()
	key = rediscli.GetBruteForceBanKey(bm.cfg().GetServer().GetRedis().GetPrefix(), network)

	return key, network, nil
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

// parsedIPFamily reports the parsed client IP family for tracing attributes.
func (bm *bucketManagerImpl) parsedIPFamily() string {
	switch {
	case bm.parsedIP != nil && bm.parsedIP.To4() != nil:
		return ipFamilyIPv4
	case bm.parsedIP != nil && bm.parsedIP.To16() != nil:
		return ipFamilyIPv6
	default:
		return ipFamilyUnknown
	}
}

func (bm *bucketManagerImpl) getBruteForceBucketBaseKey(rule *config.BruteForceRule, network *net.IPNet) string {
	if rule == nil || network == nil {
		return ""
	}

	netStr := network.String()
	ipProto, protocolPart, oidcCIDPart := bm.bruteForceBucketContextParts(rule)

	var sb strings.Builder

	sb.WriteString(bm.cfg().GetServer().GetRedis().GetPrefix())
	sb.WriteString("bf:{")
	sb.WriteString(bruteForceBucketHashTag(netStr, protocolPart, oidcCIDPart))
	sb.WriteString("}:")
	sb.WriteString(strconv.FormatInt(int64(math.Round(rule.Period.Seconds())), 10))
	sb.WriteByte(':')
	sb.WriteString(strconv.FormatUint(uint64(rule.CIDR), 10))
	sb.WriteByte(':')
	sb.WriteString(strconv.FormatUint(uint64(rule.FailedRequests), 10))
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

// bruteForceBucketContextParts resolves optional key segments for a bucket rule.
func (bm *bucketManagerImpl) bruteForceBucketContextParts(rule *config.BruteForceRule) (string, string, string) {
	ipProto := bruteForceBucketIPProto(rule)
	protocolPart := matchingOptionalFilter(rule.GetFilterByProtocol(), bm.protocol)
	oidcCIDPart := matchingOptionalFilter(rule.GetFilterByOIDCCID(), bm.oidcCID)

	return ipProto, protocolPart, oidcCIDPart
}

// bruteForceBucketIPProto returns the key suffix used for the rule IP family.
func bruteForceBucketIPProto(rule *config.BruteForceRule) string {
	if rule.IPv4 {
		return "4"
	}

	if rule.IPv6 {
		return "6"
	}

	return ""
}

// matchingOptionalFilter returns a value only when the optional filter includes it.
func matchingOptionalFilter(filter []string, value string) string {
	if len(filter) == 0 || value == "" {
		return ""
	}

	if containsString(filter, value) {
		return value
	}

	return ""
}

// bruteForceBucketHashTag builds the Redis Cluster hash tag for a bucket key.
func bruteForceBucketHashTag(netStr, protocolPart, oidcCIDPart string) string {
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

	return hashTag.String()
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
	if !bm.cfg().HasRuntimeModule(definitions.ControlBruteForce) {
		return
	}

	tr := monittrace.New("nauthilus/bruteforce")

	ctx, sp := tr.Start(bm.ctx, "bruteforce.load_all_password_histories",
		attribute.String("username", bm.username),
		attribute.String("client_ip", bm.clientIP),
	)
	defer sp.End()

	oldCtx := bm.ctx

	bm.ctx = ctx
	defer func() { bm.ctx = oldCtx }()

	readHandle := bm.redis().GetReadHandle()
	plan := bm.preparePasswordHistoryLoad(readHandle, false)

	// 1) Load account-scoped password history metrics
	bm.passwordsAccountSeen = plan.loadPasswordHistoryCount(true)

	// 2) Check if current password was already seen for this account
	plan.loadCurrentPasswordHistoryMembership()

	// 3) Load IP-only (overall) password history metrics
	bm.passwordsTotalSeen = plan.loadPasswordHistoryCount(false)
}

// passwordHistoryLoadPlan carries request-local password-history keys and read dependencies.
type passwordHistoryLoadPlan struct {
	bm         *bucketManagerImpl
	readHandle redis.UniversalClient

	accountSetKey   string
	accountTotalKey string
	ipSetKey        string
	ipTotalKey      string
	passwordHashes  internalpasswordhash.RedisCompatibilityCandidates
	accountSkipMsg  string
	hashComputed    bool
}

// preparePasswordHistoryLoad builds password-history Redis keys for one load invocation.
func (bm *bucketManagerImpl) preparePasswordHistoryLoad(readHandle redis.UniversalClient, includeLegacyTotalKeys bool) passwordHistoryLoadPlan {
	scopedIP := bm.scopedPasswordHistoryIP()
	account := bm.passwordHistoryAccount()
	prefix := bm.cfg().GetServer().GetRedis().GetPrefix()
	plan := passwordHistoryLoadPlan{
		bm:             bm,
		readHandle:     readHandle,
		accountSkipMsg: account.skipMsg,
		ipSetKey:       passwordHistoryRedisKey(prefix, definitions.RedisPwHashKey, "", scopedIP),
	}

	if account.name != "" {
		plan.accountSetKey = passwordHistoryRedisKey(prefix, definitions.RedisPwHashKey, account.name, scopedIP)
	}

	if includeLegacyTotalKeys {
		plan.ipTotalKey = passwordHistoryRedisKey(prefix, definitions.RedisPwHistTotalKey, "", scopedIP)
		if account.name != "" {
			plan.accountTotalKey = passwordHistoryRedisKey(prefix, definitions.RedisPwHistTotalKey, account.name, scopedIP)
		}
	}

	return plan
}

// passwordHistoryAccount stores the resolved account name or the skip log message for account-scoped reads.
type passwordHistoryAccount struct {
	name    string
	skipMsg string
}

// passwordHistoryAccount resolves account-scoped password-history state without emitting duplicate logs.
func (bm *bucketManagerImpl) passwordHistoryAccount() passwordHistoryAccount {
	if bm.accountName != "" {
		return passwordHistoryAccount{name: bm.accountName}
	}

	if bm.cfg().GetBruteForce().GetPWHistKnownAccountsOnlyOnAlreadyTriggered() && bm.alreadyTriggered {
		return passwordHistoryAccount{skipMsg: "Skipping account-scoped PW_HIST for unknown account on cached block"}
	}

	return passwordHistoryAccount{skipMsg: "Skipping account-scoped history: no accountName"}
}

// scopedPasswordHistoryIP returns the RWP-scoped client IP used in password-history keys.
func (bm *bucketManagerImpl) scopedPasswordHistoryIP() string {
	scoped := bm.clientIP
	if bm.scoper != nil {
		scoped = bm.scoper.Scope(ipscoper.ScopeRepeatingWrongPassword, bm.clientIP)
	}

	return scoped
}

// passwordHistoryRedisKey formats the Redis key used by password-history sets and counters.
func passwordHistoryRedisKey(prefix string, baseKey string, accountName string, scopedIP string) string {
	if accountName == "" {
		var sb strings.Builder

		sb.WriteString(prefix)
		sb.WriteString(baseKey)
		sb.WriteString(":{")
		sb.WriteString(scopedIP)
		sb.WriteString("}:")
		sb.WriteString(scopedIP)

		return sb.String()
	}

	var sbHashTag strings.Builder

	sbHashTag.WriteString(accountName)
	sbHashTag.WriteByte(':')
	sbHashTag.WriteString(scopedIP)

	hashTag := sbHashTag.String()

	var sb strings.Builder

	sb.WriteString(prefix)
	sb.WriteString(baseKey)
	sb.WriteString(":{")
	sb.WriteString(hashTag)
	sb.WriteString("}:")
	sb.WriteString(accountName)
	sb.WriteByte(':')
	sb.WriteString(scopedIP)

	return sb.String()
}

// setKey returns the prepared Redis set key for account-scoped or IP-scoped history.
func (p *passwordHistoryLoadPlan) setKey(isAccountScoped bool) string {
	if isAccountScoped {
		return p.accountSetKey
	}

	return p.ipSetKey
}

// totalKey returns the prepared Redis total counter key for account-scoped or IP-scoped history.
func (p *passwordHistoryLoadPlan) totalKey(isAccountScoped bool) string {
	if isAccountScoped {
		return p.accountTotalKey
	}

	return p.ipTotalKey
}

// loadCurrentPasswordHistoryMembership marks login attempts when the current hash was already seen.
func (p *passwordHistoryLoadPlan) loadCurrentPasswordHistoryMembership() {
	key := p.setKey(true)
	p.logSetKey(key, true)

	if key == "" || p.bm.password.IsZero() {
		return
	}

	passwordHashes := p.currentPasswordHashes()
	if passwordHashes.Full() == "" {
		return
	}

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(p.bm.ctx, p.bm.cfg())
	defer cancel()

	for _, candidate := range []string{passwordHashes.Full(), passwordHashes.Legacy()} {
		isMember, err := p.readHandle.SIsMember(dCtx, key, candidate).Result()
		if err != nil {
			return
		}

		if isMember {
			p.bm.loginAttempts = 1

			return
		}
	}
}

// currentPasswordHashes returns cached bounded hash candidates for this load invocation.
func (p *passwordHistoryLoadPlan) currentPasswordHashes() internalpasswordhash.RedisCompatibilityCandidates {
	if p.hashComputed {
		return p.passwordHashes
	}

	p.hashComputed = true
	p.passwordHashes = p.bm.currentPasswordHashCandidates()

	return p.passwordHashes
}

// loadPasswordHistoryCount reads the prepared password-history set cardinality.
func (p *passwordHistoryLoadPlan) loadPasswordHistoryCount(isAccountScoped bool) uint {
	key := p.setKey(isAccountScoped)
	p.logSetKey(key, isAccountScoped)

	if key == "" {
		return 0
	}

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(p.bm.ctx, p.bm.cfg())
	defer cancel()

	if count, err := p.readHandle.SCard(dCtx, key).Result(); err == nil {
		return uint(count)
	}

	return 0
}

// logSetKey preserves password-history set-key debug logging for each logical read.
func (p *passwordHistoryLoadPlan) logSetKey(key string, isAccountScoped bool) {
	if p.logMissingAccount(isAccountScoped, key) {
		return
	}

	util.DebugModuleWithCfg(
		p.bm.ctx,
		p.bm.cfg(),
		p.bm.logger(),
		definitions.DbgBf,
		definitions.LogKeyGUID, p.bm.guid,
		definitions.LogKeyClientIP, p.bm.clientIP,
		"key", key,
	)
}

// logTotalKey preserves password-history total-key debug logging for each logical read.
func (p *passwordHistoryLoadPlan) logTotalKey(key string, isAccountScoped bool) {
	if p.logMissingAccount(isAccountScoped, key) {
		return
	}

	util.DebugModuleWithCfg(
		p.bm.ctx,
		p.bm.cfg(),
		p.bm.logger(),
		definitions.DbgBf,
		definitions.LogKeyGUID, p.bm.guid,
		"total_key", key,
	)
}

// logMissingAccount emits the historical skip debug line for account-scoped reads without a resolved account.
func (p *passwordHistoryLoadPlan) logMissingAccount(isAccountScoped bool, key string) bool {
	if !isAccountScoped || key != "" {
		return false
	}

	if p.accountSkipMsg != "" {
		level.Debug(p.bm.logger()).Log(
			definitions.LogKeyGUID, p.bm.guid,
			definitions.LogKeyMsg, p.accountSkipMsg,
		)
	}

	return true
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

	if bm.parsedIP == nil || bm.netByCIDR == nil {
		bm.PrepareNetcalc(rules)
	}

	sp.SetAttributes(attribute.String("ip_family", bm.parsedIPFamily()))

	// Ensure IP/net precalc is available for L1 engine check
	bm.PrepareNetcalc(rules)

	if hit, index := bm.checkRepeatingL1Hit(sp, rules, network, message); hit {
		return false, true, index
	}

	sp.SetAttributes(attribute.Bool("micro_cache.hit", false))

	logger := bm.logger()
	*network = nil

	result := bm.gatherRepeatingCandidates(ctx, rules)
	if result.withError {
		return true, false, result.ruleNumber
	}

	if hit, index := bm.applyRepeatingPreResult(sp, logger, rules, result.candidates, network, message); hit {
		return false, true, index
	}

	if !result.matchedAnyRule {
		bm.logNoMatchingBruteForceBuckets()
		sp.SetAttributes(attribute.Bool("rules.matched_any", false))
	}

	sp.SetAttributes(
		attribute.Bool("triggered", false),
		attribute.Int("candidates.total", len(result.candidates)),
		attribute.Bool("rules.matched_any", result.matchedAnyRule),
	)

	return withError, false, ruleNumber
}

// checkRepeatingL1Hit applies a cached L1 decision when it matches a configured rule.
func (bm *bucketManagerImpl) checkRepeatingL1Hit(
	sp trace.Span,
	rules []config.BruteForceRule,
	network **net.IPNet,
	message *string,
) (bool, int) {
	tr := monittrace.New("nauthilus/bruteforce")

	_, msp := tr.Start(bm.ctx, "auth.bruteforce.repeating_check.l1_engine")
	defer msp.End()

	dec, ok := bm.repeatingL1Decision(rules)
	if !ok || !dec.Blocked {
		return false, 0
	}

	return bm.applyRepeatingL1Decision(sp, rules, network, message, dec)
}

// repeatingL1Decision returns a burst or network cached decision when available.
func (bm *bucketManagerImpl) repeatingL1Decision(rules []config.BruteForceRule) (l1.Decision, bool) {
	dec, ok := l1.GetEngine().Get(bm.ctx, l1.KeyBurst(bm.bfBurstKey()))
	if ok {
		return dec, true
	}

	for i := range rules {
		if network, err := bm.getNetwork(&rules[i]); err == nil && network != nil {
			if dec, ok := l1.GetEngine().Get(bm.ctx, l1.KeyNetwork(network.String())); ok && dec.Blocked {
				return dec, true
			}
		}
	}

	return l1.Decision{}, false
}

// applyRepeatingL1Decision maps a cached L1 decision back to rule state.
func (bm *bucketManagerImpl) applyRepeatingL1Decision(
	sp trace.Span,
	rules []config.BruteForceRule,
	network **net.IPNet,
	message *string,
	dec l1.Decision,
) (bool, int) {
	for i := range rules {
		if rules[i].Name != dec.Rule {
			continue
		}

		if resolved, err := bm.getNetwork(&rules[i]); err == nil && resolved != nil {
			*network = resolved
		}

		bm.bruteForceName = dec.Rule
		*message = "Brute force attack detected (L1 engine)"

		stats.GetMetrics().GetBruteForceCacheHitsTotal().WithLabelValues("micro").Inc()
		sp.SetAttributes(
			attribute.Bool("micro_cache.hit", true),
			attribute.Bool("triggered", true),
			attribute.String("rule", dec.Rule),
			attribute.Int("rule.index", i),
		)

		return true, i
	}

	return false, 0
}

type repeatingCandidate struct {
	idx   int
	field string
}

type repeatingCandidateResult struct {
	candidates     []repeatingCandidate
	ruleNumber     int
	matchedAnyRule bool
	withError      bool
}

// gatherRepeatingCandidates resolves matching rule networks for pre-result checks.
func (bm *bucketManagerImpl) gatherRepeatingCandidates(ctx context.Context, rules []config.BruteForceRule) repeatingCandidateResult {
	tr := monittrace.New("nauthilus/bruteforce")

	_, gatherSpan := tr.Start(ctx, "auth.bruteforce.repeating_check.gather_candidates")
	defer gatherSpan.End()

	result := repeatingCandidateResult{candidates: make([]repeatingCandidate, 0, len(rules))}
	logger := bm.logger()

	for i := range rules {
		if !rules[i].MatchesContext(bm.protocol, bm.oidcCID, bm.parsedIP) {
			continue
		}

		network, err := bm.getNetwork(&rules[i])
		if err != nil {
			bm.logBruteForceNetworkError(logger, err)

			result.withError = true
			result.ruleNumber = i

			break
		}

		if network != nil {
			result.matchedAnyRule = true
			result.candidates = append(result.candidates, repeatingCandidate{idx: i, field: network.String()})
		}
	}

	gatherSpan.SetAttributes(
		attribute.Bool("rules.matched_any", result.matchedAnyRule),
		attribute.Int("candidates.total", len(result.candidates)),
	)

	return result
}

// logBruteForceNetworkError logs network resolution failures for brute-force rules.
func (bm *bucketManagerImpl) logBruteForceNetworkError(logger *slog.Logger, err error) {
	level.Error(logger).Log(
		definitions.LogKeyGUID, bm.guid,
		definitions.LogKeyMsg, "Failed to get network for brute force rule",
		definitions.LogKeyError, err,
	)
}

// applyRepeatingPreResult applies the first Redis ban-key hit from candidate checks.
func (bm *bucketManagerImpl) applyRepeatingPreResult(
	sp trace.Span,
	logger *slog.Logger,
	rules []config.BruteForceRule,
	candidates []repeatingCandidate,
	network **net.IPNet,
	message *string,
) (bool, int) {
	if len(candidates) == 0 {
		return false, 0
	}

	cmds, err := bm.pipelineExistsBanKeys(bm.ctx, repeatingCandidateFields(candidates), "pipeline_exists_ban_preresult")
	if err != nil && !errors2.Is(err, redis.Nil) {
		level.Warn(logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, fmt.Sprintf("Pipeline EXISTS ban-key failed: %v", err))

		return false, 0
	}

	return bm.applyRepeatingBanHit(sp, rules, candidates, cmds, network, message)
}

// repeatingCandidateFields returns Redis ban-key network fields in candidate order.
func repeatingCandidateFields(candidates []repeatingCandidate) []string {
	fields := make([]string, len(candidates))

	for i, candidate := range candidates {
		fields[i] = candidate.field
	}

	return fields
}

// applyRepeatingBanHit maps the first positive EXISTS result back to rule state.
func (bm *bucketManagerImpl) applyRepeatingBanHit(
	sp trace.Span,
	rules []config.BruteForceRule,
	candidates []repeatingCandidate,
	cmds []*redis.IntCmd,
	network **net.IPNet,
	message *string,
) (bool, int) {
	for i, cmd := range cmds {
		exists, err := cmd.Result()
		if err != nil || exists == 0 {
			continue
		}

		ruleNumber := candidates[i].idx
		ruleName := rules[ruleNumber].Name
		bm.bruteForceName = ruleName
		*message = "Brute force attack detected (cached result)"

		stats.GetMetrics().GetBruteForceRejected().WithLabelValues(ruleName).Inc()

		if _, resolved, err := net.ParseCIDR(candidates[i].field); err == nil {
			*network = resolved
		}

		sp.SetAttributes(
			attribute.Bool("triggered", true),
			attribute.String("rule", ruleName),
			attribute.Int("rule.index", ruleNumber),
		)

		return true, ruleNumber
	}

	return false, 0
}

// CollectBucketPolicyFacts reads the current state for all configured brute-force buckets.
func (bm *bucketManagerImpl) CollectBucketPolicyFacts(rules []config.BruteForceRule) ([]BucketPolicyFact, error) {
	tr := monittrace.New("nauthilus/bruteforce")

	ctx, sp := tr.Start(bm.ctx, "auth.bruteforce.bucket_policy_facts",
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

	facts, err := bm.collectBucketPolicyFacts(ctx, rules, true)
	sp.SetAttributes(
		attribute.Int("facts.total", len(facts)),
		attribute.Bool("error", err != nil),
	)

	return facts, err
}

func (bm *bucketManagerImpl) collectBucketPolicyFacts(
	ctx context.Context,
	rules []config.BruteForceRule,
	includeBanState bool,
) ([]BucketPolicyFact, error) {
	facts := newBucketPolicyFacts(rules)

	if bm.parsedIP == nil || bm.netByCIDR == nil {
		bm.PrepareNetcalc(rules)
	}

	cands, err := bm.gatherBucketPolicyCandidates(rules, facts)
	if err != nil {
		bm.bucketPolicyFacts = facts

		return facts, err
	}

	if includeBanState {
		bm.markBucketPolicyBanState(ctx, rules, cands, facts)
	}

	if err := bm.readBucketPolicyCounters(cands, rules, facts); err != nil {
		bm.bucketPolicyFacts = facts

		return facts, err
	}

	bm.bucketPolicyFacts = facts

	return facts, nil
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

	sp.SetAttributes(attribute.String("ip_family", bm.parsedIPFamily()))

	facts, err := bm.collectBucketPolicyFacts(ctx, rules, false)
	if err != nil {
		_ = level.Error(bm.logger()).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to collect brute-force bucket policy facts",
			definitions.LogKeyError, err,
		)

		return true, false, -1
	}

	result := bm.bucketOverLimitResult(facts, message)
	if !result.matchedAnyRule {
		bm.logNoMatchingBruteForceBuckets()
	}

	if result.ruleTriggered {
		sp.SetAttributes(
			attribute.Bool("triggered", true),
			attribute.String("rule", bm.bruteForceName),
			attribute.Int("rule.index", result.ruleNumber),
			attribute.Float64("count", result.count),
			attribute.Float64("effective_limit", result.effectiveLimit),
		)
	}

	sp.SetAttributes(
		attribute.Bool("triggered", result.ruleTriggered),
		attribute.Bool("rules.matched_any", result.matchedAnyRule),
		attribute.Int("candidates.total", result.candidateCount),
	)

	return withError, result.ruleTriggered, result.ruleNumber
}

type bucketOverLimitResult struct {
	candidateCount int
	ruleNumber     int
	count          float64
	effectiveLimit float64
	matchedAnyRule bool
	ruleTriggered  bool
}

func (bm *bucketManagerImpl) bucketOverLimitResult(facts []BucketPolicyFact, message *string) bucketOverLimitResult {
	result := bucketOverLimitResult{ruleNumber: -1}

	for i := range facts {
		if !facts[i].Matched {
			continue
		}

		result.matchedAnyRule = true
		result.candidateCount++

		if facts[i].OverLimit && !result.ruleTriggered {
			result.ruleTriggered = true
			result.ruleNumber = i
			result.count = facts[i].Count
			result.effectiveLimit = facts[i].EffectiveLimit
			bm.bruteForceName = facts[i].Name
			*message = "Brute force attack detected"

			stats.GetMetrics().GetBruteForceRejected().WithLabelValues(bm.bruteForceName).Inc()
		}
	}

	return result
}

func (bm *bucketManagerImpl) logNoMatchingBruteForceBuckets() {
	_ = level.Warn(bm.logger()).Log(
		definitions.LogKeyGUID, bm.guid,
		definitions.LogKeyBruteForce, "No matching brute force buckets found",
		"protocol", bm.protocol,
		"client_ip", bm.clientIP)
}

func newBucketPolicyFacts(rules []config.BruteForceRule) []BucketPolicyFact {
	facts := make([]BucketPolicyFact, len(rules))

	for i := range rules {
		effectiveLimit := math.Max(0, float64(rules[i].FailedRequests)-1)

		facts[i] = BucketPolicyFact{
			Name:           rules[i].Name,
			Limit:          float64(rules[i].FailedRequests),
			EffectiveLimit: effectiveLimit,
			Remaining:      effectiveLimit,
			Period:         rules[i].GetPeriod(),
			BanTime:        rules[i].GetBanTime(),
			CIDR:           rules[i].GetCIDR(),
		}
	}

	return facts
}

func (bm *bucketManagerImpl) gatherBucketPolicyCandidates(
	rules []config.BruteForceRule,
	facts []BucketPolicyFact,
) ([]bkcand, error) {
	cands := make([]bkcand, 0, len(rules))
	logger := bm.logger()

	for i := range rules {
		if !rules[i].MatchesContext(bm.protocol, bm.oidcCID, bm.parsedIP) {
			continue
		}

		network, err := bm.getNetwork(&rules[i])
		if err != nil {
			_ = level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Failed to get network for brute force rule",
				definitions.LogKeyError, err,
			)

			return cands, err
		}

		if network == nil {
			continue
		}

		facts[i].Matched = true
		facts[i].ClientNet = network.String()
		cands = append(cands, bkcand{idx: i, network: network})
	}

	return cands, nil
}

func (bm *bucketManagerImpl) markBucketPolicyBanState(
	ctx context.Context,
	rules []config.BruteForceRule,
	cands []bkcand,
	facts []BucketPolicyFact,
) {
	if len(cands) == 0 {
		return
	}

	networks := make([]string, len(cands))
	for i := range cands {
		networks[i] = cands[i].network.String()
	}

	cmds, err := bm.pipelineExistsBanKeys(ctx, networks, "pipeline_exists_ban_policy_facts")
	if err != nil && !errors2.Is(err, redis.Nil) {
		_ = level.Warn(bm.logger()).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, fmt.Sprintf("Pipeline EXISTS ban-key for policy facts failed: %v", err),
		)

		return
	}

	for i, cmd := range cmds {
		exists, err := cmd.Result()
		if err != nil || exists == 0 {
			continue
		}

		idx := cands[i].idx
		facts[idx].AlreadyBanned = true
		facts[idx].Repeating = true

		if bm.bruteForceName == "" {
			bm.bruteForceName = rules[idx].Name
		}
	}
}

func (bm *bucketManagerImpl) readBucketPolicyCounters(
	cands []bkcand,
	rules []config.BruteForceRule,
	facts []BucketPolicyFact,
) error {
	if len(cands) == 0 {
		return nil
	}

	logger := bm.logger()

	scriptSHA, errUpload := rediscli.UploadScript(bm.ctx, bm.redis(), "SlidingWindowCounter", rediscli.LuaScripts["SlidingWindowCounter"])
	if errUpload != nil {
		_ = level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to upload SlidingWindowCounter script",
			definitions.LogKeyError, errUpload,
		)

		return errUpload
	}

	_, adaptiveEnabled, minPct, maxPct, scaleFactor, staticPct, positive := bm.getAdaptiveScalingConfig()

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	stats.GetMetrics().GetRedisRoundtripsTotal().WithLabelValues("pipeline_eval_bucket_counter").Inc()

	cmds, errP := bm.execBucketCounterPipeline(cands, rules, scriptSHA, adaptiveEnabled, minPct, maxPct, scaleFactor, staticPct, positive)
	if errP != nil && strings.Contains(errP.Error(), "NOSCRIPT") {
		_ = level.Warn(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Pipeline NOSCRIPT on read handle, re-uploading script to all nodes",
		)

		rediscli.InvalidateScript("SlidingWindowCounter")

		scriptSHA, errUpload = rediscli.UploadScript(bm.ctx, bm.redis(), "SlidingWindowCounter", rediscli.LuaScripts["SlidingWindowCounter"])
		if errUpload == nil {
			cmds, errP = bm.execBucketCounterPipeline(cands, rules, scriptSHA, adaptiveEnabled, minPct, maxPct, scaleFactor, staticPct, positive)
		}
	}

	if errP != nil && !errors2.Is(errP, redis.Nil) {
		_ = level.Warn(logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, fmt.Sprintf("Pipeline EVAL bucket counters failed: %v", errP))
	}

	if bm.bruteForceCounter == nil {
		bm.bruteForceCounter = make(map[string]uint)
	}

	for i, cmd := range cmds {
		res, err := cmd.Result()
		if err != nil {
			continue
		}

		bm.applyBucketPolicyCounterResult(cands[i].idx, res, rules, facts)
	}

	return nil
}

func (bm *bucketManagerImpl) applyBucketPolicyCounterResult(
	index int,
	result any,
	rules []config.BruteForceRule,
	facts []BucketPolicyFact,
) {
	resParts, ok := result.([]any)
	if !ok || len(resParts) < 2 {
		return
	}

	totalStr, _ := resParts[0].(string)
	exceeded, _ := resParts[1].(int64)

	total, err := strconv.ParseFloat(totalStr, 64)
	if err != nil {
		return
	}

	effectiveLimit := math.Max(0, float64(rules[index].FailedRequests)-1)

	if len(resParts) >= 3 {
		if effectiveLimitStr, ok := resParts[2].(string); ok {
			if parsed, parseErr := strconv.ParseFloat(effectiveLimitStr, 64); parseErr == nil {
				effectiveLimit = parsed
			}
		}
	}

	facts[index].Count = total
	facts[index].EffectiveLimit = effectiveLimit
	facts[index].Remaining = math.Max(0, effectiveLimit-total)
	facts[index].Ratio = bucketPolicyRatio(total, effectiveLimit)
	facts[index].OverLimit = exceeded == 1
	facts[index].Repeating = facts[index].Repeating || facts[index].OverLimit
	bm.bruteForceCounter[rules[index].Name] = uint(math.Round(total))
}

func bucketPolicyRatio(count float64, effectiveLimit float64) float64 {
	if effectiveLimit <= 0 {
		if count > 0 {
			return 1
		}

		return 0
	}

	return count / effectiveLimit
}

// bkcand pairs a rule index with its resolved client network for brute-force bucket evaluation.
type bkcand struct {
	idx     int
	network *net.IPNet
}

// execBucketCounterPipeline builds and executes a Redis pipeline that runs EvalSha
// for each brute-force candidate on a read handle. It returns the resulting commands
// and any pipeline execution error.
func (bm *bucketManagerImpl) execBucketCounterPipeline(
	cands []bkcand, rules []config.BruteForceRule, scriptSHA string,
	adaptiveEnabled int, minPct, maxPct uint8, scaleFactor float64, staticPct uint8, positive int64,
) ([]*redis.Cmd, error) {
	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
	defer cancel()

	pipe := bm.redis().GetReadHandle().Pipeline()
	cmds := make([]*redis.Cmd, 0, len(cands))

	for _, c := range cands {
		rule := &rules[c.idx]
		currentKey, prevKey, weight := bm.getSlidingWindowKeys(rule, c.network)
		ttl := int64(math.Round(rule.Period.Seconds() * 2))
		limit := int64(rule.FailedRequests) - 1

		// rwp_floor = 0: read-only check path must never modify counters
		cmds = append(cmds, pipe.EvalSha(dCtx, scriptSHA, []string{currentKey, prevKey},
			0, weight, ttl, limit,
			adaptiveEnabled, minPct, maxPct, scaleFactor, staticPct, positive, 0))
	}

	_, errP := pipe.Exec(dCtx)

	return cmds, errP
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

	sp.SetAttributes(
		attribute.String("ip_family", bm.parsedIPFamily()),
	)

	if alreadyTriggered || ruleTriggered {
		return bm.processTriggeredBruteForce(sp, ruleTriggered, alreadyTriggered, rule, network, message, setter)
	}

	// Also cache negative decision (allow) to avoid immediate redundant HMGET/MGET for identical attempts
	l1.GetEngine().Set(bm.ctx, l1.KeyBurst(bm.bfBurstKey()), l1.Decision{Blocked: false, Rule: ""}, 0)

	sp.SetAttributes(attribute.Bool("triggered", false))

	return false
}

// processTriggeredBruteForce handles the side effects for an active brute-force decision.
func (bm *bucketManagerImpl) processTriggeredBruteForce(
	sp trace.Span,
	ruleTriggered bool,
	alreadyTriggered bool,
	rule *config.BruteForceRule,
	network *net.IPNet,
	message string,
	setter func(),
) bool {
	sp.SetAttributes(attribute.String("rule", rule.Name))

	bm.prepareTriggeredBruteForce(rule, alreadyTriggered)

	defer setter()
	defer bm.LoadAllPasswordHistories()

	logBucketRuleDebug(bm, network, rule)

	if !alreadyTriggered && bm.blockSuppressedByToleration() {
		return false
	}

	bm.setTriggeredBruteForceName(rule, alreadyTriggered)
	bm.updateAffectedAccount()

	if ruleTriggered && !bm.activateBruteForceBan(rule, network) {
		return false
	}

	bm.recordBlockedPasswordAttempt()
	logBucketMatchingRule(bm, network, rule, message)

	bm.environmentName = definitions.ControlBruteForce
	l1.GetEngine().Set(bm.ctx, l1.KeyBurst(bm.bfBurstKey()), l1.Decision{Blocked: true, Rule: bm.bruteForceName}, 0)

	sp.SetAttributes(attribute.Bool("triggered", true))

	return true
}

// prepareTriggeredBruteForce loads counters and records cached-trigger state.
func (bm *bucketManagerImpl) prepareTriggeredBruteForce(rule *config.BruteForceRule, alreadyTriggered bool) {
	bm.alreadyTriggered = alreadyTriggered
	bm.loadBruteForceBucketCounter(rule)
}

// blockSuppressedByToleration returns true when a toleration policy suppresses the block.
func (bm *bucketManagerImpl) blockSuppressedByToleration() bool {
	tol := bm.tolerate()
	if tol == nil {
		return false
	}

	fact := tol.PolicyFact(bm.ctx, bm.clientIP)

	bm.tolerationPolicyFact = fact
	if !fact.Active {
		return false
	}

	fact.SuppressedBlock = true
	bm.tolerationPolicyFact = fact

	_ = level.Info(bm.logger()).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, "IP address is tolerated")

	return true
}

// setTriggeredBruteForceName preserves cached-hit naming semantics for triggered rules.
func (bm *bucketManagerImpl) setTriggeredBruteForceName(rule *config.BruteForceRule, alreadyTriggered bool) {
	if alreadyTriggered {
		// The HMGET pre-result path sets bm.bruteForceName when a cached hit occurs.
		if bm.bruteForceName == "" {
			bm.bruteForceName = fmt.Sprintf("%s,guessed", rule.Name)
		}

		return
	}

	bm.bruteForceName = rule.Name
}

// activateBruteForceBan writes and broadcasts a newly triggered ban.
func (bm *bucketManagerImpl) activateBruteForceBan(rule *config.BruteForceRule, network *net.IPNet) bool {
	banActive, err := bm.setPreResultBruteForceRedis(rule)
	if err != nil || !banActive {
		return false
	}

	BroadcastBlock(bm.ctx, bm.redis(), bm.cfg(), l1.KeyBurst(bm.bfBurstKey()), bm.bruteForceName)

	if network != nil {
		BroadcastBlock(bm.ctx, bm.redis(), bm.cfg(), l1.KeyNetwork(network.String()), bm.bruteForceName)
	}

	return true
}

// recordBlockedPasswordAttempt counts one failed attempt for pre-blocked requests.
func (bm *bucketManagerImpl) recordBlockedPasswordAttempt() {
	logger := bm.logger()
	if bm.burstLeaderGate(bm.ctx) {
		bm.SaveFailedPasswordCounterInRedis()
		level.Info(logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyLeadership, "bf_burst_leader")

		return
	}

	level.Info(logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyLeadership, "bf_burst_follower")
}

// ProcessPWHist processes and records the client IP for password history, ensuring data persistence, logging, and error handling.
func (bm *bucketManagerImpl) ProcessPWHist() (accountName string) {
	if bm.clientIP == "" {
		return
	}

	accountName = bm.resolveAccountNameForHistory()
	if accountName == "" {
		return
	}

	bm.updateAffectedAccount()

	key := GetPWHistIPsRedisKey(accountName, bm.cfg())
	logger := bm.logger()

	if alreadyLearned, abort := bm.passwordHistoryIPAlreadyLearned(logger, key); abort || alreadyLearned {
		// IP address already stored
		return
	}

	bm.storePasswordHistoryIP(logger, key)

	return
}

// passwordHistoryIPAlreadyLearned reports whether the client IP is already in the PW_HIST set.
func (bm *bucketManagerImpl) passwordHistoryIPAlreadyLearned(logger *slog.Logger, key string) (bool, bool) {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
	defer cancel()

	alreadyLearned, err := bm.redis().GetReadHandle().SIsMember(dCtx, key, bm.clientIP).Result()
	if err == nil || errors2.Is(err, redis.Nil) {
		return alreadyLearned, false
	}

	level.Error(logger).Log(
		definitions.LogKeyGUID, bm.guid,
		definitions.LogKeyMsg, "Failed to check if IP address is already in PW_HIST_IPS set",
		definitions.LogKeyError, err,
	)

	return false, true
}

// storePasswordHistoryIP writes the client IP into the PW_HIST set.
func (bm *bucketManagerImpl) storePasswordHistoryIP(logger *slog.Logger, key string) {
	// Use pipelining for write operations to reduce network round trips
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())
	defer cancel()

	_, err := rediscli.ExecuteWritePipeline(dCtx, bm.redis(), func(pipe redis.Pipeliner) error {
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
	if !bm.cfg().HasRuntimeModule(definitions.ControlBruteForce) {
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

	passwordHashes := bm.currentPasswordHashCandidates()
	if passwordHashes.Full() == "" {
		return
	}

	ttl := bm.cfg().GetServer().GetRedis().GetNegCacheTTL()
	maxEntries := bm.cfg().GetServer().GetMaxPasswordHistoryEntries()

	for _, key := range bm.failedPasswordHistoryKeys() {
		if key == "" {
			continue
		}

		if ok := bm.saveFailedPasswordHashToKey(logger, key, passwordHashes, ttl, maxEntries); !ok {
			return
		}
	}
}

// failedPasswordHistoryKeys returns account-scoped and IP-scoped history set keys.
func (bm *bucketManagerImpl) failedPasswordHistoryKeys() []string {
	return []string{
		bm.getPasswordHistoryRedisSetKey(true),
		bm.getPasswordHistoryRedisSetKey(false),
	}
}

// saveFailedPasswordHashToKey stores one password hash in a bounded Redis set.
func (bm *bucketManagerImpl) saveFailedPasswordHashToKey(
	logger *slog.Logger,
	key string,
	passwordHashes internalpasswordhash.RedisCompatibilityCandidates,
	ttl time.Duration,
	maxEntries int32,
) bool {
	util.DebugModuleWithCfg(bm.ctx, bm.cfg(), bm.logger(), definitions.DbgBf, definitions.LogKeyGUID, bm.guid, "set_key", key)

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())
	defer cancel()

	// We use a simple script to add to set and expire, but also respect maxEntries if possible.
	// Since it's now a Set, we don't track counters per password, just existence.
	res, err := rediscli.ExecuteScript(
		dCtx,
		bm.redis(),
		"AddToSetAndExpireLimit",
		rediscli.LuaScripts["AddToSetAndExpireLimit"],
		[]string{key},
		passwordHashes.Full(),
		strconv.FormatInt(int64(ttl.Seconds()), 10),
		strconv.Itoa(int(maxEntries)),
		passwordHashes.Legacy(),
	)

	stats.GetMetrics().GetRedisWriteCounter().Add(1)

	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to update failed password set via Lua",
			definitions.LogKeyError, err,
		)

		return false
	}

	if val, ok := res.(int64); ok && val == 0 {
		level.Info(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Too many password hashes for this account (set limit reached)",
		)
	}

	return true
}

// DeleteIPBruteForceRedis removes an IP-based brute force entry from Redis based on the provided rule and rule name.
// It returns the removed Redis key if successful or an empty string otherwise.
// Parameters: `rule` specifies the brute force rule, `ruleName` determines the entry to delete or all if set to "*".
// It handles Redis hash key operations and logs errors encountered during the deletion process.
// Returns: The key of the removed entry and an error, if any occurs.
func (bm *bucketManagerImpl) DeleteIPBruteForceRedis(rule *config.BruteForceRule, ruleName string) (string, error) {
	var removedKey string

	logger := bm.logger()

	if !bm.ruleMatchesDeleteContext(rule) {
		return "", nil
	}

	banKey, networkStr, err := bm.GetBruteForceBanRedisKey(rule)
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to get network for brute force rule",
			definitions.LogKeyError, err,
		)

		return "", err
	}

	if banKey == "" || networkStr == "" {
		return removedKey, nil
	}

	prefix := bm.cfg().GetServer().GetRedis().GetPrefix()

	if ruleName == "*" {
		return bm.deleteBruteForceBanKey(logger, prefix, banKey, networkStr), nil
	}

	current, err := bm.currentBruteForceBanName(banKey)
	if err != nil {
		return "", err
	}

	if current == ruleName {
		return bm.deleteBruteForceBanKey(logger, prefix, banKey, networkStr), nil
	}

	return removedKey, nil
}

// ruleMatchesDeleteContext reports whether the current request context can delete a rule ban.
func (bm *bucketManagerImpl) ruleMatchesDeleteContext(rule *config.BruteForceRule) bool {
	if len(rule.FilterByProtocol) > 0 && bm.protocol != "" && !slices.Contains(rule.GetFilterByProtocol(), bm.protocol) {
		return false
	}

	if len(rule.GetFilterByOIDCCID()) > 0 && bm.oidcCID != "" && !slices.Contains(rule.FilterByOIDCCID, bm.oidcCID) {
		return false
	}

	return true
}

// currentBruteForceBanName reads the current bucket name stored in a ban key.
func (bm *bucketManagerImpl) currentBruteForceBanName(banKey string) (string, error) {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
	defer cancel()

	current, err := bm.redis().GetReadHandle().Get(dCtx, banKey).Result()
	if err != nil && !errors2.Is(err, redis.Nil) {
		return "", err
	}

	return current, nil
}

// deleteBruteForceBanKey removes a ban key and its sharded index entry.
func (bm *bucketManagerImpl) deleteBruteForceBanKey(logger *slog.Logger, prefix, banKey, networkStr string) string {
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())
	defer cancel()

	removed, err := bm.redis().GetWriteHandle().Del(dCtx, banKey).Result()
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed to delete brute force ban key",
			definitions.LogKeyError, err,
		)

		return ""
	}

	if removed == 0 {
		return ""
	}

	bm.removeBanFromIndex(dCtx, prefix, networkStr, logger)

	return banKey
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
	logger := bm.logger()
	refs := bm.blockedIPFieldRefs(rules, logger)

	if len(refs) == 0 {
		return buckets, false
	}

	cmds, err := bm.pipelineExistsBanKeys(ctx, banFieldRefNetworks(refs), "pipeline_exists_ban_is_blocked")
	if err != nil && !errors2.Is(err, redis.Nil) {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Failed pipeline EXISTS in IsIPAddressBlocked",
			definitions.LogKeyError, err,
		)

		return buckets, false
	}

	buckets = blockedBucketsFromExists(cmds, refs)
	sp.SetAttributes(attribute.Int("blocked_buckets_count", len(buckets)))

	return buckets, len(buckets) > 0
}

type banFieldRef struct {
	name    string
	network string
}

// blockedIPFieldRefs resolves rule names and networks for ban-key existence checks.
func (bm *bucketManagerImpl) blockedIPFieldRefs(rules []config.BruteForceRule, logger *slog.Logger) []banFieldRef {
	refs := make([]banFieldRef, 0, len(rules))

	for i := range rules {
		network, err := bm.getNetwork(&rules[i])
		if err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Failed to get network for brute force rule",
				definitions.LogKeyError, err,
			)

			continue
		}

		if network != nil {
			refs = append(refs, banFieldRef{name: rules[i].Name, network: network.String()})
		}
	}

	return refs
}

// banFieldRefNetworks returns network strings in the same order as their rule refs.
func banFieldRefNetworks(refs []banFieldRef) []string {
	networks := make([]string, len(refs))

	for i, ref := range refs {
		networks[i] = ref.network
	}

	return networks
}

// blockedBucketsFromExists maps successful EXISTS results back to bucket names.
func blockedBucketsFromExists(cmds []*redis.IntCmd, refs []banFieldRef) []string {
	buckets := make([]string, 0)

	for i, cmd := range cmds {
		exists, err := cmd.Result()
		if err != nil || exists == 0 {
			continue
		}

		buckets = append(buckets, refs[i].name)
	}

	return buckets
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

// rwpScriptArgs holds the pre-computed arguments shared by both the RWP check and commit scripts.
type rwpScriptArgs struct {
	allowKey     string
	passwordHash string
	legacyHash   string
	argThreshold string
	argTTL       string
	argNow       string
}

// buildRWPScriptArgs computes the common arguments needed by both RWPSlidingWindowCheck and RWPSlidingWindowCommit.
// Returns nil if the key or hash cannot be determined.
func (bm *bucketManagerImpl) buildRWPScriptArgs() *rwpScriptArgs {
	allowKey, passwordHashes := bm.buildRWPKeyAndHashes()
	if allowKey == "" || passwordHashes.Full() == "" {
		return nil
	}

	cfg := bm.cfg()

	threshold := max(cfg.GetBruteForce().GetRWPAllowedUniqueHashes(), 1)

	ttl := cfg.GetBruteForce().GetRWPWindow()
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	return &rwpScriptArgs{
		allowKey:     allowKey,
		passwordHash: passwordHashes.Full(),
		legacyHash:   passwordHashes.Legacy(),
		argThreshold: strconv.FormatUint(uint64(threshold), 10),
		argTTL:       strconv.FormatInt(int64(ttl.Seconds()), 10),
		argNow:       strconv.FormatInt(time.Now().Unix(), 10),
	}
}

// CommitRWPSlidingWindow writes the current password hash into the RWP sliding window.
// It must only be called when the password was genuinely wrong (not rejected by an environment control).
func (bm *bucketManagerImpl) CommitRWPSlidingWindow() {
	args := bm.buildRWPScriptArgs()
	if args == nil {
		return
	}

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(bm.ctx, bm.cfg())
	_, execErr := rediscli.ExecuteScript(
		dCtx,
		bm.redis(),
		"RWPSlidingWindowCommit",
		rediscli.LuaScripts["RWPSlidingWindowCommit"],
		[]string{args.allowKey},
		args.passwordHash, args.argNow, args.argTTL, args.argThreshold, args.legacyHash,
	)

	cancel()

	if execErr != nil {
		level.Warn(bm.logger()).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, fmt.Sprintf("RWPSlidingWindowCommit script error: %v", execErr),
		)
	}
}

// buildRWPKeyAndHashes computes the Redis key and bounded hash candidates used by RWP.
// Returns empty strings if the password or account cannot be determined.
func (bm *bucketManagerImpl) buildRWPKeyAndHashes() (allowKey string, passwordHashes internalpasswordhash.RedisCompatibilityCandidates) {
	if bm.password.IsZero() {
		return "", internalpasswordhash.RedisCompatibilityCandidates{}
	}

	passwordHashes = bm.currentPasswordHashCandidates()
	if passwordHashes.Full() == "" {
		return "", internalpasswordhash.RedisCompatibilityCandidates{}
	}

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
		return "", internalpasswordhash.RedisCompatibilityCandidates{}
	}

	cfg := bm.cfg()
	prefix := cfg.GetServer().GetRedis().GetPrefix()

	var sb strings.Builder

	sb.WriteString(prefix)
	sb.WriteString(definitions.RedisBFRWPAllowPrefix)
	sb.WriteString(scoped)
	sb.WriteByte(':')
	sb.WriteString(acct)

	return sb.String(), passwordHashes
}

// currentPasswordHash returns the canonical normalized password hash used by new Redis writes.
func (bm *bucketManagerImpl) currentPasswordHash() string {
	return bm.currentPasswordHashCandidates().Full()
}

// currentPasswordHashCandidates derives the canonical and bounded legacy candidates.
func (bm *bucketManagerImpl) currentPasswordHashCandidates() internalpasswordhash.RedisCompatibilityCandidates {
	var candidates internalpasswordhash.RedisCompatibilityCandidates

	bm.password.WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		prepared := util.PreparePasswordBytes(value)
		defer clear(prepared)

		candidates = internalpasswordhash.DeriveRedisCompatibilityCandidates(prepared)
	})

	return candidates
}

// isRepeatingWrongPassword implements the RWP allowance logic.
// It returns true if the current wrong password should be tolerated (i.e., buckets should NOT be increased),
// based on allowing up to N distinct wrong password hashes within a rolling window. Repeats of already seen
// hashes are always tolerated within the window.
// This is a read-only check; the actual write is deferred to CommitRWPSlidingWindow.
func (bm *bucketManagerImpl) isRepeatingWrongPassword() (repeating bool, err error) {
	logger := bm.logger()

	args := bm.buildRWPScriptArgs()
	if args == nil {
		if bm.password.IsZero() {
			level.Debug(logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "Skipping isRepeatingWrongPassword: password is empty",
			)
		}

		return false, nil
	}

	// Read-only check using Lua script (no ZADD — the write is deferred to CommitRWPSlidingWindow)
	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
	res, execErr := rediscli.ExecuteScript(
		dCtx,
		bm.redis(),
		"RWPSlidingWindowCheck",
		rediscli.LuaScripts["RWPSlidingWindowCheck"],
		[]string{args.allowKey},
		args.passwordHash, args.argNow, args.argTTL, args.argThreshold, args.legacyHash,
	)

	cancel()

	if execErr != nil {
		return bm.repeatingWrongPasswordFallback(logger, args, execErr), nil
	}

	if v, ok := res.(int64); ok && v == 1 {
		return true, nil
	}

	return false, nil
}

// repeatingWrongPasswordFallback checks PW_HIST membership when the RWP script fails.
func (bm *bucketManagerImpl) repeatingWrongPasswordFallback(logger *slog.Logger, args *rwpScriptArgs, execErr error) bool {
	level.Warn(logger).Log(
		definitions.LogKeyGUID, bm.guid,
		definitions.LogKeyMsg, fmt.Sprintf("RWPSlidingWindow script error, using totals fallback: %v", execErr),
	)

	acctKey := bm.getPasswordHistoryRedisSetKey(true)
	if acctKey == "" {
		return false
	}

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
	defer cancel()

	for _, candidate := range []string{args.passwordHash, args.legacyHash} {
		isMember, _ := bm.redis().GetReadHandle().SIsMember(dCtx, acctKey, candidate).Result()
		if isMember {
			return true
		}
	}

	return false
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
	ipAddress := bm.clientIPAddress()
	if ipAddress == nil {
		return nil, fmt.Errorf("%s '%s'", errors.ErrWrongIPAddress, bm.clientIP)
	}

	ipAddress, bits, ok, err := bm.ruleNetworkIP(rule, ipAddress)
	if err != nil || !ok {
		return nil, err
	}

	if network := bm.cachedCIDRNetwork(rule.CIDR); network != nil {
		return network, nil
	}

	network, err = bm.buildCIDRNetwork(rule.CIDR, ipAddress, bits)
	if err != nil {
		return nil, err
	}

	if bm.netByCIDR != nil {
		bm.netByCIDR[rule.CIDR] = network
	}

	return network, nil
}

// clientIPAddress returns the cached or parsed client IP address.
func (bm *bucketManagerImpl) clientIPAddress() net.IP {
	if bm.parsedIP != nil {
		return bm.parsedIP
	}

	bm.parsedIP = net.ParseIP(bm.clientIP)

	return bm.parsedIP
}

// ruleNetworkIP returns the IP bytes and bit length applicable to a brute-force rule.
func (bm *bucketManagerImpl) ruleNetworkIP(rule *config.BruteForceRule, ipAddress net.IP) (net.IP, int, bool, error) {
	if bm.ipIsV4 || (!bm.ipIsV6 && ipAddress.To4() != nil) {
		bm.ipIsV4 = true
		bm.ipIsV6 = false

		if !rule.IPv4 {
			return nil, 0, false, nil
		}

		return ipAddress.To4(), 32, true, nil
	}

	if bm.ipIsV6 || ipAddress.To16() != nil {
		return bm.ruleIPv6NetworkIP(rule, ipAddress)
	}

	return nil, 0, false, nil
}

// ruleIPv6NetworkIP validates and returns IPv6 bytes for a matching rule.
func (bm *bucketManagerImpl) ruleIPv6NetworkIP(rule *config.BruteForceRule, ipAddress net.IP) (net.IP, int, bool, error) {
	bm.ipIsV6 = true
	bm.ipIsV4 = false

	if !rule.IPv6 {
		return nil, 0, false, nil
	}

	if !bm.ipv6Validated {
		if _, err := netaddr.ParseIPv6(bm.clientIP); err != nil {
			return nil, 0, false, err
		}

		bm.ipv6Validated = true
	}

	return ipAddress.To16(), 128, true, nil
}

// cachedCIDRNetwork returns a precalculated network for a CIDR when available.
func (bm *bucketManagerImpl) cachedCIDRNetwork(cidr uint) *net.IPNet {
	if bm.netByCIDR == nil {
		return nil
	}

	network, ok := bm.netByCIDR[cidr]
	if !ok {
		return nil
	}

	return network
}

// buildCIDRNetwork masks an IP address with the given CIDR and bit length.
func (bm *bucketManagerImpl) buildCIDRNetwork(cidr uint, ipAddress net.IP, bits int) (*net.IPNet, error) {
	mask := net.CIDRMask(int(cidr), bits)
	if mask == nil {
		return nil, fmt.Errorf("invalid CIDR %d for client IP '%s'", cidr, bm.clientIP)
	}

	return &net.IPNet{IP: ipAddress.Mask(mask), Mask: mask}, nil
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

	bm.ensureNetcalcCache()

	addr, err := bm.prepareNetcalcAddress()
	if err != nil {
		return
	}

	bm.precomputeRuleNetworks(rules, addr)
}

// ensureNetcalcCache initializes the CIDR network cache when needed.
func (bm *bucketManagerImpl) ensureNetcalcCache() {
	if bm.netByCIDR == nil {
		bm.netByCIDR = make(map[uint]*net.IPNet, 8)
	}
}

// prepareNetcalcAddress parses the client IP and updates cached family flags.
func (bm *bucketManagerImpl) prepareNetcalcAddress() (netip.Addr, error) {
	addr, err := netip.ParseAddr(bm.clientIP)
	if err != nil {
		return netip.Addr{}, err
	}

	bm.ipIsV4 = addr.Is4()
	bm.ipIsV6 = addr.Is6()

	if bm.parsedIP == nil {
		bm.parsedIP = addr.AsSlice()
	}

	if bm.ipIsV6 && !bm.ipv6Validated {
		bm.ipv6Validated = true
	}

	return addr, nil
}

// precomputeRuleNetworks stores unique CIDR networks applicable to the parsed address family.
func (bm *bucketManagerImpl) precomputeRuleNetworks(rules []config.BruteForceRule, addr netip.Addr) {
	for _, r := range rules {
		if !bm.ruleMatchesPreparedFamily(r) {
			continue
		}

		if _, ok := bm.netByCIDR[r.CIDR]; ok {
			continue
		}

		if network := preparedCIDRNetwork(addr, r.CIDR); network != nil {
			bm.netByCIDR[r.CIDR] = network
		}
	}
}

// ruleMatchesPreparedFamily reports whether a rule applies to the parsed IP family.
func (bm *bucketManagerImpl) ruleMatchesPreparedFamily(rule config.BruteForceRule) bool {
	return (!bm.ipIsV4 || rule.IPv4) && (!bm.ipIsV6 || rule.IPv6)
}

// preparedCIDRNetwork returns a standard-library IPNet for a netip CIDR.
func preparedCIDRNetwork(addr netip.Addr, cidr uint) *net.IPNet {
	prefix, err := addr.Prefix(int(cidr))
	if err != nil {
		return nil
	}

	masked := prefix.Masked().Addr()
	ip := net.IP(masked.AsSlice())
	mask := net.CIDRMask(int(cidr), addr.BitLen())

	return &net.IPNet{IP: ip, Mask: mask}
}

// getPasswordHistoryRedisSetKey generates the Redis set key for password history storage based on username and client IP.
func (bm *bucketManagerImpl) getPasswordHistoryRedisSetKey(withUsername bool) (key string) {
	plan := bm.preparePasswordHistoryLoad(nil, false)
	key = plan.setKey(withUsername)
	plan.logSetKey(key, withUsername)

	return
}

// getPasswordHistoryTotalRedisKey generates the Redis key for the total counter for password history.
func (bm *bucketManagerImpl) getPasswordHistoryTotalRedisKey(withUsername bool) (key string) {
	plan := bm.preparePasswordHistoryLoad(nil, true)
	key = plan.totalKey(withUsername)
	plan.logTotalKey(key, withUsername)

	return
}

// loadBruteForceBucketCounter loads a brute force bucket counter for the specified rule if the control is enabled.
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

	if resParts, ok := res.([]any); ok && len(resParts) > 0 {
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

		return bm.verifyBanKeyAfterSetError(ctx, logger, banKey, err)
	}

	if !set {
		// Ban already exists — nothing to do.
		return true, nil
	}

	// Best-effort: add network to sharded ZSET index.
	bm.addBanToIndex(dCtx, prefix, networkStr, logger)

	return true, nil
}

// verifyBanKeyAfterSetError checks whether a ban key exists despite a failed SETNX.
func (bm *bucketManagerImpl) verifyBanKeyAfterSetError(
	ctx context.Context,
	logger *slog.Logger,
	banKey string,
	setErr error,
) (bool, error) {
	stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, bm.cfg())
	defer cancel()

	exists, existsErr := bm.redis().GetReadHandle().Exists(dCtx, banKey).Result()
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

	return false, setErr
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

	isMember, abort := bm.affectedAccountAlreadyMember(ctx, logger, key, accountName)
	if abort || isMember {
		return
	}

	bm.addAffectedAccount(ctx, logger, key, accountName)
}

// affectedAccountAlreadyMember checks whether an account is already indexed as affected.
func (bm *bucketManagerImpl) affectedAccountAlreadyMember(
	ctx context.Context,
	logger *slog.Logger,
	key string,
	accountName string,
) (bool, bool) {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, bm.cfg())
	defer cancel()

	isMember, err := bm.redis().GetReadHandle().SIsMember(dCtx, key, accountName).Result()
	if err == nil || errors2.Is(err, redis.Nil) {
		return isMember, false
	}

	level.Error(logger).Log(
		definitions.LogKeyGUID, bm.guid,
		definitions.LogKeyMsg, "Error checking if account is already a member of the affected accounts set",
		definitions.LogKeyError, err,
	)

	return false, true
}

// addAffectedAccount adds an account to the affected-account set and index.
func (bm *bucketManagerImpl) addAffectedAccount(ctx context.Context, logger *slog.Logger, key string, accountName string) {
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, bm.cfg())
	defer cancel()

	if err := bm.redis().GetWriteHandle().SAdd(dCtx, key, accountName).Err(); err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Error adding account to the affected accounts set",
			definitions.LogKeyError, err,
		)

		return
	}

	bm.addAffectedAccountIndex(dCtx, logger, accountName)
}

// addAffectedAccountIndex adds an account to the sorted affected-account index.
func (bm *bucketManagerImpl) addAffectedAccountIndex(ctx context.Context, logger *slog.Logger, accountName string) {
	indexKey := rediscli.GetAffectedAccountsIndexKey(bm.cfg().GetServer().GetRedis().GetPrefix())
	if err := bm.redis().GetWriteHandle().ZAddNX(ctx, indexKey, redis.Z{
		Score:  float64(time.Now().Unix()),
		Member: accountName,
	}).Err(); err != nil {
		_ = level.Error(logger).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, "Error adding account to the affected accounts index",
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

// resolveAccountNameForHistory returns the account name for account-scoped password-history work.
func (bm *bucketManagerImpl) resolveAccountNameForHistory() string {
	account := bm.passwordHistoryAccount()
	if account.name != "" {
		return account.name
	}

	if account.skipMsg != "" {
		level.Debug(bm.logger()).Log(
			definitions.LogKeyGUID, bm.guid,
			definitions.LogKeyMsg, account.skipMsg,
		)
	}

	return ""
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
	if !bm.cfg().HasRuntimeModule(definitions.ControlBruteForce) {
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

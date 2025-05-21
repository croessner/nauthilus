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
	errors2 "errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/dspinhirne/netaddr-go"
	"github.com/go-kit/log/level"
	jsoniter "github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"
)

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

	// WithAdditionalFeatures sets additional features for the BucketManager instance and returns the updated BucketManager.
	// These features can be used by ML-based detection systems to enhance their prediction capabilities.
	WithAdditionalFeatures(features map[string]any) BucketManager

	// LoadAllPasswordHistories retrieves all recorded password history entries for further processing or analysis.
	LoadAllPasswordHistories()

	// CheckRepeatingBruteForcer evaluates if a repeating brute force attack is occurring based on the provided rules and IP network.
	// It returns whether processing should abort, if a rule is already triggered, and the index of the triggered rule.
	CheckRepeatingBruteForcer(rules []config.BruteForceRule, network **net.IPNet, message *string) (withError bool, alreadyTriggered bool, ruleNumber int)

	// CheckBucketOverLimit checks if any brute force rule is violated based on request data and network, updating the message if necessary.
	// It returns whether an error occurred, if a rule was triggered, and the rule number that was triggered (if any).
	CheckBucketOverLimit(rules []config.BruteForceRule, network **net.IPNet, message *string) (withError bool, ruleTriggered bool, ruleNumber int)

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
	additionalFeatures map[string]any
}

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
	var ipProto string
	var protocolPart string

	network, err := bm.getNetwork(rule)
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)

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

	// Add protocol information to the key if the rule has OnlyProtocols specified
	if len(rule.OnlyProtocols) > 0 && bm.protocol != "" {
		// Check if the current protocol is in the OnlyProtocols list
		protocolMatched := false
		for _, p := range rule.OnlyProtocols {
			if p == bm.protocol {
				protocolMatched = true

				break
			}
		}

		if protocolMatched {
			protocolPart = bm.protocol
		}
	}

	key = config.GetFile().GetServer().GetRedis().GetPrefix() + "bf:" + fmt.Sprintf(
		"%.0f:%d:%d:%s:%s", rule.Period.Seconds(), rule.CIDR, rule.FailedRequests, ipProto, network.String())

	// Append protocol part with a separator if it exists
	if protocolPart != "" {
		key += ":" + protocolPart
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

// WithAdditionalFeatures sets additional features for the bucket manager and returns the modified BucketManager instance.
// These features can be used by ML-based detection systems to enhance their prediction capabilities.
func (bm *bucketManagerImpl) WithAdditionalFeatures(features map[string]any) BucketManager {
	bm.additionalFeatures = features

	return bm
}

// WithProtocol sets the protocol for the bucket manager and returns the modified BucketManager instance.
func (bm *bucketManagerImpl) WithProtocol(protocol string) BucketManager {
	bm.protocol = protocol

	return bm
}

// LoadAllPasswordHistories loads and processes password history data for the current user and overall accounts from Redis.
func (bm *bucketManagerImpl) LoadAllPasswordHistories() {
	if !config.GetFile().HasFeature(definitions.FeatureBruteForce) {
		return
	}

	// Get password history for the current used username
	if key := bm.getPasswordHistoryRedisHashKey(true); key != "" {
		bm.loadPasswordHistoryFromRedis(key)
	}

	if bm.passwordHistory != nil {
		passwordHash := util.GetHash(util.PreparePassword(bm.password))
		if counter, foundPassword := (*bm.passwordHistory)[passwordHash]; foundPassword {
			bm.loginAttempts = counter
		}

		bm.passwordsAccountSeen = uint(len(*bm.passwordHistory))
	}

	// Get the overall password history
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
	var (
		ruleName string
		err      error
	)
	matchedAnyRule := false

	for ruleNumber = range rules {
		// Skip if the rule has OnlyProtocols specified and the current protocol is not in the list
		if len(rules[ruleNumber].OnlyProtocols) > 0 && bm.protocol != "" {
			protocolMatched := false
			for _, p := range rules[ruleNumber].OnlyProtocols {
				if p == bm.protocol {
					protocolMatched = true

					break
				}
			}

			if !protocolMatched {
				continue
			}
		}

		if *network, err = bm.getNetwork(&rules[ruleNumber]); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)

			return true, false, ruleNumber
		} else if network == nil {
			continue
		}

		// At this point, we've found at least one rule that matches our criteria
		matchedAnyRule = true

		if ruleName, err = bm.getPreResultBruteForceRedis(&rules[ruleNumber]); ruleName != "" && err == nil {
			alreadyTriggered = true
			*message = "Brute force attack detected (cached result)"

			stats.GetMetrics().GetBruteForceRejected().WithLabelValues(ruleName).Inc()

			break
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

	return withError, alreadyTriggered, ruleNumber
}

// CheckBucketOverLimit evaluates brute force rules for a given network to detect potential brute force attacks.
// Returns flags indicating errors, if a rule was triggered, and the index of the rule that triggered the detection.
func (bm *bucketManagerImpl) CheckBucketOverLimit(rules []config.BruteForceRule, network **net.IPNet, message *string) (withError bool, ruleTriggered bool, ruleNumber int) {
	var err error
	matchedAnyRule := false

	for ruleNumber = range rules {
		// Skip if the rule has OnlyProtocols specified and the current protocol is not in the list
		if len(rules[ruleNumber].OnlyProtocols) > 0 && bm.protocol != "" {
			protocolMatched := false
			for _, p := range rules[ruleNumber].OnlyProtocols {
				if p == bm.protocol {
					protocolMatched = true

					break
				}
			}

			if !protocolMatched {
				continue
			}
		}

		// Skip, where the current IP address does not match the current rule
		if *network, err = bm.getNetwork(&rules[ruleNumber]); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)

			return true, false, ruleNumber
		} else if network == nil {
			continue
		}

		// At this point, we've found at least one rule that matches our criteria
		matchedAnyRule = true

		bm.loadBruteForceBucketCounter(&rules[ruleNumber])

		// The counter goes from 0...N-1, but the 'failed_requests' setting from 1...N
		if bm.bruteForceCounter[rules[ruleNumber].Name]+1 > rules[ruleNumber].FailedRequests {
			ruleTriggered = true
			*message = "Brute force attack detected"
			stats.GetMetrics().GetBruteForceRejected().WithLabelValues(rules[ruleNumber].Name).Inc()

			break
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

// ProcessBruteForce evaluates and handles brute force detection logic, deciding whether further actions are necessary.
func (bm *bucketManagerImpl) ProcessBruteForce(ruleTriggered, alreadyTriggered bool, rule *config.BruteForceRule, network *net.IPNet, message string, setter func()) bool {
	if alreadyTriggered || ruleTriggered {
		var useCache bool

		defer setter()
		defer bm.LoadAllPasswordHistories()
		defer bm.SaveFailedPasswordCounterInRedis()

		logBucketRuleDebug(bm, network, rule)

		for _, backendType := range config.GetFile().GetServer().GetBackends() {
			if backendType.Get() == definitions.BackendCache {
				useCache = true

				break
			}
		}

		if !alreadyTriggered && useCache {
			if needEnforce, err := bm.checkEnforceBruteForceComputation(); err != nil {
				level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)

				return false
			} else if !needEnforce {
				stats.GetMetrics().GetBruteForceHits().WithLabelValues(rule.Name).Inc()

				return false
			}
		}

		if tolerate.GetTolerate().IsTolerated(bm.ctx, bm.clientIP) {
			level.Info(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, "IP address is tolerated")

			return false
		}

		bm.bruteForceName = rule.Name

		bm.updateAffectedAccount()

		if ruleTriggered {
			bm.setPreResultBruteForceRedis(rule)
		}

		logBucketMatchingRule(bm, network, rule, message)

		bm.featureName = definitions.FeatureBruteForce

		return true
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

	alreadyLearned, err = rediscli.GetClient().GetReadHandle().SIsMember(bm.ctx, key, bm.clientIP).Result()
	if err != nil {
		if !errors2.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)

			return
		}
	}

	if alreadyLearned {
		// IP address already stored
		return
	}

	// Use pipelining for write operations to reduce network round trips
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	_, err = rediscli.ExecuteWritePipeline(bm.ctx, func(pipe redis.Pipeliner) error {
		pipe.SAdd(bm.ctx, key, bm.clientIP)
		pipe.Expire(bm.ctx, key, config.GetFile().GetServer().Redis.NegCacheTTL)

		return nil
	})

	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)
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

		_, err := rediscli.ExecuteWritePipeline(bm.ctx, func(pipe redis.Pipeliner) error {
			// Only increment the counter if this is not the rule that triggered
			if bm.bruteForceName != rule.Name {
				pipe.Incr(bm.ctx, key)
			}

			// Always set the expiration time
			pipe.Expire(bm.ctx, key, rule.Period)

			return nil
		})

		if err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)
		}
	}
}

// SaveFailedPasswordCounterInRedis increments and persists failed password attempts in Redis for brute force protection.
func (bm *bucketManagerImpl) SaveFailedPasswordCounterInRedis() {
	if !config.GetFile().HasFeature(definitions.FeatureBruteForce) {
		return
	}

	var (
		keys          []string
		keysOverLimit bool
	)

	if bm.clientIP == "" {
		return
	}

	if bm.password == "" {
		panic("password is empty")
	}

	keys = append(keys, bm.getPasswordHistoryRedisHashKey(true))
	keys = append(keys, bm.getPasswordHistoryRedisHashKey(false))

	passwordHash := util.GetHash(util.PreparePassword(bm.password))

	for index := range keys {
		if bm.checkTooManyPasswordHashes(keys[index]) {
			keysOverLimit = true

			continue
		}

		util.DebugModule(definitions.DbgBf, definitions.LogKeyGUID, bm.guid, "incr_key", keys[index])

		// Use pipelining for write operations to reduce network round trips
		_, err := rediscli.ExecuteWritePipeline(bm.ctx, func(pipe redis.Pipeliner) error {
			// We can increment a key/value, even it never existed before.
			pipe.HIncrBy(bm.ctx, keys[index], passwordHash, 1)
			pipe.Expire(bm.ctx, keys[index], config.GetFile().GetServer().Redis.NegCacheTTL)

			return nil
		})

		// Count as two Redis operations for metrics
		stats.GetMetrics().GetRedisWriteCounter().Add(2)

		if err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)
			return
		}

		util.DebugModule(
			definitions.DbgBf,
			definitions.LogKeyGUID, bm.guid,
			"key", keys[index],
			definitions.LogKeyMsg, "Increased",
		)
	}

	if keysOverLimit {
		level.Info(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, "Too many password hashes for this account")
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

	// If the rule has OnlyProtocols specified, we need to check if the current protocol matches
	if len(rule.OnlyProtocols) > 0 && bm.protocol != "" {
		protocolMatched := false
		for _, p := range rule.OnlyProtocols {
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

	result, err := bm.getPreResultBruteForceRedis(rule)
	if result == "" {
		return "", err
	}

	if result == ruleName || ruleName == "*" {
		if network, err := bm.getNetwork(rule); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)
		} else {
			defer stats.GetMetrics().GetRedisWriteCounter().Inc()

			// For protocol-specific rules, we need to delete the entry with the network string as the key
			if removed, err := rediscli.GetClient().GetWriteHandle().HDel(bm.ctx, key, network.String()).Result(); err != nil {
				level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)
			} else {
				if removed > 0 {
					removedKey = key
				}
			}
		}

		return removedKey, err
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

	for _, rule := range rules {
		if ruleName, err := bm.getPreResultBruteForceRedis(&rule); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)
		} else {
			if ruleName == rule.Name {
				buckets = append(buckets, rule.Name)
			}
		}
	}

	return buckets, len(buckets) > 0
}

var _ BucketManager = (*bucketManagerImpl)(nil)

// isRepeatingWrongPassword checks if the current password has been repeatedly entered incorrectly and may indicate brute force.
// It returns true if the password repetition exceeds the predefined threshold; otherwise, it returns false.
// The method also logs attempts that meet the brute force detection criteria.
func (bm *bucketManagerImpl) isRepeatingWrongPassword() (repeating bool, err error) {
	if key := bm.getPasswordHistoryRedisHashKey(true); key != "" {
		bm.loadPasswordHistoryFromRedis(key)
	}

	if bm.password == "" {
		panic("password is empty")
	}

	passwordHash := util.GetHash(util.PreparePassword(bm.password))

	if bm.passwordHistory != nil {
		var (
			counter       uint
			foundPassword bool
		)

		if counter, foundPassword = (*bm.passwordHistory)[passwordHash]; !foundPassword {
			return false, nil
		}

		if key := bm.getPasswordHistoryRedisHashKey(false); key != "" {
			bm.loadPasswordHistoryFromRedis(key)
		}

		if bm.passwordHistory != nil {
			totalPasswordCounter := uint(0)

			for _, partialCounter := range *bm.passwordHistory {
				totalPasswordCounter += partialCounter
			}

			if totalPasswordCounter == counter {
				level.Info(log.Logger).Log(
					definitions.LogKeyGUID, bm.guid,
					definitions.LogKeyBruteForce, "Repeating wrong password",
					definitions.LogKeyUsername, bm.username,
					definitions.LogKeyClientIP, bm.clientIP,
					"counter", counter,
				)

				return true, nil
			}
		}
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
			level.Info(log.Logger).Log(
				definitions.LogKeyGUID, bm.guid,
				definitions.LogKeyMsg, "No negative password cache present",
				definitions.LogKeyUsername, bm.username,
				definitions.LogKeyClientIP, bm.clientIP,
			)

			return false, nil
		}
	}

	return true, nil
}

// getNetwork parses the client IP and generates a network object based on the provided brute force rule configuration.
// Returns the network object if valid, or an error if the IP address is incorrect or fails parsing.
func (bm *bucketManagerImpl) getNetwork(rule *config.BruteForceRule) (*net.IPNet, error) {
	ipAddress := net.ParseIP(bm.clientIP)

	if ipAddress == nil {
		return nil, fmt.Errorf("%s '%s'", errors.ErrWrongIPAddress, bm.clientIP)
	}

	if strings.Contains(ipAddress.String(), ":") {
		_, err := netaddr.ParseIPv6(bm.clientIP)
		if err != nil {
			return nil, err
		}
	}

	if ipAddress.To4() != nil {
		if !rule.IPv4 {
			return nil, nil
		}
	} else if ipAddress.To16() != nil {
		if !rule.IPv6 {
			return nil, nil
		}
	}

	_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", bm.clientIP, rule.CIDR))
	if err != nil {
		return nil, err
	}

	return network, nil
}

// getPasswordHistoryRedisHashKey generates the Redis hash key for password history storage based on username and client IP.
func (bm *bucketManagerImpl) getPasswordHistoryRedisHashKey(withUsername bool) (key string) {
	if withUsername {
		if bm.username == "" {
			panic("username is empty")
		}

		accountName := bm.accountName
		if accountName == "" {
			accountName = bm.username
		}

		key = config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHashKey + fmt.Sprintf(":%s:%s", accountName, bm.clientIP)
	} else {
		key = config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHashKey + ":" + bm.clientIP
	}

	util.DebugModule(
		definitions.DbgBf,
		definitions.LogKeyGUID, bm.guid,
		definitions.LogKeyClientIP, bm.clientIP,
		"key", key,
	)

	return
}

// checkTooManyPasswordHashes checks if the number of password hashes for a given Redis key exceeds the configured limit.
func (bm *bucketManagerImpl) checkTooManyPasswordHashes(key string) bool {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	if length, err := rediscli.GetClient().GetReadHandle().HLen(bm.ctx, key).Result(); err != nil {
		if !errors2.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)
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

	if passwordHistory, err := rediscli.GetClient().GetReadHandle().HGetAll(bm.ctx, key).Result(); err != nil {
		if !errors2.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)
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
					level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)
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
		level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)
	} else {
		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		if err = rediscli.GetClient().GetWriteHandle().HSet(bm.ctx, key, network.String(), bm.bruteForceName).Err(); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)
		}
	}
}

// getPreResultBruteForceRedis retrieves the name of a brute force rule from Redis based on the provided rule configuration.
// Returns the rule name and an error if any issues occur during Redis operations or while obtaining a network object.
func (bm *bucketManagerImpl) getPreResultBruteForceRedis(rule *config.BruteForceRule) (ruleName string, err error) {
	var network *net.IPNet

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisBruteForceHashKey

	network, err = bm.getNetwork(rule)
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)

		return
	} else {
		if network == nil {
			return
		}

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		if ruleName, err = rediscli.GetClient().GetReadHandle().HGet(bm.ctx, key, network.String()).Result(); err != nil {
			if !errors2.Is(err, redis.Nil) {
				level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)
			}
		}
	}

	err = nil

	return
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

	isMember, err := rediscli.GetClient().GetReadHandle().SIsMember(bm.ctx, key, bm.accountName).Result()
	if err != nil {
		if !errors2.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)

			return
		}
	}

	// If we already know it's a member, we can skip the write operation
	if isMember {
		return
	}

	// Add the account to the set
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	if err := rediscli.GetClient().GetWriteHandle().SAdd(bm.ctx, key, bm.accountName).Err(); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, bm.guid, definitions.LogKeyMsg, err)
	}
}

// NewBucketManager creates and returns a new instance of BucketManager with the provided context, GUID, and client IP.
func NewBucketManager(ctx context.Context, guid, clientIP string) BucketManager {
	return &bucketManagerImpl{
		ctx:      ctx,
		guid:     guid,
		clientIP: clientIP,
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
	var redisValue []byte

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	if redisValue, err = rediscli.GetClient().GetReadHandle().Get(ctx, key).Bytes(); err != nil {
		if errors2.Is(err, redis.Nil) {
			return nil
		}

		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return err
	}

	if err = jsoniter.ConfigFastest.Unmarshal(redisValue, bucketCounter); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return
	}

	return nil
}

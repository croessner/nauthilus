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

package core

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/dspinhirne/netaddr-go"
	"github.com/go-kit/log/level"
	"github.com/redis/go-redis/v9"
)

// BruteForceBucketCounter represents a cache mechanism to handle brute force attack mitigation using brute force buckets.
type BruteForceBucketCounter uint

// isRepeatingWrongPassword is a method associated with the AuthState struct used to check for repeated wrong password usage.
// It retrieves and loads a password history from Redis using a certain key.
// The function then checks if the current password has previously been within the loaded history and if its attempt count exceeds one.
// In such a case, it reloads the password history from Redis with an updated key.
// Finally, if the count of password attempts plus a predefined limit is greater or equal to the total count of attempts,
// an information log is created and the function returns 'true', signifying the excessive usage of the same wrong password.
// If none of these conditions are met, the function will return 'false', indicating the absence of repeated wrong password usage.
func (a *AuthState) isRepeatingWrongPassword() (repeating bool, err error) {
	if key := a.getPasswordHistoryRedisHashKey(true); key != "" {
		a.loadPasswordHistoryFromRedis(key)
	}

	passwordHash := util.GetHash(util.PreparePassword(a.Password))

	if a.PasswordHistory != nil {
		if counter, foundPassword := (*a.PasswordHistory)[passwordHash]; foundPassword {
			if counter > 1 {
				if key := a.getPasswordHistoryRedisHashKey(false); key != "" {
					a.loadPasswordHistoryFromRedis(key)
				}

				if a.PasswordHistory != nil {
					if counterTotal, foundPassword := (*a.PasswordHistory)[passwordHash]; foundPassword {
						// Hint: We may make this configurable one day.
						if counter+definitions.SamePasswordsDifferentAccountLimit >= counterTotal {
							level.Info(log.Logger).Log(
								definitions.LogKeyGUID, a.GUID,
								definitions.LogKeyBruteForce, "Repeating wrong password",
								definitions.LogKeyUsername, a.Username,
								definitions.LogKeyClientIP, a.ClientIP,
								"counter", counter,
							)

							return true, nil
						}
					}
				}
			}
		}
	}

	return false, nil
}

// userExists checks if a user exists in the backend.
// It calls the LookupUserAccountFromRedis function to look up the user's account name in Redis.
// If an error occurs during the lookup, the function returns the error.
// If the account name is empty, indicating that the user is not found, the function returns false.
// Otherwise, if the user exists, the function returns true.
//
// Usage example:
//
//	foundUser, err := a.userExists()
//	if err != nil {
//	    // handle error
//	}
//	if foundUser {
//	    // user exists
//	} else {
//	    // user does not exist
//	}
func (a *AuthState) userExists() (bool, error) {
	accountName, err := backend.LookupUserAccountFromRedis(a.HTTPClientContext, a.Username)
	if err != nil {
		return false, err
	}

	return accountName != "", nil
}

// checkEnforceBruteForceComputation checks the enforcement rules for brute force computation.
// - If the user exists and has a known UCN, the function checks for repeated wrong passwords.
//   - If this condition is met or an error occurs during checking, the function returns with false indicating "buckets" are not to be increased.
//   - If the user is not repeating wrong passwords and no cached negative password history is found, a warning is logged, and the function returns with false, signaling no bucket increase.
//
// - If the user does not exist, true is returned, enforcing the brute force computation leading to an increased bucket.
// In case of any error during user existence check, the function returns the error with a false.
func (a *AuthState) checkEnforceBruteForceComputation() (bool, error) {
	var (
		foundUser bool
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

	if foundUser, err = a.userExists(); err != nil {
		return false, err
	} else if foundUser {
		if repeating, err = a.isRepeatingWrongPassword(); err != nil {
			return false, err
		} else if repeating {
			return false, nil
		} else if a.PasswordHistory == nil {
			level.Info(log.Logger).Log(
				definitions.LogKeyGUID, a.GUID,
				definitions.LogKeyMsg, "No negative password cache present",
				definitions.LogKeyUsername, a.Username,
				definitions.LogKeyClientIP, a.ClientIP,
			)

			return false, nil
		}
	}

	return true, nil
}

// getNetwork is a method of the AuthState struct that is used to retrieve the network IP range based on a given BruteForceRule.
// It takes a pointer to a BruteForceRule struct as a parameter and returns a pointer to a net.IPNet and an error.
// The method first parses the ClientIP string into an IP address using net.ParseIP.
// If the parse is unsuccessful, it returns an error ErrWrongIPAddress.
// If the IP address has IPv6 format, it uses the netaddr.ParseIPv6 function to validate it.
// If the IP address is IPv4 and the rule does not allow IPv4, it returns nil.
// If the IP address is IPv6 and the rule does not allow IPv6, it returns nil.
// Finally, it parses the CIDR block by concatenating the ClientIP and the CIDR value from the rule,
// and returns the network IP range along with a nil error.
// If there's any error during the parsing process, it returns the error.
//
// Example usage:
//
//	network, err := a.getNetwork(rule)
//	if err != nil {
//	    log.Println("Error:", err)
//	}
//	if network == nil {
//	    log.Println("Network is nil")
//	}
func (a *AuthState) getNetwork(rule *config.BruteForceRule) (*net.IPNet, error) {
	ipAddress := net.ParseIP(a.ClientIP)

	if ipAddress == nil {
		return nil, fmt.Errorf("%s '%s'", errors.ErrWrongIPAddress, a.ClientIP)
	}

	if strings.Contains(ipAddress.String(), ":") {
		_, err := netaddr.ParseIPv6(a.ClientIP)
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

	_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", a.ClientIP, rule.CIDR))
	if err != nil {
		return nil, err
	}

	return network, nil
}

// This function 'getPasswordHistoryRedisHashKey' belongs to the AuthState struct.
// It is used to generate a unique Redis hash key based on whether a username is being included or not.
// If the 'withUsername' boolean parameter is true, the Redis hash key is generated
// using the Redis prefix, password hash key, the original username, and the client's IP address.
// If 'withUsername' is false, the Redis hash key is generated just appending the Redis prefix,
// password hash key, and the client's IP without the original username.
// This key is used for storing and retrieving the history of password usage in the context of preventing brute force attacks.
// An additional feature of this function is to log the generated key along with some context information (GUID and Client IP)
func (a *AuthState) getPasswordHistoryRedisHashKey(withUsername bool) (key string) {
	if withUsername {
		accountName := getUserAccountFromCache(a.HTTPClientContext, a.Username, *a.GUID)
		if accountName == "" {
			accountName = a.Username
		}

		key = config.LoadableConfig.Server.Redis.Prefix + definitions.RedisPwHashKey + fmt.Sprintf(":%s:%s", accountName, a.ClientIP)
	} else {
		key = config.LoadableConfig.Server.Redis.Prefix + definitions.RedisPwHashKey + ":" + a.ClientIP
	}

	util.DebugModule(
		definitions.DbgBf,
		definitions.LogKeyGUID, a.GUID,
		definitions.LogKeyClientIP, a.ClientIP,
		"key", key,
	)

	return
}

// logBruteForceRuleRedisKeyDebug logs detailed information about a brute force rule execution for debugging purposes.
func logBruteForceRuleRedisKeyDebug(auth *AuthState, rule *config.BruteForceRule, network *net.IPNet, key string) {
	util.DebugModule(
		definitions.DbgBf,
		definitions.LogKeyGUID, auth.GUID,
		definitions.LogKeyClientIP, auth.ClientIP,
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

// This function belongs to the AuthState struct. It is used to generate a unique
// Redis key for brute force rule tracking.
//
// For a given brute force rule, this function generates a Redis key used to
// maintain a record of failed requests. The key contains various components including
// the period of rule enforcement, the CIDR block, and the number of failed requests.
// Additional details related to IP version (IPv4 or IPv6) and network string are also
// incorporated as part of the Redis key.
//
// The function begins by checking the rule's network details. In cases where an error
// occurs while fetching network details or if the network details do not exist, the
// function logs the error (if any) and returns without generating a key.
//
// For IPv4 and IPv6 rules, the function assigns the IP protocol number accordingly.
// The Redis key for tracking brute force is constructed on RedisPrefix followed by
// an identifier, then it includes the rule's period, CIDR, number of failed requests,
// IP protocol version and the network string.
//
// Upon successfully generating the key, the function logs debugging information, which
// can be used for diagnostic or analytical purposes.
//
// Parameters:
// rule - The brute force rule that this function is generating a Redis key for.
//
// Returns:
// key - The generated Redis key for the given brute force rule.
func (a *AuthState) getBruteForceBucketRedisKey(rule *config.BruteForceRule) (key string) {
	var ipProto string

	network, err := a.getNetwork(rule)
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)

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

	key = config.LoadableConfig.Server.Redis.Prefix + "bf:" + fmt.Sprintf(
		"%d:%d:%d:%s:%s", rule.Period, rule.CIDR, rule.FailedRequests, ipProto, network.String())

	logBruteForceRuleRedisKeyDebug(a, rule, network, key)

	return
}

// checkTooManyPasswordHashes checks if the number of password hashes for a given Redis key exceeds the configured limit.
func (a *AuthState) checkTooManyPasswordHashes(key string) bool {
	defer stats.RedisReadCounter.Inc()

	defer stats.RedisReadCounter.Inc()

	if length, err := rediscli.ReadHandle.HLen(a.HTTPClientContext, key).Result(); err != nil {
		if !stderrors.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
		}

		return true
	} else {
		if length > int64(config.LoadableConfig.Server.MaxPasswordHistoryEntries) {
			return true
		}
	}

	return false
}

// loadPasswordHistoryFromRedis loads password history related to brute force attacks from Redis for a given key.
// The function will fetch all associated passwords in the form of a hash along with a counter.
// The Redis key is created for each unique user presented by the variable `key`, which is a GUID.
// This helps in tracking the number of attempts a user has made for password authentication.
// The function will generate an error logs for unsuccessful retrieval of password history data from Redis.
// The password history data is stored in the AuthState's `PasswordHistory` field.
//
// Parameters:
//   - key: A string that represents the unique GUID of a user
//
// Note: If the passed key is an empty string, the function will return immediately.
func (a *AuthState) loadPasswordHistoryFromRedis(key string) {
	if key == "" {
		return
	}

	util.DebugModule(definitions.DbgBf, definitions.LogKeyGUID, a.GUID, "load_key", key)

	defer stats.RedisReadCounter.Inc()

	if passwordHistory, err := rediscli.ReadHandle.HGetAll(a.HTTPClientContext, key).Result(); err != nil {
		if !stderrors.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
		}

		return
	} else {
		var counterInt int

		if a.PasswordHistory == nil {
			a.PasswordHistory = new(backend.PasswordHistory)
			*a.PasswordHistory = make(backend.PasswordHistory)
		}

		for passwordHash, counter := range passwordHistory {
			if counterInt, err = strconv.Atoi(counter); err != nil {
				if !stderrors.Is(err, redis.Nil) {
					level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
				}

				return
			}

			(*a.PasswordHistory)[passwordHash] = uint(counterInt)
		}
	}
}

// getAllPasswordHistories is a method of the AuthState struct.
// This method fetches and processes all password histories for the user represented by 'a'.
// This method performs two major operations.
// In the first phase, it fetches the password history specific to the current user using the Redis hash key.
// The password history is stored in a local variable and processed to compute login attempts and seen account passwords.
// In the second phase, it retrieves the overall password history again using the Redis hash key.
// This overall history is then used to compute the total number of seen passwords.
// Each of these phases is independent and is executed if the Redis hash key retrieval and the password history fetch operations are successful.
func (a *AuthState) getAllPasswordHistories() {
	if !config.LoadableConfig.HasFeature(definitions.FeatureBruteForce) {
		return
	}

	// Get password history for the current used username
	if key := a.getPasswordHistoryRedisHashKey(true); key != "" {
		a.loadPasswordHistoryFromRedis(key)
	}

	if a.PasswordHistory != nil {
		passwordHash := util.GetHash(util.PreparePassword(a.Password))
		if counter, foundPassword := (*a.PasswordHistory)[passwordHash]; foundPassword {
			a.LoginAttempts = counter
		}

		a.PasswordsAccountSeen = uint(len(*a.PasswordHistory))
	}

	// Get the overall password history
	if key := a.getPasswordHistoryRedisHashKey(false); key != "" {
		a.loadPasswordHistoryFromRedis(key)
	}

	if a.PasswordHistory != nil {
		a.PasswordsTotalSeen = uint(len(*a.PasswordHistory))
	}
}

// saveFailedPasswordCounterInRedis is a method of the AuthState struct that is responsible for handling brute force attempts.
// It works by saving password attempts to Redis data store. When a password is entered incorrectly,
// the function stores this incorrect password's hash within a Redis key that is specific to the account in question.
//
// This method will save keys for both brute force history and current attempt, and then for each key in the list of keys:
//
//  1. It increments the value of this key by one, creating the key if it does not already exist.
//     This increments a counter for each bad password attempt.
//  2. Log an error message if there is an error incrementing the key's value
//  3. Set an expiry time on the key. This has the effect of automatically deleting the keys after a certain period of time.
//  4. Logs an error message if there is an error setting expiry time
//
// The function concludes by logging that the process has finished.
func (a *AuthState) saveFailedPasswordCounterInRedis() {
	if !config.LoadableConfig.HasFeature(definitions.FeatureBruteForce) {
		return
	}

	var (
		keys          []string
		keysOverLimit bool
	)

	if a.ClientIP == "" {
		return
	}

	keys = append(keys, a.getPasswordHistoryRedisHashKey(true))
	keys = append(keys, a.getPasswordHistoryRedisHashKey(false))

	for index := range keys {
		if a.checkTooManyPasswordHashes(keys[index]) {
			keysOverLimit = true

			continue
		}

		util.DebugModule(definitions.DbgBf, definitions.LogKeyGUID, a.GUID, "incr_key", keys[index])

		// We can increment a key/value, even it never existed before.
		if err := rediscli.WriteHandle.HIncrBy(
			a.HTTPClientContext,
			keys[index],
			util.GetHash(util.PreparePassword(a.Password)), 1,
		).Err(); err != nil {
			stats.RedisWriteCounter.Inc()

			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)

			return
		} else {
			stats.RedisWriteCounter.Inc()
		}

		util.DebugModule(
			definitions.DbgBf,
			definitions.LogKeyGUID, a.GUID,
			"key", keys[index],
			definitions.LogKeyMsg, "Increased",
		)

		if err := rediscli.WriteHandle.Expire(a.HTTPClientContext, keys[index], time.Duration(config.LoadableConfig.Server.Redis.NegCacheTTL)*time.Second).Err(); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
		}

		stats.RedisWriteCounter.Inc()
	}

	if keysOverLimit {
		level.Info(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, "Too many password hashes for this account")
	}
}

// loadBruteForceBucketCounterFromRedis loads a bucket counter from Redis.
// Increments Redis read operations counter.
// On success, unmarshals the Redis value into bucketCounter.
// If the key doesn't exist, returns nil.
// Logs errors if Redis operations or JSON unmarshalling fails.
func loadBruteForceBucketCounterFromRedis(ctx context.Context, key string, bucketCounter *BruteForceBucketCounter) (err error) {
	var redisValue []byte

	defer stats.RedisReadCounter.Inc()

	if redisValue, err = rediscli.ReadHandle.Get(ctx, key).Bytes(); err != nil {
		if stderrors.Is(err, redis.Nil) {
			return nil
		}

		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return err
	}

	if err = json.Unmarshal(redisValue, bucketCounter); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return
	}

	return nil
}

// loadBruteForceBucketCounter is a method on the AuthState struct that loads the brute force
// bucket counter from Redis and updates the BruteForceCounter map. The given BruteForceRule is used to generate the Redis key.
// If the key is not empty, it retrieves the counter-value from Redis using the backend.LoadCacheFromRedis function.
// If an error occurs while loading the cache, the function returns.
// If the BruteForceCounter is not initialized, it creates a new map.
// Finally, it updates the BruteForceCounter map with the counter-value retrieved from Redis using the rule name as the key.
func (a *AuthState) loadBruteForceBucketCounter(rule *config.BruteForceRule) {
	if !config.LoadableConfig.HasFeature(definitions.FeatureBruteForce) {
		return
	}

	bucketCounter := new(BruteForceBucketCounter)

	if key := a.getBruteForceBucketRedisKey(rule); key != "" {
		util.DebugModule(definitions.DbgBf, definitions.LogKeyGUID, a.GUID, "load_key", key)

		if err := loadBruteForceBucketCounterFromRedis(a.HTTPClientContext, key, bucketCounter); err != nil {
			return
		}
	}

	if a.BruteForceCounter == nil {
		a.BruteForceCounter = make(map[string]uint)
	}

	a.BruteForceCounter[rule.Name] = uint(*bucketCounter)
}

// saveBruteForceBucketCounterToRedis is a method on the AuthState struct that saves brute force
// attempt information to Redis. This helps in maintaining a counter for each unique brute force rule.
// The brute force rule that is passed as param is used to generate the key for Redis.
// If the key is not empty, the related counter is incremented in Redis.
// Note that the counter is not incremented if 'BruteForceName' is equal to the 'Name' in the given rule.
// The function also sets the key expiration time in Redis as per the 'Period' field given in the rule.
// In case of any errors (while incrementing the counter or setting the expiration), the error is logged.
func (a *AuthState) saveBruteForceBucketCounterToRedis(rule *config.BruteForceRule) {
	if key := a.getBruteForceBucketRedisKey(rule); key != "" {
		util.DebugModule(definitions.DbgBf, definitions.LogKeyGUID, a.GUID, "store_key", key)

		if a.BruteForceName != rule.Name {
			defer stats.RedisWriteCounter.Inc()

			if err := rediscli.WriteHandle.Incr(a.HTTPClientContext, key).Err(); err != nil {
				level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
			}
		}

		defer stats.RedisWriteCounter.Inc()

		if err := rediscli.WriteHandle.Expire(a.HTTPClientContext, key, time.Duration(rule.Period)*time.Second).Err(); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
		}
	}
}

// setPreResultBruteForceRedis sets the BruteForceRule name in the Redis hash map based on the network IP address obtained from the given BruteForceRule parameter.
// If there is an error during the operation, it logs the error using the Logger.
func (a *AuthState) setPreResultBruteForceRedis(rule *config.BruteForceRule) {
	key := config.LoadableConfig.Server.Redis.Prefix + definitions.RedisBruteForceHashKey

	network, err := a.getNetwork(rule)
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
	} else {
		defer stats.RedisWriteCounter.Inc()

		if err = rediscli.WriteHandle.HSet(a.HTTPClientContext, key, network.String(), a.BruteForceName).Err(); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
		}
	}
}

// getPreResultBruteForceRedis retrieves the name of the BruteForceRule from the Redis hash map, based on the network IP address obtained from the given BruteForceRule parameter.
// If there is an error during the retrieval, it will log the error using the Logger.
// If the key-value pair does not exist in the Redis hash map, it will return an empty string.
// The retrieved rule name will be returned as a result.
func (a *AuthState) getPreResultBruteForceRedis(rule *config.BruteForceRule) (ruleName string, err error) {
	var network *net.IPNet

	key := config.LoadableConfig.Server.Redis.Prefix + definitions.RedisBruteForceHashKey

	network, err = a.getNetwork(rule)
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)

		return
	} else {
		defer stats.RedisReadCounter.Inc()

		if ruleName, err = rediscli.ReadHandle.HGet(a.HTTPClientContext, key, network.String()).Result(); err != nil {
			if !stderrors.Is(err, redis.Nil) {
				level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
			}
		}
	}

	err = nil

	return
}

// deleteIPBruteForceRedis deletes the IP address from the Redis hash map for brute force prevention.
// It checks if the IP address is present in the hash map and matches the provided rule name or if the rule name is "*".
// If there's a match, it retrieves the network associated with the rule, constructs the hash map key, and deletes the IP address from the hash map using Redis HDEL command.
// If there's an error, it logs the error using the Logger.
func (a *AuthState) deleteIPBruteForceRedis(rule *config.BruteForceRule, ruleName string) (string, error) {
	var removedKey string

	key := config.LoadableConfig.Server.Redis.Prefix + definitions.RedisBruteForceHashKey

	result, err := a.getPreResultBruteForceRedis(rule)
	if result == "" {
		return "", err
	}

	if result == ruleName || ruleName == "*" {
		if network, err := a.getNetwork(rule); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
		} else {
			defer stats.RedisWriteCounter.Inc()

			if removed, err := rediscli.WriteHandle.HDel(a.HTTPClientContext, key, network.String()).Result(); err != nil {
				level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
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

// processPWHist stores the client's IP address in the password history Redis set if it has not been stored already.
// Returns accountName from Redis, if available.
func (a *AuthState) processPWHist() (accountName string) {
	var (
		alreadyLearned bool
		err            error
	)

	if a.ClientIP == "" {
		return
	}

	accountName = getUserAccountFromCache(a.HTTPClientContext, a.Username, *a.GUID)
	if accountName == "" {
		return
	}

	key := getPWHistIPsRedisKey(accountName)

	defer stats.RedisReadCounter.Inc()

	alreadyLearned, err = rediscli.ReadHandle.SIsMember(a.HTTPClientContext, key, a.ClientIP).Result()
	if err != nil {
		if !stderrors.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)

			return
		}
	}

	if alreadyLearned {
		// IP address already stored
		return
	}

	defer stats.RedisWriteCounter.Inc()

	if err = rediscli.WriteHandle.SAdd(a.HTTPClientContext, key, a.ClientIP).Err(); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
	}

	defer stats.RedisWriteCounter.Inc()

	if err = rediscli.WriteHandle.Expire(a.HTTPClientContext, key, time.Duration(config.LoadableConfig.Server.Redis.NegCacheTTL)*time.Second).Err(); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
	}

	return
}

// updateAffectedAccount processes a blocked account by checking its existence in Redis and adding it if not present.
// It increments Redis read and write counters and logs errors encountered during the operations.
func (a *AuthState) updateAffectedAccount() {
	accountName := a.refreshUserAccount()
	if accountName == "" {
		return
	}

	key := config.LoadableConfig.Server.Redis.Prefix + definitions.RedisAffectedAccountsKey

	defer stats.RedisReadCounter.Inc()

	if err := rediscli.ReadHandle.SIsMember(a.HTTPClientContext, key, accountName).Err(); err != nil {
		if !stderrors.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)

			return
		}
	}

	defer stats.RedisWriteCounter.Inc()

	if err := rediscli.WriteHandle.SAdd(a.HTTPClientContext, key, accountName).Err(); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
	}

	return
}

// getPWHistIPsRedisKey generates the Redis key for storing password history associated with IPs for a specific account.
func getPWHistIPsRedisKey(accountName string) string {
	key := config.LoadableConfig.Server.Redis.Prefix + definitions.RedisPWHistIPsKey + ":" + accountName

	return key
}

// logBruteForceDebug logs debug information related to brute force authentication attempts using the provided AuthState.
func logBruteForceDebug(auth *AuthState) {
	util.DebugModule(
		definitions.DbgBf,
		definitions.LogKeyGUID, *auth.GUID,
		definitions.LogKeyClientIP, auth.ClientIP,
		definitions.LogKeyClientPort, auth.XClientPort,
		definitions.LogKeyClientHost, auth.ClientHost,
		definitions.LogKeyClientID, auth.XClientID,
		definitions.LogKeyLocalIP, auth.XLocalIP,
		definitions.LogKeyPort, auth.XPort,
		definitions.LogKeyUsername, auth.Username,
		definitions.LogKeyProtocol, auth.Protocol.Get(),
		"service", util.WithNotAvailable(auth.Service),
		"no-auth", auth.NoAuth,
		"list-accounts", auth.ListAccounts,
	)
}

// logBucketRuleDebug logs debug information for a brute force rule, including client IP, rule details, and request counts.
func logBucketRuleDebug(auth *AuthState, network *net.IPNet, rule *config.BruteForceRule) {
	util.DebugModule(definitions.DbgBf,
		definitions.LogKeyGUID, auth.GUID,
		"limit", rule.FailedRequests,
		definitions.LogKeyClientIP, auth.ClientIP,
		"rule_network", fmt.Sprintf("%v", network),
		"rule", rule.Name,
		"counter", auth.BruteForceCounter[rule.Name],
	)
}

// logBucketMatchingRule logs information about a matched brute force rule for a given authentication state.
func logBucketMatchingRule(auth *AuthState, network *net.IPNet, rule *config.BruteForceRule, message string) {
	level.Info(log.Logger).Log(
		definitions.LogKeyGUID, auth.GUID,
		definitions.LogKeyBruteForce, message,
		definitions.LogKeyUsername, auth.Username,
		definitions.LogKeyClientIP, auth.ClientIP,
		"rule_network", fmt.Sprintf("%v", network),
		"rule", rule.Name,
	)
}

// checkBucketOverLimit checks if the given network exceeds the brute force allowed thresholds based on predefined rules.
// It verifies the current network against the specified brute force rules and returns if any rule is triggered.
func (a *AuthState) checkBucketOverLimit(rules []config.BruteForceRule, network **net.IPNet, message *string) (withError bool, ruleTriggered bool, ruleNumber int) {
	var err error

	for ruleNumber = range rules {
		// Skip, where the current IP address does not match the current rule
		if *network, err = a.getNetwork(&rules[ruleNumber]); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)

			return true, false, ruleNumber
		} else if network == nil {
			continue
		}

		a.loadBruteForceBucketCounter(&rules[ruleNumber])

		// The counter goes from 0...N-1, but the 'failed_requests' setting from 1...N
		if a.BruteForceCounter[rules[ruleNumber].Name]+1 > rules[ruleNumber].FailedRequests {
			ruleTriggered = true
			*message = "Brute force attack detected"
			stats.BruteForceRejected.WithLabelValues(rules[ruleNumber].Name).Inc()

			break
		}
	}

	return withError, ruleTriggered, ruleNumber
}

// handleBruteForceLuaAction handles the brute force Lua action based on the provided authentication state and rule config.
func (a *AuthState) handleBruteForceLuaAction(alreadyTriggered bool, rule *config.BruteForceRule, network *net.IPNet) {
	if config.LoadableConfig.HaveLuaActions() {
		finished := make(chan action.Done)
		accountName := a.GetAccount()

		action.RequestChan <- &action.Action{
			LuaAction:    definitions.LuaActionBruteForce,
			Context:      a.Context,
			FinishedChan: finished,
			HTTPRequest:  a.HTTPClientContext.Request,
			CommonRequest: &lualib.CommonRequest{
				Debug:               config.LoadableConfig.Server.Log.Level.Level() == definitions.LogLevelDebug,
				Repeating:           alreadyTriggered,
				UserFound:           func() bool { return accountName != "" }(),
				Authenticated:       false, // unavailable
				NoAuth:              a.NoAuth,
				BruteForceCounter:   a.BruteForceCounter[rule.Name],
				Service:             a.Service,
				Session:             *a.GUID,
				ClientIP:            a.ClientIP,
				ClientPort:          a.XClientPort,
				ClientNet:           network.String(),
				ClientHost:          a.ClientHost,
				ClientID:            a.XClientID,
				LocalIP:             a.XLocalIP,
				LocalPort:           a.XPort,
				UserAgent:           *a.UserAgent,
				Username:            a.Username,
				Account:             accountName,
				AccountField:        a.GetAccountField(),
				UniqueUserID:        "", // unavailable
				DisplayName:         "", // unavailable
				Password:            a.Password,
				Protocol:            a.Protocol.Get(),
				BruteForceName:      rule.Name,
				FeatureName:         a.FeatureName,
				StatusMessage:       &a.StatusMessage,
				XSSL:                a.XSSL,
				XSSLSessionID:       a.XSSLSessionID,
				XSSLClientVerify:    a.XSSLClientVerify,
				XSSLClientDN:        a.XSSLClientDN,
				XSSLClientCN:        a.XSSLClientCN,
				XSSLIssuer:          a.XSSLIssuer,
				XSSLClientNotBefore: a.XSSLClientNotBefore,
				XSSLClientNotAfter:  a.XSSLClientNotAfter,
				XSSLSubjectDN:       a.XSSLSubjectDN,
				XSSLIssuerDN:        a.XSSLIssuerDN,
				XSSLClientSubjectDN: a.XSSLClientSubjectDN,
				XSSLClientIssuerDN:  a.XSSLClientIssuerDN,
				XSSLProtocol:        a.XSSLProtocol,
				XSSLCipher:          a.XSSLCipher,
				SSLSerial:           a.SSLSerial,
				SSLFingerprint:      a.SSLFingerprint,
			},
		}

		<-finished
	}
}

// processBruteForce processes authentication state to handle brute force attempts based on rule triggers and network details.
func (a *AuthState) processBruteForce(ruleTriggered, alreadyTriggered bool, rule *config.BruteForceRule, network *net.IPNet, message string) bool {
	if alreadyTriggered || ruleTriggered {
		var useCache bool

		logBucketRuleDebug(a, network, rule)

		for _, backendType := range config.LoadableConfig.Server.Backends {
			if backendType.Get() == definitions.BackendCache {
				useCache = true

				break
			}
		}

		if useCache {
			if needEnforce, err := a.checkEnforceBruteForceComputation(); err != nil {
				level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)

				return false
			} else if !needEnforce {
				stats.BruteForceHits.WithLabelValues(rule.Name).Inc()

				return false
			}
		}

		a.BruteForceName = rule.Name

		a.updateAffectedAccount()
		a.saveFailedPasswordCounterInRedis()
		a.getAllPasswordHistories()

		if ruleTriggered {
			a.setPreResultBruteForceRedis(rule)
		}

		logBucketMatchingRule(a, network, rule, message)

		a.FeatureName = definitions.FeatureBruteForce

		a.handleBruteForceLuaAction(alreadyTriggered, rule, network)

		return true
	}

	return false
}

// checkRepeatingBruteForcer analyzes if a network partakes in repeated brute force attempts,
// according to specified rules.
// It returns a boolean indicating an error, whether a brute force rule already triggered, and the rule number.
func (a *AuthState) checkRepeatingBruteForcer(rules []config.BruteForceRule, network **net.IPNet, message *string) (withError bool, alreadyTriggered bool, ruleNumber int) {
	var (
		ruleName string
		err      error
	)

	for ruleNumber = range rules {
		if *network, err = a.getNetwork(&rules[ruleNumber]); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)

			return true, false, ruleNumber
		} else if network == nil {
			continue
		}

		if ruleName, err = a.getPreResultBruteForceRedis(&rules[ruleNumber]); ruleName != "" && err == nil {
			alreadyTriggered = true
			*message = "Brute force attack detected (cached result)"
			stats.BruteForceRejected.WithLabelValues(ruleName).Inc()

			break
		}
	}

	return withError, alreadyTriggered, ruleNumber
}

// CheckBruteForce is a method of the `AuthState` struct and is responsible for
// telling whether the client IP should be blocked due to unrestricted unauthorized access attempts
// (i.e., a Brute Force attack on the system).
//
// The implementation works as follows:
//   - It initializes a handful of variables used for later computation.
//   - It verifies if the `BruteForce` property in the configuration is defined.
//   - The method logs several useful debugging properties such as client IP, username, port, etc.
//   - It looks for certain conditions such as `NoAuth` or `ListAccounts` under which the method returns 'false' immediately.
//   - The method verifies if the client IP is localhost or unavailable and logs relevant info if it is.
//   - It checks if Brute Force security is enabled for the current protocol being used, logging the data if it's not enabled.
//   - The function checks if the current client IP is in the IP allowlist and logs the relevant data if it is.
//   - It iterates over various Brute Force rules to determine if the client IP falls into any predefined rule and logs the data.
//   - Lastly, it checks if any Brute Force rule is triggered, whereupon it saves some information in Redis, retrieves it back, logs
//     the appropriate message, and runs a Lua script for handling the detected brute force attempt.
//
// It returns 'true' if a Brute Force attack is detected, otherwise returns 'false'.
func (a *AuthState) CheckBruteForce() (blockClientIP bool) {
	var (
		ruleTriggered bool
		message       string
	)

	if a.NoAuth || a.ListAccounts {
		return false
	}

	if !config.LoadableConfig.HasFeature(definitions.FeatureBruteForce) {
		return false
	}

	stopTimer := stats.PrometheusTimer(definitions.PromBruteForce, "brute_force_check_request_total")

	if stopTimer != nil {
		defer stopTimer()
	}

	// All rules
	rules := config.LoadableConfig.GetBruteForceRules()

	if len(rules) == 0 {
		return false
	}

	logBruteForceDebug(a)

	if isLocalOrEmptyIP(a.ClientIP) {
		a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyBruteForce)
		a.AdditionalLogs = append(a.AdditionalLogs, definitions.Localhost)

		return false
	}

	if len(config.LoadableConfig.BruteForce.IPWhitelist) > 0 {
		if a.IsInNetwork(config.LoadableConfig.BruteForce.IPWhitelist) {
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyBruteForce)
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.Whitelisted)

			return false
		}
	}

	if config.LoadableConfig.BruteForce.HasSoftWhitelist() {
		if util.IsSoftWhitelisted(a.Username, a.ClientIP, *a.GUID, config.LoadableConfig.BruteForce.SoftWhitelist) {
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyBruteForce)
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.SoftWhitelisted)

			return false
		}
	}

	bruteForceProtocolEnabled := false
	for _, bruteForceService := range config.LoadableConfig.Server.BruteForceProtocols {
		if bruteForceService.Get() != a.Protocol.Get() {
			continue
		}

		bruteForceProtocolEnabled = true

		break
	}

	if !bruteForceProtocolEnabled {
		level.Warn(log.Logger).Log(
			definitions.LogKeyGUID, a.GUID,
			definitions.LogKeyBruteForce, fmt.Sprintf("Not enabled for protocol '%s'", a.Protocol.Get()))

		return false
	}

	network := &net.IPNet{}

	abort, alreadyTriggered, ruleNumber := a.checkRepeatingBruteForcer(rules, &network, &message)
	if abort {
		return false
	}

	if !alreadyTriggered {
		abort, ruleTriggered, ruleNumber = a.checkBucketOverLimit(rules, &network, &message)
		if abort {
			return false
		}
	}

	return a.processBruteForce(ruleTriggered, alreadyTriggered, &rules[ruleNumber], network, message)
}

// UpdateBruteForceBucketsCounter updates the brute force buckets counter for the current authentication
// It checks if brute force is enabled for the current protocol and if the client IP is not in the whitelist
// Then it iterates through the loaded brute force rules and saves the bucket counter to Redis
// The method also logs debug information related to the authentication
//
// Parameters:
//   - a: a pointer to the AuthState struct which contains the authentication details
//
// Returns: none
func (a *AuthState) UpdateBruteForceBucketsCounter() {
	if !config.LoadableConfig.HasFeature(definitions.FeatureBruteForce) {
		return
	}

	if config.LoadableConfig.BruteForce == nil {
		return
	}

	util.DebugModule(
		definitions.DbgBf,
		definitions.LogKeyGUID, *a.GUID,
		definitions.LogKeyClientIP, a.ClientIP,
		definitions.LogKeyClientPort, a.XClientPort,
		definitions.LogKeyClientHost, a.ClientHost,
		definitions.LogKeyClientID, a.XClientID,
		definitions.LogKeyLocalIP, a.XLocalIP,
		definitions.LogKeyPort, a.XPort,
		definitions.LogKeyUsername, a.Username,
		definitions.LogKeyProtocol, a.Protocol.Get(),
		"service", util.WithNotAvailable(a.Service),
		"no-auth", a.NoAuth,
		"list-accounts", a.ListAccounts,
	)

	if a.NoAuth || a.ListAccounts {
		return
	}

	if a.ClientIP == definitions.Localhost4 || a.ClientIP == definitions.Localhost6 || a.ClientIP == definitions.NotAvailable {
		return
	}

	bruteForceEnabled := false
	for _, bruteForceService := range config.LoadableConfig.Server.BruteForceProtocols {
		if bruteForceService.Get() != a.Protocol.Get() {
			continue
		}

		bruteForceEnabled = true

		break
	}

	if !bruteForceEnabled {
		return
	}

	if len(config.LoadableConfig.BruteForce.IPWhitelist) > 0 {
		if a.IsInNetwork(config.LoadableConfig.BruteForce.IPWhitelist) {
			return
		}
	}

	matchedPeriod := uint(0)

	for _, rule := range config.LoadableConfig.GetBruteForceRules() {
		if a.BruteForceName != rule.Name {
			continue
		}

		matchedPeriod = rule.Period

		break
	}

	for _, rule := range config.LoadableConfig.GetBruteForceRules() {
		if matchedPeriod == 0 || rule.Period >= matchedPeriod {
			a.saveBruteForceBucketCounterToRedis(&rule)
		}
	}
}

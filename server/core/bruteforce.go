package core

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/util"
	"github.com/dspinhirne/netaddr-go"
	"github.com/go-kit/log/level"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"
)

// isRepeatingWrongPassword is a method associated with the Authentication struct used to check for repeated wrong password usage.
// It retrieves and loads a password history from Redis using a certain key.
// The function then checks if the current password has previously been within the loaded history and if it's attempt count exceeds one.
// In such a case, it reloads the password history from Redis with an updated key.
// Finally, if the count of password attempts plus a predefined limit is greater or equal to the total count of attempts,
// an information log is created and the function returns 'true', signifying the excessive usage of the same wrong password.
// If none of these conditions are met, the function will return 'false', indicating the absence of repeated wrong password usage.
func (a *Authentication) isRepeatingWrongPassword() (repeating bool, err error) {
	if key := a.getBruteForcePasswordHistoryRedisHashKey(true); key != "" {
		a.loadBruteForcePasswordHistoryFromRedis(key)
	}

	passwordHash := util.GetHash(util.PreparePassword(a.Password))

	if a.PasswordHistory != nil {
		if counter, foundPassword := (*a.PasswordHistory)[passwordHash]; foundPassword {
			if counter > 1 {
				if key := a.getBruteForcePasswordHistoryRedisHashKey(false); key != "" {
					a.loadBruteForcePasswordHistoryFromRedis(key)
				}

				if a.PasswordHistory != nil {
					if counterTotal, foundPassword := (*a.PasswordHistory)[passwordHash]; foundPassword {
						// Hint: We may make this configurable one day.
						if counter+global.SamePasswordsDifferentAccountLimit >= counterTotal {
							level.Info(logging.DefaultLogger).Log(
								global.LogKeyGUID, a.GUID,
								global.LogKeyBruteForce, "Repeating wrong password",
								global.LogKeyOrigUsername, a.UsernameOrig,
								global.LogKeyClientIP, a.ClientIP,
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
// It calls the LookupUserAccountFromRedis function to lookup the user's account name in Redis.
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
func (a *Authentication) userExists() (bool, error) {
	accountName, err := backend.LookupUserAccountFromRedis(a.Username)
	if err != nil {
		return false, err
	} else {
		redisReadCounter.Inc()
	}

	if accountName == "" {
		return false, nil
	}

	return true, nil
}

// checkEnforceBruteForceComputation checks the enforcement rules for brute force computation.
// - If the user exists and has a known UCN, the function checks for repeated wrong passwords.
//   - If this condition is met or an error occurs during checking, the function returns with false indicating "buckets" are not to be increased.
//   - If the user is not repeating wrong passwords and no cached negative password history is found, a warning is logged, and the function returns with false, signaling no bucket increase.
//
// - If the user does not exist, true is returned, enforcing the brute force computation leading to an increased bucket.
// In case of any error during user existence check, the function returns the error with a false.
func (a *Authentication) checkEnforceBruteForceComputation() (bool, error) {
	var (
		foundUser bool
		repeating bool
		err       error
	)

	/*
		- If user exists, then check its UCN
		-   If UCN exists, then check for repeating wrong password, else abort the request.
		==> Consequences of repeating wrong passwords: buckets won't be increased.

		- If the user is unknown, enforce the brute forcing computation.
		==> Consequences are increased buckets.

		- On any error that might occur, abort the current request.
		==> Consequences are non-increased buckets.
	*/

	if foundUser, err = a.userExists(); err != nil {
		return false, err
	} else if foundUser {
		if repeating, err = a.isRepeatingWrongPassword(); err != nil {
			return false, err
		} else if repeating {
			return false, nil
		} else if a.PasswordHistory == nil {
			level.Warn(logging.DefaultLogger).Log(
				global.LogKeyGUID, a.GUID,
				global.LogKeyMsg, "No negative password cache present",
				global.LogKeyOrigUsername, a.UsernameOrig,
				global.LogKeyClientIP, a.ClientIP,
			)

			return false, nil
		}
	}

	return true, nil
}

// getNetwork is a method of the Authentication struct that is used to retrieve the network IP range based on a given BruteForceRule.
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
func (a *Authentication) getNetwork(rule *config.BruteForceRule) (*net.IPNet, error) {
	ipAddress := net.ParseIP(a.ClientIP)

	if ipAddress == nil {
		return nil, fmt.Errorf("%s '%s'", errors2.ErrWrongIPAddress, a.ClientIP)
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

// This function 'getBruteForcePasswordHistoryRedisHashKey' belongs to the Authentication struct.
// It is used to generate a unique Redis hash key based on whether a username is being included or not.
// If the 'withUsername' boolean parameter is true, the Redis hash key is generated
// using the Redis prefix, password hash key, the original username, and the client's IP address.
// If 'withUsername' is false, the Redis hash key is generated just appending the Redis prefix,
// password hash key, and the client's IP without the original username.
// This key is used for storing and retrieving the history of password usage in the context of preventing brute force attacks.
// An additional feature of this function is to log the generated key along with some context information (GUID and Client IP)
func (a *Authentication) getBruteForcePasswordHistoryRedisHashKey(withUsername bool) (key string) {
	if withUsername {
		key = config.EnvConfig.RedisPrefix + global.RedisPwHashKey + fmt.Sprintf(":%s:%s", a.UsernameOrig, a.ClientIP)
	} else {
		key = config.EnvConfig.RedisPrefix + global.RedisPwHashKey + fmt.Sprintf(":%s", a.ClientIP)
	}

	util.DebugModule(
		global.DbgBf,
		global.LogKeyGUID, a.GUID,
		global.LogKeyClientIP, a.ClientIP,
		"key", key,
	)

	return
}

// This function belongs to the Authentication struct. It is used to generate a unique
// Redis key for brute force rule tracking.
//
// For a given brute force rule, this function generates a Redis key that is used to
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
func (a *Authentication) getBruteForceBucketRedisKey(rule *config.BruteForceRule) (key string) {
	var ipProto string

	network, err := a.getNetwork(rule)
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)

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

	key = config.EnvConfig.RedisPrefix + "bf:" + fmt.Sprintf(
		"%d:%d:%d:%s:%s", rule.Period, rule.CIDR, rule.FailedRequests, ipProto, network.String())

	util.DebugModule(
		global.DbgBf,
		global.LogKeyGUID, a.GUID,
		global.LogKeyClientIP, a.ClientIP,
		"rule", rule.Name,
		"period", rule.Period,
		"cidr", rule.CIDR,
		"ipv4", rule.IPv4,
		"ipv6", rule.IPv6,
		"failed_requests", rule.FailedRequests,
		"rule_network", network.String(),
		"key", key,
	)

	return
}

// loadBruteForcePasswordHistoryFromRedis loads password history related to brute force attacks from Redis for a given key.
// The function will fetch all associated passwords in the form of a hash along with a counter.
// The Redis key is created for each unique user presented by the variable `key` which is a GUID,
// This helps in keeping the track of the number of attempts a user has made for password authentication.
// The function will generate an error logs for unsuccessful retrieval of password history data from Redis.
// The password history data is stored in the Authentication's `PasswordHistory` field.
//
// Parameters:
//   - key: A string that represents the unique GUID of a user
//
// Note: If the passed key is an empty string, the function will return immediately.
func (a *Authentication) loadBruteForcePasswordHistoryFromRedis(key string) {
	if key == "" {
		return
	}

	util.DebugModule(global.DbgBf, global.LogKeyGUID, a.GUID, "load_key", key)

	if passwordHistory, err := backend.RedisHandleReplica.HGetAll(backend.RedisHandle.Context(), key).Result(); err != nil {
		if !errors.Is(err, redis.Nil) {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)
		} else {
			redisReadCounter.Inc()
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
				if !errors.Is(err, redis.Nil) {
					level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)
				}

				return
			}

			(*a.PasswordHistory)[passwordHash] = uint(counterInt)
		}
	}
}

// getAllPasswordHistories is a method of the Authentication struct.
// This method fetches and processes all password histories for the user represented by 'a'.
// This method performs two major operations.
// In the first phase, it fetches the password history specific to the current user using the Redis hash key.
// The password history is stored in a local variable and processed to compute login attempts and seen account passwords.
// In the second phase, it retrieves the overall password history again using the Redis hash key.
// This overall history is then used to compute the total number of seen passwords.
// Each of these phases are independent and are executed if the Redis hash key retrieval and the password history fetch operations are successful.
func (a *Authentication) getAllPasswordHistories() {
	// Get password history for the current used username
	if key := a.getBruteForcePasswordHistoryRedisHashKey(true); key != "" {
		a.loadBruteForcePasswordHistoryFromRedis(key)
	}

	if a.PasswordHistory != nil {
		passwordHash := util.GetHash(util.PreparePassword(a.Password))
		if counter, foundPassword := (*a.PasswordHistory)[passwordHash]; foundPassword {
			a.LoginAttempts = counter
		}

		a.PasswordsAccountSeen = uint(len(*a.PasswordHistory))
	}

	// Get the overall password history
	if key := a.getBruteForcePasswordHistoryRedisHashKey(false); key != "" {
		a.loadBruteForcePasswordHistoryFromRedis(key)
	}

	if a.PasswordHistory != nil {
		a.PasswordsTotalSeen = uint(len(*a.PasswordHistory))
	}
}

// saveBruteForcePasswordToRedis is a method of the Authentication struct that is responsible for handling brute force attempts.
// It works by saving password attempts to Redis data store. When a password is entered incorrectly,
// the function stores this incorrect password's hash within a Redis key that is specific to the account in question.
//
// This method will save keys for both brute force history and current attempt, and then for each key in the list of keys:
//
//  1. It increments the value of this key by one, creating the key if it does not already exist.
//     This increments a counter for each bad password attempt.
//  2. Logs an error message if there is an error incrementing the key's value
//  3. Sets an expiry time on the key. This has the effect of automatically deleting the keys after a certain period of time.
//  4. Logs an error message if there is an error setting expiry time
//
// The function concludes by logging that the process has finished.
func (a *Authentication) saveBruteForcePasswordToRedis() {
	var keys []string

	keys = append(keys, a.getBruteForcePasswordHistoryRedisHashKey(true))
	keys = append(keys, a.getBruteForcePasswordHistoryRedisHashKey(false))

	for index := range keys {
		util.DebugModule(global.DbgBf, global.LogKeyGUID, a.GUID, "incr_key", keys[index])

		// We can increment a key/value, even it never existed before.
		if err := backend.RedisHandle.HIncrBy(
			backend.RedisHandle.Context(),
			keys[index],
			util.GetHash(util.PreparePassword(a.Password)), 1,
		).Err(); err != nil {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)

			return
		} else {
			redisWriteCounter.Inc()
		}

		util.DebugModule(
			global.DbgBf,
			global.LogKeyGUID, a.GUID,
			"key", keys[index],
			global.LogKeyMsg, "Increased",
		)

		if err := backend.RedisHandle.Expire(backend.RedisHandle.Context(), keys[index], time.Duration(viper.GetInt("redis_negative_cache_ttl"))*time.Second).Err(); err != nil {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)
		} else {
			redisWriteCounter.Inc()
		}

		util.DebugModule(
			global.DbgBf,
			global.LogKeyGUID, a.GUID,
			"key", keys[index],
			global.LogKeyMsg, "Set expire",
		)
	}

	util.DebugModule(
		global.DbgBf,
		global.LogKeyGUID, a.GUID,
		global.LogKeyMsg, "Finished",
	)
}

// loadBruteForceBucketCounterFromRedis is a method on the Authentication struct that loads the brute force
// bucket counter from Redis and updates the BruteForceCounter map. The given BruteForceRule is used to generate the Redis key.
// If the key is not empty, it retrieves the counter value from Redis using the backend.LoadCacheFromRedis function.
// If an error occurs while loading the cache, the function returns.
// If the BruteForceCounter is not initialized, it creates a new map.
// Finally, it updates the BruteForceCounter map with the counter value retrieved from Redis using the rule name as the key.
func (a *Authentication) loadBruteForceBucketCounterFromRedis(rule *config.BruteForceRule) {
	cache := new(backend.BruteForceBucketCache)

	if key := a.getBruteForceBucketRedisKey(rule); key != "" {
		util.DebugModule(global.DbgBf, global.LogKeyGUID, a.GUID, "load_key", key)

		if isRedisErr, err := backend.LoadCacheFromRedis(key, &cache); err != nil {
			return
		} else {
			if !isRedisErr {
				redisReadCounter.Inc()
			}
		}
	}

	if a.BruteForceCounter == nil {
		a.BruteForceCounter = make(map[string]uint)
	}

	a.BruteForceCounter[rule.Name] = uint(*cache)
}

// saveBruteForceBucketCounterToRedis is a method on the Authentication struct that saves brute force
// attempt information to Redis. This helps in maintaining a counter for each unique brute force rule.
// The brute force rule, that is passed as param, is used to generate the key for Redis.
// If the key is not empty, the related counter is incremented in Redis.
// Note that the counter is not incremented if 'BruteForceName' is equal to the 'Name' in the given rule.
// The function also sets the key expiration time in Redis as per the 'Period' field given in the rule.
// In case of any errors (while incrementing the counter or setting the expiration), the error is logged.
func (a *Authentication) saveBruteForceBucketCounterToRedis(rule *config.BruteForceRule) {
	if key := a.getBruteForceBucketRedisKey(rule); key != "" {
		util.DebugModule(global.DbgBf, global.LogKeyGUID, a.GUID, "store_key", key)

		if a.BruteForceName != rule.Name {
			if err := backend.RedisHandle.Incr(backend.RedisHandle.Context(), key).Err(); err != nil {
				level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)
			} else {
				redisWriteCounter.Inc()
			}

		}

		if err := backend.RedisHandle.Expire(backend.RedisHandle.Context(), key, time.Duration(rule.Period)*time.Second).Err(); err != nil {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)
		} else {
			redisWriteCounter.Inc()
		}
	}
}

// setPreResultBruteForceRedis sets the BruteForceRule name in the Redis hash map based on the network IP address obtained from the given BruteForceRule parameter.
// If there is an error during the operation, it logs the error using the DefaultErrLogger.
func (a *Authentication) setPreResultBruteForceRedis(rule *config.BruteForceRule) {
	key := config.EnvConfig.RedisPrefix + global.RedisBruteForceHashKey

	network, err := a.getNetwork(rule)
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)
	} else {
		if err = backend.RedisHandle.HSet(backend.RedisHandle.Context(), key, network.String(), a.BruteForceName).Err(); err != nil {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)
		} else {
			redisWriteCounter.Inc()
		}
	}
}

// getPreResultBruteForceRedis retrieves the name of the BruteForceRule from the Redis hash map, based on the network IP address obtained from the given BruteForceRule parameter.
// If there is an error during the retrieval, it will log the error using the DefaultErrLogger.
// If the key-value pair does not exist in the Redis hash map, it will return an empty string.
// The retrieved rule name will be returned as the result.
func (a *Authentication) getPreResultBruteForceRedis(rule *config.BruteForceRule) (ruleName string, err error) {
	var network *net.IPNet

	key := config.EnvConfig.RedisPrefix + global.RedisBruteForceHashKey

	network, err = a.getNetwork(rule)
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)

		return
	} else if ruleName, err = backend.RedisHandle.HGet(backend.RedisHandle.Context(), key, network.String()).Result(); err != nil {
		if !errors.Is(err, redis.Nil) {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)
		} else {
			redisReadCounter.Inc()
		}
	}

	err = nil

	return
}

// deleteIPBruteForceRedis deletes the IP address from the Redis hash map for brute force prevention.
// It checks if the IP address is present in the hash map and matches the provided rule name or if the rule name is "*".
// If there's a match, it retrieves the network associated with the rule, constructs the hash map key, and deletes the IP address from the hash map using Redis HDEL command.
// If there's an error, it logs the error using the DefaultErrLogger.
func (a *Authentication) deleteIPBruteForceRedis(rule *config.BruteForceRule, ruleName string) error {
	key := config.EnvConfig.RedisPrefix + global.RedisBruteForceHashKey

	result, err := a.getPreResultBruteForceRedis(rule)
	if result == "" {
		return err
	}

	if result == ruleName || ruleName == "*" {
		if network, err := a.getNetwork(rule); err != nil {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)
		} else {
			if err = backend.RedisHandle.HDel(backend.RedisHandle.Context(), key, network.String()).Err(); err != nil {
				level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)
			} else {
				redisWriteCounter.Inc()
			}
		}

		return err
	}

	return nil
}

// checkBruteForce is a method of the `Authentication` struct and is responsible for
// ascertaining whether the client IP should be blocked due to unrestricted unauthorized access attempts
// (i.e., a Brute Force attack on the system).
//
// The implementation works as follows:
//   - It initializes a handful of variables used for later computation.
//   - It verifies if the `BruteForce` property in the configuration is defined.
//   - The method logs several useful debugging properties such as client IP, username, port, etc.
//   - It looks for certain conditions such as `NoAuth` or `ListAccounts` under which the method returns 'false' immediately.
//   - The method verifies if the client IP is localhost or unavailable and logs relevant info if it is.
//   - It checks if Brute Force security is enabled for the current protocol being used, logging the data if it's not enabled.
//   - The function checks if the current client IP is in the IP whitelist and logs the relevant data if it is.
//   - It iterates over various Brute Force rules to determine if the client IP falls into any predefined rule and logs the data.
//   - Lastly, it checks if any Brute Force rule is triggered, whereupon it saves some information in Redis, retrieves it back, logs
//     the appropriate message, and runs a Lua script for handling the detected brute force attempt.
//
// It returns 'true' if a Brute Force attack is detected, otherwise returns 'false'.
func (a *Authentication) checkBruteForce() (blockClientIP bool) {
	var (
		useCache         bool
		needEnforce      bool
		alreadyTriggered bool
		ruleTriggered    bool
		message          string
		err              error
		index            int
		network          *net.IPNet
	)

	timer := prometheus.NewTimer(functionDuration.WithLabelValues("BruteForce", "checkBruteForce"))

	defer timer.ObserveDuration()

	if config.LoadableConfig.BruteForce == nil {
		return false
	}

	util.DebugModule(
		global.DbgBf,
		global.LogKeyGUID, *a.GUID,
		global.LogKeyClientIP, a.ClientIP,
		global.LogKeyClientPort, a.XClientPort,
		global.LogKeyClientHost, a.ClientHost,
		global.LogKeyClientID, a.XClientID,
		global.LogKeyLocalIP, a.XLocalIP,
		global.LogKeyPort, a.XPort,
		global.LogKeyUsername, a.Username,
		global.LogKeyOrigUsername, a.UsernameOrig,
		global.LogKeyProtocol, a.Protocol.Get(),
		"service", util.WithNotAvailable(a.Service),
		"no-auth", a.NoAuth,
		"list-accounts", a.ListAccounts,
	)

	if a.NoAuth || a.ListAccounts {
		return false
	}

	if a.BruteForceCounter == nil {
		a.BruteForceCounter = make(map[string]uint)
	}

	if a.ClientIP == global.Localhost4 || a.ClientIP == global.Localhost6 || a.ClientIP == global.NotAvailable {
		level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyBruteForce, "localhost")

		return false
	}

	bruteForceEnabled := false
	for _, bruteForceService := range config.EnvConfig.BruteForce {
		if bruteForceService.Get() != a.Protocol.Get() {
			continue
		}

		bruteForceEnabled = true

		break
	}

	if !bruteForceEnabled {
		level.Info(logging.DefaultLogger).Log(
			global.LogKeyGUID, a.GUID,
			global.LogKeyBruteForce, fmt.Sprintf("Not enabled for protocol '%s'", a.Protocol.Get()))

		return false
	}

	if len(config.LoadableConfig.BruteForce.IPWhitelist) > 0 {
		if a.isInNetwork(config.LoadableConfig.BruteForce.IPWhitelist) {
			level.Info(logging.DefaultLogger).Log(
				global.LogKeyGUID, a.GUID,
				global.LogKeyBruteForce, "Client is whitelisted",
				global.LogKeyClientIP, a.ClientIP)

			return false
		}
	}

	// All rules
	rules := config.LoadableConfig.GetBruteForceRules()

	if len(rules) == 0 {
		return false
	}

	/*
		An IP address is already known as brute force attacker
	*/

	index = 0
	for index = range rules {
		// Skip, where the current IP address does not match the current rule
		if network, err = a.getNetwork(&rules[index]); err != nil {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)

			return false
		} else if network == nil {
			continue
		}

		if ruleName, err := a.getPreResultBruteForceRedis(&rules[index]); ruleName != "" && err == nil {
			alreadyTriggered = true
			message = "Brute force attack detected (cached result)"

			break
		}

	}

	/*
		A Bucket (some rule) is over limit
	*/

	if !alreadyTriggered {
		index = 0
		for index = range rules {
			// Skip, where the current IP address does not match the current rule
			if network, err = a.getNetwork(&rules[index]); err != nil {
				level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)

				return false
			} else if network == nil {
				continue
			}

			a.loadBruteForceBucketCounterFromRedis(&rules[index])

			// The counter goes from 0...N-1, but the 'failed_requests' setting from 1...N
			if a.BruteForceCounter[rules[index].Name]+1 > rules[index].FailedRequests {
				ruleTriggered = true
				message = "Brute force attack detected"

				break
			}
		}
	}

	util.DebugModule(global.DbgBf,
		global.LogKeyGUID, a.GUID,
		"failed_requests", a.BruteForceCounter[rules[index].Name],
		"limit", rules[index].FailedRequests,
		global.LogKeyClientIP, a.ClientIP,
		"rule_network", network.String(),
		"rule", rules[index].Name,
		"counter", a.BruteForceCounter[rules[index].Name],
	)

	if alreadyTriggered || ruleTriggered {
		for _, passDB := range config.EnvConfig.PassDBs {
			if passDB.Get() == global.BackendCache {
				useCache = true

				break
			}
		}

		if useCache {
			if needEnforce, err = a.checkEnforceBruteForceComputation(); err != nil {
				level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)

				return false
			} else if !needEnforce {
				return false
			}
		}

		a.BruteForceName = rules[index].Name

		a.saveBruteForcePasswordToRedis()
		a.getAllPasswordHistories()

		if ruleTriggered {
			a.setPreResultBruteForceRedis(&rules[index])
		}

		level.Info(logging.DefaultLogger).Log(
			global.LogKeyGUID, a.GUID,
			global.LogKeyBruteForce, message,
			global.LogKeyOrigUsername, a.UsernameOrig,
			global.LogKeyClientIP, a.ClientIP,
			"rule_network", network.String(),
			"rule", rules[index].Name,
		)

		finished := make(chan action.Done)

		action.RequestChan <- &action.Action{
			LuaAction:         global.LuaActionBruteForce,
			Debug:             config.EnvConfig.Verbosity.Level() == global.LogLevelDebug,
			Repeating:         alreadyTriggered,
			BruteForceCounter: a.BruteForceCounter[rules[index].Name],
			Session:           *a.GUID,
			ClientIP:          a.ClientIP,
			ClientPort:        a.XClientPort,
			ClientNet:         network.String(),
			ClientID:          a.XClientID,
			LocalIP:           a.XLocalIP,
			LocalPort:         a.XPort,
			Username:          a.Username,
			Password:          a.Password,
			Protocol:          a.Protocol.Get(),
			BruteForceName:    rules[index].Name,
			Context:           a.Context,
			FinishedChan:      finished,
		}

		<-finished

		return true
	}

	return false
}

// updateBruteForceBucketsCounter updates the brute force buckets counter for the current authentication
// It checks if brute force is enabled for the current protocol and if the client IP is not in the whitelist
// Then it iterates through the loaded brute force rules and saves the bucket counter to Redis
// The method also logs debug information related to the authentication
//
// Parameters:
//   - a: a pointer to the Authentication struct which contains the authentication details
//
// Returns: none
func (a *Authentication) updateBruteForceBucketsCounter() {
	if config.LoadableConfig.BruteForce == nil {
		return
	}

	util.DebugModule(
		global.DbgBf,
		global.LogKeyGUID, *a.GUID,
		global.LogKeyClientIP, a.ClientIP,
		global.LogKeyClientPort, a.XClientPort,
		global.LogKeyClientHost, a.ClientHost,
		global.LogKeyClientID, a.XClientID,
		global.LogKeyLocalIP, a.XLocalIP,
		global.LogKeyPort, a.XPort,
		global.LogKeyUsername, a.Username,
		global.LogKeyOrigUsername, a.UsernameOrig,
		global.LogKeyProtocol, a.Protocol.Get(),
		"service", util.WithNotAvailable(a.Service),
		"no-auth", a.NoAuth,
		"list-accounts", a.ListAccounts,
	)

	if a.NoAuth || a.ListAccounts {
		return
	}

	if a.ClientIP == global.Localhost4 || a.ClientIP == global.Localhost6 || a.ClientIP == global.NotAvailable {
		return
	}

	bruteForceEnabled := false
	for _, bruteForceService := range config.EnvConfig.BruteForce {
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
		if a.isInNetwork(config.LoadableConfig.BruteForce.IPWhitelist) {
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

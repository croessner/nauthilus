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
	"github.com/croessner/nauthilus/server/decl"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/util"
	"github.com/dspinhirne/netaddr-go"
	"github.com/go-kit/log/level"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
)

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
						if counter+decl.SamePasswordsDifferentAccountLimit >= counterTotal {
							level.Info(logging.DefaultLogger).Log(
								decl.LogKeyGUID, a.GUID,
								decl.LogKeyBruteForce, "Repeating wrong password",
								decl.LogKeyOrigUsername, a.UsernameOrig,
								decl.LogKeyClientIP, a.ClientIP,
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

func (a *Authentication) userExists() (bool, error) {
	accountName, err := backend.LookupUserAccountFromRedis(a.Username)
	if err != nil {
		return false, err
	}

	if accountName == "" {
		return false, nil
	}

	return true, nil
}

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
				decl.LogKeyGUID, a.GUID,
				decl.LogKeyMsg, "No negative password cache present",
				decl.LogKeyOrigUsername, a.UsernameOrig,
				decl.LogKeyClientIP, a.ClientIP,
			)

			return false, nil
		}
	}

	return true, nil
}

func (a *Authentication) getNetwork(rule *config.BruteForceRule) (*net.IPNet, error) {
	ipAddress := net.ParseIP(a.ClientIP)

	if ipAddress == nil {
		return nil, errors2.ErrWrongIPAddress
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

func (a *Authentication) getBruteForcePasswordHistoryRedisHashKey(withUsername bool) (key string) {
	if withUsername {
		key = config.EnvConfig.RedisPrefix + decl.RedisPwHashKey + fmt.Sprintf(":%s:%s", a.UsernameOrig, a.ClientIP)
	} else {
		key = config.EnvConfig.RedisPrefix + decl.RedisPwHashKey + fmt.Sprintf(":%s", a.ClientIP)
	}

	util.DebugModule(
		decl.DbgBf,
		decl.LogKeyGUID, a.GUID,
		decl.LogKeyClientIP, a.ClientIP,
		"key", key,
	)

	return
}

func (a *Authentication) getBruteForceBucketRedisKey(rule *config.BruteForceRule) (key string) {
	var ipProto string

	network, err := a.getNetwork(rule)
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)

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
		decl.DbgBf,
		decl.LogKeyGUID, a.GUID,
		decl.LogKeyClientIP, a.ClientIP,
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

func (a *Authentication) loadBruteForcePasswordHistoryFromRedis(key string) {
	if key == "" {
		return
	}

	util.DebugModule(decl.DbgBf, decl.LogKeyGUID, a.GUID, "load_key", key)

	if passwordHistory, err := backend.RedisHandleReplica.HGetAll(backend.RedisHandle.Context(), key).Result(); err != nil {
		if !errors.Is(err, redis.Nil) {
			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)
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
					level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)
				}

				return
			}

			(*a.PasswordHistory)[passwordHash] = uint(counterInt)
		}
	}
}

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

func (a *Authentication) saveBruteForcePasswordToRedis() {
	var keys []string

	keys = append(keys, a.getBruteForcePasswordHistoryRedisHashKey(true))
	keys = append(keys, a.getBruteForcePasswordHistoryRedisHashKey(false))

	for index := range keys {
		util.DebugModule(decl.DbgBf, decl.LogKeyGUID, a.GUID, "incr_key", keys[index])

		// We can increment a key/value, even it never existed before.
		if err := backend.RedisHandle.HIncrBy(
			backend.RedisHandle.Context(),
			keys[index],
			util.GetHash(util.PreparePassword(a.Password)), 1,
		).Err(); err != nil {
			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)

			return
		}

		util.DebugModule(
			decl.DbgBf,
			decl.LogKeyGUID, a.GUID,
			"key", keys[index],
			decl.LogKeyMsg, "Increased",
		)

		if err := backend.RedisHandle.Expire(backend.RedisHandle.Context(), keys[index], time.Duration(viper.GetInt("redis_negative_cache_ttl"))*time.Second).Err(); err != nil {
			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)
		}

		util.DebugModule(
			decl.DbgBf,
			decl.LogKeyGUID, a.GUID,
			"key", keys[index],
			decl.LogKeyMsg, "Set expire",
		)
	}

	util.DebugModule(
		decl.DbgBf,
		decl.LogKeyGUID, a.GUID,
		decl.LogKeyMsg, "Finished",
	)
}

func (a *Authentication) loadBruteForceBucketCounterFromRedis(rule *config.BruteForceRule) {
	cache := new(backend.BruteForceBucketCache)

	if key := a.getBruteForceBucketRedisKey(rule); key != "" {
		util.DebugModule(decl.DbgBf, decl.LogKeyGUID, a.GUID, "load_key", key)

		if err := backend.LoadCacheFromRedis(key, &cache); err != nil {
			return
		}
	}

	if a.BruteForceCounter == nil {
		a.BruteForceCounter = make(map[string]uint)
	}

	a.BruteForceCounter[rule.Name] = uint(*cache)
}

func (a *Authentication) saveBruteForceBucketCounterToRedis(rule *config.BruteForceRule) {
	if key := a.getBruteForceBucketRedisKey(rule); key != "" {
		util.DebugModule(decl.DbgBf, decl.LogKeyGUID, a.GUID, "store_key", key)

		if a.BruteForceName != rule.Name {
			if err := backend.RedisHandle.Incr(backend.RedisHandle.Context(), key).Err(); err != nil {
				level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)
			}

		}

		if err := backend.RedisHandle.Expire(backend.RedisHandle.Context(), key, time.Duration(rule.Period)*time.Second).Err(); err != nil {
			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)
		}
	}
}

// SetPreResultBruteForceRedis adds the current IP address to a Redis hash map
func (a *Authentication) SetPreResultBruteForceRedis(rule *config.BruteForceRule) {
	key := config.EnvConfig.RedisPrefix + decl.RedisBruteForceHashKey

	network, err := a.getNetwork(rule)
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)
	} else if err = backend.RedisHandle.HSet(backend.RedisHandle.Context(), key, network.String(), a.BruteForceName).Err(); err != nil {
		level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)
	}
}

// GetPreResultBruteForceRedis checks the Redis Database for a known brute force attacker based on the client IP address.
func (a *Authentication) GetPreResultBruteForceRedis(rule *config.BruteForceRule) (ruleName string) {
	key := config.EnvConfig.RedisPrefix + decl.RedisBruteForceHashKey

	network, err := a.getNetwork(rule)
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)
	} else if ruleName, err = backend.RedisHandle.HGet(backend.RedisHandle.Context(), key, network.String()).Result(); err != nil {
		if !errors.Is(err, redis.Nil) {
			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)
		}
	}

	return
}

// DelIPBruteForceRedis removes an IP address from Redis by its rule name. The wildcard '*' removes the IP address
// regardless of any rule name.
func (a *Authentication) DelIPBruteForceRedis(rule *config.BruteForceRule, ruleName string) {
	key := config.EnvConfig.RedisPrefix + decl.RedisBruteForceHashKey

	result := a.GetPreResultBruteForceRedis(rule)
	if result == "" {
		return
	}

	if result == ruleName || ruleName == "*" {
		if network, err := a.getNetwork(rule); err != nil {
			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)
		} else if err = backend.RedisHandle.HDel(backend.RedisHandle.Context(), key, network.String()).Err(); err != nil {
			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)
		}
	}
}

// CheckBruteForce is called after a user has sent its credentials. It checks, if the user is already over limits. The
// main password verification process ends, if a rule has triggered and no authentication is done at all.
func (a *Authentication) CheckBruteForce() (blockClientIP bool) {
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

	if config.LoadableConfig.BruteForce == nil {
		return false
	}

	util.DebugModule(
		decl.DbgBf,
		decl.LogKeyGUID, *a.GUID,
		decl.LogKeyClientIP, a.ClientIP,
		decl.LogKeyClientPort, a.XClientPort,
		decl.LogKeyClientHost, a.ClientHost,
		decl.LogKeyClientID, a.XClientID,
		decl.LogKeyLocalIP, a.XLocalIP,
		decl.LogKeyPort, a.XPort,
		decl.LogKeyUsername, a.Username,
		decl.LogKeyOrigUsername, a.UsernameOrig,
		decl.LogKeyProtocol, a.Protocol.Get(),
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

	if a.ClientIP == decl.Localhost4 || a.ClientIP == decl.Localhost6 || a.ClientIP == decl.NotAvailable {
		level.Info(logging.DefaultLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyBruteForce, "localhost")

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
			decl.LogKeyGUID, a.GUID,
			decl.LogKeyBruteForce, fmt.Sprintf("Not enabled for protocol '%s'", a.Protocol.Get()))

		return false
	}

	if len(config.LoadableConfig.BruteForce.IPWhitelist) > 0 {
		if a.IsInNetwork(config.LoadableConfig.BruteForce.IPWhitelist) {
			level.Info(logging.DefaultLogger).Log(
				decl.LogKeyGUID, a.GUID,
				decl.LogKeyBruteForce, "Client is whitelisted",
				decl.LogKeyClientIP, a.ClientIP)

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
			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)

			return false
		} else if network == nil {
			continue
		}

		if ruleName := a.GetPreResultBruteForceRedis(&rules[index]); ruleName != "" {
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
				level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)

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

	util.DebugModule(decl.DbgBf,
		decl.LogKeyGUID, a.GUID,
		"failed_requests", a.BruteForceCounter[rules[index].Name],
		"limit", rules[index].FailedRequests,
		decl.LogKeyClientIP, a.ClientIP,
		"rule_network", network.String(),
		"rule", rules[index].Name,
		"counter", a.BruteForceCounter[rules[index].Name],
	)

	if alreadyTriggered || ruleTriggered {
		for _, passDB := range config.EnvConfig.PassDBs {
			if passDB.Get() == decl.BackendCache {
				useCache = true

				break
			}
		}

		if useCache {
			if needEnforce, err = a.checkEnforceBruteForceComputation(); err != nil {
				level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)

				return false
			} else if !needEnforce {
				return false
			}
		}

		a.BruteForceName = rules[index].Name

		a.saveBruteForcePasswordToRedis()
		a.getAllPasswordHistories()

		if ruleTriggered {
			a.SetPreResultBruteForceRedis(&rules[index])
		}

		level.Info(logging.DefaultLogger).Log(
			decl.LogKeyGUID, a.GUID,
			decl.LogKeyBruteForce, message,
			decl.LogKeyOrigUsername, a.UsernameOrig,
			decl.LogKeyClientIP, a.ClientIP,
			"rule_network", network.String(),
			"rule", rules[index].Name,
		)

		finished := make(chan action.Done)

		action.RequestChan <- &action.Action{
			LuaAction:         decl.LuaActionBruteForce,
			Debug:             config.EnvConfig.Verbosity.Level() == decl.LogLevelDebug,
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

// UpdateBruteForceBucketsCounter is called after a CheckBruteForce call had triggered.
func (a *Authentication) UpdateBruteForceBucketsCounter() {
	if config.LoadableConfig.BruteForce == nil {
		return
	}

	util.DebugModule(
		decl.DbgBf,
		decl.LogKeyGUID, *a.GUID,
		decl.LogKeyClientIP, a.ClientIP,
		decl.LogKeyClientPort, a.XClientPort,
		decl.LogKeyClientHost, a.ClientHost,
		decl.LogKeyClientID, a.XClientID,
		decl.LogKeyLocalIP, a.XLocalIP,
		decl.LogKeyPort, a.XPort,
		decl.LogKeyUsername, a.Username,
		decl.LogKeyOrigUsername, a.UsernameOrig,
		decl.LogKeyProtocol, a.Protocol.Get(),
		"service", util.WithNotAvailable(a.Service),
		"no-auth", a.NoAuth,
		"list-accounts", a.ListAccounts,
	)

	if a.NoAuth || a.ListAccounts {
		return
	}

	if a.ClientIP == decl.Localhost4 || a.ClientIP == decl.Localhost6 || a.ClientIP == decl.NotAvailable {
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

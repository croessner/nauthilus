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
	stderrors "errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/redis/go-redis/v9"
)

// For brief documentation of this file please have a look at the Markdown document REST-API.md.

// FlushUserCmdStatus represents an user's command status.
type FlushUserCmdStatus struct {
	// User holds the identifier of a user.
	User string `json:"user"`

	// RemovedKeys contains a list of keys that have been removed during the user's command execution.
	RemovedKeys []string `json:"removed_keys"`

	// Status represents the status of the user's command.
	Status string `json:"status"`
}

// FlushUserCmd is a data structure used to handle user commands for flushing data.
type FlushUserCmd struct {
	// User is the field representing the name of the user to be flushed.
	User string `json:"user" binding:"required"`
}

// FlushRuleCmdStatus is a structure representing the status of a Flush Rule command
type FlushRuleCmdStatus struct {
	// IPAddress is the IP address that the rule was applied to
	IPAddress string `json:"ip_address"`

	// RuleName is the name of the rule that was flushed
	RuleName string `json:"rule_name"`

	// RemovedKeys contains a list of Redis keys that were successfully removed during the flush operation.
	RemovedKeys []string `json:"removed_keys"`

	// Status is the current status of the rule following the Flush Command
	Status string `json:"status"`
}

// FlushRuleCmd represents a command to flush a specific rule.
// It contains the necessary information needed to identify the rule to be flushed.
type FlushRuleCmd struct {
	// IPAddress is the IP address associated with the rule to be flushed.
	// It must be in a format valid for an IP address.
	IPAddress string `json:"ip_address" binding:"required,ip"`

	// RuleName is the name of the rule to be flushed.
	// This value should reference an existing rule.
	RuleName string `json:"rule_name" binding:"required"`
}

// BlockedIPAddresses represents a structure to hold blocked IP addresses retrieved from Redis.
// IPAddresses maps IP addresses to their corresponding rules/buckets.
// Error holds any error encountered during the retrieval process.
type BlockedIPAddresses struct {
	// IPAddresses maps IP addresses to their respective buckets/rules that triggered blocking.
	IPAddresses map[string]string `json:"ip_addresses"`

	// Error holds any error encountered during the retrieval process.
	Error *string `json:"error"`
}

// BlockedAccounts represents a list of blocked user accounts and potential error information.
type BlockedAccounts struct {
	// Accounts represents a list of user accounts.
	Accounts map[string][]string `json:"accounts"`

	// Error represents the error message, if any, encountered during the account retrieval process.
	Error *string `json:"error"`
}

// FilterCmd defines a struct for command filters with optional fields for Accounts and IP Address.
type FilterCmd struct {
	// Accounts represents an optional filter criterion for user accounts in the FilterCmd struct.
	Accounts []string `json:"accounts,omitempty"`

	// IPAddress represents an optional filter criterion for IP addresses in the FilterCmd struct.
	IPAddress []string `json:"ip_addresses,omitempty"`
}

// HandleAuthentication handles the authentication logic based on the selected service type.
func (a *AuthState) HandleAuthentication(ctx *gin.Context) {
	if a.Service == definitions.ServBasic {
		var httpBasicAuthOk bool

		// Decode HTTP basic Auth
		a.Username, a.Password, httpBasicAuthOk = ctx.Request.BasicAuth()
		if !httpBasicAuthOk {
			ctx.Header("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			ctx.AbortWithError(http.StatusUnauthorized, errors.ErrUnauthorized)

			return
		}
	}

	if a.ListAccounts {
		allAccountsList := a.ListUserAccounts()

		acceptHeader := ctx.GetHeader("Accept")

		switch acceptHeader {
		case "application/json":
			ctx.JSON(http.StatusOK, allAccountsList)
		case "*/*", "text/plain":
			for _, account := range allAccountsList {
				ctx.Data(http.StatusOK, "text/plain", []byte(account+"\r\n"))
			}
		case "application/x-www-form-urlencoded":
			for _, account := range allAccountsList {
				ctx.Data(http.StatusOK, "application/x-www-form-urlencoded", []byte(account+"\r\n"))
			}
		default:
			ctx.Error(errors.ErrUnsupportedMediaType).SetType(gin.ErrorTypeBind)
			ctx.AbortWithStatus(http.StatusUnsupportedMediaType)
		}

		level.Info(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMode, ctx.Query("mode"))
	} else {
		if !(a.NoAuth || ctx.GetBool(definitions.CtxLocalCacheAuthKey)) {
			//nolint:exhaustive // Ignore some results
			switch a.HandleFeatures(ctx) {
			case definitions.AuthResultFeatureTLS:
				a.PostLuaAction(&PassDBResult{})
				a.AuthTempFail(ctx, definitions.TempFailNoTLS)
				ctx.Abort()

				return
			case definitions.AuthResultFeatureRelayDomain, definitions.AuthResultFeatureRBL, definitions.AuthResultFeatureLua:
				a.PostLuaAction(&PassDBResult{})
				a.AuthFail(ctx)
				ctx.Abort()

				return
			case definitions.AuthResultUnset:
			case definitions.AuthResultOK:
			case definitions.AuthResultTempFail:
				a.AuthTempFail(ctx, definitions.TempFailDefault)
				ctx.Abort()

				return
			default:
				ctx.AbortWithStatus(a.StatusCodeInternalError)

				return
			}
		}

		//nolint:exhaustive // Ignore some results
		switch a.HandlePassword(ctx) {
		case definitions.AuthResultOK:
			tolerate.GetTolerate().SetIPAddress(a.HTTPClientContext, a.ClientIP, a.Username, true)
			a.AuthOK(ctx)
		case definitions.AuthResultFail:
			tolerate.GetTolerate().SetIPAddress(a.HTTPClientContext, a.ClientIP, a.Username, false)
			a.AuthFail(ctx)
			ctx.Abort()
		case definitions.AuthResultTempFail:
			a.AuthTempFail(ctx, definitions.TempFailDefault)
			ctx.Abort()
		case definitions.AuthResultEmptyUsername:
			a.AuthTempFail(ctx, definitions.TempFailEmptyUser)
			ctx.Abort()
		case definitions.AuthResultEmptyPassword:
			a.AuthFail(ctx)
			ctx.Abort()
		default:
			ctx.AbortWithStatus(a.StatusCodeInternalError)
		}
	}
}

// HandleSASLAuthdAuthentication handles the authentication logic for the HandleSASLAuthdAuthentication service.
func (a *AuthState) HandleSASLAuthdAuthentication(ctx *gin.Context) {
	switch a.HandlePassword(ctx) {
	case definitions.AuthResultOK:
		tolerate.GetTolerate().SetIPAddress(a.HTTPClientContext, a.ClientIP, a.Username, true)
		a.AuthOK(ctx)
	case definitions.AuthResultFail:
		tolerate.GetTolerate().SetIPAddress(a.HTTPClientContext, a.ClientIP, a.Username, false)
		a.AuthFail(ctx)
		ctx.Abort()
	case definitions.AuthResultTempFail:
		a.AuthTempFail(ctx, definitions.TempFailDefault)
		ctx.Abort()
	case definitions.AuthResultEmptyUsername:
		a.AuthTempFail(ctx, definitions.TempFailEmptyUser)
		ctx.Abort()
	case definitions.AuthResultEmptyPassword:
		a.AuthFail(ctx)
		ctx.Abort()
	default:
		ctx.AbortWithStatus(a.StatusCodeInternalError)
	}
}

// HealthCheck handles the health check functionality by logging a message and returning "pong" as the response.
func HealthCheck(ctx *gin.Context) {
	level.Info(log.Logger).Log(definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey), definitions.LogKeyMsg, "Health check")

	ctx.String(http.StatusOK, "pong")
}

// listBlockedIPAddresses retrieves a list of blocked IP addresses from Redis.
func listBlockedIPAddresses(ctx context.Context, filterCmd *FilterCmd, guid string) (*BlockedIPAddresses, error) {
	blockedIPAddresses := &BlockedIPAddresses{}

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisBruteForceHashKey

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	ipAddresses, err := rediscli.GetClient().GetReadHandle().HGetAll(ctx, key).Result()
	if err != nil {
		if !stderrors.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)

			errMsg := err.Error()
			blockedIPAddresses.Error = &errMsg

			return blockedIPAddresses, err
		}
	} else {
		if filterCmd != nil {
			filteredIPs := make(map[string]string)

			if len(filterCmd.IPAddress) == 0 {
				ipAddresses = make(map[string]string)
			}

			for _, filterIPWanted := range filterCmd.IPAddress {
				for network, bucket := range ipAddresses {
					if util.IsInNetwork([]string{network}, guid, filterIPWanted) {
						filteredIPs[network] = bucket

						break
					}
				}

				ipAddresses = filteredIPs
			}
		}

		blockedIPAddresses.IPAddresses = ipAddresses
		blockedIPAddresses.Error = nil
	}

	return blockedIPAddresses, nil
}

// listBlockedAccounts retrieves a list of blocked user accounts from Redis and returns them along with any potential errors.
func listBlockedAccounts(ctx context.Context, filterCmd *FilterCmd, guid string) (*BlockedAccounts, error) {
	blockedAccounts := &BlockedAccounts{Accounts: make(map[string][]string)}

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisAffectedAccountsKey

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	accounts, err := rediscli.GetClient().GetReadHandle().SMembers(ctx, key).Result()
	if err != nil {
		if !stderrors.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)

			errMsg := err.Error()
			blockedAccounts.Error = &errMsg
		} else {
			err = nil
		}

		return blockedAccounts, err
	} else {
		if filterCmd != nil {
			var (
				account          string
				filteredAccounts []string
			)

			for _, accountWanted := range filterCmd.Accounts {
				for _, account = range accounts {
					if account == accountWanted {
						break
					} else {
						account = ""
					}
				}

				if account != "" {
					filteredAccounts = append(filteredAccounts, account)
				}
			}

			accounts = filteredAccounts
		}

		for _, account := range accounts {
			var accountIPs []string

			key = config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistIPsKey + ":" + account
			if accountIPs, err = rediscli.GetClient().GetReadHandle().SMembers(ctx, key).Result(); err != nil {
				stats.GetMetrics().GetRedisReadCounter().Inc()

				if !stderrors.Is(err, redis.Nil) {
					level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)

					errMsg := err.Error()
					blockedAccounts.Error = &errMsg

					break
				} else {
					err = nil
				}

				continue
			}

			stats.GetMetrics().GetRedisReadCounter().Inc()
			blockedAccounts.Accounts[account] = accountIPs
		}

		blockedAccounts.Error = nil
	}

	return blockedAccounts, err
}

// HanldeBruteForceList lists all blocked IP addresses and accounts in response to a brute force attack event.
func HanldeBruteForceList(ctx *gin.Context) {
	var filterCmd *FilterCmd

	guid := ctx.GetString(definitions.CtxGUIDKey)
	httpStatusCode := http.StatusOK

	if ctx.Request.Method == http.MethodPost {
		filterCmd = &FilterCmd{}

		if err := ctx.ShouldBindJSON(filterCmd); err != nil {
			HandleJSONError(ctx, err)

			return
		}
	}

	blockedIPAddresses, err := listBlockedIPAddresses(ctx, filterCmd, guid)
	if err != nil {
		httpStatusCode = http.StatusInternalServerError
	}

	blockedAccounts, err := listBlockedAccounts(ctx, filterCmd, guid)
	if err != nil {
		httpStatusCode = http.StatusInternalServerError
	}

	level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, definitions.ServList)

	ctx.JSON(httpStatusCode, &RESTResult{
		GUID:      guid,
		Object:    definitions.CatBruteForce,
		Operation: definitions.ServList,
		Result:    []any{blockedIPAddresses, blockedAccounts},
	})
}

// HandleUserFlush is a handler function for a Gin HTTP server. It takes a gin.Context as a parameter
// and attempts to flush the cache according to the *FlushUserCmd in the request's JSON body.
//
// Parameters:
//   - ctx:  A pointer to gin.Context. The context is used for retrieving a *FlushUserCmd
//     payload from the request and for sending HTTP responses. The context also carries a
//     globally unique identifier (GUID) for logging purposes.
//
// Local variables:
//   - userCmd:   A pointer to a FlushUserCmd object. This object is populated with data from the
//     request's JSON body.
//   - guid:      The globally unique identifier retrieved from the context for logging.
//   - useCache:  A flag indicating whether the cache backend is currently in use by the application.
//     When true, the function can remove password history keys from the cache.
//   - statusMsg: A variable for storing the status message. This message will be either "flushed"
//     or "not flushed", based on the outcome of the cache flush operation.
//
// Procedure:
//  1. The function first retrieves the GUID from the context.
//  2. Then, it logs the GUID along with the flushing information.
//  3. It attempts to bind the JSON payload from the request to a FlushUserCmd object.
//  4. If any error occurs during this binding, the function logs the error and the GUID.
//     After that, it aborts the current HTTP request by sending a 400 (Bad Request)
//     status code as a response. Then the function returns.
//  5. If there are no binding errors, the function processes the cache flush.
//  6. Based on the useCache flag and the outcome of the cache flush operation, the function
//     updates the statusMsg and sends the cache status to the client.
func HandleUserFlush(ctx *gin.Context) {
	guid := ctx.GetString(definitions.CtxGUIDKey)
	userCmd := &FlushUserCmd{}

	level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.CatCache, definitions.ServFlush)

	if err := ctx.ShouldBindJSON(userCmd); err != nil {
		HandleJSONError(ctx, err)

		return
	}

	removedKeys, noUserAccoundFound := processFlushCache(ctx, userCmd, guid)

	statusMsg := fmt.Sprintf("%d keys flushed", len(removedKeys))

	if noUserAccoundFound || len(removedKeys) == 0 {
		statusMsg = "not flushed"
	}

	sendCacheStatus(ctx, guid, userCmd, statusMsg, removedKeys)
}

// processFlushCache takes a user command and a GUID and processes the cache flush.
// It iterates through the backends in the GetFile() and checks if the backend is BackendCache.
// If it is, it sets useCache to true and calls processUserCmd to process the user command.
// If there is an error during the cache flush, cacheFlushError is set to true and the loop breaks.
// It returns cacheFlushError and useCache flags.
func processFlushCache(ctx *gin.Context, userCmd *FlushUserCmd, guid string) (removedKeys []string, noUserAccountFound bool) {
	for _, backendType := range config.GetFile().GetServer().GetBackends() {
		if backendType.Get() != definitions.BackendCache {
			continue
		}

		removedKeys, noUserAccountFound = processUserCmd(ctx, userCmd, guid)
		if noUserAccountFound {
			break
		}
	}

	return
}

// processUserCmd processes the user command by performing the following steps:
// 1. Calls the GetUserAccountFromCache function to set up the cache flush and retrieve the account name, removeHash flag, and cacheFlushError flag.
// 2. If cacheFlushError is true, returns true immediately.
// 3. Calls the prepareRedisUserKeys function to set the user keys using the user command and account name.
// 4. Calls the removeUserFromCache function to remove the user from the cache by providing the user command, user keys, guid, and removeHash flag.
// 5. Returns false.
func processUserCmd(ctx *gin.Context, userCmd *FlushUserCmd, guid string) (removedKeys []string, noUserAccountFound bool) {
	var (
		result        int64
		removeHash    bool
		accountName   string
		ipAddresses   []string
		removedIPKeys []string
		err           error
		userKeys      config.StringSet
	)

	if accountName = backend.GetUserAccountFromCache(ctx, userCmd.User, guid); accountName == "" {
		return nil, true
	}

	ipAddresses, userKeys = prepareRedisUserKeys(ctx, guid, accountName)

	// Remove all buckets (bf) associated with the user
	for _, ipAddress := range ipAddresses {
		_, removedIPKeys, err = processBruteForceRules(ctx, &FlushRuleCmd{
			IPAddress: ipAddress,
			RuleName:  "*",
		}, guid)

		if err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)
		}
	}

	removedKeys = append(removedKeys, removedIPKeys...)

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	// Remove PW_HIST_SET from Redis
	key := bruteforce.GetPWHistIPsRedisKey(accountName)
	if result, err = rediscli.GetClient().GetWriteHandle().Del(ctx, key).Result(); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)
	} else {
		if result > 0 {
			removedKeys = append(removedKeys, key)
		}
	}

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	// Remove an account from AFFECTED_ACCOUNTS
	key = config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisAffectedAccountsKey
	if result, err = rediscli.GetClient().GetWriteHandle().SRem(ctx, key, accountName).Result(); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)
	} else {
		if result > 0 {
			removedKeys = append(removedKeys, key)
		}
	}

	removedKeys = append(removedKeys, removeUserFromCache(ctx, userCmd, userKeys, guid, removeHash)...)

	return removedKeys, noUserAccountFound
}

func getIPsFromPWHistSet(ctx context.Context, accountName string) ([]string, error) {
	var ips []string

	key := bruteforce.GetPWHistIPsRedisKey(accountName)

	if result, err := rediscli.GetClient().GetReadHandle().SMembers(ctx, key).Result(); err != nil {
		if !stderrors.Is(err, redis.Nil) {
			return nil, err
		}

		return nil, nil
	} else if result != nil {
		ips = result
	}

	return ips, nil
}

// prepareRedisUserKeys populates a string set with user keys based on the given FlushUserCmd and accountName.
// The function creates a new empty string set using the NewStringSet function from the config package.
// It then sets two keys in the string set: one is a concatenation of the RedisPrefix constant from the config package,
// "ucp:__default__:", and the accountName parameter. The other key is a concatenation of the RedisPrefix constant,
// the RedisPwHashKey constant from the global package, ":", the User field from the userCmd parameter, and ":*".
// Next, it iterates over the protocols obtained from the GetFile().GetAllProtocols function from the config package.
// For each protocol, it retrieves the cache names using the backend.GetCacheNames function from the backend package,
// passing the protocol and the definitions.CacheAll constant. For each cache name, it sets a key in the string set
// by concatenating the RedisPrefix constant, "ucp:", the cache name, ":", and the accountName parameter.
// Finally, the function returns the populated string set.
func prepareRedisUserKeys(ctx context.Context, guid string, accountName string) ([]string, config.StringSet) {
	ips, err := getIPsFromPWHistSet(ctx, accountName)
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)
	}

	userKeys := config.NewStringSet()

	userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisUserPositiveCachePrefix + "__default__:" + accountName)

	if ips != nil {
		for _, ip := range ips {
			userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHashKey + ":" + accountName + ":" + ip)
			userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHashKey + ":" + ip)
		}
	}

	protocols := config.GetFile().GetAllProtocols()
	for index := range protocols {
		cacheNames := backend.GetCacheNames(protocols[index], definitions.CacheAll)
		for _, cacheName := range cacheNames.GetStringSlice() {
			userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisUserPositiveCachePrefix + cacheName + ":" + accountName)
		}
	}

	return ips, userKeys
}

// removeUserFromCache removes a user from the cache based on the given parameters.
// If removeHash is true, it deletes the entire Redis hash map associated with the user.
// Otherwise, it only removes the specific user key from the hash map.
// It also deletes other user keys stored in the userKeys string set.
// If any error occurs during the removal process, it logs the error and immediately returns.
// After successful removal, it logs the keys that have been flushed.
func removeUserFromCache(ctx context.Context, userCmd *FlushUserCmd, userKeys config.StringSet, guid string, removeHash bool) []string {
	var (
		result int64
		err    error
	)

	removedKeys := make([]string, 0)

	redisKey := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisUserHashKey

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	if removeHash {
		err = rediscli.GetClient().GetWriteHandle().Del(ctx, redisKey).Err()
	} else {
		err = rediscli.GetClient().GetWriteHandle().HDel(ctx, redisKey, userCmd.User).Err()
	}

	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)

		return removedKeys
	}

	for _, userKey := range userKeys.GetStringSlice() {
		if result, err = rediscli.GetClient().GetWriteHandle().Del(ctx, userKey).Result(); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)

			return removedKeys
		}

		stats.GetMetrics().GetRedisWriteCounter().Inc()

		if result > 0 {
			removedKeys = append(removedKeys, userKey)

			level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, "keys", userKey, "status", "flushed")
		}
	}

	return removedKeys
}

// sendCacheStatus is a function that sends the cache status as a response to the client.
// If the useCache parameter is true, it sends a JSON response with the cache status message and the user command details.
// If useCache is false, it sends a JSON response with an error message indicating that the cache backend is not enabled.
//
// Parameters:
// - ctx: The gin.Context object representing the HTTP request and response context.
// - guid: The GUID string associated with the request.
// - userCmd: A pointer to a FlushUserCmd object containing user command details.
// - statusMsg: The status message to be included in the response.
func sendCacheStatus(ctx *gin.Context, guid string, userCmd *FlushUserCmd, statusMsg string, removedKeys []string) {
	level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, statusMsg)

	sort.Strings(removedKeys)

	ctx.JSON(http.StatusOK, &RESTResult{
		GUID:      guid,
		Object:    definitions.CatCache,
		Operation: definitions.ServFlush,
		Result: &FlushUserCmdStatus{
			User:        userCmd.User,
			RemovedKeys: removedKeys,
			Status:      statusMsg,
		},
	})
}

// HandleBruteForceRuleFlush handles the flushing of a brute force rule by processing the provided IP command and updating the necessary data.
// It logs information about the action, including the GUID, brute force category, and flush operation.
// If the IP command fails to bind, an error is logged, and a bad request status is returned.
// If there is an error processing the brute force rules, an error is logged, and an internal server error status is returned.
// If the rule flush error flag is true, the status message is set to "not flushed".
// The function then logs the status message and returns a JSON response containing the GUID, brute force category, flush operation, and the result of the command, including the IP address
func HandleBruteForceRuleFlush(ctx *gin.Context) {
	var (
		ruleFlushError bool
		removedKeys    []string
		err            error
	)

	guid := ctx.GetString(definitions.CtxGUIDKey)

	level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.CatBruteForce, definitions.ServFlush)

	ipCmd := &FlushRuleCmd{}

	if err = ctx.ShouldBindJSON(ipCmd); err != nil {
		HandleJSONError(ctx, err)

		return
	}

	level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, "ip_address", ipCmd.IPAddress)

	ruleFlushError, removedKeys, err = processBruteForceRules(ctx, ipCmd, guid)
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	statusMsg := fmt.Sprintf("%d keys flushed", len(removedKeys))

	if ruleFlushError || len(removedKeys) == 0 {
		statusMsg = "not flushed"
	}

	level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, statusMsg)

	sort.Strings(removedKeys)

	ctx.JSON(http.StatusOK, &RESTResult{
		GUID:      guid,
		Object:    definitions.CatBruteForce,
		Operation: definitions.ServFlush,
		Result: &FlushRuleCmdStatus{
			IPAddress:   ipCmd.IPAddress,
			RuleName:    ipCmd.RuleName,
			RemovedKeys: removedKeys,
			Status:      statusMsg,
		},
	})
}

// processBruteForceRules handles the deletion of IP brute force rules and flushing of brute force buckets in Redis.
// It takes the current Gin context, the command containing the IP address and rule name to be flushed, and a GUID as parameters.
// It returns a boolean indicating if there was an error while flushing the rules or not, and an error object if any occurred.
//
// The function loops through all the brute force rules defined in the loaded configuration.
// If the rule name matches the one provided in the command or the command specifies to flush all rules,
// it proceeds with deleting the matching rule from Redis.
// If the rule has a corresponding brute force bucket Redis key, it deletes that key as well.
// If any errors occur during the deletion or Redis operations, it sets the ruleFlushError flag to true,
// returns the error, and exits the loop.
//
// Finally, it returns the ruleFlushError flag indicating if there was any error during rule flushing,
// and a nil error value if no error occurred.
func processBruteForceRules(ctx *gin.Context, ipCmd *FlushRuleCmd, guid string) (bool, []string, error) {
	var removedKeys []string

	ruleFlushError := false

	for _, rule := range config.GetFile().GetBruteForceRules() {
		if rule.Name == ipCmd.RuleName || ipCmd.RuleName == "*" {
			bm := bruteforce.NewBucketManager(ctx, guid, ipCmd.IPAddress)

			if removedKey, err := bm.DeleteIPBruteForceRedis(&rule, ipCmd.RuleName); err != nil {
				ruleFlushError = true

				return ruleFlushError, removedKeys, err
			} else {
				if removedKey != "" {
					removedKeys = append(removedKeys, removedKey)
				}
			}

			if key := bm.GetBruteForceBucketRedisKey(&rule); key != "" {
				if result, err := rediscli.GetClient().GetWriteHandle().Del(ctx, key).Result(); err != nil {
					stats.GetMetrics().GetRedisWriteCounter().Inc()

					ruleFlushError = true

					return ruleFlushError, removedKeys, err
				} else if result > 0 {
					removedKeys = append(removedKeys, key)

					level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, "key", key, "status", "flushed")
				}

				stats.GetMetrics().GetRedisWriteCounter().Inc()
			}
		}
	}

	return ruleFlushError, removedKeys, nil
}

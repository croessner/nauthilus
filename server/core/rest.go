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
	"crypto/rand"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/ipscoper"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/model/admin"
	bf "github.com/croessner/nauthilus/server/model/bruteforce"
	restdto "github.com/croessner/nauthilus/server/model/rest"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/svcctx"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// For brief documentation of this file please have a look at the Markdown document REST-API.md.

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
		if abort := a.ProcessFeatures(ctx); !abort {
			a.ProcessAuthentication(ctx)
		}
	}
}

// ProcessFeatures handles the processing of authentication-related features for a given context.
// It determines the action to take based on various authentication results and applies the necessary response.
func (a *AuthState) ProcessFeatures(ctx *gin.Context) (abort bool) {
	if !(a.NoAuth || ctx.GetBool(definitions.CtxLocalCacheAuthKey)) {
		switch a.HandleFeatures(ctx) {
		case definitions.AuthResultFeatureTLS:
			result := GetPassDBResultFromPool()
			a.PostLuaAction(result)
			PutPassDBResultToPool(result)
			a.AuthTempFail(ctx, definitions.TempFailNoTLS)
			ctx.Abort()

			return true
		case definitions.AuthResultFeatureRelayDomain, definitions.AuthResultFeatureRBL, definitions.AuthResultFeatureLua:
			result := GetPassDBResultFromPool()
			a.PostLuaAction(result)
			PutPassDBResultToPool(result)
			a.AuthFail(ctx)
			ctx.Abort()

			return true
		case definitions.AuthResultUnset:
			return true
		case definitions.AuthResultOK:
			return false
		case definitions.AuthResultTempFail:
			a.AuthTempFail(ctx, definitions.TempFailDefault)
			ctx.Abort()

			return true
		default:
			ctx.AbortWithStatus(a.StatusCodeInternalError)

			return true
		}
	}

	return false
}

// ProcessAuthentication handles the authentication logic for all services.
func (a *AuthState) ProcessAuthentication(ctx *gin.Context) {
	switch a.HandlePassword(ctx) {
	case definitions.AuthResultOK:
		tolerate.GetTolerate().SetIPAddress(a.Ctx(), a.ClientIP, a.Username, true)
		a.AuthOK(ctx)
	case definitions.AuthResultFail:
		tolerate.GetTolerate().SetIPAddress(a.Ctx(), a.ClientIP, a.Username, false)
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

// listBlockedIPAddresses retrieves a list of blocked IP addresses from Redis.
func listBlockedIPAddresses(ctx context.Context, filterCmd *bf.FilterCmd, guid string) (*bf.BlockedIPAddresses, error) {
	blockedIPAddresses := &bf.BlockedIPAddresses{}

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisBruteForceHashKey

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	ipAddresses, err := rediscli.GetClient().GetReadHandle().HGetAll(ctx, key).Result()
	if err != nil {
		if !stderrors.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Error retrieving IP addresses from Redis",
				definitions.LogKeyError, err,
			)

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
func listBlockedAccounts(ctx context.Context, filterCmd *bf.FilterCmd, guid string) (*bf.BlockedAccounts, error) {
	blockedAccounts := &bf.BlockedAccounts{Accounts: make(map[string][]string)}

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisAffectedAccountsKey

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	accounts, err := rediscli.GetClient().GetReadHandle().SMembers(ctx, key).Result()
	if err != nil {
		if !stderrors.Is(err, redis.Nil) {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Error retrieving accounts from Redis",
				definitions.LogKeyError, err,
			)

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
					level.Error(log.Logger).Log(
						definitions.LogKeyGUID, guid,
						definitions.LogKeyMsg, "Error retrieving IP addresses for account from Redis",
						definitions.LogKeyError, err,
					)

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
	// Check if JWT auth is enabled
	if config.GetFile().GetServer().GetJWTAuth().IsEnabled() {
		// Extract token
		tokenString, err := ExtractJWTToken(ctx)
		if err == nil {
			// Validate token
			claims, err := ValidateJWTToken(ctx, tokenString)
			if err == nil {
				// Check if user has the security or admin role
				hasRequiredRole := false
				for _, role := range claims.Roles {
					if role == definitions.RoleSecurity || role == definitions.RoleAdmin {
						hasRequiredRole = true
						break
					}
				}

				if !hasRequiredRole {
					ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "missing required role: security or admin"})
					return
				}
			} else {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
				return
			}
		} else {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
	}

	var filterCmd *bf.FilterCmd

	guid := ctx.GetString(definitions.CtxGUIDKey)
	httpStatusCode := http.StatusOK

	if ctx.Request.Method == http.MethodPost {
		filterCmd = &bf.FilterCmd{}

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

	ctx.JSON(httpStatusCode, &restdto.Result{
		GUID:      guid,
		Object:    definitions.CatBruteForce,
		Operation: definitions.ServList,
		Result:    []any{blockedIPAddresses, blockedAccounts},
	})
}

// HandleConfigLoad handles loading the server configuration and applies necessary JWT authentication checks.
// This function validates a provided JWT token for required roles when authentication is enabled.
// If JWT authentication fails, appropriate HTTP error responses are returned, such as Unauthorized or Forbidden.
// On success, it retrieves the server configuration as JSON and binds it to the request context.
func HandleConfigLoad(ctx *gin.Context) {
	// Check if JWT auth is enabled
	if config.GetFile().GetServer().GetJWTAuth().IsEnabled() {
		// Extract token
		tokenString, err := ExtractJWTToken(ctx)
		if err == nil {
			// Validate token
			claims, err := ValidateJWTToken(ctx, tokenString)
			if err == nil {
				// Check if user has the security or admin role
				hasRequiredRole := false
				for _, role := range claims.Roles {
					if role == definitions.RoleAdmin {
						hasRequiredRole = true
						break
					}
				}

				if !hasRequiredRole {
					ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "missing required role: security or admin"})
					return
				}
			} else {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
				return
			}
		} else {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
	}

	guid := ctx.GetString(definitions.CtxGUIDKey)

	level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "Loading configuration")

	jsonBytes, err := config.GetFile().GetConfigFileAsJSON()
	if err != nil {
		HandleJSONError(ctx, err)

		return
	}

	ctx.JSON(http.StatusOK, &restdto.Result{
		GUID:      guid,
		Object:    definitions.CatConfig,
		Operation: definitions.ServLoad,
		Result:    string(jsonBytes),
	})
}

// HandleUserFlush handles a user cache flush request by processing the input, flushing relevant cache keys, and sending a response.
func HandleUserFlush(ctx *gin.Context) {
	guid := ctx.GetString(definitions.CtxGUIDKey)
	userCmd := &admin.FlushUserCmd{}

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
func processFlushCache(ctx *gin.Context, userCmd *admin.FlushUserCmd, guid string) (removedKeys []string, noUserAccountFound bool) {
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
func processUserCmd(ctx *gin.Context, userCmd *admin.FlushUserCmd, guid string) (removedKeys []string, noUserAccountFound bool) {
	var (
		result        int64
		removeHash    bool
		accountName   string
		ipAddresses   []string
		removedIPKeys []string
		err           error
		userKeys      config.StringSet
	)

	// Accept either a username (resolved via USER hash) or a direct account name
	if accountName = backend.ResolveAccountIdentifier(ctx, userCmd.User, guid); accountName == "" {
		return nil, true
	}

	ipAddresses, userKeys = prepareRedisUserKeys(ctx, guid, accountName)

	// Remove all buckets (bf) associated with the user
	for _, ipAddress := range ipAddresses {
		_, removedIPKeys, err = processBruteForceRules(ctx, &bf.FlushRuleCmd{
			IPAddress: ipAddress,
			RuleName:  "*",
		}, guid)

		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Error while flushing brute force rules",
				definitions.LogKeyError, err,
			)
		}
	}

	removedKeys = append(removedKeys, removedIPKeys...)

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	// Remove PW_HIST_SET from Redis (use UNLINK to avoid blocking)
	key := bruteforce.GetPWHistIPsRedisKey(accountName)
	if result, err = rediscli.GetClient().GetWriteHandle().Unlink(ctx, key).Result(); err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error while flushing PW_HIST_SET",
			definitions.LogKeyError, err,
		)
	} else {
		if result > 0 {
			removedKeys = append(removedKeys, key)
		}
	}

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	// Remove an account from AFFECTED_ACCOUNTS
	key = config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisAffectedAccountsKey
	if result, err = rediscli.GetClient().GetWriteHandle().SRem(ctx, key, accountName).Result(); err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error while flushing AFFECTED_ACCOUNTS",
			definitions.LogKeyError, err,
		)
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

// prepareRedisUserKeys generates a set of Redis keys related to the provided user and their IPs for cleanup or processing.
func prepareRedisUserKeys(ctx context.Context, guid string, accountName string) ([]string, config.StringSet) {
	ips, err := getIPsFromPWHistSet(ctx, accountName)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error while retrieving IPs from PW_HIST_SET",
			definitions.LogKeyError, err,
		)
	}

	userKeys := config.NewStringSet()

	userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisUserPositiveCachePrefix + "__default__:" + accountName)

	if ips != nil {
		// Shared scoper used to compute CIDR-scoped identifiers when configured (IPv6)
		scoper := ipscoper.NewIPScoper()

		for _, ip := range ips {
			// Compute scoped identifier for both contexts we need to clean up
			scopedRWP := scoper.Scope(ipscoper.ScopeRepeatingWrongPassword, ip)
			scopedTol := scoper.Scope(ipscoper.ScopeTolerations, ip)

			// Password-history hashes (account+IP and IP-only) — delete for raw and scoped identifiers
			userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHashKey + ":" + accountName + ":" + ip)
			userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHashKey + ":" + ip)

			// PW_HIST totals (account+IP and IP-only) — delete for raw and scoped identifiers
			userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + ":" + accountName + ":" + ip)
			userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + ":" + ip)

			if scopedRWP != ip {
				userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHashKey + ":" + accountName + ":" + scopedRWP)
				userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHashKey + ":" + scopedRWP)
				userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + ":" + accountName + ":" + scopedRWP)
				userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHistTotalKey + ":" + scopedRWP)
			}

			// Tolerations keys — delete base hash and both positive/negative ZSETs for raw and scoped identifiers
			baseTolRaw := config.GetFile().GetServer().GetRedis().GetPrefix() + "bf:TR:" + ip

			userKeys.Set(baseTolRaw)        // hash with aggregated counters
			userKeys.Set(baseTolRaw + ":P") // positives ZSET
			userKeys.Set(baseTolRaw + ":N") // negatives ZSET

			if scopedTol != ip {
				baseTolScoped := config.GetFile().GetServer().GetRedis().GetPrefix() + "bf:TR:" + scopedTol

				userKeys.Set(baseTolScoped)
				userKeys.Set(baseTolScoped + ":P")
				userKeys.Set(baseTolScoped + ":N")
			}

			// Also remove the PW_HIST meta key for this IP (protocol/oidc persistence)
			userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistMetaKey + ":" + ip)

			// Remove network-scoped PW_HIST meta keys for this IP for all matching brute-force rules
			parsed := net.ParseIP(ip)
			if parsed != nil {
				for _, rule := range config.GetFile().GetBruteForceRules() {
					// Respect IPv4/IPv6 flags
					if (parsed.To4() != nil && !rule.IPv4) || (parsed.To4() == nil && !rule.IPv6) {
						continue
					}
					_, network, nerr := net.ParseCIDR(fmt.Sprintf("%s/%d", ip, rule.CIDR))
					if nerr == nil && network != nil {
						userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistMetaKey + ":" + network.String())
					}
				}
			}
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

// removeUserFromCache removes a user and related keys from the cache based on the given parameters and context.
// Parameters: ctx is the request context, userCmd contains user info, userKeys is a set of keys to remove,
// guid is a unique identifier for logs, and removeHash indicates whether to delete the entire hash or specific fields.
// Returns a slice of strings representing the removed keys.
func removeUserFromCache(ctx context.Context, userCmd *admin.FlushUserCmd, userKeys config.StringSet, guid string, removeHash bool) []string {
	removedKeys := make([]string, 0)

	redisKey := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisUserHashKey

	// Increment write counter once for the whole pipeline execution
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	keys := userKeys.GetStringSlice()

	cmds, err := rediscli.ExecuteWritePipeline(ctx, func(pipe redis.Pipeliner) error {
		// Remove hash (whole hash or a single field) first
		if removeHash {
			pipe.Del(ctx, redisKey)
		} else {
			pipe.HDel(ctx, redisKey, userCmd.User)
		}

		// Queue deletion of all user keys
		for _, userKey := range keys {
			// Use UNLINK to avoid blocking Redis on large keys
			pipe.Unlink(ctx, userKey)
		}

		return nil
	})

	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error while flushing user keys",
			definitions.LogKeyError, err,
		)

		return removedKeys
	}

	// cmds[0] corresponds to Del/HDel of redisKey, which we do not report in removedKeys (preserving prior behavior)
	// Collect results for user keys deletions
	for i, userKey := range keys {
		idx := i + 1 // shift due to the first command being Del/HDel
		if idx >= 0 && idx < len(cmds) {
			if intCmd, ok := cmds[idx].(*redis.IntCmd); ok {
				if val, cerr := intCmd.Result(); cerr == nil && val > 0 {
					removedKeys = append(removedKeys, userKey)

					level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, "keys", userKey, "status", "flushed")
				}
			} else {
				level.Error(log.Logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyMsg, "Unexpected command type in pipeline result",
					definitions.LogKeyError, err,
				)
			}
		}
	}

	return removedKeys
}

// sendCacheStatus sends a JSON response with the cache flush status, including user details and removed keys.
func sendCacheStatus(ctx *gin.Context, guid string, userCmd *admin.FlushUserCmd, statusMsg string, removedKeys []string) {
	level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, statusMsg)

	sort.Strings(removedKeys)

	ctx.JSON(http.StatusOK, &restdto.Result{
		GUID:      guid,
		Object:    definitions.CatCache,
		Operation: definitions.ServFlush,
		Result: &admin.FlushUserCmdStatus{
			User:        userCmd.User,
			RemovedKeys: removedKeys,
			Status:      statusMsg,
		},
	})
}

// HandleBruteForceRuleFlush handles the flushing of brute force rules for a given IP address and rule criteria.
// It processes the request, binds JSON input, validates data, performs the flush operation, and returns the result.
// The function logs the operation details, including rule applicability, flushed keys, and any encountered errors.
func HandleBruteForceRuleFlush(ctx *gin.Context) {
	var (
		ruleFlushError bool
		removedKeys    []string
		err            error
	)

	guid := ctx.GetString(definitions.CtxGUIDKey)

	level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.CatBruteForce, definitions.ServFlush)

	ipCmd := &bf.FlushRuleCmd{}

	if err = ctx.ShouldBindJSON(ipCmd); err != nil {
		HandleJSONError(ctx, err)

		return
	}

	level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, "ip_address", ipCmd.IPAddress)

	ruleFlushError, removedKeys, err = processBruteForceRules(ctx, ipCmd, guid)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error while flushing brute force rules",
			definitions.LogKeyError, err,
		)
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	statusMsg := fmt.Sprintf("%d keys flushed", len(removedKeys))

	if ruleFlushError || len(removedKeys) == 0 {
		statusMsg = "not flushed"
	}

	level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, statusMsg)

	sort.Strings(removedKeys)

	ctx.JSON(http.StatusOK, &restdto.Result{
		GUID:      guid,
		Object:    definitions.CatBruteForce,
		Operation: definitions.ServFlush,
		Result: &bf.FlushRuleCmdStatus{
			IPAddress:   ipCmd.IPAddress,
			RuleName:    ipCmd.RuleName,
			Protocol:    ipCmd.Protocol,
			OIDCCID:     ipCmd.OIDCCID,
			RemovedKeys: removedKeys,
			Status:      statusMsg,
		},
	})
}

// --- Async job infrastructure ---

const (
	jobStatusQueued     = "QUEUED"
	jobStatusInProgress = "INPROGRESS"
	jobStatusDone       = "DONE"
	jobStatusError      = "ERROR"
)

// Test seams for determinism and stubbing in unit tests.
// They preserve default behavior in production builds but can be overridden in tests.
var (
	genJobID     = generateJobID
	asyncStarter = startAsync
	nowFunc      = time.Now
)

func asyncJobKey(jobID string) string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + "async:job:" + jobID
}

// generateJobID creates a random URL-safe identifier.
func generateJobID() string {
	// Generate a 16-byte random ID encoded as hex with a time prefix for debugging order
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}

	return fmt.Sprintf("%d-%s", time.Now().UTC().UnixNano(), hex.EncodeToString(b))
}

// createAsyncJob persists a new job with QUEUED status and TTL.
func createAsyncJob(ctx context.Context, jobType string) (string, error) {
	jobID := genJobID()
	key := asyncJobKey(jobID)

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	// Use ordered field/values to make unit testing with redismock deterministic
	if _, err := rediscli.GetClient().GetWriteHandle().HSet(
		ctx,
		key,
		"status", jobStatusQueued,
		"type", jobType,
		"createdAt", nowFunc().UTC().Format(time.RFC3339Nano),
		"resultCount", 0,
	).Result(); err != nil {
		return "", err
	}

	// Apply TTL (reuse NegCacheTTL if no dedicated TTL exists)
	_, _ = rediscli.GetClient().GetWriteHandle().Expire(ctx, key, config.GetFile().GetServer().Redis.NegCacheTTL).Result()
	stats.GetMetrics().GetRedisWriteCounter().Inc()

	return jobID, nil
}

// startAsync runs fn in a background goroutine using the service root context.
func startAsync(jobID string, guid string, fn func(context.Context) (int, []string, error)) {
	go func() {
		base := svcctx.Get()

		key := asyncJobKey(jobID)

		// Mark INPROGRESS
		func() {
			defer stats.GetMetrics().GetRedisWriteCounter().Inc()

			_, _ = rediscli.GetClient().GetWriteHandle().HSet(base, key, map[string]any{
				"status":    jobStatusInProgress,
				"startedAt": nowFunc().UTC().Format(time.RFC3339Nano),
			}).Result()
		}()

		// Execute task
		count, _, err := fn(base)

		// Persist final state
		updates := map[string]any{
			"finishedAt":  nowFunc().UTC().Format(time.RFC3339Nano),
			"resultCount": count,
		}

		if err != nil {
			updates["status"] = jobStatusError
			updates["error"] = err.Error()
			level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "async job failed", definitions.LogKeyError, err)
		} else {
			updates["status"] = jobStatusDone
		}

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		_, _ = rediscli.GetClient().GetWriteHandle().HSet(base, key, updates).Result()
		_, _ = rediscli.GetClient().GetWriteHandle().Expire(base, key, config.GetFile().GetServer().Redis.NegCacheTTL).Result()
		stats.GetMetrics().GetRedisWriteCounter().Inc()
	}()
}

// HandleAsyncJobStatus returns the current status for a specific job ID.
func HandleAsyncJobStatus(ctx *gin.Context) {
	guid := ctx.GetString(definitions.CtxGUIDKey)
	jobID := ctx.Param("jobId")
	key := asyncJobKey(jobID)

	defer stats.GetMetrics().GetRedisReadCounter().Inc()
	data, err := rediscli.GetClient().GetReadHandle().HGetAll(ctx.Request.Context(), key).Result()
	if err != nil || len(data) == 0 {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	ctx.JSON(http.StatusOK, &restdto.Result{
		GUID:      guid,
		Object:    "async",
		Operation: "status",
		Result: gin.H{
			"jobId":       jobID,
			"status":      data["status"],
			"type":        data["type"],
			"createdAt":   data["createdAt"],
			"startedAt":   data["startedAt"],
			"finishedAt":  data["finishedAt"],
			"resultCount": data["resultCount"],
			"error":       data["error"],
		},
	})
}

// HandleUserFlushAsync enqueues a user flush as a background job and returns 202 with jobId.
func HandleUserFlushAsync(ctx *gin.Context) {
	guid := ctx.GetString(definitions.CtxGUIDKey)
	userCmd := &admin.FlushUserCmd{}

	if err := ctx.ShouldBindJSON(userCmd); err != nil {
		HandleJSONError(ctx, err)

		return
	}

	jobID, err := createAsyncJob(ctx.Request.Context(), "CACHE_FLUSH")
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	asyncStarter(jobID, guid, func(base context.Context) (int, []string, error) {
		// Reuse existing logic, but without relying on the HTTP request lifetime
		// Create a fresh gin.Context-independent execution by calling helpers that accept context.Context where possible
		// Here we reuse processFlushCache by constructing a lightweight adapter using a temporary gin.Context only for param flow
		// However, the heavy work inside uses redis contexts derived from request ctx, which is fine since svcctx is long-lived
		// To avoid tying to original ctx, we call the same pipeline but pass a dummy gin.Context wrapper with base as Request.Context
		gctx := &gin.Context{}
		// Gin context is needed by processFlushCache; create one with request context fallback from svcctx
		gctx.Request = ctx.Request.Clone(base)
		removedKeys, _ := processFlushCache(gctx, userCmd, guid)

		return len(removedKeys), removedKeys, nil
	})

	ctx.JSON(http.StatusAccepted, &restdto.Result{
		GUID:      guid,
		Object:    definitions.CatCache,
		Operation: definitions.ServFlush + "_async",
		Result: gin.H{
			"jobId":  jobID,
			"status": jobStatusQueued,
		},
	})
}

// HandleBruteForceRuleFlushAsync enqueues a brute-force flush job and returns 202 with jobId.
func HandleBruteForceRuleFlushAsync(ctx *gin.Context) {
	guid := ctx.GetString(definitions.CtxGUIDKey)
	ipCmd := &bf.FlushRuleCmd{}

	if err := ctx.ShouldBindJSON(ipCmd); err != nil {
		HandleJSONError(ctx, err)

		return
	}

	jobID, err := createAsyncJob(ctx.Request.Context(), "BF_FLUSH")
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	asyncStarter(jobID, guid, func(base context.Context) (int, []string, error) {
		gctx := &gin.Context{}
		gctx.Request = ctx.Request.Clone(base)
		_, removed, err := processBruteForceRules(gctx, ipCmd, guid)

		return len(removed), removed, err
	})

	ctx.JSON(http.StatusAccepted, &restdto.Result{
		GUID:      guid,
		Object:    definitions.CatBruteForce,
		Operation: definitions.ServFlush + "_async",
		Result: gin.H{
			"jobId":  jobID,
			"status": jobStatusQueued,
		},
	})
}

// deleteKeyIfExists checks if a Redis key exists, deletes it if present, and returns the key or error if any occurs.
func deleteKeyIfExists(ctx context.Context, key string, guid string) (string, error) {
	// Single roundtrip: prefer UNLINK to avoid blocking Redis server threads on large keys
	stats.GetMetrics().GetRedisWriteCounter().Inc()

	result, err := rediscli.GetClient().GetWriteHandle().Unlink(ctx, key).Result()
	if err != nil {
		return "", err
	}

	if result > 0 {
		level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, "key", key, "status", "flushed")

		return key, nil
	}

	return "", nil
}

// bulkUnlink removes all provided keys using a single write pipeline with UNLINK.
// Returns the subset of keys that were actually removed.
func bulkUnlink(ctx context.Context, guid string, keys []string) ([]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}

	// Count a single write operation for the whole pipeline
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	cmds, err := rediscli.ExecuteWritePipeline(ctx, func(pipe redis.Pipeliner) error {
		for _, k := range keys {
			pipe.Unlink(ctx, k)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	removed := make([]string, 0, len(keys))
	for i, k := range keys {
		if i < len(cmds) {
			if intCmd, ok := cmds[i].(*redis.IntCmd); ok {
				if n, _ := intCmd.Result(); n > 0 {
					removed = append(removed, k)

					level.Info(log.Logger).Log(definitions.LogKeyGUID, guid, "key", k, "status", "flushed")
				}
			}
		}
	}

	return removed, nil
}

// createBucketManager creates a new bucket manager with the given parameters.
func createBucketManager(ctx context.Context, guid string, ipAddress string, protocol string, oidcCID string) bruteforce.BucketManager {
	var bm bruteforce.BucketManager

	bm = bruteforce.NewBucketManager(ctx, guid, ipAddress)

	// Set the protocol if specified
	if protocol != "" {
		bm = bm.WithProtocol(protocol)
	}

	// Set the OIDC Client ID if specified
	if oidcCID != "" {
		bm = bm.WithOIDCCID(oidcCID)
	}

	return bm
}

// isRuleApplicable determines if a brute force rule is applicable based on IP version and rule name criteria.
func isRuleApplicable(r config.BruteForceRule, isIPv4 bool, cmd *bf.FlushRuleCmd) bool {
	if r.IPv4 != isIPv4 {
		return false
	}

	return cmd.RuleName == "*" || r.Name == cmd.RuleName
}

// iterateCombinations processes combinations of protocols and OIDC Client IDs defined in a brute force rule.
// It iterates through the Cartesian product of protocol and OIDC CID filters, applying the rule's logic.
// If no protocol filters are set, it iterates only through OIDC CIDs as a fallback.
// Adds a final safety net to ensure every protocol in the configuration file is processed.
// Returns a slice of removed entries and an error if any issues occur.
func iterateCombinations(ctx *gin.Context, guid string, cmd *bf.FlushRuleCmd, rule *config.BruteForceRule, removed []string) ([]string, error) {
	// 1) Cartesian product of FilterByProtocol × FilterByOIDCCID
	for _, proto := range rule.FilterByProtocol {
		oidcCids := rule.FilterByOIDCCID
		if len(oidcCids) == 0 {
			oidcCids = []string{""} // protocol-only variant
		}

		for _, cid := range oidcCids {
			bm := createBucketManager(ctx.Request.Context(), guid, cmd.IPAddress, proto, cid)

			var err error
			if removed, err = flushForBucket(ctx, bm, rule, cmd.RuleName, removed); err != nil {
				return removed, err
			}
		}
	}

	// 2) OIDC-CID only (when no protocol filters are present)
	if len(rule.FilterByProtocol) == 0 {
		for _, cid := range rule.FilterByOIDCCID {
			bm := createBucketManager(ctx.Request.Context(), guid, cmd.IPAddress, "", cid)

			var err error
			if removed, err = flushForBucket(ctx, bm, rule, cmd.RuleName, removed); err != nil {
				return removed, err
			}
		}
	}

	// 3) Safety net: iterate over every configured protocol
	for _, proto := range config.GetFile().GetAllProtocols() {
		bm := createBucketManager(ctx.Request.Context(), guid, cmd.IPAddress, proto, "")

		var err error
		if removed, err = flushForBucket(ctx, bm, rule, cmd.RuleName, removed); err != nil {
			return removed, err
		}
	}

	return removed, nil
}

// flushForBucket deletes brute force data for a specific rule and updates the list of removed keys. Returns updated keys and error.
func flushForBucket(ctx *gin.Context, bm bruteforce.BucketManager, rule *config.BruteForceRule, ruleName string, removed []string) ([]string, error) {
	if key, err := bm.DeleteIPBruteForceRedis(rule, ruleName); err != nil {
		return removed, err
	} else if key != "" {
		removed = append(removed, key)
	}

	if bucketKey := bm.GetBruteForceBucketRedisKey(rule); bucketKey != "" {
		var err error
		if removed, err = flushKey(ctx, bucketKey, bm.GetBruteForceName(), removed); err != nil {
			return removed, err
		}
	}

	return removed, nil
}

// flushKey deletes a Redis key if it exists, appends the removed key to a list, and returns the updated list with an error if any.
func flushKey(ctx *gin.Context, key string, guid string, removed []string) ([]string, error) {
	if rm, err := deleteKeyIfExists(ctx.Request.Context(), key, guid); err != nil {
		return removed, err
	} else if rm != "" {
		removed = append(removed, rm)
	}

	return removed, nil
}

// processBruteForceRules processes and flushes brute force rules based on the provided command and context.
// It evaluates rule applicability, flushes matched rules, and removes derived and tolerable combinations.
func processBruteForceRules(ctx *gin.Context, cmd *bf.FlushRuleCmd, guid string) (hadError bool, removed []string, err error) {
	var trSuffixes = []string{":P", ":N"}

	// Detect address family once – saves many To4() calls later
	ip := net.ParseIP(cmd.IPAddress)
	isIPv4 := ip.To4() != nil

	// Phase 1: pre-filter rules that could possibly match
	for _, rule := range config.GetFile().GetBruteForceRules() {
		if !isRuleApplicable(rule, isIPv4, cmd) {
			continue
		}

		// Phase 2: flush the exact combination given by the user
		bm := createBucketManager(ctx.Request.Context(), guid, cmd.IPAddress, cmd.Protocol, cmd.OIDCCID)
		if removed, err = flushForBucket(ctx, bm, &rule, cmd.RuleName, removed); err != nil {
			return true, removed, err
		}

		// Phase 3: flush all derived combinations (rule filters + safety net)
		if removed, err = iterateCombinations(ctx, guid, cmd, &rule, removed); err != nil {
			return true, removed, err
		}
	}

	// Phase 4: always drop tolerate-bucket keys for the IP using a single pipeline
	base := config.GetFile().GetServer().GetRedis().GetPrefix() + "bf:TR:" + cmd.IPAddress
	keys := make([]string, 0, 1+len(trSuffixes))
	keys = append(keys, base)

	for _, s := range trSuffixes {
		keys = append(keys, base+s)
	}

	if removedTr, berr := bulkUnlink(ctx.Request.Context(), guid, keys); berr != nil {
		return true, removed, berr
	} else if len(removedTr) > 0 {
		removed = append(removed, removedTr...)
	}

	return false, removed, nil
}

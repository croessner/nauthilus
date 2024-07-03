package core

import (
	"context"
	"errors"
	"net/http"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib/callback"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/redis/go-redis/v9"
)

// For a brief documentation of this file please have a look at the Markdown document REST-API.md.

// FlushUserCmdStatus represents an user's command status.
type FlushUserCmdStatus struct {
	// User holds the identifier of a user.
	User string `json:"user"`

	// Status represents the status of the user's command.
	Status string `json:"status"`
}

// FlushUserCmd is a data structure used to handle user commands for flushing data.
type FlushUserCmd struct {
	// User is the field representing the name of the user to be flushed.
	User string `json:"user"`
}

// FlushRuleCmdStatus is a structure representing the status of a Flush Rule command
type FlushRuleCmdStatus struct {
	// IPAddress is the IP address that the rule was applied to
	IPAddress string `json:"ip_address"`

	// RuleName is the name of the rule that was flushed
	RuleName string `json:"rule_name"`

	// Status is the current status of the rule following the Flush Command
	Status string `json:"status"`
}

// FlushRuleCmd represents a command to flush a specific rule.
// It contains the necessary information needed to identify the rule to be flushed.
type FlushRuleCmd struct {
	// IPAddress is the IP address associated with the rule to be flushed.
	// It must be in a format valid for an IP address.
	IPAddress string `json:"ip_address"`

	// RuleName is the name of the rule to be flushed.
	// This value should reference an existing rule.
	RuleName string `json:"rule_name"`
}

// generic handles the generic authentication logic based on the selected service type.
func (a *Authentication) generic(ctx *gin.Context) {
	var mode string

	if a.Service == global.ServBasicAuth {
		var httpBasicAuthOk bool

		// Decode HTTP basic Auth
		a.Username, a.Password, httpBasicAuthOk = ctx.Request.BasicAuth()
		if !httpBasicAuthOk {
			ctx.Header("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			ctx.AbortWithError(http.StatusUnauthorized, errors2.ErrUnauthorized)

			return
		}

		a.UsernameOrig = a.Username
	}

	if a.ListAccounts {
		allAccountsList := a.listUserAccounts()

		for _, account := range allAccountsList {
			ctx.Data(http.StatusOK, "text/plain", []byte(account+"\r\n"))
		}

		level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyMode, mode)
	} else {
		if !(a.NoAuth || ctx.GetBool(global.CtxLocalCacheAuthKey)) {
			//nolint:exhaustive // Ignore some results
			switch a.handleFeatures(ctx) {
			case global.AuthResultFeatureTLS:
				a.postLuaAction(&PassDBResult{})
				a.authTempFail(ctx, global.TempFailNoTLS)

				return
			case global.AuthResultFeatureRelayDomain, global.AuthResultFeatureRBL, global.AuthResultFeatureLua:
				a.postLuaAction(&PassDBResult{})
				a.authFail(ctx)

				return
			case global.AuthResultUnset:
			case global.AuthResultOK:
			case global.AuthResultFail:
			case global.AuthResultTempFail:
			case global.AuthResultEmptyUsername:
			case global.AuthResultEmptyPassword:
			}
		}

		//nolint:exhaustive // Ignore some results
		switch a.handlePassword(ctx) {
		case global.AuthResultOK:
			a.authOK(ctx)
		case global.AuthResultFail:
			a.authFail(ctx)
		case global.AuthResultTempFail:
			a.authTempFail(ctx, global.TempFailDefault)
		case global.AuthResultEmptyUsername:
			a.authTempFail(ctx, global.TempFailEmptyUser)
		case global.AuthResultEmptyPassword:
			a.authFail(ctx)
		case global.AuthResultUnset:
		case global.AuthResultFeatureRBL:
		case global.AuthResultFeatureTLS:
		case global.AuthResultFeatureRelayDomain:
		case global.AuthResultFeatureLua:
		}
	}
}

// saslAuthd handles the authentication logic for the saslAuthd service.
func (a *Authentication) saslAuthd(ctx *gin.Context) {
	switch a.handlePassword(ctx) {
	case global.AuthResultOK:
		a.authOK(ctx)
	case global.AuthResultFail:
		a.authFail(ctx)
	case global.AuthResultTempFail:
		a.authTempFail(ctx, global.TempFailDefault)
	case global.AuthResultEmptyUsername:
		a.authTempFail(ctx, global.TempFailEmptyUser)
	case global.AuthResultEmptyPassword:
		a.authFail(ctx)
	case global.AuthResultUnset:
	case global.AuthResultFeatureRBL:
	case global.AuthResultFeatureTLS:
	case global.AuthResultFeatureRelayDomain:
	case global.AuthResultFeatureLua:
	}
}

// callback handles the execution of a Lua callback request in a Gin context.
func (a *Authentication) callback(ctx *gin.Context) {
	callback.RunCallbackLuaRequest(ctx)
}

// healthCheck handles the health check functionality by logging a message and returning "pong" as the response.
func healthCheck(ctx *gin.Context) {
	level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, ctx.GetString(global.CtxGUIDKey), global.LogKeyMsg, "Health check")

	ctx.String(http.StatusOK, "pong")
}

// listBruteforce handles the retrieval of brute force IP addresses and errors.
// It fetches the previously stored IP addresses from a Redis hash, storing them in a List struct.
// If there is an error during the retrieval, the error message is stored in the List struct as well.
// The List struct is then returned as JSON in the response.
func listBruteforce(ctx *gin.Context) {
	//nolint:tagliatelle // We want lower camel case
	type List struct {
		IPAddresses map[string]string `json:"ip_addresses"`
		Error       string            `json:"error"`
	}

	guid := ctx.GetString(global.CtxGUIDKey)
	httpStatusCode := http.StatusOK
	list := &List{}
	key := config.LoadableConfig.Server.Redis.Prefix + global.RedisBruteForceHashKey

	result, err := rediscli.ReadHandle.HGetAll(context.Background(), key).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)

			httpStatusCode = http.StatusInternalServerError
			list.Error = err.Error()
		} else {
			list.Error = "none"

			stats.RedisReadCounter.Inc()
		}
	} else {
		level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, global.LogKeyMsg, global.ServList)

		list.IPAddresses = result
		list.Error = "none"
	}

	ctx.JSON(httpStatusCode, &RESTResult{
		GUID:      guid,
		Object:    global.CatBruteForce,
		Operation: global.ServList,
		Result:    list,
	})
}

// flushCache is a handler function for a Gin HTTP server. It takes a gin.Context as a parameter
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
func flushCache(ctx *gin.Context) {
	guid := ctx.GetString(global.CtxGUIDKey)
	userCmd := &FlushUserCmd{}

	level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, global.CatCache, global.ServFlush)

	if err := ctx.BindJSON(userCmd); err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	cacheFlushError, useCache := processFlushCache(userCmd, guid)

	statusMsg := "flushed"
	if cacheFlushError {
		statusMsg = "not flushed"
	}

	sendCacheStatus(ctx, guid, userCmd, useCache, statusMsg)
}

// processFlushCache takes a user command and a GUID and processes the cache flush.
// It iterates through the backends in the LoadableConfig and checks if the backend is BackendCache.
// If it is, it sets useCache to true and calls processUserCmd to process the user command.
// If there is an error during the cache flush, cacheFlushError is set to true and the loop breaks.
// It returns cacheFlushError and useCache flags.
func processFlushCache(userCmd *FlushUserCmd, guid string) (cacheFlushError bool, useCache bool) {
	for _, backendType := range config.LoadableConfig.Server.Backends {
		if backendType.Get() != global.BackendCache {
			continue
		}

		useCache = true

		cacheFlushError = processUserCmd(userCmd, guid)
		if cacheFlushError {
			break
		}
	}

	return cacheFlushError, useCache
}

// processUserCmd processes the user command by performing the following steps:
// 1. Calls the setupCacheFlush function to set up the cache flush and retrieve the account name, removeHash flag, and cacheFlushError flag.
// 2. If cacheFlushError is true, returns true immediately.
// 3. Calls the setUserKeys function to set the user keys using the user command and account name.
// 4. Calls the removeUserFromCache function to remove the user from the cache by providing the user command, user keys, guid, and removeHash flag.
// 5. Returns false.
func processUserCmd(userCmd *FlushUserCmd, guid string) bool {
	accountName, removeHash, cacheFlushError := setupCacheFlush(userCmd)
	if cacheFlushError {
		return true
	}

	userKeys := setUserKeys(userCmd, accountName)

	removeUserFromCache(userCmd, userKeys, guid, removeHash)

	return false
}

// setupCacheFlush handles the caching flush logic based on the provided user command.
// It checks if the user command is a wildcard ("*"), in which case it returns "*", true, false.
// If the user command is not a wildcard, it looks up the user account name using the backend.LookupUserAccountFromRedis function.
// If there is an error during the lookup or the account name is empty, it returns "", false, true.
// Otherwise, it returns the account name, false, false.
//
// Example usage:
//
//	userCmd := &FlushUserCmd{
//		User: "john.doe",
//	}
//	accountName, removeHash, cacheFlushError := setupCacheFlush(userCmd)
//	if cacheFlushError {
//		// WriteHandle cache flush error
//	}
//	// Continue with cache flushing logic
//
// Note: The `FlushUserCmd` type is defined as follows:
//
//	type FlushUserCmd struct {
//		User string `json:"user"`
//	}
//
// Note: The `backend.LookupUserAccountFromRedis` function is defined as follows:
//
//	func LookupUserAccountFromRedis(username string) (accountName string, err error) {
//		// ...
//	}
func setupCacheFlush(userCmd *FlushUserCmd) (string, bool, bool) {
	if userCmd.User == "*" {
		return "*", true, false
	}

	accountName, err := backend.LookupUserAccountFromRedis(userCmd.User)
	if err != nil || accountName == "" {
		if err == nil {
			stats.RedisReadCounter.Inc()
		}

		return "", false, true
	}

	stats.RedisReadCounter.Inc()

	return accountName, false, false
}

// setUserKeys populates a string set with user keys based on the given FlushUserCmd and accountName.
// The function creates a new empty string set using the NewStringSet function from the config package.
// It then sets two keys in the string set: one is a concatenation of the RedisPrefix constant from the config package,
// "ucp:__default__:", and the accountName parameter. The other key is a concatenation of the RedisPrefix constant,
// the RedisPwHashKey constant from the global package, ":", the User field from the userCmd parameter, and ":*".
// Next, it iterates over the protocols obtained from the LoadableConfig.GetAllProtocols function from the config package.
// For each protocol, it retrieves the cache names using the backend.GetCacheNames function from the backend package,
// passing the protocol and the global.CacheAll constant. For each cache name, it sets a key in the string set
// by concatenating the RedisPrefix constant, "ucp:", the cache name, ":", and the accountName parameter.
// Finally, the function returns the populated string set.
func setUserKeys(userCmd *FlushUserCmd, accountName string) config.StringSet {
	userKeys := config.NewStringSet()

	userKeys.Set(config.LoadableConfig.Server.Redis.Prefix + "ucp:__default__:" + accountName)
	userKeys.Set(config.LoadableConfig.Server.Redis.Prefix + global.RedisPwHashKey + ":" + userCmd.User + ":*")

	protocols := config.LoadableConfig.GetAllProtocols()
	for index := range protocols {
		cacheNames := backend.GetCacheNames(protocols[index], global.CacheAll)
		for _, cacheName := range cacheNames.GetStringSlice() {
			userKeys.Set(config.LoadableConfig.Server.Redis.Prefix + "ucp:" + cacheName + ":" + accountName)
		}
	}

	return userKeys
}

// removeUserFromCache removes a user from the cache based on the given parameters.
// If removeHash is true, it deletes the entire Redis hash map associated with the user.
// Otherwise, it only removes the specific user key from the hash map.
// It also deletes other user keys stored in the userKeys string set.
// If any error occurs during the removal process, it logs the error and immediately returns.
// After successful removal, it logs the keys that have been flushed.
func removeUserFromCache(userCmd *FlushUserCmd, userKeys config.StringSet, guid string, removeHash bool) {
	var err error

	redisKey := config.LoadableConfig.Server.Redis.Prefix + global.RedisUserHashKey

	if removeHash {
		err = rediscli.WriteHandle.Del(context.Background(), redisKey).Err()
	} else {
		err = rediscli.WriteHandle.HDel(context.Background(), redisKey, userCmd.User).Err()
	}

	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)

		return
	}

	stats.RedisWriteCounter.Inc()

	for _, userKey := range userKeys.GetStringSlice() {
		if _, err = rediscli.WriteHandle.Del(context.Background(), userKey).Result(); err != nil {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)

			return
		}

		stats.RedisWriteCounter.Inc()

		level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, "keys", userKey, "status", "flushed")
	}
}

// sendCacheStatus is a function that sends the cache status as a response to the client.
// If the useCache parameter is true, it sends a JSON response with the cache status message and the user command details.
// If useCache is false, it sends a JSON response with an error message indicating that the cache backend is not enabled.
//
// Parameters:
// - ctx: The gin.Context object representing the HTTP request and response context.
// - guid: The GUID string associated with the request.
// - userCmd: A pointer to a FlushUserCmd object containing user command details.
// - useCache: A boolean indicating whether the cache backend is enabled or not.
// - statusMsg: The status message to be included in the response.
//
// Example usage:
//
//	func flushCache(ctx *gin.Context) {
//	   guid := ctx.GetString(global.CtxGUIDKey)
//	   userCmd := &FlushUserCmd{}
//
//	   level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, global.CatCache, global.ServFlush)
//
//	   if err := ctx.BindJSON(userCmd); err != nil {
//	       level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)
//	       ctx.AbortWithStatus(http.StatusBadRequest)
//	       return
//	   }
//
//	   cacheFlushError, useCache := processFlushCache(userCmd, guid)
//
//	   statusMsg := "flushed"
//	   if cacheFlushError {
//	       statusMsg = "not flushed"
//	   }
//
//	   sendCacheStatus(ctx, guid, userCmd, useCache, statusMsg)
//	}
func sendCacheStatus(ctx *gin.Context, guid string, userCmd *FlushUserCmd, useCache bool, statusMsg string) {
	if useCache {
		level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, global.LogKeyMsg, statusMsg)

		ctx.JSON(http.StatusOK, &RESTResult{
			GUID:      guid,
			Object:    global.CatCache,
			Operation: global.ServFlush,
			Result: &FlushUserCmdStatus{
				User:   userCmd.User,
				Status: statusMsg,
			},
		})
	} else {
		msg := "Cache backend not enabled"

		level.Warn(logging.DefaultLogger).Log(global.LogKeyGUID, guid, global.LogKeyMsg, msg)

		ctx.JSON(http.StatusInternalServerError, &RESTResult{
			GUID:      guid,
			Object:    global.CatCache,
			Operation: global.ServFlush,
			Result:    msg,
		})
	}
}

// flushBruteForceRule handles the flushing of a brute force rule by processing the provided IP command and updating the necessary data.
// It logs information about the action, including the GUID, brute force category, and flush operation.
// If the IP command fails to bind, an error is logged, and a bad request status is returned.
// If there is an error processing the brute force rules, an error is logged, and an internal server error status is returned.
// If the rule flush error flag is true, the status message is set to "not flushed".
// The function then logs the status message and returns a JSON response containing the GUID, brute force category, flush operation, and the result of the command, including the IP address
func flushBruteForceRule(ctx *gin.Context) {
	var (
		ruleFlushError bool
		err            error
	)

	guid := ctx.GetString(global.CtxGUIDKey)
	statusMsg := "flushed"

	level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, global.CatBruteForce, global.ServFlush)

	ipCmd := &FlushRuleCmd{}

	if err = ctx.BindJSON(ipCmd); err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, "ip_address", ipCmd.IPAddress)

	ruleFlushError, err = processBruteForceRules(ctx, ipCmd, guid)
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	if ruleFlushError {
		statusMsg = "not flushed"
	}

	level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, global.LogKeyMsg, statusMsg)

	ctx.JSON(http.StatusOK, &RESTResult{
		GUID:      guid,
		Object:    global.CatBruteForce,
		Operation: global.ServFlush,
		Result: &FlushRuleCmdStatus{
			IPAddress: ipCmd.IPAddress,
			RuleName:  ipCmd.RuleName,
			Status:    statusMsg,
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
func processBruteForceRules(ctx *gin.Context, ipCmd *FlushRuleCmd, guid string) (bool, error) {
	var err error

	ruleFlushError := false

	auth := &Authentication{
		HTTPClientContext: ctx.Copy(),
		Username:          "*",
		ClientIP:          ipCmd.IPAddress,
	}

	for _, rule := range config.LoadableConfig.GetBruteForceRules() {
		if rule.Name == ipCmd.RuleName || ipCmd.RuleName == "*" {
			if err = auth.deleteIPBruteForceRedis(&rule, ipCmd.RuleName); err != nil {
				ruleFlushError = true

				return ruleFlushError, err
			}
			if key := auth.getBruteForceBucketRedisKey(&rule); key != "" {
				if err = rediscli.WriteHandle.Del(context.Background(), key).Err(); err != nil {
					ruleFlushError = true

					return ruleFlushError, err
				}

				stats.RedisWriteCounter.Inc()

				level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, "key", key, "status", "flushed")
			}
		}
	}

	return ruleFlushError, nil
}

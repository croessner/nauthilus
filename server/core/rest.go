package core

import (
	"errors"
	"net/http"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/go-redis/redis/v8"
)

// For a brief documentation of this file please have a look at the Markdown document REST-API.md.

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
		if !a.NoAuth {
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

// healthCheck handles the health check functionality by logging a message and returning "pong" as the response.
func healthCheck(ctx *gin.Context) {
	level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, ctx.Value(global.GUIDKey).(string), global.LogKeyMsg, "Health check")

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

	guid := ctx.Value(global.GUIDKey).(string)
	httpStatusCode := http.StatusOK
	list := &List{}
	key := config.EnvConfig.RedisPrefix + global.RedisBruteForceHashKey

	result, err := backend.RedisHandleReplica.HGetAll(backend.RedisHandleReplica.Context(), key).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)

			httpStatusCode = http.StatusInternalServerError
			list.Error = err.Error()
		} else {
			list.Error = "none"
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

//nolint:gocognit // Ignore
func flushCache(ctx *gin.Context) {
	type FlushUserCmdStatus struct {
		User   string `json:"user"`
		Status string `json:"status"`
	}

	type FlushUserCmd struct {
		User string `json:"user"`
	}

	var (
		cacheFlushError bool
		useCache        bool
		removeHash      bool
		accountName     string
		protocols       []string
		err             error
	)

	guid := ctx.Value(global.GUIDKey).(string)
	userKeys := config.NewStringSet()
	statusMsg := "flushed"
	userCmd := &FlushUserCmd{}

	level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, global.CatCache, global.ServFlush)

	if err = ctx.BindJSON(userCmd); err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	for _, passDB := range config.EnvConfig.PassDBs {
		if passDB.Get() != global.BackendCache {
			continue
		}

		useCache = true

		level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, "user", userCmd.User)

		if userCmd.User == "*" {
			accountName = "*"
			removeHash = true
		} else {
			accountName, err = backend.LookupUserAccountFromRedis(userCmd.User)
			if err != nil {
				cacheFlushError = true

				break
			}

			// User not known in positive password cache. Fallback to requested address.
			if accountName == "" {
				accountName = userCmd.User
			}
		}

		// Make sure that the requested address was not empty.
		if accountName == "" {
			cacheFlushError = true

			break
		}

		userKeys.Set(config.EnvConfig.RedisPrefix + "ucp:__default__:" + accountName)
		userKeys.Set(config.EnvConfig.RedisPrefix + global.RedisPwHashKey + ":" + userCmd.User + ":*")

		protocols = config.LoadableConfig.GetAllProtocols()

		for index := range protocols {
			cacheNames := backend.GetCacheNames(protocols[index], global.CacheAll)

			for _, cacheName := range cacheNames.GetStringSlice() {
				userKeys.Set(config.EnvConfig.RedisPrefix + "ucp:" + cacheName + ":" + accountName)
			}
		}

		// Remove user from hash map.
		redisKey := config.EnvConfig.RedisPrefix + global.RedisUserHashKey

		if removeHash {
			// User command is a wildcard.
			if err = backend.RedisHandle.Del(backend.RedisHandle.Context(), redisKey).Err(); err != nil {
				level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)

				cacheFlushError = true

				break
			}
		} else if err = backend.RedisHandle.HDel(backend.RedisHandle.Context(), redisKey, userCmd.User).Err(); err != nil {
			// User command is a specific user.
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)

			cacheFlushError = true

			break
		}

		// Remove user associated object from ucp-namespace(s).
		for _, userKey := range userKeys.GetStringSlice() {
			if _, err = backend.RedisHandle.Del(backend.RedisHandle.Context(), userKey).Result(); err != nil {
				level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)

				cacheFlushError = true

				break
			}

			level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, "keys", userKey, "status", "flushed")
		}

		break
	}

	if cacheFlushError {
		statusMsg = "not flushed"
	}

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

//nolint:gocognit // Ignore
func flushBruteForceRule(ctx *gin.Context) {
	//nolint:tagliatelle // We want lower camel case
	type FlushRuleCmdStatus struct {
		IPAddress string `json:"ip_address"`
		RuleName  string `json:"rule_name"`
		Status    string `json:"status"`
	}

	//nolint:tagliatelle // We want lower camel case
	type FlushRuleCmd struct {
		IPAddress string `json:"ip_address"`
		RuleName  string `json:"rule_name"`
	}

	var (
		ruleFlushError bool
		err            error
	)

	guid := ctx.Value(global.GUIDKey).(string)
	statusMsg := "flushed"

	level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, global.CatBruteForce, global.ServFlush)

	ipCmd := &FlushRuleCmd{}
	if err = ctx.BindJSON(ipCmd); err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, "ip_address", ipCmd.IPAddress)

	auth := &Authentication{
		HTTPClientContext: ctx,
		Username:          "*",
		ClientIP:          ipCmd.IPAddress,
	}

	for _, rule := range config.LoadableConfig.GetBruteForceRules() {
		if rule.Name == ipCmd.RuleName || ipCmd.RuleName == "*" {
			if err = auth.deleteIPBruteForceRedis(&rule, ipCmd.RuleName); err != nil {
				ruleFlushError = true

				break
			}

			if key := auth.getBruteForceBucketRedisKey(&rule); key != "" {
				if err = backend.RedisHandle.Del(backend.RedisHandle.Context(), key).Err(); err != nil {
					level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)

					ruleFlushError = true

					break
				}

				level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, guid, "key", key, "status", "flushed")
			}
		}
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

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
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/ipscoper"
	"github.com/croessner/nauthilus/server/log/level"
	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	"github.com/croessner/nauthilus/server/middleware/oidcbearer"
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

// TokenFlusher abstracts the ability to flush all OIDC/SAML2 tokens for a user.
// It is implemented by idp.RedisTokenStorage and injected into restAdminDeps to
// avoid a cyclic import between core and idp.
type TokenFlusher interface {
	FlushUserTokens(ctx context.Context, userID string) error
}

type restAdminDeps struct {
	Cfg          config.File
	Logger       *slog.Logger
	Redis        rediscli.Client
	Channel      backend.Channel
	TokenFlusher TokenFlusher
}

const bruteForceBanScanCount int64 = 500

func (deps restAdminDeps) effectiveLogger() *slog.Logger {
	return deps.Logger
}

func (deps restAdminDeps) effectiveCfg() config.File {
	return deps.Cfg
}

func (deps restAdminDeps) effectiveRedis() rediscli.Client {
	return deps.Redis
}

// NewBruteForceListHandler constructs a Gin handler for the BruteForce list endpoint
// using injected dependencies.
func NewBruteForceListHandler(cfg config.File, logger *slog.Logger, redisClient rediscli.Client) gin.HandlerFunc {
	deps := restAdminDeps{Cfg: cfg, Logger: logger, Redis: redisClient}

	return func(ctx *gin.Context) {
		if err := deps.validate(); err != nil {
			ctx.AbortWithStatus(http.StatusInternalServerError)

			return
		}

		handleBruteForceList(ctx, deps)
	}
}

// NewBruteForceFlushHandler constructs a Gin handler for the BruteForce flush endpoint
// using injected dependencies.
func NewBruteForceFlushHandler(cfg config.File, logger *slog.Logger, redisClient rediscli.Client) gin.HandlerFunc {
	deps := restAdminDeps{Cfg: cfg, Logger: logger, Redis: redisClient}

	return func(ctx *gin.Context) {
		deps.HandleBruteForceFlush(ctx)
	}
}

// NewBruteForceFlushAsyncHandler constructs a Gin handler for the BruteForce flush async endpoint
// using injected dependencies.
func NewBruteForceFlushAsyncHandler(cfg config.File, logger *slog.Logger, redisClient rediscli.Client) gin.HandlerFunc {
	deps := restAdminDeps{Cfg: cfg, Logger: logger, Redis: redisClient}

	return func(ctx *gin.Context) {
		deps.HandleBruteForceRuleFlushAsync(ctx)
	}
}

// NewConfigLoadHandler constructs a Gin handler for the config load endpoint
// using injected dependencies.
func NewConfigLoadHandler(cfg config.File, logger *slog.Logger, redisClient rediscli.Client) gin.HandlerFunc {
	deps := restAdminDeps{Cfg: cfg, Logger: logger, Redis: redisClient}

	return func(ctx *gin.Context) {
		deps.HandleConfigLoad(ctx)
	}
}

// For brief documentation of this file please have a look at the Markdown document REST-API.md.

func (a *AuthState) handleMasterUserMode() string {
	cfg := a.deps.Cfg
	if !cfg.GetServer().GetMasterUser().IsEnabled() {
		return a.Request.Username
	}

	delimiter := cfg.GetServer().GetMasterUser().GetDelimiter()
	if delimiter == "" {
		return a.Request.Username
	}

	left, right, ok := strings.Cut(a.Request.Username, delimiter)
	if !ok {
		return a.Request.Username
	}

	if left == "" || right == "" || strings.Contains(right, delimiter) {
		return a.Request.Username
	}

	if a.Runtime.MasterUserMode {
		a.Runtime.MasterUserMode = false

		// Return real user
		return left
	}

	a.Runtime.MasterUserMode = true

	// Return master user
	return right
}

// HandleAuthentication handles the authentication logic based on the selected service type.
func (a *AuthState) HandleAuthentication(ctx *gin.Context) {
	if a.Request.ListAccounts {
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

		level.Info(a.logger()).Log(definitions.LogKeyGUID, a.Runtime.GUID, definitions.LogKeyMode, ctx.Query("mode"))
	} else {
		if abort := a.ProcessFeatures(ctx); !abort {
			a.ProcessAuthentication(ctx)
		}
	}
}

// ProcessFeatures handles the processing of authentication-related features for a given context.
// It determines the action to take based on various authentication results and applies the necessary response.
func (a *AuthState) ProcessFeatures(ctx *gin.Context) (abort bool) {
	if a.Request.Service == definitions.ServBasic {
		var httpBasicAuthOk bool

		// Decode HTTP basic Auth
		a.Request.Username, a.Request.Password, httpBasicAuthOk = ctx.Request.BasicAuth()
		if !httpBasicAuthOk {
			ctx.Header("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			ctx.AbortWithError(http.StatusUnauthorized, errors.ErrUnauthorized)

			return true
		}

		if a.Request.Username == "" {
			ctx.Error(errors.ErrEmptyUsername)
		} else if !util.ValidateUsername(a.Request.Username) {
			ctx.Error(errors.ErrInvalidUsername)
		}

		if a.Request.Password == "" {
			ctx.Error(errors.ErrEmptyPassword)
		}
	}

	if a.Request.Service == definitions.ServIdP {
		a.handleMasterUserMode()
	}

	if !a.Request.NoAuth && !ctx.GetBool(definitions.CtxLocalCacheAuthKey) {
		switch a.HandleFeatures(ctx) {
		case definitions.AuthResultFeatureTLS:
			result := GetPassDBResultFromPool()
			a.PostLuaAction(ctx, result)
			PutPassDBResultToPool(result)
			a.AuthTempFail(ctx, definitions.TempFailNoTLS)
			ctx.Abort()

			return true
		case definitions.AuthResultFeatureRelayDomain, definitions.AuthResultFeatureRBL, definitions.AuthResultFeatureLua:
			result := GetPassDBResultFromPool()
			a.PostLuaAction(ctx, result)
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
			ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)

			return true
		}
	}

	return false
}

// ProcessAuthentication handles the authentication logic for all services.
func (a *AuthState) ProcessAuthentication(ctx *gin.Context) {
	if a.Request.Service == definitions.ServBasic {
		var httpBasicAuthOk bool

		if a.deps.Cfg.GetServer().GetBasicAuth().IsEnabled() {
			if a.deps.Cfg.GetServer().GetLog().GetLogLevel() >= definitions.LogLevelDebug {
				level.Debug(a.deps.Logger).Log(
					definitions.LogKeyGUID, a.Runtime.GUID,
					definitions.LogKeyUsername, a.Request.Username,
					definitions.LogKeyMsg, "Processing HTTP Basic Auth",
				)
			}

			httpBasicAuthOk = mdauth.CheckAndRequireBasicAuth(ctx, a.deps.Cfg)
		} else {
			httpBasicAuthOk = true
		}

		if httpBasicAuthOk {
			a.AuthOK(ctx)
		}

		return
	}

	if a.Request.Service == definitions.ServIdP {
		a.handleMasterUserMode()
	}

	switch a.HandlePassword(ctx) {
	case definitions.AuthResultOK:
		if a.deps.Tolerate != nil {
			a.deps.Tolerate.SetIPAddress(a.Ctx(), a.Request.ClientIP, a.Request.Username, true)
		}
		a.AuthOK(ctx)
	case definitions.AuthResultFail:
		if a.deps.Tolerate != nil {
			a.deps.Tolerate.SetIPAddress(a.Ctx(), a.Request.ClientIP, a.Request.Username, false)
		}
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
		ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)
	}
}

// listBlockedIPAddresses retrieves a list of blocked IP addresses from Redis using the
// sharded ZSET ban index and per-network ban keys with TTL.
func listBlockedIPAddresses(ctx context.Context, deps restAdminDeps, filterCmd *bf.FilterCmd, guid string) (*bf.BlockedIPAddresses, error) {
	blockedIPAddresses := &bf.BlockedIPAddresses{}

	if deps.Cfg == nil {
		err := stderrors.New("config is nil")
		errMsg := err.Error()
		blockedIPAddresses.Error = &errMsg

		return blockedIPAddresses, err
	}

	if deps.Redis == nil {
		err := stderrors.New("redis client is nil")
		errMsg := err.Error()
		blockedIPAddresses.Error = &errMsg

		return blockedIPAddresses, err
	}

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	logger := deps.effectiveLogger()
	cfg := deps.effectiveCfg()
	prefix := cfg.GetServer().GetRedis().GetPrefix()

	// Build a lookup map: bucket name → configured ban time
	ruleMap := make(map[string]time.Duration)
	if bfCfg := cfg.GetBruteForce(); bfCfg != nil {
		for i := range bfCfg.Buckets {
			ruleMap[bfCfg.Buckets[i].Name] = bfCfg.Buckets[i].GetBanTime()
		}
	}

	// Step 1: Query all 16 ZSET shards via pipeline
	indexKeys := rediscli.GetAllBruteForceBanIndexKeys(prefix)

	dCtxR, cancelR := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
	defer cancelR()

	pipe := deps.Redis.GetReadHandle().Pipeline()
	rangeCmds := make([]*redis.ZSliceCmd, len(indexKeys))

	for i, key := range indexKeys {
		rangeCmds[i] = pipe.ZRangeWithScores(dCtxR, key, 0, -1)
	}

	_, err := pipe.Exec(dCtxR)
	if err != nil && !stderrors.Is(err, redis.Nil) {
		level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error reading ban index shards",
			definitions.LogKeyError, err,
		)

		errMsg := err.Error()
		blockedIPAddresses.Error = &errMsg

		return blockedIPAddresses, err
	}

	// Parse ZSET results from all shards
	type indexEntry struct {
		network  string
		bannedAt float64
	}

	entries := make([]indexEntry, 0)
	seenNetworks := make(map[string]struct{})

	for _, cmd := range rangeCmds {
		if cmd == nil {
			continue
		}

		for _, z := range cmd.Val() {
			var networkStr string

			switch v := z.Member.(type) {
			case string:
				networkStr = v
			case []byte:
				networkStr = string(v)
			default:
				networkStr = fmt.Sprint(v)
			}

			if networkStr == "" {
				continue
			}

			if _, exists := seenNetworks[networkStr]; exists {
				continue
			}

			seenNetworks[networkStr] = struct{}{}

			entries = append(entries, indexEntry{network: networkStr, bannedAt: z.Score})
		}
	}

	// Step 1b: Scan ban keys to repair missing index entries
	dCtxRScan, cancelRScan := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
	defer cancelRScan()

	scanPattern := rediscli.GetBruteForceBanKeyPattern(prefix)
	var cursor uint64

	for {
		keys, nextCursor, scanErr := deps.Redis.GetReadHandle().Scan(dCtxRScan, cursor, scanPattern, bruteForceBanScanCount).Result()
		if scanErr != nil && !stderrors.Is(scanErr, redis.Nil) {
			level.Warn(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Error scanning brute force ban keys",
				definitions.LogKeyError, scanErr,
			)

			break
		}

		for _, key := range keys {
			networkStr, ok := rediscli.ParseBruteForceBanKey(prefix, key)
			if !ok {
				continue
			}

			if _, exists := seenNetworks[networkStr]; exists {
				continue
			}

			seenNetworks[networkStr] = struct{}{}
			entries = append(entries, indexEntry{network: networkStr})
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	if len(entries) == 0 {
		blockedIPAddresses.Entries = []bf.BanEntry{}

		return blockedIPAddresses, nil
	}

	// Step 2: Pipeline GET + TTL for each ban key
	dCtxR2, cancelR2 := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
	defer cancelR2()

	pipe2 := deps.Redis.GetReadHandle().Pipeline()
	getCmds := make([]*redis.StringCmd, len(entries))
	ttlCmds := make([]*redis.DurationCmd, len(entries))

	for i, e := range entries {
		banKey := rediscli.GetBruteForceBanKey(prefix, e.network)
		getCmds[i] = pipe2.Get(dCtxR2, banKey)
		ttlCmds[i] = pipe2.TTL(dCtxR2, banKey)
	}

	_, _ = pipe2.Exec(dCtxR2)

	// Step 3: Build result entries + lazy cleanup for expired bans
	now := time.Now()
	var cleanupNetworks []string
	banEntries := make([]bf.BanEntry, 0, len(entries))

	for i, e := range entries {
		bucket, getErr := getCmds[i].Result()
		if getErr != nil || bucket == "" {
			// Ban key expired — schedule lazy cleanup from ZSET index
			cleanupNetworks = append(cleanupNetworks, e.network)

			continue
		}

		ttlVal, ttlErr := ttlCmds[i].Result()
		if ttlErr != nil || ttlVal < 0 {
			// Key exists but has no TTL or is expiring — skip
			cleanupNetworks = append(cleanupNetworks, e.network)

			continue
		}

		// Look up configured ban time
		configuredBanTime := definitions.DefaultBanTime
		if bt, found := ruleMap[bucket]; found {
			configuredBanTime = bt
		}

		// Calculate banned_at: now - (configuredBanTime - remaining TTL)
		bannedAt := now.Add(-(configuredBanTime - ttlVal))

		entry := bf.BanEntry{
			Network:  e.network,
			Bucket:   bucket,
			BanTime:  configuredBanTime,
			TTL:      ttlVal,
			BannedAt: bannedAt,
		}

		banEntries = append(banEntries, entry)
	}

	// Step 4: Lazy cleanup of stale ZSET entries (best-effort, fire-and-forget)
	if len(cleanupNetworks) > 0 {
		go func() {
			cleanupCtx, cleanupCancel := util.GetCtxWithDeadlineRedisWrite(context.Background(), cfg)
			defer cleanupCancel()

			cleanupPipe := deps.Redis.GetWriteHandle().Pipeline()

			for _, n := range cleanupNetworks {
				shard := rediscli.GetBanIndexShard(n)
				shardKey := rediscli.GetBruteForceBanIndexShardKey(prefix, shard)
				cleanupPipe.ZRem(cleanupCtx, shardKey, n)
			}

			if _, err := cleanupPipe.Exec(cleanupCtx); err != nil {
				level.Warn(logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyMsg, "Lazy cleanup of stale ban index entries failed",
					definitions.LogKeyError, err,
				)
			}
		}()
	}

	// Apply IP filter if specified
	if filterCmd != nil && len(filterCmd.IPAddress) > 0 {
		filtered := make([]bf.BanEntry, 0)

		for _, entry := range banEntries {
			for _, filterIPWanted := range filterCmd.IPAddress {
				if util.IsInNetworkWithCfg(ctx, deps.Cfg, deps.Logger, []string{entry.Network}, guid, filterIPWanted) {
					filtered = append(filtered, entry)

					break
				}
			}
		}

		banEntries = filtered
	}

	blockedIPAddresses.Entries = banEntries

	return blockedIPAddresses, nil
}

func listBlockedAccounts(ctx context.Context, deps restAdminDeps, filterCmd *bf.FilterCmd, guid string) (*bf.BlockedAccounts, error) {
	blockedAccounts := &bf.BlockedAccounts{Accounts: make(map[string][]string)}

	if deps.Cfg == nil {
		err := stderrors.New("config is nil")
		errMsg := err.Error()
		blockedAccounts.Error = &errMsg

		return blockedAccounts, err
	}

	if deps.Redis == nil {
		err := stderrors.New("redis client is nil")
		errMsg := err.Error()
		blockedAccounts.Error = &errMsg

		return blockedAccounts, err
	}

	logger := deps.effectiveLogger()
	cfg := deps.effectiveCfg()
	key := cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisAffectedAccountsKey

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	accounts, err := deps.Redis.GetReadHandle().SMembers(ctx, key).Result()
	if err != nil {
		if !stderrors.Is(err, redis.Nil) {
			level.Error(logger).Log(
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
	}

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

		key = cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisPWHistIPsKey + ":" + account
		if accountIPs, err = deps.Redis.GetReadHandle().SMembers(ctx, key).Result(); err != nil {
			stats.GetMetrics().GetRedisReadCounter().Inc()

			if !stderrors.Is(err, redis.Nil) {
				level.Error(logger).Log(
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

	return blockedAccounts, err
}

func (deps restAdminDeps) effectiveChannel() backend.Channel {
	if deps.Channel != nil {
		return deps.Channel
	}

	return nil
}

func (deps restAdminDeps) validate() error {
	if deps.Cfg == nil {
		return stderrors.New("config is nil")
	}

	if deps.Redis == nil {
		return stderrors.New("redis client is nil")
	}

	return nil
}

func handleBruteForceList(ctx *gin.Context, deps restAdminDeps) {
	logger := deps.effectiveLogger()

	// Check if OIDC Bearer token has the required scope
	claims := oidcbearer.GetClaimsFromContext(ctx)

	if claims != nil {
		if !oidcbearer.HasAnyScope(claims, definitions.ScopeSecurity, definitions.ScopeAdmin) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "missing required scope: " + definitions.ScopeSecurity + " or " + definitions.ScopeAdmin})

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

	blockedIPAddresses, err := listBlockedIPAddresses(ctx, deps, filterCmd, guid)
	if err != nil {
		httpStatusCode = http.StatusInternalServerError
	}

	blockedAccounts, err := listBlockedAccounts(ctx, deps, filterCmd, guid)
	if err != nil {
		httpStatusCode = http.StatusInternalServerError
	}

	level.Info(logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, definitions.ServList)

	ctx.JSON(httpStatusCode, &restdto.Result{
		GUID:      guid,
		Object:    definitions.CatBruteForce,
		Operation: definitions.ServList,
		Result:    []any{blockedIPAddresses, blockedAccounts},
	})
}

// HandleConfigLoad handles loading the server configuration with OIDC scope checks.
// If an OIDC Bearer token is present, it verifies the security or admin scope.
// On success, it retrieves the server configuration as JSON and returns it.
func (deps restAdminDeps) HandleConfigLoad(ctx *gin.Context) {
	if err := deps.validate(); err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	cfg := deps.effectiveCfg()
	logger := deps.effectiveLogger()

	// Check if OIDC Bearer token has the required scope
	claims := oidcbearer.GetClaimsFromContext(ctx)

	if claims != nil {
		if !oidcbearer.HasAnyScope(claims, definitions.ScopeSecurity, definitions.ScopeAdmin) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "missing required scope: " + definitions.ScopeSecurity + " or " + definitions.ScopeAdmin})

			return
		}
	}

	jsonBytes, err := cfg.GetConfigFileAsJSON()
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to get config as JSON"})

		return
	}

	guid := ctx.GetString(definitions.CtxGUIDKey)

	level.Info(logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, definitions.ServLoad)

	ctx.JSON(http.StatusOK, &restdto.Result{
		GUID:      guid,
		Object:    definitions.CatConfig,
		Operation: definitions.ServLoad,
		Result:    string(jsonBytes),
	})
}

// Flush User

func (deps restAdminDeps) HandleUserFlush(ctx *gin.Context) {
	guid := ctx.GetString(definitions.CtxGUIDKey)
	userCmd := &admin.FlushUserCmd{}
	logger := deps.effectiveLogger()

	level.Info(logger).Log(definitions.LogKeyGUID, guid, definitions.CatCache, definitions.ServFlush)

	if err := ctx.ShouldBindJSON(userCmd); err != nil {
		HandleJSONError(ctx, err)

		return
	}

	removedKeys, noUserAccoundFound := processFlushCache(ctx, deps, userCmd, guid)

	statusMsg := fmt.Sprintf("%d keys flushed", len(removedKeys))

	if noUserAccoundFound || len(removedKeys) == 0 {
		statusMsg = "not flushed"
	}

	sendCacheStatus(ctx, logger, guid, userCmd, statusMsg, removedKeys)
}

// NewUserFlushHandler constructs a Gin handler for the user cache flush endpoint
// using injected dependencies.
func NewUserFlushHandler(cfg config.File, logger *slog.Logger, redisClient rediscli.Client, tokenFlusher ...TokenFlusher) gin.HandlerFunc {
	deps := restAdminDeps{Cfg: cfg, Logger: logger, Redis: redisClient}

	if len(tokenFlusher) > 0 {
		deps.TokenFlusher = tokenFlusher[0]
	}

	return func(ctx *gin.Context) {
		deps.HandleUserFlush(ctx)
	}
}

// processFlushCache takes a user command and a GUID and processes the cache flush.
// It iterates through the backends in the GetFile() and checks if the backend is BackendCache.
// If it is, it sets useCache to true and calls processUserCmd to process the user command.
// If there is an error during the cache flush, cacheFlushError is set to true and the loop breaks.
// It returns cacheFlushError and useCache flags.
func processFlushCache(ctx *gin.Context, deps restAdminDeps, userCmd *admin.FlushUserCmd, guid string) (removedKeys []string, noUserAccountFound bool) {
	cfg := deps.effectiveCfg()
	for _, backendType := range cfg.GetServer().GetBackends() {
		if backendType.Get() != definitions.BackendCache {
			continue
		}

		removedKeys, noUserAccountFound = processUserCmd(ctx, deps, userCmd, guid)
		if noUserAccountFound {
			break
		}
	}

	return removedKeys, noUserAccountFound
}

func collectUserAccountMappings(ctx context.Context, deps restAdminDeps, username, guid string) (config.StringSet, config.StringSet) {
	accountNames := config.NewStringSet()
	fields := config.NewStringSet()

	redisClient := deps.effectiveRedis()
	logger := deps.effectiveLogger()
	cfg := deps.effectiveCfg()

	key := rediscli.GetUserHashKey(cfg.GetServer().GetRedis().GetPrefix(), username)
	data, err := redisClient.GetReadHandle().HGetAll(ctx, key).Result()
	if err != nil {
		if !stderrors.Is(err, redis.Nil) {
			level.Error(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Error while retrieving user account mappings",
				definitions.LogKeyError, err,
			)
		}

		return accountNames, fields
	}

	fieldPrefix := username + "|"
	for field, accountName := range data {
		if _, ok := strings.CutPrefix(field, fieldPrefix); !ok {
			continue
		}

		fields.Set(field)

		if accountName != "" {
			accountNames.Set(accountName)
		}
	}

	return accountNames, fields
}

// processUserCmd processes the user command by performing the following steps:
// 1. Calls the GetUserAccountFromCache function to set up the cache flush and retrieve the account name, removeHash flag, and cacheFlushError flag.
// 2. If cacheFlushError is true, returns true immediately.
// 3. Calls the prepareRedisUserKeys function to set the user keys using the user command and account name.
// 4. Calls the removeUserFromCache function to remove the user from the cache by providing the user command, user keys, guid, and removeHash flag.
// 5. Returns false.
func processUserCmd(ctx *gin.Context, deps restAdminDeps, userCmd *admin.FlushUserCmd, guid string) (removedKeys []string, noUserAccountFound bool) {
	var (
		result        int64
		removeHash    bool
		removedIPKeys []string
		err           error
	)

	logger := deps.effectiveLogger()
	redisClient := deps.effectiveRedis()
	cfg := deps.effectiveCfg()

	mappedAccounts, hashFields := collectUserAccountMappings(ctx.Request.Context(), deps, userCmd.User, guid)
	cleanupAccounts := config.NewStringSet()
	tokenAccounts := config.NewStringSet()
	userKeys := config.NewStringSet()
	ipAddressSet := config.NewStringSet()

	for _, accountName := range mappedAccounts.GetStringSlice() {
		cleanupAccounts.Set(accountName)
		tokenAccounts.Set(accountName)
	}

	cleanupAccounts.Set(userCmd.User)
	hashFields.Set(userCmd.User)

	if len(tokenAccounts) == 0 {
		tokenAccounts.Set(userCmd.User)
	}

	cleanupAccountNames := cleanupAccounts.GetStringSlice()
	sort.Strings(cleanupAccountNames)

	tokenAccountNames := tokenAccounts.GetStringSlice()
	sort.Strings(tokenAccountNames)

	for _, accountName := range cleanupAccountNames {
		ipAddresses, keys := prepareRedisUserKeys(ctx, deps, guid, accountName)
		for _, ipAddress := range ipAddresses {
			ipAddressSet.Set(ipAddress)
		}

		for _, key := range keys.GetStringSlice() {
			userKeys.Set(key)
		}
	}

	// Remove all buckets (bf) associated with the user
	ipAddresses := ipAddressSet.GetStringSlice()
	sort.Strings(ipAddresses)

	for _, ipAddress := range ipAddresses {
		_, removedIPKeys, err = processBruteForceRules(ctx, deps, &bf.FlushRuleCmd{
			IPAddress: ipAddress,
			RuleName:  "*",
		}, guid)

		if err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Error while flushing brute force rules",
				definitions.LogKeyError, err,
			)
		}
	}

	removedKeySet := config.NewStringSet()
	for _, removedKey := range removedIPKeys {
		removedKeySet.Set(removedKey)
	}

	for _, accountName := range cleanupAccountNames {
		stats.GetMetrics().GetRedisWriteCounter().Inc()

		// Remove PW_HIST_SET from Redis (use UNLINK to avoid blocking)
		key := bruteforce.GetPWHistIPsRedisKey(accountName, cfg)
		if result, err = redisClient.GetWriteHandle().Unlink(ctx, key).Result(); err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Error while flushing PW_HIST_SET",
				definitions.LogKeyError, err,
			)
		} else if result > 0 {
			removedKeySet.Set(key)
		}

	}

	if len(cleanupAccountNames) > 0 {
		members := make([]any, 0, len(cleanupAccountNames))
		for _, accountName := range cleanupAccountNames {
			members = append(members, accountName)
		}

		stats.GetMetrics().GetRedisWriteCounter().Inc()

		// Remove accounts from AFFECTED_ACCOUNTS
		key := cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisAffectedAccountsKey
		if result, err = redisClient.GetWriteHandle().SRem(ctx, key, members...).Result(); err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Error while flushing AFFECTED_ACCOUNTS",
				definitions.LogKeyError, err,
			)
		} else if result > 0 {
			removedKeySet.Set(key)
		}
	}

	removedKeys = removeUserFromCache(ctx, deps, userCmd, userKeys, guid, removeHash, hashFields.GetStringSlice())
	for _, removedKey := range removedKeys {
		removedKeySet.Set(removedKey)
	}

	// Flush OIDC/SAML2 tokens (access tokens, refresh tokens) for the user
	if deps.TokenFlusher != nil {
		for _, accountName := range tokenAccountNames {
			if err := deps.TokenFlusher.FlushUserTokens(ctx.Request.Context(), accountName); err != nil {
				level.Error(logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyMsg, "Error while flushing IdP tokens",
					definitions.LogKeyError, err,
				)
			} else {
				level.Info(logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyMsg, "IdP tokens flushed for user",
					"account", accountName,
				)
			}
		}
	}

	return removedKeySet.GetStringSlice(), noUserAccountFound
}

func getIPsFromPWHistSet(ctx context.Context, deps restAdminDeps, accountName string) ([]string, error) {
	var ips []string

	redisClient := deps.effectiveRedis()
	key := bruteforce.GetPWHistIPsRedisKey(accountName, deps.Cfg)

	if result, err := redisClient.GetReadHandle().SMembers(ctx, key).Result(); err != nil {
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
func prepareRedisUserKeys(ctx context.Context, deps restAdminDeps, guid string, accountName string) ([]string, config.StringSet) {
	cfg := deps.effectiveCfg()
	logger := deps.effectiveLogger()

	ips, err := getIPsFromPWHistSet(ctx, deps, accountName)
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error while retrieving IPs from PW_HIST_SET",
			definitions.LogKeyError, err,
		)
	}

	userKeys := config.NewStringSet()
	prefix := cfg.GetServer().GetRedis().GetPrefix()

	var sb strings.Builder

	sb.WriteString(prefix)
	sb.WriteString(definitions.RedisUserPositiveCachePrefix)
	sb.WriteString("__default__:")
	sb.WriteString(accountName)

	userKeys.Set(sb.String())

	if ips != nil {
		// Shared scoper used to compute CIDR-scoped identifiers when configured (IPv6)
		scoper := ipscoper.NewIPScoper().WithCfg(cfg)

		for _, ip := range ips {
			// Compute scoped identifier for both contexts we need to clean up
			scopedRWP := scoper.Scope(ipscoper.ScopeRepeatingWrongPassword, ip)
			scopedTol := scoper.Scope(ipscoper.ScopeTolerations, ip)

			// Password-history hashes (account+IP and IP-only) — delete for raw and scoped identifiers
			sb.Reset()
			sb.WriteString(prefix)
			sb.WriteString(definitions.RedisPwHashKey)
			sb.WriteString(":{")
			sb.WriteString(accountName)
			sb.WriteByte(':')
			sb.WriteString(ip)
			sb.WriteString("}:")
			sb.WriteString(accountName)
			sb.WriteByte(':')
			sb.WriteString(ip)
			userKeys.Set(sb.String())

			sb.Reset()
			sb.WriteString(prefix)
			sb.WriteString(definitions.RedisPwHashKey)
			sb.WriteString(":{")
			sb.WriteString(ip)
			sb.WriteString("}:")
			sb.WriteString(ip)
			userKeys.Set(sb.String())

			// PW_HIST totals (account+IP and IP-only) — delete for raw and scoped identifiers
			sb.Reset()
			sb.WriteString(prefix)
			sb.WriteString(definitions.RedisPwHistTotalKey)
			sb.WriteString(":{")
			sb.WriteString(accountName)
			sb.WriteByte(':')
			sb.WriteString(ip)
			sb.WriteString("}:")
			sb.WriteString(accountName)
			sb.WriteByte(':')
			sb.WriteString(ip)
			userKeys.Set(sb.String())

			sb.Reset()
			sb.WriteString(prefix)
			sb.WriteString(definitions.RedisPwHistTotalKey)
			sb.WriteString(":{")
			sb.WriteString(ip)
			sb.WriteString("}:")
			sb.WriteString(ip)
			userKeys.Set(sb.String())

			if scopedRWP != ip {
				sb.Reset()
				sb.WriteString(prefix)
				sb.WriteString(definitions.RedisPwHashKey)
				sb.WriteString(":{")
				sb.WriteString(accountName)
				sb.WriteByte(':')
				sb.WriteString(scopedRWP)
				sb.WriteString("}:")
				sb.WriteString(accountName)
				sb.WriteByte(':')
				sb.WriteString(scopedRWP)
				userKeys.Set(sb.String())

				sb.Reset()
				sb.WriteString(prefix)
				sb.WriteString(definitions.RedisPwHashKey)
				sb.WriteString(":{")
				sb.WriteString(scopedRWP)
				sb.WriteString("}:")
				sb.WriteString(scopedRWP)
				userKeys.Set(sb.String())

				sb.Reset()
				sb.WriteString(prefix)
				sb.WriteString(definitions.RedisPwHistTotalKey)
				sb.WriteString(":{")
				sb.WriteString(accountName)
				sb.WriteByte(':')
				sb.WriteString(scopedRWP)
				sb.WriteString("}:")
				sb.WriteString(accountName)
				sb.WriteByte(':')
				sb.WriteString(scopedRWP)
				userKeys.Set(sb.String())

				sb.Reset()
				sb.WriteString(prefix)
				sb.WriteString(definitions.RedisPwHistTotalKey)
				sb.WriteString(":{")
				sb.WriteString(scopedRWP)
				sb.WriteString("}:")
				sb.WriteString(scopedRWP)
				userKeys.Set(sb.String())
			}

			// Tolerations keys — delete base hash and both positive/negative ZSETs for raw and scoped identifiers
			sb.Reset()
			sb.WriteString(prefix)
			sb.WriteString(definitions.RedisBFTolerationPrefix)
			sb.WriteString(ip)
			baseTolRaw := sb.String()

			userKeys.Set(baseTolRaw) // hash with aggregated counters

			sb.WriteString(":P")
			userKeys.Set(sb.String()) // positives ZSET

			sb.Reset()
			sb.WriteString(baseTolRaw)
			sb.WriteString(":N")
			userKeys.Set(sb.String()) // negatives ZSET

			if scopedTol != ip {
				sb.Reset()
				sb.WriteString(prefix)
				sb.WriteString(definitions.RedisBFTolerationPrefix)
				sb.WriteString(scopedTol)
				baseTolScoped := sb.String()

				userKeys.Set(baseTolScoped)

				sb.WriteString(":P")
				userKeys.Set(sb.String())

				sb.Reset()
				sb.WriteString(baseTolScoped)
				sb.WriteString(":N")
				userKeys.Set(sb.String())
			}

			// RWP allowance keys — delete for both raw and scoped IP combined with account
			sb.Reset()
			sb.WriteString(prefix)
			sb.WriteString(definitions.RedisBFRWPAllowPrefix)
			sb.WriteString(ip)
			sb.WriteByte(':')
			sb.WriteString(accountName)
			userKeys.Set(sb.String())

			if scopedRWP != ip {
				sb.Reset()
				sb.WriteString(prefix)
				sb.WriteString(definitions.RedisBFRWPAllowPrefix)
				sb.WriteString(scopedRWP)
				sb.WriteByte(':')
				sb.WriteString(accountName)
				userKeys.Set(sb.String())
			}
		}
	}

	protocols := cfg.GetAllProtocols()
	channel := deps.effectiveChannel()
	for index := range protocols {
		cacheNames := backend.GetCacheNames(cfg, channel, protocols[index], definitions.CacheAll)
		for _, cacheName := range cacheNames.GetStringSlice() {
			sb.Reset()
			sb.WriteString(prefix)
			sb.WriteString(definitions.RedisUserPositiveCachePrefix)
			sb.WriteString(cacheName)
			sb.WriteByte(':')
			sb.WriteString(accountName)

			userKeys.Set(sb.String())
		}
	}

	return ips, userKeys
}

// removeUserFromCache removes a user and related keys from the cache based on the given parameters and context.
// Parameters: ctx is the request context, userCmd contains user info, userKeys is a set of keys to remove,
// guid is a unique identifier for logs, and removeHash indicates whether to delete the entire hash or specific fields.
// Returns a slice of strings representing the removed keys.
func removeUserFromCache(ctx context.Context, deps restAdminDeps, userCmd *admin.FlushUserCmd, userKeys config.StringSet, guid string, removeHash bool, hashFields []string) []string {
	// Legacy wrapper: delegate to deps-based implementation using injected defaults.
	return removeUserFromCacheWithDeps(
		ctx,
		userCmd,
		userKeys,
		guid,
		removeHash,
		hashFields,
		deps,
	)
}

func removeUserFromCacheWithDeps(ctx context.Context, userCmd *admin.FlushUserCmd, userKeys config.StringSet, guid string, removeHash bool, hashFields []string, deps restAdminDeps) []string {
	removedKeys := make([]string, 0)

	cfg := deps.effectiveCfg()
	logger := deps.effectiveLogger()
	redisClient := deps.effectiveRedis()

	prefix := cfg.GetServer().GetRedis().GetPrefix()

	// Increment write counter once for the whole pipeline execution
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	keys := userKeys.GetStringSlice()
	sort.Strings(keys)

	pipe := redisClient.GetWriteHandle().Pipeline()
	// Remove hash (whole hash or a single field) first
	if removeHash {
		// Flush all 256 shards
		for i := range 256 {
			shardKey := fmt.Sprintf("%s%s:{%02x}", prefix, definitions.RedisUserHashKey, i)
			pipe.Del(ctx, shardKey)
		}
	} else {
		redisKey := rediscli.GetUserHashKey(prefix, userCmd.User)
		fields := append([]string(nil), hashFields...)
		if len(fields) == 0 {
			fields = []string{userCmd.User}
		}
		sort.Strings(fields)
		pipe.HDel(ctx, redisKey, fields...)
	}

	// Queue deletion of all user keys
	for _, userKey := range keys {
		// Use UNLINK to avoid blocking Redis on large keys
		pipe.Unlink(ctx, userKey)
	}

	cmds, err := pipe.Exec(ctx)
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error while flushing user keys",
			definitions.LogKeyError, err,
		)

		return removedKeys
	}

	// Calculate the offset for cmds based on whether we flushed one shard or 256
	offset := 1
	if removeHash {
		offset = 256
	}

	for i, userKey := range keys {
		idx := i + offset
		if idx >= 0 && idx < len(cmds) {
			if intCmd, ok := cmds[idx].(*redis.IntCmd); ok {
				if val, cerr := intCmd.Result(); cerr == nil && val > 0 {
					removedKeys = append(removedKeys, userKey)
					level.Info(logger).Log(definitions.LogKeyGUID, guid, "keys", userKey, "status", "flushed")
				}
			} else {
				level.Error(logger).Log(
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
func sendCacheStatus(ctx *gin.Context, logger *slog.Logger, guid string, userCmd *admin.FlushUserCmd, statusMsg string, removedKeys []string) {
	level.Info(logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, statusMsg)

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

func (deps restAdminDeps) HandleBruteForceFlush(ctx *gin.Context) {
	var (
		removedKeys []string
		err         error
	)

	guid := ctx.GetString(definitions.CtxGUIDKey)
	logger := deps.effectiveLogger()

	level.Info(logger).Log(definitions.LogKeyGUID, guid, definitions.CatBruteForce, definitions.ServFlush)

	ipCmd := &bf.FlushRuleCmd{}

	if err = ctx.ShouldBindJSON(ipCmd); err != nil {
		HandleJSONError(ctx, err)

		return
	}

	level.Info(logger).Log(definitions.LogKeyGUID, guid, "ip_address", ipCmd.IPAddress)

	_, removedKeys, err = processBruteForceRules(ctx, deps, ipCmd, guid)
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error while flushing brute force rules",
			definitions.LogKeyError, err,
		)
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	statusMsg := fmt.Sprintf("%d keys flushed", len(removedKeys))

	if len(removedKeys) == 0 {
		statusMsg = "not flushed"
	}

	level.Info(logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, statusMsg)

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
	genJobID             = generateJobID
	asyncStarterWithDeps = startAsync
	nowFunc              = time.Now
)

type asyncJobDeps struct {
	Cfg    config.File
	Logger *slog.Logger
	Redis  rediscli.Client
}

func (deps asyncJobDeps) validate() error {
	if deps.Cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if deps.Logger == nil {
		return fmt.Errorf("logger is nil")
	}
	if deps.Redis == nil {
		return fmt.Errorf("redis client is nil")
	}
	return nil
}

func asyncJobKey(cfg config.File, jobID string) string {
	var sb strings.Builder

	sb.WriteString(cfg.GetServer().GetRedis().GetPrefix())
	sb.WriteString("async:job:")
	sb.WriteString(jobID)

	return sb.String()
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
func createAsyncJob(ctx context.Context, jobType string, deps asyncJobDeps) (string, error) {
	if err := deps.validate(); err != nil {
		return "", err
	}

	// Capture the time source once to avoid races in tests that temporarily override `nowFunc`.
	now := nowFunc

	jobID := genJobID()
	key := asyncJobKey(deps.Cfg, jobID)

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	// Use ordered field/values to make unit testing with redismock deterministic
	if _, err := deps.Redis.GetWriteHandle().HSet(
		ctx,
		key,
		"status", jobStatusQueued,
		"type", jobType,
		"createdAt", now().UTC().Format(time.RFC3339Nano),
		"resultCount", 0,
	).Result(); err != nil {
		return "", err
	}

	// Apply TTL (reuse NegCacheTTL if no dedicated TTL exists)
	_, _ = deps.Redis.GetWriteHandle().Expire(ctx, key, deps.Cfg.GetServer().Redis.NegCacheTTL).Result()
	stats.GetMetrics().GetRedisWriteCounter().Inc()

	return jobID, nil
}

// startAsync runs fn in a background goroutine using the service root context.
func startAsync(deps asyncJobDeps, jobID string, guid string, fn func(context.Context) (int, []string, error)) {
	if err := deps.validate(); err != nil {
		level.Error(deps.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "async job misconfigured", definitions.LogKeyError, err)

		return
	}

	go func() {
		// Capture the time source once to avoid races in tests that temporarily override `nowFunc`.
		now := nowFunc

		base := svcctx.Get()

		key := asyncJobKey(deps.Cfg, jobID)

		// Mark INPROGRESS
		func() {
			defer stats.GetMetrics().GetRedisWriteCounter().Inc()

			_, _ = deps.Redis.GetWriteHandle().HSet(base, key, map[string]any{
				"status":    jobStatusInProgress,
				"startedAt": now().UTC().Format(time.RFC3339Nano),
			}).Result()
		}()

		// Execute task
		count, _, err := fn(base)

		// Persist final state
		updates := map[string]any{
			"finishedAt":  now().UTC().Format(time.RFC3339Nano),
			"resultCount": count,
		}

		if err != nil {
			updates["status"] = jobStatusError
			updates["error"] = err.Error()
			level.Error(deps.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "async job failed", definitions.LogKeyError, err)
		} else {
			updates["status"] = jobStatusDone
		}

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		_, _ = deps.Redis.GetWriteHandle().HSet(base, key, updates).Result()
		_, _ = deps.Redis.GetWriteHandle().Expire(base, key, deps.Cfg.GetServer().Redis.NegCacheTTL).Result()
		stats.GetMetrics().GetRedisWriteCounter().Inc()
	}()
}

// NewAsyncJobStatusHandler constructs a Gin handler for querying async job status
// using injected dependencies.
func NewAsyncJobStatusHandler(cfg config.File, logger *slog.Logger, redisClient rediscli.Client) gin.HandlerFunc {
	deps := asyncJobDeps{Cfg: cfg, Logger: logger, Redis: redisClient}

	return func(ctx *gin.Context) {
		deps.HandleAsyncJobStatus(ctx)
	}
}

func (deps asyncJobDeps) HandleAsyncJobStatus(ctx *gin.Context) {
	guid := ctx.GetString(definitions.CtxGUIDKey)

	if err := deps.validate(); err != nil {
		level.Error(deps.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "async job status misconfigured", definitions.LogKeyError, err)
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	jobID := ctx.Param("jobId")
	key := asyncJobKey(deps.Cfg, jobID)

	defer stats.GetMetrics().GetRedisReadCounter().Inc()
	data, err := deps.Redis.GetReadHandle().HGetAll(ctx.Request.Context(), key).Result()
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

// NewUserFlushAsyncHandler constructs a Gin handler for the async user cache flush endpoint
// using injected dependencies.
func NewUserFlushAsyncHandler(cfg config.File, logger *slog.Logger, redisClient rediscli.Client, tokenFlusher ...TokenFlusher) gin.HandlerFunc {
	deps := restAdminDeps{Cfg: cfg, Logger: logger, Redis: redisClient}

	if len(tokenFlusher) > 0 {
		deps.TokenFlusher = tokenFlusher[0]
	}

	return func(ctx *gin.Context) {
		deps.HandleUserFlushAsync(ctx)
	}
}

func (deps restAdminDeps) HandleUserFlushAsync(ctx *gin.Context) {
	guid := ctx.GetString(definitions.CtxGUIDKey)
	userCmd := &admin.FlushUserCmd{}
	logger := deps.effectiveLogger()

	if err := ctx.ShouldBindJSON(userCmd); err != nil {
		HandleJSONError(ctx, err)

		return
	}

	jobDeps := asyncJobDeps{Cfg: deps.Cfg, Logger: deps.Logger, Redis: deps.Redis}
	jobID, err := createAsyncJob(ctx.Request.Context(), "CACHE_FLUSH", jobDeps)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	startAsync(jobDeps, jobID, guid, func(base context.Context) (int, []string, error) {
		gctx := &gin.Context{}
		gctx.Request = ctx.Request.Clone(base)
		removedKeys, _ := processFlushCache(gctx, deps, userCmd, guid)

		return len(removedKeys), removedKeys, nil
	})

	level.Debug(logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "async cache flush enqueued", "jobId", jobID)

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

func (deps restAdminDeps) HandleBruteForceRuleFlushAsync(ctx *gin.Context) {
	guid := ctx.GetString(definitions.CtxGUIDKey)
	ipCmd := &bf.FlushRuleCmd{}

	if err := ctx.ShouldBindJSON(ipCmd); err != nil {
		HandleJSONError(ctx, err)

		return
	}

	jobDeps := asyncJobDeps{Cfg: deps.Cfg, Logger: deps.Logger, Redis: deps.Redis}
	jobID, err := createAsyncJob(ctx.Request.Context(), "BF_FLUSH", jobDeps)

	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	startAsync(jobDeps, jobID, guid, func(base context.Context) (int, []string, error) {
		gctx := &gin.Context{}
		gctx.Request = ctx.Request.Clone(base)
		_, removed, err := processBruteForceRules(gctx, deps, ipCmd, guid)

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

func createBucketManager(ctx context.Context, deps restAdminDeps, guid string, ipAddress string, protocol string, oidcCID string) bruteforce.BucketManager {
	cfg := deps.effectiveCfg()
	logger := deps.effectiveLogger()
	redisClient := deps.effectiveRedis()

	bm := bruteforce.NewBucketManagerWithDeps(ctx, guid, ipAddress, bruteforce.BucketManagerDeps{
		Cfg:    cfg,
		Logger: logger,
		Redis:  redisClient,
	})

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
func iterateCombinations(ctx *gin.Context, deps restAdminDeps, guid string, cmd *bf.FlushRuleCmd, rule *config.BruteForceRule, removed []string) ([]string, error) {
	cfg := deps.effectiveCfg()

	// 1) Cartesian product of FilterByProtocol × FilterByOIDCCID
	for _, proto := range rule.FilterByProtocol {
		oidcCids := rule.FilterByOIDCCID
		if len(oidcCids) == 0 {
			oidcCids = []string{""} // protocol-only variant
		}

		for _, cid := range oidcCids {
			bm := createBucketManager(ctx.Request.Context(), deps, guid, cmd.IPAddress, proto, cid)

			var err error
			if removed, err = flushForBucket(ctx, deps, bm, rule, cmd.RuleName, removed); err != nil {
				return removed, err
			}
		}
	}

	// 2) OIDC-CID only (when no protocol filters are present)
	if len(rule.FilterByProtocol) == 0 {
		for _, cid := range rule.FilterByOIDCCID {
			bm := createBucketManager(ctx.Request.Context(), deps, guid, cmd.IPAddress, "", cid)

			var err error
			if removed, err = flushForBucket(ctx, deps, bm, rule, cmd.RuleName, removed); err != nil {
				return removed, err
			}
		}
	}

	// 3) Safety net: iterate over every configured protocol
	for _, proto := range cfg.GetAllProtocols() {
		bm := createBucketManager(ctx.Request.Context(), deps, guid, cmd.IPAddress, proto, "")

		var err error
		if removed, err = flushForBucket(ctx, deps, bm, rule, cmd.RuleName, removed); err != nil {
			return removed, err
		}
	}

	return removed, nil
}

func deleteKeyIfExists(ctx context.Context, deps restAdminDeps, key string, guid string) (string, error) {
	logger := deps.effectiveLogger()
	cfg := deps.effectiveCfg()
	redisClient := deps.effectiveRedis()

	stats.GetMetrics().GetRedisWriteCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
	defer cancel()

	result, err := redisClient.GetWriteHandle().Unlink(dCtx, key).Result()
	if err != nil {
		return "", err
	}

	if result > 0 {
		level.Info(logger).Log(definitions.LogKeyGUID, guid, "key", key, "status", "flushed")

		return key, nil
	}

	return "", nil
}

// bulkUnlink removes all provided keys using a single write pipeline with UNLINK.
// Returns the subset of keys that were actually removed.
func bulkUnlink(ctx context.Context, deps restAdminDeps, guid string, keys []string) ([]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}

	logger := deps.effectiveLogger()
	cfg := deps.effectiveCfg()
	redisClient := deps.effectiveRedis()

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	pipe := redisClient.GetWriteHandle().Pipeline()
	for _, k := range keys {
		pipe.Unlink(ctx, k)
	}

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
	defer cancel()

	cmds, err := pipe.Exec(dCtx)
	if err != nil {
		return nil, err
	}

	removed := make([]string, 0, len(keys))
	for i, k := range keys {
		if i < len(cmds) {
			if intCmd, ok := cmds[i].(*redis.IntCmd); ok {
				if n, _ := intCmd.Result(); n > 0 {
					removed = append(removed, k)
					level.Info(logger).Log(definitions.LogKeyGUID, guid, "key", k, "status", "flushed")
				}
			}
		}
	}

	return removed, nil
}

// flushForBucket deletes brute force data for a specific rule and updates the list of removed keys. Returns updated keys and error.
func flushForBucket(ctx *gin.Context, deps restAdminDeps, bm bruteforce.BucketManager, rule *config.BruteForceRule, ruleName string, removed []string) ([]string, error) {
	if key, err := bm.DeleteIPBruteForceRedis(rule, ruleName); err != nil {
		return removed, err
	} else if key != "" {
		removed = append(removed, key)
	}

	for _, bucketKey := range bm.GetBucketKeys(rule) {
		var err error
		if removed, err = flushKey(ctx, deps, bucketKey, bm.GetBruteForceName(), removed); err != nil {
			return removed, err
		}
	}

	return removed, nil
}

// flushKey deletes a Redis key if it exists, appends the removed key to a list, and returns the updated list with an error if any.
func flushKey(ctx *gin.Context, deps restAdminDeps, key string, guid string, removed []string) ([]string, error) {
	if rm, err := deleteKeyIfExists(ctx.Request.Context(), deps, key, guid); err != nil {
		return removed, err
	} else if rm != "" {
		removed = append(removed, rm)
	}

	return removed, nil
}

// processBruteForceRules processes and flushes brute force rules based on the provided command and context.
// It evaluates rule applicability, flushes matched rules, and removes derived and tolerable combinations.
func processBruteForceRules(ctx *gin.Context, deps restAdminDeps, cmd *bf.FlushRuleCmd, guid string) (hadError bool, removed []string, err error) {
	cfg := deps.effectiveCfg()

	var trSuffixes = []string{":P", ":N"}

	// Detect address family once – saves many To4() calls later
	ip := net.ParseIP(cmd.IPAddress)
	isIPv4 := ip.To4() != nil

	// Phase 1: pre-filter rules that could possibly match
	for _, rule := range cfg.GetBruteForceRules() {
		if !isRuleApplicable(rule, isIPv4, cmd) {
			continue
		}

		// Phase 2: flush the exact combination given by the user
		bm := createBucketManager(ctx.Request.Context(), deps, guid, cmd.IPAddress, cmd.Protocol, cmd.OIDCCID)
		if removed, err = flushForBucket(ctx, deps, bm, &rule, cmd.RuleName, removed); err != nil {
			return true, removed, err
		}

		// Phase 3: flush all derived combinations (rule filters + safety net)
		if removed, err = iterateCombinations(ctx, deps, guid, cmd, &rule, removed); err != nil {
			return true, removed, err
		}
	}

	// Phase 4: always drop tolerate-bucket keys for the IP using a single pipeline
	base := cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisBFTolerationPrefix + cmd.IPAddress
	keys := make([]string, 0, 1+len(trSuffixes))
	keys = append(keys, base)

	for _, s := range trSuffixes {
		keys = append(keys, base+s)
	}

	if removedTr, berr := bulkUnlink(ctx.Request.Context(), deps, guid, keys); berr != nil {
		return true, removed, berr
	} else if len(removedTr) > 0 {
		removed = append(removed, removedTr...)
	}

	return false, removed, nil
}

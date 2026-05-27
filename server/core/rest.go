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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/encoding/cborcodec"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/ipscoper"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib/cacheflush"
	"github.com/croessner/nauthilus/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/server/model/admin"
	bf "github.com/croessner/nauthilus/server/model/bruteforce"
	restdto "github.com/croessner/nauthilus/server/model/rest"
	"github.com/croessner/nauthilus/server/policy"
	"github.com/croessner/nauthilus/server/policy/observability"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/svcctx"
	"github.com/croessner/nauthilus/server/util"
	"github.com/croessner/nauthilus/server/util/contentneg"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// listAccountsNegotiator selects the response media type for list-accounts
// answers. Entries are listed in server-preferred order: ties on quality and
// specificity fall back to the leftmost entry.
var listAccountsNegotiator = contentneg.New(
	"application/cbor",
	"application/json",
	"application/x-www-form-urlencoded",
	"text/plain",
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

const (
	bruteForceListDefaultLimit int64 = 100
	bruteForceListMaxLimit     int64 = 1000
	bruteForceListNoPageOffset int64 = 0
	bruteForceListNoPageLimit  int64 = 0
	bruteForceListOffsetParam        = "offset"
	bruteForceListLimitParam         = "limit"
)

type bruteForceListPageQuery struct {
	limit   int64
	offset  int64
	enabled bool
}

type bruteForceBanIndexEntry struct {
	network  string
	bannedAt float64
}

// Enabled reports whether the caller requested a paged brute-force list.
func (query bruteForceListPageQuery) Enabled() bool {
	return query.enabled
}

// Stop returns the inclusive Redis range stop used to overfetch one item.
func (query bruteForceListPageQuery) Stop() int64 {
	if !query.Enabled() {
		return -1
	}

	return query.offset + query.limit
}

// PageInfo converts this query and has-more state into response metadata.
func (query bruteForceListPageQuery) PageInfo(hasMore bool) *bf.PageInfo {
	if !query.Enabled() {
		return nil
	}

	return &bf.PageInfo{
		Limit:      int(query.limit),
		Offset:     int(query.offset),
		NextOffset: int(query.offset + query.limit),
		HasMore:    hasMore,
	}
}

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

// parseBruteForceListPageQuery parses optional paging controls shared by GET and POST list requests.
func parseBruteForceListPageQuery(ctx *gin.Context) (bruteForceListPageQuery, error) {
	hasLimit, hasOffset := bruteForceListPagingFlags(ctx)
	if !hasLimit && !hasOffset {
		return bruteForceListPageQuery{
			limit:  bruteForceListNoPageLimit,
			offset: bruteForceListNoPageOffset,
		}, nil
	}

	limit, err := parseBruteForceListLimit(ctx, hasLimit)
	if err != nil {
		return bruteForceListPageQuery{}, err
	}

	offset, err := parseBruteForceListOffset(ctx, hasOffset)
	if err != nil {
		return bruteForceListPageQuery{}, err
	}

	return bruteForceListPageQuery{
		limit:   limit,
		offset:  offset,
		enabled: true,
	}, nil
}

// bruteForceListPagingFlags reports which paging controls are present.
func bruteForceListPagingFlags(ctx *gin.Context) (bool, bool) {
	_, hasLimit := ctx.GetQuery(bruteForceListLimitParam)
	_, hasOffset := ctx.GetQuery(bruteForceListOffsetParam)

	return hasLimit, hasOffset
}

// parseBruteForceListLimit parses the optional limit control.
func parseBruteForceListLimit(ctx *gin.Context, hasLimit bool) (int64, error) {
	limit := bruteForceListDefaultLimit

	if hasLimit {
		parsedLimit, err := parseBruteForceListNonNegativeInt(ctx.Query(bruteForceListLimitParam), bruteForceListLimitParam)
		if err != nil {
			return 0, err
		}

		if parsedLimit == 0 {
			return 0, fmt.Errorf("query parameter %q must be greater than zero", bruteForceListLimitParam)
		}

		if parsedLimit > bruteForceListMaxLimit {
			return 0, fmt.Errorf("query parameter %q must not exceed %d", bruteForceListLimitParam, bruteForceListMaxLimit)
		}

		limit = parsedLimit
	}

	return limit, nil
}

// parseBruteForceListOffset parses the optional offset control.
func parseBruteForceListOffset(ctx *gin.Context, hasOffset bool) (int64, error) {
	offset := bruteForceListNoPageOffset

	if hasOffset {
		parsedOffset, err := parseBruteForceListNonNegativeInt(ctx.Query(bruteForceListOffsetParam), bruteForceListOffsetParam)
		if err != nil {
			return 0, err
		}

		offset = parsedOffset
	}

	return offset, nil
}

// parseBruteForceListNonNegativeInt parses a non-negative query parameter value.
func parseBruteForceListNonNegativeInt(rawValue string, name string) (int64, error) {
	value, err := strconv.ParseInt(rawValue, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("query parameter %q must be a non-negative integer", name)
	}

	if value < 0 {
		return 0, fmt.Errorf("query parameter %q must be a non-negative integer", name)
	}

	return value, nil
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

type masterUserIdentity struct {
	targetUser string
	masterUser string
	active     bool
}

// parseMasterUserIdentity validates the configured master-user login syntax.
func parseMasterUserIdentity(username string, masterUser *config.MasterUser) masterUserIdentity {
	if !masterUser.IsEnabled() {
		return masterUserIdentity{}
	}

	targetUser, masterUserName, ok := config.ParseMasterUserLogin(username, masterUser.GetUserFormat())
	if !ok {
		return masterUserIdentity{}
	}

	return masterUserIdentity{
		targetUser: targetUser,
		masterUser: masterUserName,
		active:     true,
	}
}

// masterUserIdentity returns the parsed master-user request identity.
func (a *AuthState) masterUserIdentity() masterUserIdentity {
	if a == nil || a.deps.Cfg == nil {
		return masterUserIdentity{}
	}

	return parseMasterUserIdentity(a.Request.Username, a.deps.Cfg.GetServer().GetMasterUser())
}

// handleMasterUserMode switches between master and target identity lookups for one request.
func (a *AuthState) handleMasterUserMode() string {
	identity := a.masterUserIdentity()
	if !identity.active {
		return a.Request.Username
	}

	if a.Runtime.MasterUserMode {
		a.Runtime.MasterUserMode = false

		// Return real user
		return identity.targetUser
	}

	a.Runtime.MasterUserMode = true

	// Return master user
	return identity.masterUser
}

// HandleAuthentication handles the authentication logic based on the selected service type.
func (a *AuthState) HandleAuthentication(ctx *gin.Context) {
	if a.Request.ListAccounts {
		a.writeListAccountsResponse(ctx)

		level.Info(a.logger()).Log(definitions.LogKeyGUID, a.Runtime.GUID, definitions.LogKeyMode, ctx.Query("mode"))
	} else {
		a.runAuthPipelineFSM(ctx)
	}
}

// writeListAccountsResponse renders the account list using the response
// media type negotiated from the Accept header. It dispatches to the
// matching encoder and aborts with 415 when the client cannot be served
// any of the supported types.
func (a *AuthState) writeListAccountsResponse(ctx *gin.Context) {
	accounts := a.ListUserAccounts()
	if ctx.IsAborted() || ctx.Writer.Written() {
		return
	}

	chosen := listAccountsNegotiator.BestMatch(ctx.GetHeader("Accept"))

	switch chosen {
	case "application/json":
		ctx.JSON(http.StatusOK, accounts)
	case "application/cbor":
		writeCBORList(ctx, accounts)
	case "text/plain":
		writeLineSeparated(ctx, accounts, "text/plain")
	case "application/x-www-form-urlencoded":
		writeLineSeparated(ctx, accounts, "application/x-www-form-urlencoded")
	default:
		_ = ctx.Error(errors.ErrUnsupportedMediaType).SetType(gin.ErrorTypeBind)
		ctx.AbortWithStatus(http.StatusUnsupportedMediaType)
	}
}

// writeCBORList encodes the account list as a single CBOR array body.
func writeCBORList(ctx *gin.Context, accounts AccountList) {
	body, err := cborcodec.Marshal(accounts)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	ctx.Data(http.StatusOK, "application/cbor", body)
}

// writeLineSeparated streams the account list as CRLF-separated entries with
// the given content type. Used by both text/plain and form-urlencoded paths,
// which differ only in the response Content-Type they advertise.
func writeLineSeparated(ctx *gin.Context, accounts AccountList, contentType string) {
	for _, account := range accounts {
		ctx.Data(http.StatusOK, contentType, []byte(account+"\r\n"))
	}
}

func (a *AuthState) runAuthPipelineFSM(ctx *gin.Context) {
	current := authFSMStateInit
	nextState, err := a.advanceAuthFSM(current, authFSMEventParseOK)
	if err != nil {
		ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)

		return
	}

	current = nextState

	if abort := a.preprocessBasicEndpointInput(ctx); abort {
		if _, err = a.advanceAuthFSM(current, authFSMEventAbort); err != nil {
			ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)
		}

		return
	}

	if a.Request.Service == definitions.ServIdP {
		a.handleMasterUserMode()
	}

	if ctx.GetBool(definitions.CtxLocalCacheAuthKey) {
		// Local-cache hit represents a previously authenticated identity.
		// Ensure subject-source predicates based on Authenticated evaluate consistently.
		a.Runtime.Authenticated = true
	}

	preAuthResult := a.HandleEnvironment(ctx)

	event, ok := mapPreAuthResultToFSMEvent(preAuthResult)
	if !ok {
		ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)

		return
	}

	nextState, err = nextAuthFSMState(current, event)
	if err != nil {
		ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)

		return
	}

	a.auditAuthFSMTransition(current, event, nextState)

	if nextState != authFSMStatePreAuthChecked {
		a.applyPreAuthFSMOutcome(ctx, nextState, preAuthResult)

		return
	}

	current = nextState

	if handled := a.handleBasicEndpointAuthPhase(ctx, current); handled {
		return
	}

	passwordResult := a.HandlePassword(ctx)

	nextState, err = nextAuthFSMState(current, authFSMEventAuthEvaluated)
	if err != nil {
		ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)

		return
	}

	a.auditAuthFSMTransition(current, authFSMEventAuthEvaluated, nextState)
	current = nextState

	event, ok = mapAuthPasswordResultToFSMEvent(passwordResult)
	if !ok {
		ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)

		return
	}

	nextState, err = nextAuthFSMState(current, event)
	if err != nil {
		ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)

		return
	}

	a.auditAuthFSMTransition(current, event, nextState)
	a.applyPasswordFSMOutcome(ctx, nextState, passwordResult)
}

func (a *AuthState) auditAuthFSMTransition(from authFSMState, event authFSMEvent, to authFSMState) {
	a.Runtime.AuthFSMEventPath = append(a.Runtime.AuthFSMEventPath, string(event))
	if isAuthFSMTerminal(to) {
		a.Runtime.AuthFSMTerminalState = string(to)
	}

	stats.GetMetrics().GetAuthFSMTransitionsTotal().WithLabelValues(string(from), string(event), string(to)).Inc()
	observability.DefaultRecorder().RecordFSMTransition(a.Ctx(), observability.FSMMeasurement{
		Result:         observability.ResultSuccess,
		FSMEventMarker: string(event),
		Operation:      a.policyOperation(),
		Stage:          authFSMMetricStage(event),
	})

	if a.deps.Logger == nil || a.deps.Cfg == nil {
		return
	}

	if a.deps.Cfg.GetServer().GetLog().GetLogLevel() < definitions.LogLevelDebug {
		return
	}

	level.Debug(a.deps.Logger).Log(
		definitions.LogKeyGUID, a.Runtime.GUID,
		"component", "auth_fsm",
		"from", string(from),
		"event", string(event),
		"to", string(to),
	)
}

func (a *AuthState) advanceAuthFSM(current authFSMState, event authFSMEvent) (authFSMState, error) {
	next, err := nextAuthFSMState(current, event)
	if err != nil {
		return "", err
	}

	a.auditAuthFSMTransition(current, event, next)

	return next, nil
}

func (a *AuthState) applyAuthFSMMarkers(markers []string) error {
	if a == nil || len(markers) == 0 || len(a.Runtime.AuthFSMEventPath) > 0 || a.Runtime.AuthFSMTerminalState != "" {
		return nil
	}

	current := authFSMStateInit
	for _, marker := range markers {
		next, err := a.advanceAuthFSM(current, authFSMEvent(marker))
		if err != nil {
			return err
		}

		current = next
	}

	return nil
}

func authFSMMetricStage(event authFSMEvent) policy.Stage {
	switch event {
	case authFSMEventAuthEvaluated:
		return policy.StageAuthBackend
	case authFSMEventAccountProviderEvaluated:
		return policy.StageAccountProvider
	case authFSMEventAuthPermit, authFSMEventAuthDeny, authFSMEventAuthTempFail, authFSMEventAuthEmptyUser, authFSMEventAuthEmptyPass:
		return policy.StageAuthDecision
	default:
		return policy.StagePreAuth
	}
}

func mapPreAuthResultToFSMEvent(result definitions.AuthResult) (authFSMEvent, bool) {
	switch result {
	case definitions.AuthResultPreAuthTLS:
		return authFSMEventPreAuthTempFail, true
	case definitions.AuthResultPreAuthRelayDomain, definitions.AuthResultPreAuthRBL, definitions.AuthResultLuaEnvironment:
		return authFSMEventPreAuthDeny, true
	case definitions.AuthResultUnset:
		return authFSMEventPreAuthAbort, true
	case definitions.AuthResultOK:
		return authFSMEventPreAuthOK, true
	case definitions.AuthResultTempFail:
		return authFSMEventPreAuthTempFail, true
	default:
		return "", false
	}
}

func (a *AuthState) applyPreAuthFSMOutcome(ctx *gin.Context, nextState authFSMState, preAuthResult definitions.AuthResult) bool {
	if nextState == authFSMStatePreAuthChecked {
		return false
	}

	dispatchAuthFSMTerminalOutcome(nextState, authFSMTerminalHandlers{
		onAuthFail: func() {
			result := GetPassDBResultFromPool()
			a.PostLuaAction(ctx, result)
			PutPassDBResultToPool(result)
			a.AuthFail(ctx)
			ctx.Abort()
		},
		onAuthTempFail: func() {
			if preAuthResult == definitions.AuthResultPreAuthTLS {
				result := GetPassDBResultFromPool()
				a.PostLuaAction(ctx, result)
				PutPassDBResultToPool(result)
				a.AuthTempFail(ctx, definitions.TempFailNoTLS)
				ctx.Abort()

				return
			}

			a.AuthTempFail(ctx, definitions.TempFailDefault)
			ctx.Abort()
		},
		// Keep previous behavior for AuthResultUnset: stop processing without aborting context.
		onAborted: func() {},
		onInvalid: func() {
			ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)
		},
	})

	return true
}

type authFSMTerminalHandlers struct {
	onAuthOK       func()
	onAuthFail     func()
	onAuthTempFail func()
	onAborted      func()
	onInvalid      func()
}

func dispatchAuthFSMTerminalOutcome(nextState authFSMState, handlers authFSMTerminalHandlers) bool {
	switch nextState {
	case authFSMStateAuthOK:
		if handlers.onAuthOK != nil {
			handlers.onAuthOK()
		}
		return true
	case authFSMStateAuthFail:
		if handlers.onAuthFail != nil {
			handlers.onAuthFail()
		}
		return true
	case authFSMStateAuthTempFail:
		if handlers.onAuthTempFail != nil {
			handlers.onAuthTempFail()
		}
		return true
	case authFSMStateAborted:
		if handlers.onAborted != nil {
			handlers.onAborted()
		}
		return true
	default:
		if handlers.onInvalid != nil {
			handlers.onInvalid()
		}
		return false
	}
}

func mapAuthPasswordResultToFSMEvent(result definitions.AuthResult) (authFSMEvent, bool) {
	switch result {
	case definitions.AuthResultOK:
		return authFSMEventAuthPermit, true
	case definitions.AuthResultFail:
		return authFSMEventAuthDeny, true
	case definitions.AuthResultTempFail:
		return authFSMEventAuthTempFail, true
	case definitions.AuthResultEmptyUsername:
		return authFSMEventAuthEmptyUser, true
	case definitions.AuthResultEmptyPassword:
		return authFSMEventAuthEmptyPass, true
	default:
		return "", false
	}
}

func (a *AuthState) applyPasswordFSMOutcome(ctx *gin.Context, nextState authFSMState, passwordResult definitions.AuthResult) {
	dispatchAuthFSMTerminalOutcome(nextState, authFSMTerminalHandlers{
		onAuthOK: func() {
			if a.deps.Tolerate != nil {
				a.deps.Tolerate.SetIPAddress(a.Ctx(), a.Request.ClientIP, a.Request.Username, true)
			}

			a.AuthOK(ctx)
		},
		onAuthFail: func() {
			if a.deps.Tolerate != nil {
				a.deps.Tolerate.SetIPAddress(a.Ctx(), a.Request.ClientIP, a.Request.Username, false)
			}

			a.AuthFail(ctx)
			ctx.Abort()
		},
		onAuthTempFail: func() {
			// Preserve legacy behavior: empty-username uses dedicated temp-fail reason.
			if passwordResult == definitions.AuthResultEmptyUsername {
				a.AuthTempFail(ctx, definitions.TempFailEmptyUser)
			} else {
				a.AuthTempFail(ctx, definitions.TempFailDefault)
			}

			ctx.Abort()
		},
		onInvalid: func() {
			ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)
		},
	})
}

// listBlockedIPAddresses retrieves a list of blocked IP addresses from Redis using the
// sharded ZSET ban index and per-network ban keys with TTL.
func listBlockedIPAddresses(ctx context.Context, deps restAdminDeps, filterCmd *bf.FilterCmd, pageQuery bruteForceListPageQuery, guid string) (*bf.BlockedIPAddresses, error) {
	blockedIPAddresses, err := validateBlockedIPListDeps(deps)
	if err != nil {
		return blockedIPAddresses, err
	}

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	cfg := deps.effectiveCfg()
	prefix := cfg.GetServer().GetRedis().GetPrefix()
	ruleMap := bruteForceBanTimeByBucket(cfg)

	if filterCmd != nil && len(filterCmd.IPAddress) > 0 {
		entries := collectFilteredBruteForceBanIndexEntries(ctx, deps, filterCmd.IPAddress, guid)
		hasMore := false

		if pageQuery.Enabled() {
			entries, hasMore = pageBruteForceBanIndexEntries(entries, pageQuery)
		}

		return buildBlockedIPAddressesFromIndexEntries(ctx, deps, prefix, ruleMap, entries, pageQuery, hasMore, guid)
	}

	entries, err := readBruteForceBanIndexEntries(ctx, deps, pageQuery, guid)
	if err != nil {
		errMsg := err.Error()
		blockedIPAddresses.Error = &errMsg

		return blockedIPAddresses, err
	}

	var hasMore bool
	if pageQuery.Enabled() {
		entries, hasMore = pageBruteForceBanIndexEntries(entries, pageQuery)
	}

	return buildBlockedIPAddressesFromIndexEntries(ctx, deps, prefix, ruleMap, entries, pageQuery, hasMore, guid)
}

// validateBlockedIPListDeps prepares the response object and validates required dependencies.
func validateBlockedIPListDeps(deps restAdminDeps) (*bf.BlockedIPAddresses, error) {
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

	return blockedIPAddresses, nil
}

// bruteForceBanTimeByBucket builds a lookup map from bucket name to configured ban time.
func bruteForceBanTimeByBucket(cfg config.File) map[string]time.Duration {
	ruleMap := make(map[string]time.Duration)
	if bfCfg := cfg.GetBruteForce(); bfCfg != nil {
		for i := range bfCfg.Buckets {
			ruleMap[bfCfg.Buckets[i].Name] = bfCfg.Buckets[i].GetBanTime()
		}
	}

	return ruleMap
}

// readBruteForceBanIndexEntries reads bounded candidate entries from all ban-index shards.
func readBruteForceBanIndexEntries(
	ctx context.Context,
	deps restAdminDeps,
	pageQuery bruteForceListPageQuery,
	guid string,
) ([]bruteForceBanIndexEntry, error) {
	cfg := deps.effectiveCfg()
	logger := deps.effectiveLogger()
	prefix := cfg.GetServer().GetRedis().GetPrefix()
	indexKeys := rediscli.GetAllBruteForceBanIndexKeys(prefix)

	dCtxR, cancelR := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
	defer cancelR()

	pipe := deps.Redis.GetReadHandle().Pipeline()
	rangeCmds := make([]*redis.ZSliceCmd, len(indexKeys))

	for i, key := range indexKeys {
		rangeCmds[i] = pipe.ZRangeWithScores(dCtxR, key, 0, pageQuery.Stop())
	}

	_, err := pipe.Exec(dCtxR)
	if err != nil && !stderrors.Is(err, redis.Nil) {
		_ = level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error reading ban index shards",
			definitions.LogKeyError, err,
		)

		return nil, err
	}

	return decodeBruteForceBanIndexEntries(rangeCmds), nil
}

// decodeBruteForceBanIndexEntries normalizes Redis ZSET members into ban-index entries.
func decodeBruteForceBanIndexEntries(rangeCmds []*redis.ZSliceCmd) []bruteForceBanIndexEntry {
	entries := make([]bruteForceBanIndexEntry, 0)
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

			entries = append(entries, bruteForceBanIndexEntry{network: networkStr, bannedAt: z.Score})
		}
	}

	return entries
}

// collectFilteredBruteForceBanIndexEntries derives candidate ban networks from explicit IP filters.
func collectFilteredBruteForceBanIndexEntries(
	ctx context.Context,
	deps restAdminDeps,
	ipAddresses []string,
	guid string,
) []bruteForceBanIndexEntry {
	cfg := deps.effectiveCfg()
	entries := make([]bruteForceBanIndexEntry, 0)
	seenNetworks := make(map[string]struct{})

	for _, ipAddress := range uniqueStrings(ipAddresses) {
		parsedIP := net.ParseIP(ipAddress)
		if parsedIP == nil {
			continue
		}

		bm := createBucketManager(ctx, deps, guid, ipAddress, "", "")
		isIPv4 := parsedIP.To4() != nil

		for _, rule := range cfg.GetBruteForceRules() {
			if rule.IPv4 != isIPv4 {
				continue
			}

			_, network, err := bm.GetBruteForceBanRedisKey(&rule)
			if err != nil || network == "" {
				continue
			}

			if _, exists := seenNetworks[network]; exists {
				continue
			}

			seenNetworks[network] = struct{}{}
			entries = append(entries, bruteForceBanIndexEntry{network: network})
		}
	}

	return entries
}

// buildBlockedIPAddressesFromIndexEntries hydrates candidate networks into response entries.
func buildBlockedIPAddressesFromIndexEntries(
	ctx context.Context,
	deps restAdminDeps,
	prefix string,
	ruleMap map[string]time.Duration,
	entries []bruteForceBanIndexEntry,
	pageQuery bruteForceListPageQuery,
	hasMore bool,
	guid string,
) (*bf.BlockedIPAddresses, error) {
	blockedIPAddresses := &bf.BlockedIPAddresses{}
	if len(entries) == 0 {
		blockedIPAddresses.Entries = []bf.BanEntry{}
		blockedIPAddresses.Page = pageQuery.PageInfo(false)

		return blockedIPAddresses, nil
	}

	logger := deps.effectiveLogger()

	getCmds, ttlCmds, err := queueBruteForceBanDetailReads(ctx, deps, prefix, entries)
	if err != nil {
		_ = level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error hydrating brute-force ban entries",
			definitions.LogKeyError, err,
		)

		errMsg := err.Error()
		blockedIPAddresses.Error = &errMsg

		return blockedIPAddresses, err
	}

	banEntries, cleanupNetworks := buildHydratedBruteForceBanEntries(time.Now(), ruleMap, entries, getCmds, ttlCmds)

	cleanupStaleBruteForceBanIndexEntries(deps, prefix, cleanupNetworks, guid, logger)

	blockedIPAddresses.Entries = banEntries
	blockedIPAddresses.Page = pageQuery.PageInfo(hasMore)

	return blockedIPAddresses, nil
}

// queueBruteForceBanDetailReads queues per-network bucket and TTL reads.
func queueBruteForceBanDetailReads(
	ctx context.Context,
	deps restAdminDeps,
	prefix string,
	entries []bruteForceBanIndexEntry,
) ([]*redis.StringCmd, []*redis.DurationCmd, error) {
	cfg := deps.effectiveCfg()

	dCtxR, cancelR := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
	defer cancelR()

	pipe := deps.Redis.GetReadHandle().Pipeline()
	getCmds := make([]*redis.StringCmd, len(entries))
	ttlCmds := make([]*redis.DurationCmd, len(entries))

	for i, entry := range entries {
		banKey := rediscli.GetBruteForceBanKey(prefix, entry.network)
		getCmds[i] = pipe.Get(dCtxR, banKey)
		ttlCmds[i] = pipe.TTL(dCtxR, banKey)
	}

	_, err := pipe.Exec(dCtxR)
	if err != nil && !stderrors.Is(err, redis.Nil) {
		return nil, nil, err
	}

	return getCmds, ttlCmds, nil
}

// buildHydratedBruteForceBanEntries converts Redis read results into response entries.
func buildHydratedBruteForceBanEntries(
	now time.Time,
	ruleMap map[string]time.Duration,
	entries []bruteForceBanIndexEntry,
	getCmds []*redis.StringCmd,
	ttlCmds []*redis.DurationCmd,
) ([]bf.BanEntry, []string) {
	cleanupNetworks := make([]string, 0)
	banEntries := make([]bf.BanEntry, 0, len(entries))

	for i, entry := range entries {
		bucket, getErr := getCmds[i].Result()
		if getErr != nil || bucket == "" {
			cleanupNetworks = append(cleanupNetworks, entry.network)

			continue
		}

		ttlVal, ttlErr := ttlCmds[i].Result()
		if ttlErr != nil || ttlVal < 0 {
			cleanupNetworks = append(cleanupNetworks, entry.network)

			continue
		}

		configuredBanTime := definitions.DefaultBanTime
		if bt, found := ruleMap[bucket]; found {
			configuredBanTime = bt
		}

		banEntries = append(banEntries, bf.BanEntry{
			Network:  entry.network,
			Bucket:   bucket,
			BanTime:  configuredBanTime,
			TTL:      ttlVal,
			BannedAt: now.Add(-(configuredBanTime - ttlVal)),
		})
	}

	return banEntries, cleanupNetworks
}

// cleanupStaleBruteForceBanIndexEntries removes stale ban-index members in the background.
func cleanupStaleBruteForceBanIndexEntries(
	deps restAdminDeps,
	prefix string,
	networks []string,
	guid string,
	logger *slog.Logger,
) {
	if len(networks) == 0 {
		return
	}

	cfg := deps.effectiveCfg()
	go func() {
		cleanupCtx, cleanupCancel := util.GetCtxWithDeadlineRedisWrite(context.Background(), cfg)
		defer cleanupCancel()

		cleanupPipe := deps.Redis.GetWriteHandle().Pipeline()

		for _, network := range networks {
			shard := rediscli.GetBanIndexShard(network)
			shardKey := rediscli.GetBruteForceBanIndexShardKey(prefix, shard)
			cleanupPipe.ZRem(cleanupCtx, shardKey, network)
		}

		if _, err := cleanupPipe.Exec(cleanupCtx); err != nil {
			_ = level.Warn(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Lazy cleanup of stale ban index entries failed",
				definitions.LogKeyError, err,
			)
		}
	}()
}

// pageBruteForceBanIndexEntries sorts and slices ban-index entries for a page.
func pageBruteForceBanIndexEntries(entries []bruteForceBanIndexEntry, pageQuery bruteForceListPageQuery) ([]bruteForceBanIndexEntry, bool) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].bannedAt == entries[j].bannedAt {
			return entries[i].network < entries[j].network
		}

		return entries[i].bannedAt < entries[j].bannedAt
	})

	start := pageQuery.offset
	if start >= int64(len(entries)) {
		return []bruteForceBanIndexEntry{}, false
	}

	end := start + pageQuery.limit

	hasMore := int64(len(entries)) > end
	if end > int64(len(entries)) {
		end = int64(len(entries))
	}

	return entries[int(start):int(end)], hasMore
}

// listBlockedAccounts retrieves affected accounts and their known IP history from Redis.
func listBlockedAccounts(ctx context.Context, deps restAdminDeps, filterCmd *bf.FilterCmd, pageQuery bruteForceListPageQuery, guid string) (*bf.BlockedAccounts, error) {
	blockedAccounts, err := validateBlockedAccountsDeps(deps)
	if err != nil {
		return blockedAccounts, err
	}

	logger := deps.effectiveLogger()
	cfg := deps.effectiveCfg()
	prefix := cfg.GetServer().GetRedis().GetPrefix()
	key := prefix + definitions.RedisAffectedAccountsKey

	accounts, hasMore, err := listBlockedAccountNames(ctx, deps, filterCmd, pageQuery, key)
	if err != nil {
		if !stderrors.Is(err, redis.Nil) {
			_ = level.Error(logger).Log(
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

	if err = populateBlockedAccountIPHistory(ctx, deps, prefix, accounts, blockedAccounts, guid); err != nil {
		return blockedAccounts, err
	}

	blockedAccounts.Error = nil
	blockedAccounts.Page = pageQuery.PageInfo(hasMore)

	return blockedAccounts, err
}

// validateBlockedAccountsDeps prepares the response object and validates required dependencies.
func validateBlockedAccountsDeps(deps restAdminDeps) (*bf.BlockedAccounts, error) {
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

	return blockedAccounts, nil
}

// populateBlockedAccountIPHistory attaches known password-history IPs to each account.
func populateBlockedAccountIPHistory(
	ctx context.Context,
	deps restAdminDeps,
	prefix string,
	accounts []string,
	blockedAccounts *bf.BlockedAccounts,
	guid string,
) error {
	logger := deps.effectiveLogger()

	for _, account := range accounts {
		key := prefix + definitions.RedisPWHistIPsKey + ":" + account
		accountIPs, err := deps.Redis.GetReadHandle().SMembers(ctx, key).Result()

		stats.GetMetrics().GetRedisReadCounter().Inc()

		if err == nil {
			blockedAccounts.Accounts[account] = accountIPs

			continue
		}

		if stderrors.Is(err, redis.Nil) {
			continue
		}

		_ = level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error retrieving IP addresses for account from Redis",
			definitions.LogKeyError, err,
		)

		errMsg := err.Error()
		blockedAccounts.Error = &errMsg

		return err
	}

	return nil
}

// listBlockedAccountNames selects account names using filters, the legacy set, or the paged index.
func listBlockedAccountNames(
	ctx context.Context,
	deps restAdminDeps,
	filterCmd *bf.FilterCmd,
	pageQuery bruteForceListPageQuery,
	key string,
) ([]string, bool, error) {
	if filterCmd != nil && len(filterCmd.Accounts) > 0 {
		return listFilteredBlockedAccountNames(ctx, deps, filterCmd.Accounts, key, pageQuery)
	}

	if pageQuery.Enabled() {
		return listPagedBlockedAccountNames(ctx, deps, pageQuery)
	}

	stats.GetMetrics().GetRedisReadCounter().Inc()

	accounts, err := deps.Redis.GetReadHandle().SMembers(ctx, key).Result()

	return accounts, false, err
}

// listFilteredBlockedAccountNames checks requested accounts directly against the affected-account set.
func listFilteredBlockedAccountNames(
	ctx context.Context,
	deps restAdminDeps,
	wantedAccounts []string,
	key string,
	pageQuery bruteForceListPageQuery,
) ([]string, bool, error) {
	uniqueAccounts := uniqueStrings(wantedAccounts)
	if len(uniqueAccounts) == 0 {
		return []string{}, false, nil
	}

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, deps.effectiveCfg())
	defer cancel()

	pipe := deps.Redis.GetReadHandle().Pipeline()
	memberCmds := make([]*redis.BoolCmd, len(uniqueAccounts))

	for index, account := range uniqueAccounts {
		memberCmds[index] = pipe.SIsMember(dCtx, key, account)
	}

	if _, err := pipe.Exec(dCtx); err != nil && !stderrors.Is(err, redis.Nil) {
		return nil, false, err
	}

	stats.GetMetrics().GetRedisReadCounter().Inc()

	accounts := make([]string, 0, len(uniqueAccounts))

	for index, cmd := range memberCmds {
		isMember, err := cmd.Result()
		if err != nil && !stderrors.Is(err, redis.Nil) {
			return nil, false, err
		}

		if isMember {
			accounts = append(accounts, uniqueAccounts[index])
		}
	}

	if !pageQuery.Enabled() {
		return accounts, false, nil
	}

	return pageStringSlice(accounts, pageQuery)
}

// listPagedBlockedAccountNames reads a bounded account page from the sorted account index.
func listPagedBlockedAccountNames(
	ctx context.Context,
	deps restAdminDeps,
	pageQuery bruteForceListPageQuery,
) ([]string, bool, error) {
	cfg := deps.effectiveCfg()
	prefix := cfg.GetServer().GetRedis().GetPrefix()
	indexKey := rediscli.GetAffectedAccountsIndexKey(prefix)

	accounts, err := readPagedBlockedAccountIndex(ctx, deps, indexKey, pageQuery)
	if err != nil {
		return nil, false, err
	}

	return trimOverfetchedStrings(accounts, pageQuery.limit), len(accounts) > int(pageQuery.limit), nil
}

// readPagedBlockedAccountIndex reads one overfetched account page from the sorted account index.
func readPagedBlockedAccountIndex(
	ctx context.Context,
	deps restAdminDeps,
	indexKey string,
	pageQuery bruteForceListPageQuery,
) ([]string, error) {
	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, deps.effectiveCfg())
	defer cancel()

	stats.GetMetrics().GetRedisReadCounter().Inc()

	return deps.Redis.GetReadHandle().ZRange(dCtx, indexKey, pageQuery.offset, pageQuery.Stop()).Result()
}

// pageStringSlice applies page controls to an in-memory string slice.
func pageStringSlice(values []string, pageQuery bruteForceListPageQuery) ([]string, bool, error) {
	if !pageQuery.Enabled() {
		return values, false, nil
	}

	if pageQuery.offset >= int64(len(values)) {
		return []string{}, false, nil
	}

	end := pageQuery.offset + pageQuery.limit

	hasMore := int64(len(values)) > end
	if end > int64(len(values)) {
		end = int64(len(values))
	}

	return values[int(pageQuery.offset):int(end)], hasMore, nil
}

// trimOverfetchedStrings removes the extra lookahead element from a paged string slice.
func trimOverfetchedStrings(values []string, limit int64) []string {
	if int64(len(values)) <= limit {
		return values
	}

	return values[:int(limit)]
}

// uniqueStrings removes duplicate strings while preserving first-seen order.
func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))

	for _, value := range values {
		if value == "" {
			continue
		}

		if _, exists := seen[value]; exists {
			continue
		}

		seen[value] = struct{}{}
		result = append(result, value)
	}

	return result
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

// handleBruteForceList renders blocked IP and account data for the management list endpoint.
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

	pageQuery, err := parseBruteForceListPageQuery(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})

		return
	}

	if ctx.Request.Method == http.MethodPost {
		filterCmd, err = bindOptionalBruteForceFilter(ctx)
		if err != nil {
			HandleJSONError(ctx, err)

			return
		}
	}

	blockedIPAddresses, err := listBlockedIPAddresses(ctx, deps, filterCmd, pageQuery, guid)
	if err != nil {
		httpStatusCode = http.StatusInternalServerError
	}

	blockedAccounts, err := listBlockedAccounts(ctx, deps, filterCmd, pageQuery, guid)
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

// bindOptionalBruteForceFilter binds a POST filter body while allowing an empty optional body.
func bindOptionalBruteForceFilter(ctx *gin.Context) (*bf.FilterCmd, error) {
	if ctx.Request.Body == nil {
		return nil, nil
	}

	rawBody, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(string(rawBody)) == "" {
		return nil, nil
	}

	ctx.Request.Body = io.NopCloser(bytes.NewReader(rawBody))

	filterCmd := &bf.FilterCmd{}
	if err = ctx.ShouldBindJSON(filterCmd); err != nil {
		return nil, err
	}

	return filterCmd, nil
}

// HandleConfigLoad handles loading the server configuration with strict auth checks.
// If OIDC backchannel auth is enabled, a valid Bearer token with security/admin
// scope is required. If only Basic auth is enabled, the request must have passed
// Basic auth middleware. On success, the configuration is returned as JSON.
func (deps restAdminDeps) HandleConfigLoad(ctx *gin.Context) {
	if err := deps.validate(); err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	cfg := deps.effectiveCfg()
	logger := deps.effectiveLogger()

	basicAuthEnabled := cfg.GetServer().GetBasicAuth().IsEnabled()
	oidcAuthEnabled := cfg.GetServer().GetOIDCAuth().IsEnabled()
	developerMode := getDefaultEnvironment().GetDevMode()

	// Backchannel config endpoint must never be reachable without at least one auth mechanism.
	if !developerMode && !basicAuthEnabled && !oidcAuthEnabled {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "backchannel authentication is not configured"})

		return
	}

	basicAuthValidated, _ := ctx.Get(definitions.CtxBasicAuthValidatedKey)

	// Check if OIDC Bearer token has the required scope.
	claims := oidcbearer.GetClaimsFromContext(ctx)
	if oidcAuthEnabled {
		if claims == nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid authorization header"})

			return
		}

		if !oidcbearer.HasAnyScope(claims, definitions.ScopeSecurity, definitions.ScopeAdmin) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "missing required scope: " + definitions.ScopeSecurity + " or " + definitions.ScopeAdmin})

			return
		}
	} else if basicAuthEnabled {
		authenticated, ok := basicAuthValidated.(bool)
		if !ok || !authenticated {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid authorization header"})

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

// processFlushCache takes a user command and a GUID and processes the
// instance-local cache flush. The endpoint also applies to split deployments
// where an edge may use only remote backends but still owns local IdP tokens,
// session-adjacent Redis keys, and optional edge cache state.
func processFlushCache(ctx *gin.Context, deps restAdminDeps, userCmd *admin.FlushUserCmd, guid string) (removedKeys []string, noUserAccountFound bool) {
	return processUserCmd(ctx, deps, userCmd, guid)
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

	// Run optional Lua cache flush script before account lookup.
	var luaAdditionalKeys []string

	luaResult, luaErr := cacheflush.RunCacheFlushScript(ctx.Request.Context(), cfg, logger, redisClient, userCmd.User, guid)
	if luaErr != nil {
		_ = level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error executing Lua cache flush script",
			definitions.LogKeyError, luaErr,
		)
	} else if luaResult != nil {
		luaAdditionalKeys = luaResult.AdditionalKeys
	}

	cleanupAccounts := config.NewStringSet()
	tokenAccounts := config.NewStringSet()
	userKeys := config.NewStringSet()
	ipAddressSet := config.NewStringSet()

	var mappedAccounts config.StringSet
	var hashFields config.StringSet

	// If the Lua script provided an account name, use it directly instead of looking up account mappings.
	if luaResult != nil && luaResult.AccountName != "" {
		_ = level.Info(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Lua cache flush script provided account name, skipping account lookup",
			"account", luaResult.AccountName,
		)

		mappedAccounts = config.NewStringSet()
		mappedAccounts.Set(luaResult.AccountName)
		hashFields = config.NewStringSet()
	} else {
		mappedAccounts, hashFields = collectUserAccountMappings(ctx.Request.Context(), deps, userCmd.User, guid)
	}

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
		prefix := cfg.GetServer().GetRedis().GetPrefix()
		key := prefix + definitions.RedisAffectedAccountsKey

		if result, err = redisClient.GetWriteHandle().SRem(ctx, key, members...).Result(); err != nil {
			_ = level.Error(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Error while flushing AFFECTED_ACCOUNTS",
				definitions.LogKeyError, err,
			)
		} else if result > 0 {
			removedKeySet.Set(key)
		}

		indexKey := rediscli.GetAffectedAccountsIndexKey(prefix)
		if _, err = redisClient.GetWriteHandle().ZRem(ctx, indexKey, members...).Result(); err != nil {
			_ = level.Error(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Error while flushing affected-account index",
				definitions.LogKeyError, err,
			)
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

	// Delete additional Redis keys provided by the Lua cache flush script.
	if len(luaAdditionalKeys) > 0 {
		stats.GetMetrics().GetRedisWriteCounter().Inc()

		unlinkResult, unlinkErr := redisClient.GetWriteHandle().Unlink(ctx, luaAdditionalKeys...).Result()
		if unlinkErr != nil {
			_ = level.Error(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Error while unlinking Lua-provided additional keys",
				definitions.LogKeyError, unlinkErr,
			)
		} else if unlinkResult > 0 {
			for _, key := range luaAdditionalKeys {
				removedKeySet.Set(key)
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

type asyncJobState string

type asyncJobEvent string

const (
	asyncJobStateQueued     asyncJobState = jobStatusQueued
	asyncJobStateInProgress asyncJobState = jobStatusInProgress
	asyncJobStateDone       asyncJobState = jobStatusDone
	asyncJobStateError      asyncJobState = jobStatusError
)

const (
	asyncJobEventStart   asyncJobEvent = "start"
	asyncJobEventSucceed asyncJobEvent = "succeed"
	asyncJobEventFail    asyncJobEvent = "fail"
)

var errAsyncJobNotFound = stderrors.New("async job not found")

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

func nextAsyncJobState(current asyncJobState, event asyncJobEvent) (asyncJobState, error) {
	switch current {
	case asyncJobStateQueued:
		if event == asyncJobEventStart {
			return asyncJobStateInProgress, nil
		}
	case asyncJobStateInProgress:
		switch event {
		case asyncJobEventSucceed:
			return asyncJobStateDone, nil
		case asyncJobEventFail:
			return asyncJobStateError, nil
		}
	}

	return "", fmt.Errorf("invalid async job transition: state=%s event=%s", current, event)
}

func applyAsyncJobTransition(
	ctx context.Context,
	deps asyncJobDeps,
	jobID string,
	event asyncJobEvent,
	fields map[string]any,
) (asyncJobState, error) {
	key := asyncJobKey(deps.Cfg, jobID)

	var nextState asyncJobState

	for range 3 {
		err := deps.Redis.GetWriteHandle().Watch(ctx, func(tx *redis.Tx) error {
			status, err := tx.HGet(ctx, key, "status").Result()
			if err != nil {
				if stderrors.Is(err, redis.Nil) {
					return errAsyncJobNotFound
				}

				return err
			}

			nextState, err = nextAsyncJobState(asyncJobState(status), event)
			if err != nil {
				return err
			}

			updates := make(map[string]any, len(fields)+1)
			updates["status"] = string(nextState)

			maps.Copy(updates, fields)

			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, key, updates)

				return nil
			})

			return err
		}, key)

		if err == nil {
			stats.GetMetrics().GetRedisWriteCounter().Inc()

			return nextState, nil
		}

		if stderrors.Is(err, redis.TxFailedErr) {
			continue
		}

		return "", err
	}

	return "", fmt.Errorf("async job transition failed due to concurrent updates: job=%s event=%s", jobID, event)
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

		// Mark INPROGRESS
		if _, err := applyAsyncJobTransition(base, deps, jobID, asyncJobEventStart, map[string]any{
			"startedAt": now().UTC().Format(time.RFC3339Nano),
		}); err != nil {
			level.Error(deps.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "async job start transition failed",
				"jobId", jobID,
				definitions.LogKeyError, err,
			)

			return
		}

		// Execute task
		count, _, err := fn(base)

		// Persist final state
		updates := map[string]any{
			"finishedAt":  now().UTC().Format(time.RFC3339Nano),
			"resultCount": count,
		}

		key := asyncJobKey(deps.Cfg, jobID)

		event := asyncJobEventSucceed
		if err != nil {
			event = asyncJobEventFail
			updates["error"] = err.Error()
			level.Error(deps.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "async job failed", definitions.LogKeyError, err)
		}

		if _, transitionErr := applyAsyncJobTransition(base, deps, jobID, event, updates); transitionErr != nil {
			level.Error(deps.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "async job completion transition failed",
				"jobId", jobID,
				definitions.LogKeyError, transitionErr,
			)

			return
		}

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

type bruteForceBanFlushTarget struct {
	key      string
	network  string
	ruleName string
}

type bruteForceFlushPlan struct {
	banTargets map[string]bruteForceBanFlushTarget
	bucketKeys config.StringSet
}

func newBruteForceFlushPlan() *bruteForceFlushPlan {
	return &bruteForceFlushPlan{
		banTargets: make(map[string]bruteForceBanFlushTarget),
		bucketKeys: config.NewStringSet(),
	}
}

func (plan *bruteForceFlushPlan) addBanTarget(target bruteForceBanFlushTarget) {
	if target.key == "" || target.network == "" {
		return
	}

	existing, found := plan.banTargets[target.key]
	if !found || (existing.ruleName != "*" && target.ruleName == "*") {
		plan.banTargets[target.key] = target
	}
}

func (plan *bruteForceFlushPlan) addBucketKeys(keys []string) {
	for _, key := range keys {
		if key == "" {
			continue
		}

		plan.bucketKeys.Set(key)
	}
}

func collectBruteForceFlushTargets(plan *bruteForceFlushPlan, bm bruteforce.BucketManager, rule *config.BruteForceRule, ruleName string) error {
	banKey, network, err := bm.GetBruteForceBanRedisKey(rule)
	if err != nil {
		return err
	}

	plan.addBanTarget(bruteForceBanFlushTarget{
		key:      banKey,
		network:  network,
		ruleName: ruleName,
	})
	plan.addBucketKeys(bm.GetBucketKeys(rule))

	return nil
}

// collectBruteForceCombinations collects combinations of protocols and OIDC Client IDs defined in a brute force rule.
func collectBruteForceCombinations(plan *bruteForceFlushPlan, ctx *gin.Context, deps restAdminDeps, guid string, cmd *bf.FlushRuleCmd, rule *config.BruteForceRule) error {
	cfg := deps.effectiveCfg()

	// 1) Cartesian product of FilterByProtocol × FilterByOIDCCID
	for _, proto := range rule.FilterByProtocol {
		oidcCids := rule.FilterByOIDCCID
		if len(oidcCids) == 0 {
			oidcCids = []string{""} // protocol-only variant
		}

		for _, cid := range oidcCids {
			bm := createBucketManager(ctx.Request.Context(), deps, guid, cmd.IPAddress, proto, cid)

			if err := collectBruteForceFlushTargets(plan, bm, rule, cmd.RuleName); err != nil {
				return err
			}
		}
	}

	// 2) OIDC-CID only (when no protocol filters are present)
	if len(rule.FilterByProtocol) == 0 {
		for _, cid := range rule.FilterByOIDCCID {
			bm := createBucketManager(ctx.Request.Context(), deps, guid, cmd.IPAddress, "", cid)

			if err := collectBruteForceFlushTargets(plan, bm, rule, cmd.RuleName); err != nil {
				return err
			}
		}
	}

	// 3) Safety net: iterate over every configured protocol
	for _, proto := range cfg.GetAllProtocols() {
		bm := createBucketManager(ctx.Request.Context(), deps, guid, cmd.IPAddress, proto, "")

		if err := collectBruteForceFlushTargets(plan, bm, rule, cmd.RuleName); err != nil {
			return err
		}
	}

	return nil
}

func sortBruteForceBanTargets(targets map[string]bruteForceBanFlushTarget) []bruteForceBanFlushTarget {
	keys := make([]string, 0, len(targets))
	for key := range targets {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	sortedTargets := make([]bruteForceBanFlushTarget, 0, len(keys))
	for _, key := range keys {
		sortedTargets = append(sortedTargets, targets[key])
	}

	return sortedTargets
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

func removeBruteForceBansFromIndex(ctx context.Context, deps restAdminDeps, guid string, removedTargets []bruteForceBanFlushTarget) {
	if len(removedTargets) == 0 {
		return
	}

	cfg := deps.effectiveCfg()
	logger := deps.effectiveLogger()
	redisClient := deps.effectiveRedis()
	prefix := cfg.GetServer().GetRedis().GetPrefix()

	pipe := redisClient.GetWriteHandle().Pipeline()
	for _, target := range removedTargets {
		shardKey := rediscli.GetBruteForceBanIndexShardKey(prefix, rediscli.GetBanIndexShard(target.network))
		pipe.ZRem(ctx, shardKey, target.network)
	}

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
	defer cancel()

	if _, err := pipe.Exec(dCtx); err != nil {
		_ = level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Error removing networks from brute force ban index ZSET",
			definitions.LogKeyError, err,
		)

		return
	}

	stats.GetMetrics().GetRedisWriteCounter().Inc()
}

func bulkDeleteBruteForceBanTargets(ctx context.Context, deps restAdminDeps, guid string, targets []bruteForceBanFlushTarget) ([]string, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	logger := deps.effectiveLogger()
	cfg := deps.effectiveCfg()
	redisClient := deps.effectiveRedis()

	pipe := redisClient.GetWriteHandle().Pipeline()
	for _, target := range targets {
		pipe.Del(ctx, target.key)
	}

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
	defer cancel()

	cmds, err := pipe.Exec(dCtx)
	if err != nil {
		return nil, err
	}

	stats.GetMetrics().GetRedisWriteCounter().Inc()

	removed := make([]string, 0, len(targets))
	removedTargets := make([]bruteForceBanFlushTarget, 0, len(targets))

	for index, target := range targets {
		if index >= len(cmds) {
			continue
		}

		intCmd, ok := cmds[index].(*redis.IntCmd)
		if !ok {
			continue
		}

		if removedCount, resultErr := intCmd.Result(); resultErr == nil && removedCount > 0 {
			removed = append(removed, target.key)
			removedTargets = append(removedTargets, target)
			_ = level.Info(logger).Log(definitions.LogKeyGUID, guid, "key", target.key, "status", "flushed")
		}
	}

	removeBruteForceBansFromIndex(ctx, deps, guid, removedTargets)

	return removed, nil
}

func deleteMatchingBruteForceBanTargets(ctx context.Context, deps restAdminDeps, guid string, targets []bruteForceBanFlushTarget) ([]string, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	cfg := deps.effectiveCfg()
	redisClient := deps.effectiveRedis()

	pipe := redisClient.GetReadHandle().Pipeline()
	for _, target := range targets {
		pipe.Get(ctx, target.key)
	}

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
	defer cancel()

	cmds, err := pipe.Exec(dCtx)
	if err != nil && !stderrors.Is(err, redis.Nil) {
		return nil, err
	}

	stats.GetMetrics().GetRedisReadCounter().Inc()

	deleteTargets := make([]bruteForceBanFlushTarget, 0, len(targets))
	for index, target := range targets {
		if index >= len(cmds) {
			continue
		}

		stringCmd, ok := cmds[index].(*redis.StringCmd)
		if !ok {
			continue
		}

		current, resultErr := stringCmd.Result()
		if stderrors.Is(resultErr, redis.Nil) {
			continue
		}

		if resultErr != nil {
			return nil, resultErr
		}

		if current == target.ruleName {
			deleteTargets = append(deleteTargets, target)
		}
	}

	return bulkDeleteBruteForceBanTargets(ctx, deps, guid, deleteTargets)
}

func flushBruteForceBanTargets(ctx context.Context, deps restAdminDeps, guid string, targets map[string]bruteForceBanFlushTarget) ([]string, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	sortedTargets := sortBruteForceBanTargets(targets)
	wildcardTargets := make([]bruteForceBanFlushTarget, 0, len(sortedTargets))
	selectiveTargets := make([]bruteForceBanFlushTarget, 0, len(sortedTargets))

	for _, target := range sortedTargets {
		if target.ruleName == "*" {
			wildcardTargets = append(wildcardTargets, target)
		} else {
			selectiveTargets = append(selectiveTargets, target)
		}
	}

	removed := make([]string, 0, len(sortedTargets))

	if removedWildcard, err := bulkDeleteBruteForceBanTargets(ctx, deps, guid, wildcardTargets); err != nil {
		return nil, err
	} else if len(removedWildcard) > 0 {
		removed = append(removed, removedWildcard...)
	}

	if removedSelective, err := deleteMatchingBruteForceBanTargets(ctx, deps, guid, selectiveTargets); err != nil {
		return nil, err
	} else if len(removedSelective) > 0 {
		removed = append(removed, removedSelective...)
	}

	return removed, nil
}

func executeBruteForceFlushPlan(ctx context.Context, deps restAdminDeps, guid string, plan *bruteForceFlushPlan) ([]string, error) {
	removed := make([]string, 0)

	if removedBans, err := flushBruteForceBanTargets(ctx, deps, guid, plan.banTargets); err != nil {
		return nil, err
	} else if len(removedBans) > 0 {
		removed = append(removed, removedBans...)
	}

	bucketKeys := plan.bucketKeys.GetStringSlice()
	sort.Strings(bucketKeys)

	if removedBucketKeys, err := bulkUnlink(ctx, deps, guid, bucketKeys); err != nil {
		return nil, err
	} else if len(removedBucketKeys) > 0 {
		removed = append(removed, removedBucketKeys...)
	}

	return removed, nil
}

// processBruteForceRules processes and flushes brute force rules based on the provided command and context.
// It evaluates rule applicability, flushes matched rules, and removes derived and tolerable combinations.
func processBruteForceRules(ctx *gin.Context, deps restAdminDeps, cmd *bf.FlushRuleCmd, guid string) (hadError bool, removed []string, err error) {
	cfg := deps.effectiveCfg()
	plan := newBruteForceFlushPlan()

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
		if err = collectBruteForceFlushTargets(plan, bm, &rule, cmd.RuleName); err != nil {
			return true, nil, err
		}

		// Phase 3: flush all derived combinations (rule filters + safety net)
		if err = collectBruteForceCombinations(plan, ctx, deps, guid, cmd, &rule); err != nil {
			return true, nil, err
		}
	}

	// Phase 4: always drop tolerate-bucket keys for the IP using a single pipeline
	base := cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisBFTolerationPrefix + cmd.IPAddress
	keys := make([]string, 0, 1+len(trSuffixes))
	keys = append(keys, base)

	for _, s := range trSuffixes {
		keys = append(keys, base+s)
	}

	plan.addBucketKeys(keys)

	if removed, err = executeBruteForceFlushPlan(ctx.Request.Context(), deps, guid, plan); err != nil {
		return true, nil, err
	}

	return false, removed, nil
}

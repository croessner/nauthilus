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
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/bruteforce/l1"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
)

// handleBruteForceLuaAction handles the brute force Lua action based on the provided authentication state and rule config.
func (a *AuthState) handleBruteForceLuaAction(ctx *gin.Context, alreadyTriggered bool, rule *config.BruteForceRule, network *net.IPNet) {
	tr := monittrace.New("nauthilus/auth")
	bctx, bspan := tr.Start(ctx.Request.Context(), "auth.bruteforce.lua_action",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
		attribute.String("rule", rule.Name),
		attribute.Bool("already_triggered", alreadyTriggered),
	)

	ctx.Request = ctx.Request.WithContext(bctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(bctx)
	}

	defer bspan.End()

	cfg := a.cfg()

	if cfg.HaveLuaActions() {
		finished := make(chan action.Done)
		accountName := a.GetAccount()

		// Get a CommonRequest from the pool
		commonRequest := lualib.GetCommonRequest()

		// Set the fields
		commonRequest.Debug = cfg.GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
		// repeating is true if either pre-detection flagged (alreadyTriggered) or the
		// brute-force bucket counter has reached or exceeded the rule limit.
		bfCount := a.Security.BruteForceCounter[rule.Name]

		// Derive client_net robustly: prefer provided network; fallback to CIDR from ClientIP and rule.
		clientNet := ""

		if network != nil && network.IP != nil && network.Mask != nil {
			clientNet = network.String()
		} else if a.Request.ClientIP != "" && rule.CIDR > 0 {
			if _, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", a.Request.ClientIP, rule.CIDR)); err == nil && n != nil {
				clientNet = n.String()
			}
		}

		isRepeating := alreadyTriggered || (bfCount >= rule.GetFailedRequests())

		// If still unknown, combine account lookup + repeating flag via Redis pipeline
		if (!isRepeating || accountName == "") && clientNet != "" {
			prefix := a.cfg().GetServer().GetRedis().GetPrefix()
			userKey := rediscli.GetUserHashKey(prefix, a.Request.Username)
			bfKey := rediscli.GetBruteForceHashKey(prefix, clientNet)

			dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx.Request.Context(), a.cfg())
			pipe := a.Redis().GetReadHandle().Pipeline()
			userCmd := pipe.HGet(dCtx, userKey, a.Request.Username)
			bfCmd := pipe.HExists(dCtx, bfKey, clientNet)
			_, err := pipe.Exec(dCtx)
			cancel()

			if err == nil || errors.Is(err, redis.Nil) {
				acc, _ := userCmd.Result()
				rep, _ := bfCmd.Result()

				if accountName == "" && acc != "" {
					accountName = acc
					// Mirror into AuthState
					if a.Runtime.AccountField == "" {
						a.Runtime.AccountField = definitions.MetaUserAccount
					}

					if a.Attributes.Attributes == nil || len(a.Attributes.Attributes) == 0 {
						attrs := make(bktype.AttributeMapping)
						attrs[definitions.MetaUserAccount] = []any{acc}
						a.ReplaceAllAttributes(attrs)
					}

					// Store into in-process account cache
					a.AccountCache().Set(a.Cfg(), a.Request.Username, acc)
				}

				if !isRepeating && rep {
					isRepeating = true
				}
			}
		}

		bspan.SetAttributes(
			attribute.Bool("repeating", isRepeating),
			attribute.Int("bf.count", int(a.Security.BruteForceCounter[rule.Name])),
		)

		commonRequest.Repeating = isRepeating
		commonRequest.UserFound = func() bool { return accountName != "" }()
		commonRequest.Authenticated = false // unavailable
		commonRequest.NoAuth = a.Request.NoAuth
		commonRequest.BruteForceCounter = a.Security.BruteForceCounter[rule.Name]
		commonRequest.Service = a.Request.Service
		commonRequest.Session = a.Runtime.GUID
		commonRequest.ClientIP = a.Request.ClientIP
		commonRequest.ClientPort = a.Request.XClientPort
		commonRequest.ClientNet = clientNet
		commonRequest.ClientHost = a.Request.ClientHost
		commonRequest.ClientID = a.Request.XClientID
		commonRequest.LocalIP = a.Request.XLocalIP
		commonRequest.LocalPort = a.Request.XPort
		commonRequest.UserAgent = a.Request.UserAgent
		commonRequest.Username = a.Request.Username
		commonRequest.Account = accountName
		commonRequest.AccountField = a.GetAccountField()
		commonRequest.UniqueUserID = "" // unavailable
		commonRequest.DisplayName = ""  // unavailable
		commonRequest.Password = a.Request.Password
		commonRequest.Protocol = a.Request.Protocol.Get()
		commonRequest.BruteForceName = rule.Name
		commonRequest.FeatureName = a.Runtime.FeatureName
		commonRequest.StatusMessage = &a.Runtime.StatusMessage
		commonRequest.XSSL = a.Request.XSSL
		commonRequest.XSSLSessionID = a.Request.XSSLSessionID
		commonRequest.XSSLClientVerify = a.Request.XSSLClientVerify
		commonRequest.XSSLClientDN = a.Request.XSSLClientDN
		commonRequest.XSSLClientCN = a.Request.XSSLClientCN
		commonRequest.XSSLIssuer = a.Request.XSSLIssuer
		commonRequest.XSSLClientNotBefore = a.Request.XSSLClientNotBefore
		commonRequest.XSSLClientNotAfter = a.Request.XSSLClientNotAfter
		commonRequest.XSSLSubjectDN = a.Request.XSSLSubjectDN
		commonRequest.XSSLIssuerDN = a.Request.XSSLIssuerDN
		commonRequest.XSSLClientSubjectDN = a.Request.XSSLClientSubjectDN
		commonRequest.XSSLClientIssuerDN = a.Request.XSSLClientIssuerDN
		commonRequest.XSSLProtocol = a.Request.XSSLProtocol
		commonRequest.XSSLCipher = a.Request.XSSLCipher
		commonRequest.SSLSerial = a.Request.SSLSerial
		commonRequest.SSLFingerprint = a.Request.SSLFingerprint

		action.RequestChan <- &action.Action{
			LuaAction:     definitions.LuaActionBruteForce,
			Context:       a.Runtime.Context,
			FinishedChan:  finished,
			HTTPRequest:   ctx.Request,
			HTTPContext:   ctx,
			CommonRequest: commonRequest,
		}

		<-finished

		// Return the CommonRequest to the pool
		lualib.PutCommonRequest(commonRequest)
	}
}

// logBruteForceDebug logs debug information related to brute force authentication attempts.
func (a *AuthState) logBruteForceDebug(ctx context.Context) {
	util.DebugModuleWithCfg(
		ctx,
		a.Cfg(),
		a.Logger(),
		definitions.DbgBf,
		definitions.LogKeyGUID, a.Runtime.GUID,
		definitions.LogKeyClientIP, a.Request.ClientIP,
		definitions.LogKeyClientPort, a.Request.XClientPort,
		definitions.LogKeyClientHost, a.Request.ClientHost,
		definitions.LogKeyClientID, a.Request.XClientID,
		definitions.LogKeyLocalIP, a.Request.XLocalIP,
		definitions.LogKeyPort, a.Request.XPort,
		definitions.LogKeyUsername, a.Request.Username,
		definitions.LogKeyProtocol, a.Request.Protocol.Get(),
		"service", util.WithNotAvailable(a.Request.Service),
		"no-auth", a.Request.NoAuth,
		"list-accounts", a.Request.ListAccounts,
	)
}

// filterActiveBruteForceRules filters and returns the active brute force rules based on protocol and IP family criteria.
func (a *AuthState) filterActiveBruteForceRules(ctx *gin.Context, tr monittrace.Tracer, rules []config.BruteForceRule, ip net.IP) []config.BruteForceRule {
	activeRules := make([]config.BruteForceRule, 0, len(rules))

	var ipFamily string
	switch {
	case ip != nil && ip.To4() != nil:
		ipFamily = "ipv4"
	case ip != nil && ip.To16() != nil:
		ipFamily = "ipv6"
	default:
		ipFamily = "unknown"
	}

	proto := ""
	if a.Request.Protocol != nil {
		proto = a.Request.Protocol.Get()
	}

	_, filterSpan := tr.Start(ctx.Request.Context(), "auth.bruteforce.rule_filter",
		attribute.String("protocol", proto),
		attribute.String("client_ip", a.Request.ClientIP),
		attribute.String("oidc_cid", a.Request.OIDCCID),
		attribute.String("ip_family", ipFamily),
		attribute.Int("rules.total", len(rules)),
	)
	defer filterSpan.End()

	skipped := 0

	for _, r := range rules {
		if !r.MatchesContext(proto, a.Request.OIDCCID, ip) {
			skipped++

			continue
		}

		activeRules = append(activeRules, r)
	}

	filterSpan.SetAttributes(
		attribute.Int("rules.active", len(activeRules)),
		attribute.Int("rules.skipped", skipped),
	)

	return activeRules
}

// CheckBruteForce checks if a client is triggering brute force detection based on predefined rules and configurations.
// It evaluates conditions like authentication state, IP whitelisting, protocol enforcement, and bucket rate limits.
// Returns true if brute force detection is triggered, and false otherwise.
func (a *AuthState) CheckBruteForce(ctx *gin.Context) (blockClientIP bool) {
	tr := monittrace.New("nauthilus/auth")
	cctx, cspan := tr.Start(ctx.Request.Context(), "auth.bruteforce.check",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
		attribute.String("client_ip", a.Request.ClientIP),
		attribute.String("protocol", a.Request.Protocol.Get()),
	)

	ctx.Request = ctx.Request.WithContext(cctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(cctx)
	}

	defer cspan.End()

	// Overall BF check timer
	var stopOverall func()
	if s := stats.PrometheusTimer(a.Cfg(), definitions.PromBruteForce, "bf_overall_total"); s != nil {
		stopOverall = s

		defer stopOverall()
	}

	var (
		ruleTriggered bool
		message       string
		bm            bruteforce.BucketManager
	)

	if a.Request.NoAuth || a.Request.ListAccounts {
		cspan.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "noauth_or_list"))

		return false
	}

	cfg := a.cfg()

	if !cfg.HasFeature(definitions.FeatureBruteForce) {
		cspan.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "feature_disabled"))

		return false
	}

	if isLocalOrEmptyIP(a.Request.ClientIP) {
		cspan.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "local_or_empty_ip"))

		a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, definitions.LogKeyBruteForce)
		a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, definitions.Localhost)

		return false
	}

	bfCfg := cfg.GetBruteForce()
	if bfCfg != nil && bfCfg.HasSoftWhitelist() {
		engine := l1.GetEngine()
		swlKey := l1.KeySoftWhitelist(a.Request.Username, a.Request.ClientIP)
		if dec, ok := engine.Get(swlKey); ok && dec.Allowed {
			a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, definitions.LogKeyBruteForce)
			a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, definitions.SoftWhitelisted)

			cspan.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "soft_whitelisted_l1"))

			return false
		}

		if util.IsSoftWhitelisted(cctx, a.Cfg(), a.Logger(), a.Request.Username, a.Request.ClientIP, a.Runtime.GUID, bfCfg.SoftWhitelist) {
			a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, definitions.LogKeyBruteForce)
			a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, definitions.SoftWhitelisted)

			cspan.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "soft_whitelisted"))

			// Cache result in L1
			engine.Set(swlKey, l1.L1Decision{Allowed: true, Reason: "SoftWhitelist"}, 0)

			return false
		}
	}

	if bfCfg != nil && len(bfCfg.GetIPWhitelist()) > 0 {
		engine := l1.GetEngine()
		wlKey := l1.KeyWhitelist(a.Request.ClientIP)
		if dec, ok := engine.Get(wlKey); ok && dec.Allowed {
			a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, definitions.LogKeyBruteForce)
			a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, definitions.Whitelisted)

			cspan.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "ip_whitelisted_l1"))

			return false
		}

		if a.IsInNetwork(bfCfg.IPWhitelist) {
			a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, definitions.LogKeyBruteForce)
			a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, definitions.Whitelisted)

			cspan.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "ip_whitelisted"))

			// Cache result in L1
			engine.Set(wlKey, l1.L1Decision{Allowed: true, Reason: "IPWhitelist"}, 0)

			return false
		}
	}

	// Existing generic timer
	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromBruteForce, "brute_force_check_request_total")

	// E2E histogram for BF path
	bfStart := time.Now()

	if stopTimer != nil {
		defer stopTimer()
	}

	// Defer to set final outcome
	defer func() {
		cspan.SetAttributes(
			attribute.Bool("triggered", ruleTriggered),
			attribute.String("bf.rule", a.Security.BruteForceName),
		)
	}()

	defer func() {
		stats.GetMetrics().GetBruteForceEvalSeconds().Observe(time.Since(bfStart).Seconds())
	}()

	// All rules
	rules := cfg.GetBruteForceRules()

	if len(rules) == 0 {
		return false
	}

	a.logBruteForceDebug(ctx.Request.Context())

	bruteForceProtocolEnabled := false
	for _, bruteForceService := range cfg.GetServer().GetBruteForceProtocols() {
		if bruteForceService.Get() != a.Request.Protocol.Get() {
			continue
		}

		bruteForceProtocolEnabled = true

		break
	}

	if !bruteForceProtocolEnabled {
		level.Warn(a.logger()).Log(
			definitions.LogKeyGUID, a.Runtime.GUID,
			definitions.LogKeyBruteForce, fmt.Sprintf("Not enabled for protocol '%s'", a.Request.Protocol.Get()))

		return false
	}

	bm = bruteforce.NewBucketManagerWithDeps(ctx.Request.Context(), a.Runtime.GUID, a.Request.ClientIP, bruteforce.BucketManagerDeps{
		Cfg:    a.Cfg(),
		Logger: a.Logger(),
		Redis:  a.Redis(),
	})

	// Set the protocol on the bucket manager
	if a.Request.Protocol != nil && a.Request.Protocol.Get() != "" {
		bm = bm.WithProtocol(a.Request.Protocol.Get())
	}

	// Set the OIDC Client ID on the bucket manager
	if a.Request.OIDCCID != "" {
		bm = bm.WithOIDCCID(a.Request.OIDCCID)
	}

	// IMPORTANT: set request attributes before running checks
	accountName := backend.GetUserAccountFromCache(ctx.Request.Context(), a.Cfg(), a.Logger(), a.deps.Redis, a.AccountCache(), a.Request.Username, a.Runtime.GUID)
	bm = bm.WithPassword(a.Request.Password).WithAccountName(accountName).WithUsername(a.Request.Username)

	// Determine IP once
	ip := net.ParseIP(a.Request.ClientIP)

	activeRules := a.filterActiveBruteForceRules(ctx, tr, rules, ip)

	// Use filtered rules from here on and precompute networks
	rules = activeRules

	// Precompute network strings per CIDR for active rules (no behavior change)
	bm.PrepareNetcalc(rules)

	network := &net.IPNet{}

	abort, alreadyTriggered, ruleNumber := bm.CheckRepeatingBruteForcer(rules, &network, &message)

	if abort {
		return false
	}

	if !alreadyTriggered {
		abort, ruleTriggered, ruleNumber = bm.CheckBucketOverLimit(rules, &message)
		if abort {
			return false
		}
	}

	// If neither path matched any rule/network, do not proceed further.
	if !alreadyTriggered && !ruleTriggered {
		return false
	}

	// A rule matched either in pre-result or bucket evaluation
	stats.GetMetrics().GetBruteForceRulesMatchedTotal().Inc()

	triggered := bm.ProcessBruteForce(ruleTriggered, alreadyTriggered, &rules[ruleNumber], network, message, func() {
		a.Runtime.FeatureName = bm.GetFeatureName()
		a.Security.BruteForceName = bm.GetBruteForceName()
		a.Security.BruteForceCounter = bm.GetBruteForceCounter()
		// Synchronize login attempts from bucket manager into centralized LAM (bucket has authority)
		if lam := a.ensureLAM(); lam != nil {
			lam.InitFromBucket(bm.GetLoginAttempts())
			a.Security.LoginAttempts = lam.FailCount()
		} else {
			a.Security.LoginAttempts = bm.GetLoginAttempts()
		}
		a.Security.PasswordHistory = bm.GetPasswordHistory()
	})

	// Compute and store brute-force hints for the Post-Action.
	// 1) Derive client_net from the matched network; fallback to ClientIP/CIDR.
	bfClientNet := ""
	if network != nil && network.IP != nil && network.Mask != nil {
		bfClientNet = network.String()
	} else if a.Request.ClientIP != "" && rules[ruleNumber].CIDR > 0 {
		if _, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", a.Request.ClientIP, rules[ruleNumber].CIDR)); err == nil && n != nil {
			bfClientNet = n.String()
		}
	}

	// 2) Determine repeating based on alreadyTriggered or counter >= limit; fallback to pre-result hash if buckets expired.
	bfRepeating := alreadyTriggered || (a.Security.BruteForceCounter[rules[ruleNumber].Name] >= rules[ruleNumber].GetFailedRequests())
	if !bfRepeating && bfClientNet != "" {
		prefix := a.cfg().GetServer().GetRedis().GetPrefix()
		key := rediscli.GetBruteForceHashKey(prefix, bfClientNet)

		stats.GetMetrics().GetRedisReadCounter().Inc()

		exists, err := a.deps.Redis.GetReadHandle().HExists(ctx.Request.Context(), key, bfClientNet).Result()
		if err == nil && exists {
			bfRepeating = true
		}
	}

	// Store hints on AuthState for consumption by Post-Action
	a.Runtime.BFClientNet = bfClientNet
	a.Runtime.BFRepeating = bfRepeating

	if triggered || alreadyTriggered {
		a.updateLuaContext(definitions.FeatureBruteForce)

		// Time the Lua action execution
		var stopLua func()
		if s := stats.PrometheusTimer(a.Cfg(), definitions.PromBruteForce, "bf_lua_action_total"); s != nil {
			stopLua = s
		}

		a.handleBruteForceLuaAction(ctx, alreadyTriggered, &rules[ruleNumber], network)
		if stopLua != nil {
			stopLua()
		}
	}

	return triggered
}

// UpdateBruteForceBucketsCounter updates brute force protection rules based on client and protocol details.
func (a *AuthState) UpdateBruteForceBucketsCounter(ctx *gin.Context) {
	tr := monittrace.New("nauthilus/auth")
	uctx, uspan := tr.Start(ctx.Request.Context(), "auth.bruteforce.update",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
		attribute.String("client_ip", a.Request.ClientIP),
		attribute.String("protocol", a.Request.Protocol.Get()),
		attribute.String("bf.rule", a.Security.BruteForceName),
	)

	ctx.Request = ctx.Request.WithContext(uctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(uctx)
	}

	defer uspan.End()

	// Overall timer for updating BF buckets after an auth failure
	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromBruteForce, "bf_update_overall_total"); stop != nil {
		defer stop()
	}

	var bm bruteforce.BucketManager

	cfg := a.cfg()

	if !cfg.HasFeature(definitions.FeatureBruteForce) {
		return
	}

	if isLocalOrEmptyIP(a.Request.ClientIP) {
		return
	}

	bfCfg := cfg.GetBruteForce()
	if bfCfg == nil {
		return
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		a.Cfg(),
		a.Logger(),
		definitions.DbgBf,
		definitions.LogKeyGUID, a.Runtime.GUID,
		definitions.LogKeyClientIP, a.Request.ClientIP,
		definitions.LogKeyClientPort, a.Request.XClientPort,
		definitions.LogKeyClientHost, a.Request.ClientHost,
		definitions.LogKeyClientID, a.Request.XClientID,
		definitions.LogKeyLocalIP, a.Request.XLocalIP,
		definitions.LogKeyPort, a.Request.XPort,
		definitions.LogKeyUsername, a.Request.Username,
		definitions.LogKeyProtocol, a.Request.Protocol.Get(),
		"service", util.WithNotAvailable(a.Request.Service),
		"no-auth", a.Request.NoAuth,
		"list-accounts", a.Request.ListAccounts,
	)

	if a.Request.NoAuth || a.Request.ListAccounts {
		return
	}

	if a.Request.ClientIP == definitions.Localhost4 || a.Request.ClientIP == definitions.Localhost6 || a.Request.ClientIP == definitions.NotAvailable {
		return
	}

	bruteForceEnabled := false
	for _, bruteForceService := range a.cfg().GetServer().GetBruteForceProtocols() {
		if bruteForceService.Get() != a.Request.Protocol.Get() {
			continue
		}

		bruteForceEnabled = true

		break
	}

	if !bruteForceEnabled {
		return
	}

	if len(a.cfg().GetBruteForce().IPWhitelist) > 0 {
		if a.IsInNetwork(a.cfg().GetBruteForce().IPWhitelist) {
			return
		}
	}

	matchedPeriod := time.Duration(0)

	for _, rule := range a.cfg().GetBruteForceRules() {
		if a.Security.BruteForceName != rule.Name {
			continue
		}

		matchedPeriod = rule.Period.Round(time.Second)

		uspan.SetAttributes(
			attribute.String("bf.matched_rule", rule.Name),
			attribute.String("bf.period", matchedPeriod.String()),
		)

		break
	}

	bm = bruteforce.NewBucketManagerWithDeps(ctx.Request.Context(), a.Runtime.GUID, a.Request.ClientIP, bruteforce.BucketManagerDeps{
		Cfg:      a.Cfg(),
		Logger:   a.Logger(),
		Redis:    a.Redis(),
		Tolerate: a.deps.Tolerate,
	})

	// Set the protocol if available
	if a.Request.Protocol != nil && a.Request.Protocol.Get() != "" {
		bm = bm.WithProtocol(a.Request.Protocol.Get())
	}

	// Set the OIDC Client ID if available
	if a.Request.OIDCCID != "" {
		bm = bm.WithOIDCCID(a.Request.OIDCCID)
	}

	// IMPORTANT: set request attributes before saving counters
	// Try to avoid Redis if possible: use state or in-process cache first
	accountName := a.GetAccount()
	if accountName == "" {
		if acc, ok := a.AccountCache().Get(a.Request.Username); ok {
			accountName = acc
		}
	}

	if accountName == "" {
		accountName = backend.GetUserAccountFromCache(ctx.Request.Context(), a.Cfg(), a.Logger(), a.deps.Redis, a.AccountCache(), a.Request.Username, a.Runtime.GUID)
	}

	bm = bm.WithUsername(a.Request.Username).WithPassword(a.Request.Password).WithAccountName(accountName)

	proto := ""
	if a.Request.Protocol != nil {
		proto = a.Request.Protocol.Get()
	}

	ip := net.ParseIP(a.Request.ClientIP)

	for _, rule := range a.cfg().GetBruteForceRules() {
		// Per-rule iteration timer
		var stopIter func()
		if s := stats.PrometheusTimer(a.Cfg(), definitions.PromBruteForce, "bf_update_loop_total"); s != nil {
			stopIter = s
		}

		if !rule.MatchesContext(proto, a.Request.OIDCCID, ip) {
			continue
		}

		if matchedPeriod == 0 || rule.Period.Round(time.Second) >= matchedPeriod {
			bm.SaveBruteForceBucketCounterToRedis(&rule)
		}

		if stopIter != nil {
			stopIter()
		}
	}
}

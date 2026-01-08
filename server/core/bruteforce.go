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
	"fmt"
	"net"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
)

// handleBruteForceLuaAction handles the brute force Lua action based on the provided authentication state and rule config.
func (a *AuthState) handleBruteForceLuaAction(ctx *gin.Context, alreadyTriggered bool, rule *config.BruteForceRule, network *net.IPNet) {
	tr := monittrace.New("nauthilus/auth")
	bctx, bspan := tr.Start(ctx.Request.Context(), "auth.bruteforce.lua_action",
		attribute.String("service", a.Service),
		attribute.String("username", a.Username),
		attribute.String("rule", rule.Name),
		attribute.Bool("already_triggered", alreadyTriggered),
	)

	ctx.Request = ctx.Request.WithContext(bctx)

	defer bspan.End()

	if config.GetFile().HaveLuaActions() {
		finished := make(chan action.Done)
		accountName := a.GetAccount()

		// Get a CommonRequest from the pool
		commonRequest := lualib.GetCommonRequest()

		// Set the fields
		commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
		// repeating is true if either pre-detection flagged (alreadyTriggered) or the
		// brute-force bucket counter has reached or exceeded the rule limit.
		bfCount := a.BruteForceCounter[rule.Name]

		// Derive client_net robustly: prefer provided network; fallback to CIDR from ClientIP and rule.
		clientNet := ""

		if network != nil && network.IP != nil && network.Mask != nil {
			clientNet = network.String()
		} else if a.ClientIP != "" && rule.CIDR > 0 {
			if _, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", a.ClientIP, rule.CIDR)); err == nil && n != nil {
				clientNet = n.String()
			}
		}

		isRepeating := alreadyTriggered || (bfCount >= rule.GetFailedRequests())

		// If still unknown, combine account lookup + repeating flag via Redis Lua preflight
		if (!isRepeating || accountName == "") && clientNet != "" {
			if acc, rep, err := rediscli.AuthPreflight(ctx.Request.Context(), a.Username, clientNet); err == nil {
				if accountName == "" && acc != "" {
					accountName = acc
					// Mirror into AuthState
					if a.AccountField == "" {
						a.AccountField = definitions.MetaUserAccount
					}

					if a.Attributes == nil || len(a.Attributes) == 0 {
						attrs := make(bktype.AttributeMapping)
						attrs[definitions.MetaUserAccount] = []any{acc}
						a.ReplaceAllAttributes(attrs)
					}

					// Store into in-process account cache
					accountcache.GetManager().Set(a.Username, acc)
				}

				if !isRepeating && rep {
					isRepeating = true
				}
			}
		}

		bspan.SetAttributes(
			attribute.Bool("repeating", isRepeating),
			attribute.Int("bf.count", int(a.BruteForceCounter[rule.Name])),
		)

		commonRequest.Repeating = isRepeating
		commonRequest.UserFound = func() bool { return accountName != "" }()
		commonRequest.Authenticated = false // unavailable
		commonRequest.NoAuth = a.NoAuth
		commonRequest.BruteForceCounter = a.BruteForceCounter[rule.Name]
		commonRequest.Service = a.Service
		commonRequest.Session = a.GUID
		commonRequest.ClientIP = a.ClientIP
		commonRequest.ClientPort = a.XClientPort
		commonRequest.ClientNet = clientNet
		commonRequest.ClientHost = a.ClientHost
		commonRequest.ClientID = a.XClientID
		commonRequest.LocalIP = a.XLocalIP
		commonRequest.LocalPort = a.XPort
		commonRequest.UserAgent = a.UserAgent
		commonRequest.Username = a.Username
		commonRequest.Account = accountName
		commonRequest.AccountField = a.GetAccountField()
		commonRequest.UniqueUserID = "" // unavailable
		commonRequest.DisplayName = ""  // unavailable
		commonRequest.Password = a.Password
		commonRequest.Protocol = a.Protocol.Get()
		commonRequest.BruteForceName = rule.Name
		commonRequest.FeatureName = a.FeatureName
		commonRequest.StatusMessage = &a.StatusMessage
		commonRequest.XSSL = a.XSSL
		commonRequest.XSSLSessionID = a.XSSLSessionID
		commonRequest.XSSLClientVerify = a.XSSLClientVerify
		commonRequest.XSSLClientDN = a.XSSLClientDN
		commonRequest.XSSLClientCN = a.XSSLClientCN
		commonRequest.XSSLIssuer = a.XSSLIssuer
		commonRequest.XSSLClientNotBefore = a.XSSLClientNotBefore
		commonRequest.XSSLClientNotAfter = a.XSSLClientNotAfter
		commonRequest.XSSLSubjectDN = a.XSSLSubjectDN
		commonRequest.XSSLIssuerDN = a.XSSLIssuerDN
		commonRequest.XSSLClientSubjectDN = a.XSSLClientSubjectDN
		commonRequest.XSSLClientIssuerDN = a.XSSLClientIssuerDN
		commonRequest.XSSLProtocol = a.XSSLProtocol
		commonRequest.XSSLCipher = a.XSSLCipher
		commonRequest.SSLSerial = a.SSLSerial
		commonRequest.SSLFingerprint = a.SSLFingerprint

		action.RequestChan <- &action.Action{
			LuaAction:     definitions.LuaActionBruteForce,
			Context:       a.Context,
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

// logBruteForceDebug logs debug information related to brute force authentication attempts using the provided AuthState.
func logBruteForceDebug(auth *AuthState) {
	util.DebugModule(
		definitions.DbgBf,
		definitions.LogKeyGUID, auth.GUID,
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
	if a.Protocol != nil {
		proto = a.Protocol.Get()
	}

	_, filterSpan := tr.Start(ctx.Request.Context(), "auth.bruteforce.rule_filter",
		attribute.String("protocol", proto),
		attribute.String("client_ip", a.ClientIP),
		attribute.String("oidc_cid", a.OIDCCID),
		attribute.String("ip_family", ipFamily),
		attribute.Int("rules.total", len(rules)),
	)
	defer filterSpan.End()

	skipped := 0

	for _, r := range rules {
		if !r.MatchesContext(proto, a.OIDCCID, ip) {
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
		attribute.String("service", a.Service),
		attribute.String("username", a.Username),
		attribute.String("client_ip", a.ClientIP),
		attribute.String("protocol", a.Protocol.Get()),
	)

	ctx.Request = ctx.Request.WithContext(cctx)

	defer cspan.End()

	// Overall BF check timer
	var stopOverall func()
	if s := stats.PrometheusTimer(definitions.PromBruteForce, "bf_overall_total"); s != nil {
		stopOverall = s

		defer stopOverall()
	}

	var (
		ruleTriggered bool
		message       string
		bm            bruteforce.BucketManager
	)

	if a.NoAuth || a.ListAccounts {
		cspan.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "noauth_or_list"))

		return false
	}

	if !config.GetFile().HasFeature(definitions.FeatureBruteForce) {
		cspan.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "feature_disabled"))

		return false
	}

	if isLocalOrEmptyIP(a.ClientIP) {
		cspan.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "local_or_empty_ip"))

		a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyBruteForce)
		a.AdditionalLogs = append(a.AdditionalLogs, definitions.Localhost)

		return false
	}

	if config.GetFile().GetBruteForce().HasSoftWhitelist() {
		if util.IsSoftWhitelisted(a.Username, a.ClientIP, a.GUID, config.GetFile().GetBruteForce().SoftWhitelist) {
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyBruteForce)
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.SoftWhitelisted)

			cspan.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "soft_whitelisted"))

			return false
		}
	}

	if len(config.GetFile().GetBruteForce().GetIPWhitelist()) > 0 {
		if a.IsInNetwork(config.GetFile().GetBruteForce().IPWhitelist) {
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyBruteForce)
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.Whitelisted)

			cspan.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "ip_whitelisted"))

			return false
		}
	}

	// Existing generic timer
	stopTimer := stats.PrometheusTimer(definitions.PromBruteForce, "brute_force_check_request_total")

	// E2E histogram for BF path
	bfStart := time.Now()

	if stopTimer != nil {
		defer stopTimer()
	}

	// Defer to set final outcome
	defer func() {
		cspan.SetAttributes(
			attribute.Bool("triggered", ruleTriggered),
			attribute.String("bf.rule", a.BruteForceName),
		)
	}()

	defer func() {
		stats.GetMetrics().GetBruteForceEvalSeconds().Observe(time.Since(bfStart).Seconds())
	}()

	// All rules
	rules := config.GetFile().GetBruteForceRules()

	if len(rules) == 0 {
		return false
	}

	logBruteForceDebug(a)

	bruteForceProtocolEnabled := false
	for _, bruteForceService := range config.GetFile().GetServer().GetBruteForceProtocols() {
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

	bm = bruteforce.NewBucketManager(ctx.Request.Context(), a.GUID, a.ClientIP)

	// Set the protocol on the bucket manager
	if a.Protocol != nil && a.Protocol.Get() != "" {
		bm = bm.WithProtocol(a.Protocol.Get())
	}

	// Set the OIDC Client ID on the bucket manager
	if a.OIDCCID != "" {
		bm = bm.WithOIDCCID(a.OIDCCID)
	}

	// IMPORTANT: set request attributes before running checks
	accountName := backend.GetUserAccountFromCache(ctx.Request.Context(), a.Username, a.GUID)
	bm = bm.WithPassword(a.Password).WithAccountName(accountName).WithUsername(a.Username)

	// Determine IP once
	ip := net.ParseIP(a.ClientIP)

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
		a.FeatureName = bm.GetFeatureName()
		a.BruteForceName = bm.GetBruteForceName()
		a.BruteForceCounter = bm.GetBruteForceCounter()
		// Synchronize login attempts from bucket manager into centralized LAM (bucket has authority)
		if lam := a.ensureLAM(); lam != nil {
			lam.InitFromBucket(bm.GetLoginAttempts())
			a.LoginAttempts = lam.FailCount()
		} else {
			a.LoginAttempts = bm.GetLoginAttempts()
		}
		a.PasswordHistory = bm.GetPasswordHistory()
	})

	// Compute and store brute-force hints for the Post-Action.
	// 1) Derive client_net from the matched network; fallback to ClientIP/CIDR.
	bfClientNet := ""
	if network != nil && network.IP != nil && network.Mask != nil {
		bfClientNet = network.String()
	} else if a.ClientIP != "" && rules[ruleNumber].CIDR > 0 {
		if _, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", a.ClientIP, rules[ruleNumber].CIDR)); err == nil && n != nil {
			bfClientNet = n.String()
		}
	}

	// 2) Determine repeating based on alreadyTriggered or counter >= limit; fallback to pre-result hash if buckets expired.
	bfRepeating := alreadyTriggered || (a.BruteForceCounter[rules[ruleNumber].Name] >= rules[ruleNumber].GetFailedRequests())
	if !bfRepeating && bfClientNet != "" {
		key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisBruteForceHashKey

		stats.GetMetrics().GetRedisReadCounter().Inc()

		exists, err := rediscli.GetClient().GetReadHandle().HExists(ctx.Request.Context(), key, bfClientNet).Result()
		if err == nil && exists {
			bfRepeating = true
		}
	}

	// Store hints on AuthState for consumption by Post-Action
	a.BFClientNet = bfClientNet
	a.BFRepeating = bfRepeating

	if triggered || alreadyTriggered {
		updateLuaContext(a.Context, definitions.FeatureBruteForce)
		// Time the Lua action execution
		var stopLua func()
		if s := stats.PrometheusTimer(definitions.PromBruteForce, "bf_lua_action_total"); s != nil {
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
		attribute.String("service", a.Service),
		attribute.String("username", a.Username),
		attribute.String("client_ip", a.ClientIP),
		attribute.String("protocol", a.Protocol.Get()),
		attribute.String("bf.rule", a.BruteForceName),
	)

	ctx.Request = ctx.Request.WithContext(uctx)

	defer uspan.End()

	// Overall timer for updating BF buckets after an auth failure
	if stop := stats.PrometheusTimer(definitions.PromBruteForce, "bf_update_overall_total"); stop != nil {
		defer stop()
	}

	var bm bruteforce.BucketManager

	if !config.GetFile().HasFeature(definitions.FeatureBruteForce) {
		return
	}

	if isLocalOrEmptyIP(a.ClientIP) {
		return
	}

	if config.GetFile().GetBruteForce() == nil {
		return
	}

	util.DebugModule(
		definitions.DbgBf,
		definitions.LogKeyGUID, a.GUID,
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
	for _, bruteForceService := range config.GetFile().GetServer().GetBruteForceProtocols() {
		if bruteForceService.Get() != a.Protocol.Get() {
			continue
		}

		bruteForceEnabled = true

		break
	}

	if !bruteForceEnabled {
		return
	}

	if len(config.GetFile().GetBruteForce().IPWhitelist) > 0 {
		if a.IsInNetwork(config.GetFile().GetBruteForce().IPWhitelist) {
			return
		}
	}

	matchedPeriod := time.Duration(0)

	for _, rule := range config.GetFile().GetBruteForceRules() {
		if a.BruteForceName != rule.Name {
			continue
		}

		matchedPeriod = rule.Period.Round(time.Second)

		uspan.SetAttributes(
			attribute.String("bf.matched_rule", rule.Name),
			attribute.String("bf.period", matchedPeriod.String()),
		)

		break
	}

	bm = bruteforce.NewBucketManager(ctx.Request.Context(), a.GUID, a.ClientIP)

	// Set the protocol if available
	if a.Protocol != nil && a.Protocol.Get() != "" {
		bm = bm.WithProtocol(a.Protocol.Get())
	}

	// Set the OIDC Client ID if available
	if a.OIDCCID != "" {
		bm = bm.WithOIDCCID(a.OIDCCID)
	}

	// IMPORTANT: set request attributes before saving counters
	// Try to avoid Redis if possible: use state or in-process cache first
	accountName := a.GetAccount()
	if accountName == "" {
		if acc, ok := accountcache.GetManager().Get(a.Username); ok {
			accountName = acc
		}
	}

	if accountName == "" {
		accountName = backend.GetUserAccountFromCache(ctx.Request.Context(), a.Username, a.GUID)
	}

	bm = bm.WithUsername(a.Username).WithPassword(a.Password).WithAccountName(accountName)

	proto := ""
	if a.Protocol != nil {
		proto = a.Protocol.Get()
	}

	ip := net.ParseIP(a.ClientIP)

	for _, rule := range config.GetFile().GetBruteForceRules() {
		// Per-rule iteration timer
		var stopIter func()
		if s := stats.PrometheusTimer(definitions.PromBruteForce, "bf_update_loop_total"); s != nil {
			stopIter = s
		}

		if !rule.MatchesContext(proto, a.OIDCCID, ip) {
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

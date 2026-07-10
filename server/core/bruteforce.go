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
	"fmt"
	"net"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/bruteforce"
	"github.com/croessner/nauthilus/v3/server/bruteforce/l1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"

	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

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
	tr, cctx, cspan := a.startBruteForceCheckTrace(ctx)
	a.attachBruteForceCheckContext(cctx, ctx)

	defer cspan.End()

	if stopOverall := a.startBruteForceOverallTimer(ctx); stopOverall != nil {
		defer stopOverall()
	}

	cfg := a.cfg()
	if a.skipBruteForceCheck(ctx, cspan, cfg) {
		return false
	}

	defer func() {
		a.recordPolicyBruteForce(ctx, blockClientIP)
	}()

	bfCfg := cfg.GetBruteForce()
	if a.isBruteForceWhitelisted(cctx, cspan, bfCfg) {
		return false
	}

	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromBruteForce, "brute_force_check_request_total", ctx.FullPath())
	bfStart := time.Now()

	if stopTimer != nil {
		defer stopTimer()
	}

	ruleTriggered := false

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

	rules := cfg.GetBruteForceRules()
	if len(rules) == 0 {
		return false
	}

	a.logBruteForceDebug(ctx.Request.Context())

	if !a.isBruteForceCheckProtocolEnabled(cfg) {
		return false
	}

	bm := a.newBruteForceBucketManager(ctx)
	a.cacheBruteForceRWPDecision(ctx, bm)

	triggered, ruleTriggered := a.runBruteForceRuleCheck(ctx, tr, bm, rules)

	return triggered
}

// startBruteForceCheckTrace starts the tracing span for brute-force checks.
func (a *AuthState) startBruteForceCheckTrace(ctx *gin.Context) (monittrace.Tracer, context.Context, trace.Span) {
	tr := monittrace.New("nauthilus/auth")
	cctx, cspan := tr.Start(ctx.Request.Context(), "auth.bruteforce.check",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
		attribute.String("client_ip", a.Request.ClientIP),
		attribute.String("protocol", a.Request.Protocol.Get()),
	)

	return tr, cctx, cspan
}

// attachBruteForceCheckContext propagates the tracing context to HTTP request holders.
func (a *AuthState) attachBruteForceCheckContext(cctx context.Context, ctx *gin.Context) {
	ctx.Request = ctx.Request.WithContext(cctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(cctx)
	}
}

// startBruteForceOverallTimer starts the top-level brute-force check metric timer.
func (a *AuthState) startBruteForceOverallTimer(ctx *gin.Context) func() {
	return stats.PrometheusTimer(a.Cfg(), definitions.PromBruteForce, "bf_overall_total", ctx.FullPath())
}

// isBruteForceWhitelisted checks both soft and hard brute-force whitelists.
func (a *AuthState) isBruteForceWhitelisted(ctx context.Context, span trace.Span, bfCfg *config.BruteForceSection) bool {
	return a.isBruteForceSoftWhitelisted(ctx, span, bfCfg) || a.isBruteForceIPWhitelisted(ctx, span, bfCfg)
}

// isBruteForceCheckProtocolEnabled validates protocol enablement and logs disabled protocols.
func (a *AuthState) isBruteForceCheckProtocolEnabled(cfg config.File) bool {
	if bruteForceProtocolEnabled(cfg, a.Request.Protocol.Get()) {
		return true
	}

	level.Warn(a.logger()).Log(
		definitions.LogKeyGUID, a.Runtime.GUID,
		definitions.LogKeyBruteForce, fmt.Sprintf("Not enabled for protocol '%s'", a.Request.Protocol.Get()))

	return false
}

// runBruteForceRuleCheck evaluates configured rules and applies matched brute-force state.
func (a *AuthState) runBruteForceRuleCheck(
	ctx *gin.Context,
	tr monittrace.Tracer,
	bm bruteforce.BucketManager,
	rules []config.BruteForceRule,
) (bool, bool) {
	eval, abort := a.evaluateBruteForceRules(ctx, tr, bm, rules)
	if abort {
		return false, false
	}

	if !eval.alreadyTriggered && !eval.ruleTriggered {
		return false, eval.ruleTriggered
	}

	stats.GetMetrics().GetBruteForceRulesMatchedTotal().Inc()

	triggered := bm.ProcessBruteForce(eval.ruleTriggered, eval.alreadyTriggered, &eval.rules[eval.ruleNumber], eval.network, eval.message, func() {
		a.applyTriggeredBruteForceRuntime(bm)
	})
	a.storeBruteForceRuntimeHints(ctx, eval)

	if triggered || eval.alreadyTriggered {
		a.updateLuaContext(definitions.ControlBruteForce)
	}

	return triggered || eval.alreadyTriggered, eval.ruleTriggered
}

// applyTriggeredBruteForceRuntime copies matched bucket manager state into AuthState.
func (a *AuthState) applyTriggeredBruteForceRuntime(bm bruteforce.BucketManager) {
	a.Runtime.EnvironmentName = bm.GetEnvironmentName()
	a.Security.BruteForceName = bm.GetBruteForceName()
	a.Security.BruteForceCounter = bm.GetBruteForceCounter()
	a.Runtime.BruteForceToleration = bm.GetTolerationPolicyFact()

	if lam := a.ensureLAM(); lam != nil {
		lam.InitFromBucket(bm.GetLoginAttempts())
		a.Security.LoginAttempts = lam.FailCount()

		return
	}

	a.Security.LoginAttempts = bm.GetLoginAttempts()
}

type bruteForceRuleEvaluation struct {
	network          *net.IPNet
	rules            []config.BruteForceRule
	message          string
	ruleNumber       int
	alreadyTriggered bool
	ruleTriggered    bool
}

// skipBruteForceCheck handles early exits before any bucket lookup is needed.
func (a *AuthState) skipBruteForceCheck(ctx *gin.Context, span trace.Span, cfg config.File) bool {
	if a.Request.NoAuth || a.Request.ListAccounts {
		span.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "noauth_or_list"))

		return true
	}

	if !cfg.HasRuntimeModule(definitions.ControlBruteForce) {
		span.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "control_disabled"))
		a.markPolicyUnavailable(ctx, "brute_force", "control_disabled")

		return true
	}

	if !a.policyCheckScheduled(ctx, bruteForcePolicySelector()) {
		span.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "scheduler_guard"))

		return true
	}

	return false
}

// isBruteForceSoftWhitelisted checks user/IP soft whitelist decisions and caches positive hits.
func (a *AuthState) isBruteForceSoftWhitelisted(ctx context.Context, span trace.Span, bfCfg *config.BruteForceSection) bool {
	if bfCfg == nil || !bfCfg.HasSoftWhitelist() {
		return false
	}

	engine := l1.GetEngine()

	swlKey := l1.KeySoftWhitelist(a.Request.Username, a.Request.ClientIP)
	if dec, ok := engine.Get(ctx, swlKey); ok && dec.Allowed {
		a.markBruteForceWhitelist(definitions.SoftWhitelisted)
		span.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "soft_whitelisted_l1"))

		return true
	}

	if !util.IsSoftWhitelisted(ctx, a.Cfg(), a.Logger(), a.Request.Username, a.Request.ClientIP, a.Runtime.GUID, bfCfg.SoftWhitelist) {
		return false
	}

	a.markBruteForceWhitelist(definitions.SoftWhitelisted)
	span.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "soft_whitelisted"))
	engine.Set(ctx, swlKey, l1.Decision{Allowed: true, Reason: "SoftWhitelist"}, time.Second)

	return true
}

// isBruteForceIPWhitelisted checks the hard IP whitelist and caches positive hits.
func (a *AuthState) isBruteForceIPWhitelisted(ctx context.Context, span trace.Span, bfCfg *config.BruteForceSection) bool {
	if bfCfg == nil || len(bfCfg.GetIPWhitelist()) == 0 {
		return false
	}

	engine := l1.GetEngine()

	wlKey := l1.KeyWhitelist(a.Request.ClientIP)
	if dec, ok := engine.Get(ctx, wlKey); ok && dec.Allowed {
		a.markBruteForceWhitelist(definitions.Whitelisted)
		span.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "ip_whitelisted_l1"))

		return true
	}

	if !a.IsInNetwork(bfCfg.IPWhitelist) {
		return false
	}

	a.markBruteForceWhitelist(definitions.Whitelisted)
	span.SetAttributes(attribute.Bool("skipped", true), attribute.String("reason", "ip_whitelisted"))
	engine.Set(ctx, wlKey, l1.Decision{Allowed: true, Reason: "IPWhitelist"}, time.Second)

	return true
}

// markBruteForceWhitelist records whitelist state in additional logs.
func (a *AuthState) markBruteForceWhitelist(value string) {
	a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, definitions.LogKeyBruteForce)
	a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, value)
}

// newBruteForceBucketManager builds the bucket manager with request identity attributes.
func (a *AuthState) newBruteForceBucketManager(ctx *gin.Context) bruteforce.BucketManager {
	bm := bruteforce.NewBucketManagerWithDeps(ctx.Request.Context(), a.Runtime.GUID, a.Request.ClientIP, bruteforce.BucketManagerDeps{
		Cfg:    a.Cfg(),
		Logger: a.Logger(),
		Redis:  a.Redis(),
	})

	if a.Request.Protocol != nil && a.Request.Protocol.Get() != "" {
		bm = bm.WithProtocol(a.Request.Protocol.Get())
	}

	if a.Request.OIDCCID != "" {
		bm = bm.WithOIDCCID(a.Request.OIDCCID)
	}

	accountName := backend.GetUserAccountFromCache(ctx.Request.Context(), a.Cfg(), a.Logger(), a.deps.Redis, a.AccountCache(), a.Request.Username, a.Request.Protocol.Get(), a.Request.OIDCCID, a.Runtime.GUID)

	return bm.WithPassword(a.Request.Password).WithAccountName(accountName).WithUsername(a.Request.Username)
}

// cacheBruteForceRWPDecision stores the repeating-wrong-password precheck for later reuse.
func (a *AuthState) cacheBruteForceRWPDecision(ctx *gin.Context, bm bruteforce.BucketManager) {
	if needEnforce, err := bm.ShouldEnforceBucketUpdate(); err == nil {
		ctx.Set(definitions.CtxRWPResultKey, needEnforce)
		a.Runtime.BFRWP = !needEnforce
	}
}

// evaluateBruteForceRules filters active rules and evaluates repeat and over-limit paths.
func (a *AuthState) evaluateBruteForceRules(
	ctx *gin.Context,
	tr monittrace.Tracer,
	bm bruteforce.BucketManager,
	rules []config.BruteForceRule,
) (bruteForceRuleEvaluation, bool) {
	ip := net.ParseIP(a.Request.ClientIP)
	activeRules := a.filterActiveBruteForceRules(ctx, tr, rules, ip)
	bm.PrepareNetcalc(activeRules)

	eval := bruteForceRuleEvaluation{
		network: &net.IPNet{},
		rules:   activeRules,
	}

	abort, alreadyTriggered, ruleNumber := bm.CheckRepeatingBruteForcer(activeRules, &eval.network, &eval.message)
	if abort {
		return eval, true
	}

	eval.alreadyTriggered = alreadyTriggered

	eval.ruleNumber = ruleNumber
	if !alreadyTriggered {
		abort, eval.ruleTriggered, eval.ruleNumber = bm.CheckBucketOverLimit(activeRules, &eval.message)
		if abort {
			return eval, true
		}
	}

	a.storeBruteForceBucketPolicyFacts(bm, activeRules, eval.alreadyTriggered, eval.ruleTriggered, eval.ruleNumber, eval.network)

	return eval, false
}

// storeBruteForceRuntimeHints stores post-action hint fields from the matched rule.
func (a *AuthState) storeBruteForceRuntimeHints(ctx *gin.Context, eval bruteForceRuleEvaluation) {
	bfClientNet := a.bruteForceClientNetwork(eval)

	bfRepeating := eval.alreadyTriggered || (a.Security.BruteForceCounter[eval.rules[eval.ruleNumber].Name] >= eval.rules[eval.ruleNumber].GetFailedRequests())
	if !bfRepeating && bfClientNet != "" {
		bfRepeating = a.bruteForceBanExists(ctx, bfClientNet)
	}

	a.Runtime.BFClientNet = bfClientNet
	a.Runtime.BFRepeating = bfRepeating || bruteForceBucketFactsRepeat(a.Runtime.BruteForceBuckets)
}

// bruteForceClientNetwork derives the matched client network for post-action hints.
func (a *AuthState) bruteForceClientNetwork(eval bruteForceRuleEvaluation) string {
	if eval.network != nil && eval.network.IP != nil && eval.network.Mask != nil {
		return eval.network.String()
	}

	if a.Request.ClientIP == "" || eval.rules[eval.ruleNumber].CIDR == 0 {
		return ""
	}

	if _, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", a.Request.ClientIP, eval.rules[eval.ruleNumber].CIDR)); err == nil && network != nil {
		return network.String()
	}

	return ""
}

// bruteForceBanExists checks whether the matched network is already banned.
func (a *AuthState) bruteForceBanExists(ctx *gin.Context, clientNet string) bool {
	prefix := a.cfg().GetServer().GetRedis().GetPrefix()
	banKey := rediscli.GetBruteForceBanKey(prefix, clientNet)

	stats.GetMetrics().GetRedisReadCounter().Inc()

	existsVal, err := a.deps.Redis.GetReadHandle().Exists(ctx.Request.Context(), banKey).Result()

	return err == nil && existsVal > 0
}

func (a *AuthState) storeBruteForceBucketPolicyFacts(
	bm bruteforce.BucketManager,
	rules []config.BruteForceRule,
	alreadyTriggered bool,
	ruleTriggered bool,
	ruleNumber int,
	network *net.IPNet,
) {
	facts := bm.GetBucketPolicyFacts()
	if len(facts) == 0 {
		collected, err := bm.CollectBucketPolicyFacts(rules)
		if err != nil {
			_ = level.Warn(a.logger()).Log(
				definitions.LogKeyGUID, a.Runtime.GUID,
				definitions.LogKeyMsg, "Failed to collect brute-force bucket policy facts",
				definitions.LogKeyError, err,
			)
		}

		facts = collected
	}

	a.Runtime.BruteForceBuckets = markBruteForceBucketPolicyFacts(facts, rules, alreadyTriggered, ruleTriggered, ruleNumber, network)
	if bruteForceBucketFactsRepeat(a.Runtime.BruteForceBuckets) {
		a.Runtime.BFRepeating = true
	}
}

func markBruteForceBucketPolicyFacts(
	facts []bruteforce.BucketPolicyFact,
	rules []config.BruteForceRule,
	alreadyTriggered bool,
	ruleTriggered bool,
	ruleNumber int,
	network *net.IPNet,
) []bruteforce.BucketPolicyFact {
	marked := append([]bruteforce.BucketPolicyFact(nil), facts...)
	if ruleNumber < 0 || ruleNumber >= len(rules) {
		return marked
	}

	rule := rules[ruleNumber]
	if len(marked) == 0 {
		marked = append(marked, bruteForceBucketFactFromRule(rule, network))
	}

	updated := false

	for i := range marked {
		if marked[i].Name != rule.Name {
			continue
		}

		markBruteForceBucketPolicyFact(&marked[i], alreadyTriggered, ruleTriggered, network)

		updated = true
	}

	if !updated {
		fact := bruteForceBucketFactFromRule(rule, network)
		markBruteForceBucketPolicyFact(&fact, alreadyTriggered, ruleTriggered, network)
		marked = append(marked, fact)
	}

	return marked
}

func bruteForceBucketFactFromRule(rule config.BruteForceRule, network *net.IPNet) bruteforce.BucketPolicyFact {
	effectiveLimit := float64(rule.GetFailedRequests()) - 1
	if effectiveLimit < 0 {
		effectiveLimit = 0
	}

	fact := bruteforce.BucketPolicyFact{
		Name:           rule.Name,
		Limit:          float64(rule.GetFailedRequests()),
		EffectiveLimit: effectiveLimit,
		Remaining:      effectiveLimit,
		Period:         rule.GetPeriod(),
		BanTime:        rule.GetBanTime(),
		CIDR:           rule.GetCIDR(),
		Matched:        true,
	}

	if network != nil {
		fact.ClientNet = network.String()
	}

	return fact
}

func markBruteForceBucketPolicyFact(
	fact *bruteforce.BucketPolicyFact,
	alreadyTriggered bool,
	ruleTriggered bool,
	network *net.IPNet,
) {
	if fact == nil {
		return
	}

	fact.Matched = true
	if network != nil && fact.ClientNet == "" {
		fact.ClientNet = network.String()
	}

	if alreadyTriggered {
		fact.AlreadyBanned = true
	}

	if ruleTriggered {
		fact.OverLimit = true
	}

	fact.Repeating = fact.Repeating || alreadyTriggered || ruleTriggered
}

func bruteForceBucketFactsRepeat(facts []bruteforce.BucketPolicyFact) bool {
	for i := range facts {
		if facts[i].Repeating {
			return true
		}
	}

	return false
}

// commitRWPIfAllowed commits the RWP sliding window write unless an environment control rejected the request
// without learning being active for that environment control. In that case, the password was never verified,
// so recording it in the RWP window would be incorrect.
func (a *AuthState) commitRWPIfAllowed(ctx *gin.Context, bm bruteforce.BucketManager) {
	if ctx.GetBool(definitions.CtxEnvironmentRejectedKey) {
		bfCfg := a.cfg().GetBruteForce()

		if bfCfg == nil || !bfCfg.LearnFromControl(a.Runtime.EnvironmentName) {
			return
		}
	}

	bm.CommitRWPSlidingWindow()
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
	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromBruteForce, "bf_update_overall_total", ctx.FullPath()); stop != nil {
		defer stop()
	}

	cfg := a.cfg()

	if !cfg.HasRuntimeModule(definitions.ControlBruteForce) {
		return
	}

	bfCfg := cfg.GetBruteForce()
	if bfCfg == nil {
		return
	}

	a.logBruteForceDebug(ctx.Request.Context())

	if a.Request.NoAuth || a.Request.ListAccounts {
		return
	}

	if !bruteForceProtocolEnabled(a.cfg(), a.Request.Protocol.Get()) {
		return
	}

	if a.isBruteForceUpdateIPWhitelisted(bfCfg) {
		return
	}

	matchedPeriod := a.matchedBruteForceUpdatePeriod(uspan)
	bm := a.newBruteForceUpdateBucketManager(ctx)

	bm, enforceBuckets := a.shouldEnforceBruteForceBucketUpdate(ctx, bm)

	// Commit the RWP sliding window write only if the rejection is genuine
	// (not caused by an environment control like RBL that never verified the password).
	a.commitRWPIfAllowed(ctx, bm)

	if !enforceBuckets {
		return
	}

	a.saveBruteForceBucketCounters(ctx, bm, matchedPeriod)
}

// isBruteForceUpdateIPWhitelisted checks whether bucket updates should skip a whitelisted IP.
func (a *AuthState) isBruteForceUpdateIPWhitelisted(bfCfg *config.BruteForceSection) bool {
	return len(bfCfg.IPWhitelist) > 0 && a.IsInNetwork(bfCfg.IPWhitelist)
}

// matchedBruteForceUpdatePeriod returns the period of the matched rule for counter updates.
func (a *AuthState) matchedBruteForceUpdatePeriod(span trace.Span) time.Duration {
	matchedPeriod := time.Duration(0)

	for _, rule := range a.cfg().GetBruteForceRules() {
		if a.Security.BruteForceName != rule.Name {
			continue
		}

		matchedPeriod = rule.Period.Round(time.Second)

		span.SetAttributes(
			attribute.String("bf.matched_rule", rule.Name),
			attribute.String("bf.period", matchedPeriod.String()),
		)

		break
	}

	return matchedPeriod
}

// newBruteForceUpdateBucketManager builds the bucket manager used for failed-login updates.
func (a *AuthState) newBruteForceUpdateBucketManager(ctx *gin.Context) bruteforce.BucketManager {
	bm := bruteforce.NewBucketManagerWithDeps(ctx.Request.Context(), a.Runtime.GUID, a.Request.ClientIP, bruteforce.BucketManagerDeps{
		Cfg:      a.Cfg(),
		Logger:   a.Logger(),
		Redis:    a.Redis(),
		Tolerate: a.deps.Tolerate,
	})

	if a.Request.Protocol != nil && a.Request.Protocol.Get() != "" {
		bm = bm.WithProtocol(a.Request.Protocol.Get())
	}

	if a.Request.OIDCCID != "" {
		bm = bm.WithOIDCCID(a.Request.OIDCCID)
	}

	return bm.WithUsername(a.Request.Username).
		WithPassword(a.Request.Password).
		WithAccountName(a.bruteForceUpdateAccountName(ctx))
}

// bruteForceUpdateAccountName resolves account name without Redis when local state already knows it.
func (a *AuthState) bruteForceUpdateAccountName(ctx *gin.Context) string {
	accountName := a.GetAccount()
	if accountName != "" {
		return accountName
	}

	if acc, ok := a.AccountCache().Get(a.Request.Username, a.Request.Protocol.Get(), a.Request.OIDCCID); ok {
		return acc
	}

	return backend.GetUserAccountFromCache(ctx.Request.Context(), a.Cfg(), a.Logger(), a.deps.Redis, a.AccountCache(), a.Request.Username, a.Request.Protocol.Get(), a.Request.OIDCCID, a.Runtime.GUID)
}

// shouldEnforceBruteForceBucketUpdate decides whether to increase bucket counters.
func (a *AuthState) shouldEnforceBruteForceBucketUpdate(ctx *gin.Context, bm bruteforce.BucketManager) (bruteforce.BucketManager, bool) {
	if cached, exists := ctx.Get(definitions.CtxRWPResultKey); exists {
		if enforce, ok := cached.(bool); ok {
			bm = bm.WithRWPDecision(enforce)

			return bm, a.handleCachedRWPEnforcement(bm, enforce)
		}

		return bm, true
	}

	needEnforce, err := bm.ShouldEnforceBucketUpdate()
	if err != nil {
		return bm, false
	}

	if !needEnforce {
		bm = bm.WithRWPDecision(false)

		ctx.Set(definitions.CtxRWPResultKey, false)

		return bm, a.activateRWPAllowance(bm)
	}

	ctx.Set(definitions.CtxRWPResultKey, true)

	return bm, true
}

// handleCachedRWPEnforcement applies the cached repeating-wrong-password decision.
func (a *AuthState) handleCachedRWPEnforcement(bm bruteforce.BucketManager, enforce bool) bool {
	if enforce {
		return true
	}

	return a.activateRWPAllowance(bm)
}

// activateRWPAllowance records a confirmed failed request that must not increase brute-force buckets.
func (a *AuthState) activateRWPAllowance(bm bruteforce.BucketManager) bool {
	a.Runtime.BFRWP = true
	a.logRWPAllowanceActive()

	bm.ProcessPWHist()

	return false
}

// logRWPAllowanceActive records the confirmed request-level RWP allowance decision.
func (a *AuthState) logRWPAllowanceActive() {
	level.Info(a.Logger()).Log(
		definitions.LogKeyGUID, a.Runtime.GUID,
		definitions.LogKeyBruteForce, "RWP allowance active",
		definitions.LogKeyUsername, a.Request.Username,
		definitions.LogKeyClientIP, a.Request.ClientIP,
		"allowed_unique_hashes", a.cfg().GetBruteForce().GetRWPAllowedUniqueHashes(),
	)
}

// saveBruteForceBucketCounters writes counters for active rules matching the request context.
func (a *AuthState) saveBruteForceBucketCounters(ctx *gin.Context, bm bruteforce.BucketManager, matchedPeriod time.Duration) {
	proto := ""
	if a.Request.Protocol != nil {
		proto = a.Request.Protocol.Get()
	}

	ip := net.ParseIP(a.Request.ClientIP)

	for _, rule := range a.cfg().GetBruteForceRules() {
		// Per-rule iteration timer
		var stopIter func()
		if s := stats.PrometheusTimer(a.Cfg(), definitions.PromBruteForce, "bf_update_loop_total", ctx.FullPath()); s != nil {
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

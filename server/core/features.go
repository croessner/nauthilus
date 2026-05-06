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
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/environment"
	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	featureDecisionAbort        = "abort_features"
	featureDecisionLua          = "feature_lua"
	featureDecisionOK           = "ok"
	featureDecisionRBL          = "feature_rbl"
	featureDecisionRelayDomains = "feature_relay_domains"
	featureDecisionTLS          = "feature_tls"
	featureDecisionTempFail     = "tempfail"
	policyContinueAttribute     = "policy_continue"
	policyContinueConfigured    = "configured"
	policySkipRemainingAttr     = "policy_skip_remaining"
)

type preAuthFeatureOutcome struct {
	current                 definitions.AuthResult
	decision                string
	reject                  bool
	continuePolicyAuthority bool
	markPolicyContinue      bool
}

// isLocalOrEmptyIP checks whether the provided IP is empty, an IPv4 localhost, or an IPv6 localhost.
func isLocalOrEmptyIP(ip string) bool {
	return ip == definitions.Localhost4 || ip == definitions.Localhost6 || ip == ""
}

// logAddMessage appends a feature and message to the AdditionalLogs slice.
func (a *AuthState) logAddMessage(message, feature string) {
	a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, feature)
	a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, message)
}

// logAddLocalhost appends feature-specific logs and the "localhost" indicator to the auth state.
func (a *AuthState) logAddLocalhost(feature string) {
	a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, fmt.Sprintf("%s_%s", definitions.LogKeyFeatureName, feature))
	a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, definitions.Localhost)
}

// updateLuaContext updates the Lua context with a new feature in the Gin context, ensuring unique entries.
func (a *AuthState) updateLuaContext(feature string) {
	var featureList config.StringSet

	curFeatures, exists := a.Runtime.Context.GetExists(definitions.LuaCtxBuiltin)
	if !exists {
		featureList = config.NewStringSet()
	} else {
		featureList = curFeatures.(config.StringSet)
	}

	featureList.Set(feature)

	a.Runtime.Context.Set(definitions.LuaCtxBuiltin, featureList)
}

// EnvironmentLua runs Lua environment source scripts and returns a trigger result.
func (a *AuthState) EnvironmentLua(ctx *gin.Context) (triggered bool, abortFeatures bool, err error) {
	if isLocalOrEmptyIP(a.Request.ClientIP) {
		a.logAddLocalhost(definitions.FeatureLua)

		return
	}

	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromFeature, definitions.FeatureLua, ctx.FullPath())

	if stopTimer != nil {
		defer stopTimer()
	}

	cr := lualib.GetCommonRequest()
	defer lualib.PutCommonRequest(cr)

	a.FillCommonRequest(cr)

	policyCtx := a.requestPolicyContext(ctx)
	fr := &environment.Request{
		Session:            a.Runtime.GUID,
		Username:           a.Request.Username,
		Password:           a.passwordBytes(),
		ClientIP:           a.Request.ClientIP,
		AccountName:        a.GetAccount(),
		UsedBackendPort:    &a.Runtime.UsedBackendPort,
		Logs:               nil,
		Context:            a.Runtime.Context,
		HTTPClientContext:  a.Request.HTTPClientContext,
		HTTPClientRequest:  a.Request.HTTPClientRequest,
		Authenticated:      a.Runtime.Authenticated,
		NoAuth:             a.Request.NoAuth,
		BruteForceCounter:  0,
		MasterUserMode:     a.Runtime.MasterUserMode,
		AdditionalFeatures: a.Runtime.AdditionalFeatures,
		CommonRequest:      cr,
		ScriptRecorder:     policycollection.NewScriptSink(policyCtx),
		PolicyContext:      policyCtx,
	}

	triggered, abortFeatures, err = fr.CallEnvironmentLua(ctx, a.Cfg(), a.Logger(), a.Redis())

	if err != nil {
		return
	}

	a.Security.Logs = fr.Logs

	return
}

// FeatureTLSEncryption checks, if the remote client connection was secured.
func (a *AuthState) FeatureTLSEncryption(ctx *gin.Context) (triggered bool) {
	if config.GetEnvironment().GetDevMode() {
		return
	}

	if isLocalOrEmptyIP(a.Request.ClientIP) {
		a.logAddLocalhost(definitions.FeatureTLSEncryption)

		return
	}

	if a.Request.XSSL != "" {
		return
	}

	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromFeature, definitions.FeatureTLSEncryption, ctx.FullPath())

	if stopTimer != nil {
		defer stopTimer()
	}

	if !util.IsInNetworkWithCfg(ctx.Request.Context(), a.Cfg(), a.Logger(), a.cfg().GetClearTextList(), a.Runtime.GUID, a.Request.ClientIP) {
		a.logAddMessage(definitions.NoTLS, definitions.FeatureTLSEncryption)
		a.updateLuaContext(definitions.FeatureTLSEncryption)

		triggered = true

		return
	}

	a.logAddMessage(definitions.Whitelisted, definitions.FeatureTLSEncryption)

	return
}

// FeatureRelayDomains triggers if a user sent an email address as a login name and the domain component does not
// match the list of known domains.
func (a *AuthState) FeatureRelayDomains() (triggered bool) {
	relayDomains := a.cfg().GetRelayDomains()
	if relayDomains == nil {
		return
	}

	if len(relayDomains.StaticDomains) == 0 {
		return
	}

	if isLocalOrEmptyIP(a.Request.ClientIP) {
		a.logAddLocalhost(definitions.FeatureRelayDomains)

		return
	}

	resource := util.RequestResource(a.Request.HTTPClientContext, a.Request.HTTPClientRequest, a.Request.Service)
	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromFeature, definitions.FeatureRelayDomains, resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	username := a.handleMasterUserMode()
	fact := a.relayDomainPolicyFact(username, relayDomains, false)
	a.Runtime.RelayDomainPolicy = fact

	if fact.Rejected {
		a.logAddMessage(fmt.Sprintf("%s not our domain", fact.Value), definitions.FeatureRelayDomains)
		a.updateLuaContext(definitions.FeatureRelayDomains)

		triggered = true
	}

	return
}

func (a *AuthState) relayDomainPolicyFact(
	username string,
	relayDomains *config.RelayDomainsSection,
	softAllowlisted bool,
) RelayDomainPolicyFact {
	fact := RelayDomainPolicyFact{SoftAllowlisted: softAllowlisted}
	if relayDomains == nil {
		return fact
	}

	staticDomains := relayDomains.GetStaticDomains()
	fact.ConfiguredCount = len(staticDomains)

	domain, present := usernameDomain(username)
	fact.Value = domain
	fact.Present = present
	if !present {
		return fact
	}

	for _, configuredDomain := range staticDomains {
		if !strings.EqualFold(configuredDomain, domain) {
			continue
		}

		fact.Known = true
		fact.StaticMatch = true
		fact.MatchedDomain = configuredDomain

		return fact
	}

	fact.Rejected = !softAllowlisted

	return fact
}

// FeatureRBLs is a method that checks if the client IP address is whitelisted, and then performs an RBL check
// on the client's IP address. If the RBL score exceeds the configured threshold, the 'triggered' flag is set to true.
// It returns the 'triggered' flag and any error that occurred during the check.
func (a *AuthState) FeatureRBLs(ctx *gin.Context) (triggered bool, err error) {
	rbls := a.cfg().GetRBLs()
	if rbls == nil {
		return
	}

	a.Runtime.RBLPolicy = RBLPolicyFact{
		Threshold: rbls.GetThreshold(),
		ListCount: len(rbls.GetLists()),
	}

	if isLocalOrEmptyIP(a.Request.ClientIP) {
		a.logAddLocalhost(definitions.FeatureRBL)

		return
	}

	if util.IsInNetworkWithCfg(ctx.Request.Context(), a.Cfg(), a.Logger(), rbls.GetIPWhiteList(), a.Runtime.GUID, a.Request.ClientIP) {
		a.logAddMessage(definitions.Whitelisted, definitions.FeatureRBL)
		a.Runtime.RBLPolicy.IPAllowlisted = true

		return
	}

	// Tracing: RBL lookup evaluation
	tr := monittrace.New("nauthilus/rbl")
	rctx, rsp := tr.Start(ctx.Request.Context(), "rbl.lookup",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
		attribute.String("client_ip", a.Request.ClientIP),
		attribute.String("protocol", a.Request.Protocol.Get()),
		attribute.Int("providers", func() int {
			if rbls != nil {
				return len(rbls.GetLists())
			}

			return 0
		}()),
		attribute.Int("threshold", rbls.GetThreshold()),
	)

	// propagate context
	ctx.Request = ctx.Request.WithContext(rctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(rctx)
	}

	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromDNS, definitions.FeatureRBL, ctx.FullPath())
	if stopTimer != nil {
		defer stopTimer()
	}

	if svc := GetRBLService(); svc != nil {
		score, e := a.scoreRBLService(ctx, svc)
		if e != nil {
			rsp.RecordError(e)
			rsp.End()

			return false, e
		}

		rsp.SetAttributes(
			attribute.Int("score", score),
			attribute.Bool("matched", score >= svc.Threshold()),
		)

		if score >= svc.Threshold() {
			a.updateLuaContext(definitions.FeatureRBL)
			rsp.End()

			return true, nil
		}
	}

	rsp.End()

	return false, nil
}

func (a *AuthState) scoreRBLService(ctx *gin.Context, svc RBLService) (int, error) {
	if factService, ok := svc.(RBLFactService); ok {
		fact, err := factService.ScoreWithFacts(ctx, a.View())
		a.Runtime.RBLPolicy = fact

		return fact.Score, err
	}

	score, err := svc.Score(ctx, a.View())
	a.Runtime.RBLPolicy.Score = score
	a.Runtime.RBLPolicy.Threshold = svc.Threshold()

	return score, err
}

// logFeatureWhitelisting appends the given feature name and a soft whitelisted message to the additional logs of AuthState.
func (a *AuthState) logFeatureWhitelisting(featureName string) {
	a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, featureName, definitions.SoftWhitelisted)
}

// checkFeatureWithWhitelist checks if a feature is enabled and if a whitelist applies, executes the feature check function.
// If the feature is enabled and the whitelist applies, logs the event and returns false.
// Executes the checkFunc when the feature is enabled and not whitelisted, returning its outcome.
// Returns false if the feature is not enabled in the configuration.
func (a *AuthState) checkFeatureWithWhitelist(featureName string, isWhitelisted func() bool, checkFunc func()) {
	if a.cfg().ShouldRunFeature(featureName, a.Request.NoAuth) {
		if isWhitelisted() {
			a.logFeatureWhitelisting(featureName)
		} else {
			checkFunc()
		}
	}
}

// checkLuaEnvironmentSource evaluates Lua-based features for the given authentication context.
// It determines if a feature is triggered or if further processing should be aborted.
// It uses a whitelist check and processes environment source actions if the Lua environment source is activated.
// Returns triggered when a Lua environment source triggered and abortFeatures when later server features should be skipped.
func (a *AuthState) checkLuaEnvironmentSource(ctx *gin.Context) (triggered bool, abortFeatures bool, err error) {
	tr := monittrace.New("nauthilus/auth")
	fctx, fspan := tr.Start(ctx.Request.Context(), "auth.environment.lua",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	ctx.Request = ctx.Request.WithContext(fctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(fctx)
	}

	defer fspan.End()

	checkFunc := func() {
		triggered, abortFeatures, err = a.EnvironmentLua(ctx)
		if err != nil {
			a.Runtime.FeatureName = ""

			return
		}

		if triggered {
			a.processFeatureAction(ctx, definitions.FeatureLua)
		}

		if abortFeatures {
			a.Runtime.FeatureName = ""
			abortFeatures = true
		}
	}

	a.checkFeatureWithWhitelist(definitions.FeatureLua, func() bool { return false }, checkFunc)

	return
}

// checkTLSEncryptionFeature determines if the TLS encryption feature should be processed for the current authentication state.
// It uses a whitelist check to decide if the feature action needs to be executed based on the current auth state.
func (a *AuthState) checkTLSEncryptionFeature(ctx *gin.Context) (triggered bool) {
	tr := monittrace.New("nauthilus/auth")
	fctx, fspan := tr.Start(ctx.Request.Context(), "auth.features.tls",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	ctx.Request = ctx.Request.WithContext(fctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(fctx)
	}

	defer fspan.End()

	checkFunc := func() {
		if triggered = a.FeatureTLSEncryption(ctx); triggered {
			a.processFeatureAction(ctx, definitions.FeatureTLSEncryption)
		}
	}

	a.checkFeatureWithWhitelist(definitions.FeatureTLSEncryption, func() bool { return false }, checkFunc)

	return
}

// checkRelayDomainsFeature evaluates if the relay domains feature should be activated for the given AuthState instance.
// It checks if the client is whitelisted and processes the feature action accordingly.
func (a *AuthState) checkRelayDomainsFeature(ctx *gin.Context) (triggered bool) {
	tr := monittrace.New("nauthilus/auth")
	fctx, fspan := tr.Start(ctx.Request.Context(), "auth.features.relay_domains",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	ctx.Request = ctx.Request.WithContext(fctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(fctx)
	}

	defer fspan.End()

	isWhitelisted := func() bool {
		relayDomains := a.cfg().GetRelayDomains()
		if relayDomains == nil {
			return false
		}

		return relayDomains.HasSoftWhitelist() &&
			util.IsSoftWhitelisted(fctx, a.Cfg(), a.Logger(), a.Request.Username, a.Request.ClientIP, a.Runtime.GUID, relayDomains.SoftWhitelist)
	}

	checkFunc := func() {
		if triggered = a.FeatureRelayDomains(); triggered {
			a.processFeatureAction(ctx, definitions.FeatureRelayDomains)
		}
	}

	if a.cfg().ShouldRunFeature(definitions.FeatureRelayDomains, a.Request.NoAuth) {
		if isWhitelisted() {
			a.logFeatureWhitelisting(definitions.FeatureRelayDomains)
			a.Runtime.RelayDomainPolicy = a.relayDomainPolicyFact(a.handleMasterUserMode(), a.cfg().GetRelayDomains(), true)
		} else {
			checkFunc()
		}
	}

	return
}

// checkRBLFeature checks if a Real-time Blackhole List (RBL) feature is triggered for the current request.
// Returns true if the feature is triggered and processed, otherwise false.
func (a *AuthState) checkRBLFeature(ctx *gin.Context) (triggered bool, err error) {
	tr := monittrace.New("nauthilus/auth")
	fctx, fspan := tr.Start(ctx.Request.Context(), "auth.features.rbl",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	ctx.Request = ctx.Request.WithContext(fctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(fctx)
	}

	defer fspan.End()

	isWhitelisted := func() bool {
		rbls := a.cfg().GetRBLs()
		if rbls == nil {
			return false
		}

		return rbls.HasSoftWhitelist() &&
			util.IsSoftWhitelisted(fctx, a.Cfg(), a.Logger(), a.Request.Username, a.Request.ClientIP, a.Runtime.GUID, rbls.SoftWhitelist)
	}

	checkFunc := func() {
		triggered, err = a.FeatureRBLs(ctx)
		if err != nil || !triggered {
			a.Runtime.FeatureName = ""

			return
		}

		a.processFeatureAction(ctx, definitions.FeatureRBL)
	}

	if a.cfg().ShouldRunFeature(definitions.FeatureRBL, a.Request.NoAuth) {
		if isWhitelisted() {
			a.logFeatureWhitelisting(definitions.FeatureRBL)
			rbls := a.cfg().GetRBLs()
			if rbls != nil {
				a.Runtime.RBLPolicy = RBLPolicyFact{
					Threshold:       rbls.GetThreshold(),
					ListCount:       len(rbls.GetLists()),
					SoftAllowlisted: true,
				}
			}
		} else {
			checkFunc()
		}
	}

	return
}

// processFeatureAction records the triggering feature for policy-selected obligations.
func (a *AuthState) processFeatureAction(ctx *gin.Context, featureName string) {
	if util.IsHTTPRequestCanceled(a.Logger(), ctx.Request, a.Runtime.GUID, "feature.action") {
		return
	}

	a.Runtime.FeatureName = featureName
}

// performAction triggers the execution of a specified Lua action if Lua actions are enabled in the configuration.
// It initializes an account name if absent, sends the action request to the RequestChan channel,
// and waits for the action to complete.
func (a *AuthState) performAction(luaAction definitions.LuaAction, luaActionName string) {
	if !a.cfg().HaveLuaActions() {
		return
	}

	resource := util.RequestResource(a.Request.HTTPClientContext, a.Request.HTTPClientRequest, a.Request.Service)
	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromAction, luaActionName, resource)
	if stopTimer != nil {
		defer stopTimer()
	}

	if a.GetAccount() == "" {
		a.refreshUserAccount()
	}

	if disp := GetActionDispatcher(); disp != nil {
		disp.Dispatch(a.View(), a.Runtime.FeatureName, luaAction)
	}
}

// HandleFeatures processes multiple security features associated with authentication requests and returns the result.
// It checks for various features like TLS encryption, relay domains, RBL, and Lua scripting.
// The method returns an appropriate authentication result based on the features that are triggered or aborted.
func (a *AuthState) HandleFeatures(ctx *gin.Context) definitions.AuthResult {
	if util.IsHTTPRequestCanceled(a.Logger(), ctx.Request, a.Runtime.GUID, "features.evaluate") {
		return definitions.AuthResultTempFail
	}

	defer a.completePolicyStage(ctx, policy.StagePreAuth)

	// Root span for features evaluation
	tr := monittrace.New("nauthilus/features")
	fctx, fsp := tr.Start(ctx.Request.Context(), "features.evaluate",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
		attribute.String("protocol", a.Request.Protocol.Get()),
	)

	// propagate context so any inner call attaches to this span
	ctx.Request = ctx.Request.WithContext(fctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(fctx)
	}

	if a.configuredPreAuthChecksSkipped(ctx) {
		return finishPreAuthFeatureOK(fsp, true)
	}

	if !a.cfg().HasFeature(definitions.FeatureBruteForce) {
		a.refreshUserAccount()
	}

	if triggered, abortFeatures, err := a.checkLuaEnvironmentSource(ctx); err != nil {
		fsp.RecordError(err)
		if result, handled := a.resolvePreAuthFeatureOutcome(ctx, fsp, preAuthFeatureOutcome{
			current:  definitions.AuthResultTempFail,
			decision: featureDecisionTempFail,
		}); handled {
			return result
		}

		return definitions.AuthResultOK
	} else if triggered {
		if result, handled := a.resolvePreAuthFeatureOutcome(ctx, fsp, preAuthFeatureOutcome{
			current:                 definitions.AuthResultFeatureLua,
			decision:                featureDecisionLua,
			reject:                  true,
			continuePolicyAuthority: true,
			markPolicyContinue:      true,
		}); handled {
			return result
		}
	} else if abortFeatures {
		if result, handled := a.resolvePreAuthFeatureOutcome(ctx, fsp, preAuthFeatureOutcome{
			current:  definitions.AuthResultOK,
			decision: featureDecisionAbort,
		}); handled {
			return result
		}

		return definitions.AuthResultOK
	}

	tlsTriggered := a.checkTLSEncryptionFeature(ctx)
	a.recordPolicyTLS(ctx, tlsTriggered)

	if tlsTriggered {
		if result, handled := a.resolvePreAuthFeatureOutcome(ctx, fsp, preAuthFeatureOutcome{
			current:                 definitions.AuthResultFeatureTLS,
			decision:                featureDecisionTLS,
			reject:                  true,
			continuePolicyAuthority: true,
			markPolicyContinue:      true,
		}); handled {
			return result
		}
	}

	relayTriggered := a.checkRelayDomainsFeature(ctx)
	a.recordPolicyRelayDomains(ctx, relayTriggered)

	if relayTriggered {
		if result, handled := a.resolvePreAuthFeatureOutcome(ctx, fsp, preAuthFeatureOutcome{
			current:                 definitions.AuthResultFeatureRelayDomain,
			decision:                featureDecisionRelayDomains,
			reject:                  true,
			continuePolicyAuthority: true,
			markPolicyContinue:      true,
		}); handled {
			return result
		}
	}

	triggered, err := a.checkRBLFeature(ctx)
	if err != nil {
		a.recordPolicyRBL(ctx, triggered, err)
		fsp.RecordError(err)
		if result, handled := a.resolvePreAuthFeatureOutcome(ctx, fsp, preAuthFeatureOutcome{
			current:            definitions.AuthResultTempFail,
			decision:           featureDecisionTempFail,
			markPolicyContinue: true,
		}); handled {
			return result
		}

		return definitions.AuthResultOK
	}

	if triggered {
		a.recordPolicyRBL(ctx, triggered, nil)
		if result, handled := a.resolvePreAuthFeatureOutcome(ctx, fsp, preAuthFeatureOutcome{
			current:            definitions.AuthResultFeatureRBL,
			decision:           featureDecisionRBL,
			reject:             true,
			markPolicyContinue: true,
		}); handled {
			return result
		}

		return definitions.AuthResultOK
	}

	a.recordPolicyRBL(ctx, triggered, nil)

	if result, handled := a.resolvePreAuthFeatureOutcome(ctx, fsp, preAuthFeatureOutcome{
		current:  definitions.AuthResultOK,
		decision: featureDecisionOK,
	}); handled {
		return result
	}

	return definitions.AuthResultOK
}

func (a *AuthState) resolvePreAuthFeatureOutcome(
	ctx *gin.Context,
	span trace.Span,
	outcome preAuthFeatureOutcome,
) (definitions.AuthResult, bool) {
	span.SetAttributes(attribute.String("decision", outcome.decision))

	if result, handled := a.configuredPolicyPreAuthResult(ctx, outcome.current); handled {
		markEnvironmentRejected(ctx, outcome.reject)
		span.End()

		return result, true
	}

	if a.HasConfiguredPreAuthPolicyAuthority(ctx) {
		if outcome.markPolicyContinue {
			span.SetAttributes(attribute.String(policyContinueAttribute, policyContinueConfigured))
		}

		if outcome.continuePolicyAuthority {
			return definitions.AuthResultOK, false
		}

		span.End()

		return definitions.AuthResultOK, true
	}

	markEnvironmentRejected(ctx, outcome.reject)
	span.End()

	return a.defaultPolicyPreAuthResult(ctx, outcome.current), true
}

func markEnvironmentRejected(ctx *gin.Context, reject bool) {
	if reject {
		ctx.Set(definitions.CtxEnvironmentRejectedKey, true)
	}
}

func finishPreAuthFeatureOK(span trace.Span, skipRemaining bool) definitions.AuthResult {
	attributes := []attribute.KeyValue{attribute.String("decision", featureDecisionOK)}
	if skipRemaining {
		attributes = append(attributes, attribute.Bool(policySkipRemainingAttr, true))
	}

	span.SetAttributes(attributes...)
	span.End()

	return definitions.AuthResultOK
}

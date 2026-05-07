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
	environmentDecisionAbort        = "abort_environment"
	environmentDecisionLua          = "environment_lua"
	environmentDecisionOK           = "ok"
	environmentDecisionRBL          = "environment_rbl"
	environmentDecisionRelayDomains = "environment_relay_domains"
	environmentDecisionTLS          = "environment_tls"
	environmentDecisionTempFail     = "tempfail"
	policyContinueAttribute         = "policy_continue"
	policyContinueConfigured        = "configured"
	policySkipRemainingAttr         = "policy_skip_remaining"
)

type preAuthEnvironmentOutcome struct {
	current                 definitions.AuthResult
	decision                string
	reject                  bool
	continuePolicyAuthority bool
	markPolicyContinue      bool
}

// logAddMessage appends a environment name and message to the AdditionalLogs slice.
func (a *AuthState) logAddMessage(message, environmentName string) {
	a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, environmentName)
	a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, message)
}

// updateLuaContext updates the Lua context with a new environment control in the Gin context, ensuring unique entries.
func (a *AuthState) updateLuaContext(environmentName string) {
	var environmentControlSet config.StringSet

	currentEnvironmentControls, exists := a.Runtime.Context.GetExists(definitions.LuaCtxBuiltin)
	if !exists {
		environmentControlSet = config.NewStringSet()
	} else {
		environmentControlSet = currentEnvironmentControls.(config.StringSet)
	}

	environmentControlSet.Set(environmentName)

	a.Runtime.Context.Set(definitions.LuaCtxBuiltin, environmentControlSet)
}

// EnvironmentLua runs Lua environment source scripts and returns a trigger result.
func (a *AuthState) EnvironmentLua(ctx *gin.Context) (triggered bool, skipRemainingEnvironment bool, err error) {
	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromEnvironment, definitions.ControlLua, ctx.FullPath())

	if stopTimer != nil {
		defer stopTimer()
	}

	cr := lualib.GetCommonRequest()
	defer lualib.PutCommonRequest(cr)

	a.FillCommonRequest(cr)

	policyCtx := a.requestPolicyContext(ctx)
	fr := &environment.Request{
		Session:              a.Runtime.GUID,
		Username:             a.Request.Username,
		Password:             a.passwordBytes(),
		ClientIP:             a.Request.ClientIP,
		AccountName:          a.GetAccount(),
		UsedBackendPort:      &a.Runtime.UsedBackendPort,
		Logs:                 nil,
		Context:              a.Runtime.Context,
		HTTPClientContext:    a.Request.HTTPClientContext,
		HTTPClientRequest:    a.Request.HTTPClientRequest,
		Authenticated:        a.Runtime.Authenticated,
		NoAuth:               a.Request.NoAuth,
		BruteForceCounter:    0,
		MasterUserMode:       a.Runtime.MasterUserMode,
		AdditionalAttributes: a.Runtime.AdditionalAttributes,
		CommonRequest:        cr,
		ScriptRecorder:       policycollection.NewScriptSink(policyCtx),
		PolicyContext:        policyCtx,
	}

	triggered, skipRemainingEnvironment, err = fr.CallEnvironmentLua(ctx, a.Cfg(), a.Logger(), a.Redis())

	if err != nil {
		return
	}

	a.Security.Logs = fr.Logs

	return
}

// ControlTLSEncryption checks, if the remote client connection was secured.
func (a *AuthState) ControlTLSEncryption(ctx *gin.Context) (triggered bool) {
	if config.GetEnvironment().GetDevMode() {
		return
	}

	if a.Request.XSSL != "" {
		return
	}

	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromEnvironment, definitions.ControlTLSEncryption, ctx.FullPath())

	if stopTimer != nil {
		defer stopTimer()
	}

	if !util.IsInNetworkWithCfg(ctx.Request.Context(), a.Cfg(), a.Logger(), a.cfg().GetClearTextList(), a.Runtime.GUID, a.Request.ClientIP) {
		a.logAddMessage(definitions.NoTLS, definitions.ControlTLSEncryption)
		a.updateLuaContext(definitions.ControlTLSEncryption)

		triggered = true

		return
	}

	a.logAddMessage(definitions.Whitelisted, definitions.ControlTLSEncryption)

	return
}

// ControlRelayDomains triggers if a user sent an email address as a login name and the domain component does not
// match the list of known domains.
func (a *AuthState) ControlRelayDomains() (triggered bool) {
	relayDomains := a.cfg().GetRelayDomains()
	if relayDomains == nil {
		return
	}

	if len(relayDomains.StaticDomains) == 0 {
		return
	}

	resource := util.RequestResource(a.Request.HTTPClientContext, a.Request.HTTPClientRequest, a.Request.Service)
	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromEnvironment, definitions.ControlRelayDomains, resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	username := a.handleMasterUserMode()
	fact := a.relayDomainPolicyFact(username, relayDomains, false)
	a.Runtime.RelayDomainPolicy = fact

	if fact.Rejected {
		a.logAddMessage(fmt.Sprintf("%s not our domain", fact.Value), definitions.ControlRelayDomains)
		a.updateLuaContext(definitions.ControlRelayDomains)

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

// ControlRBL checks the client IP address against configured RBL providers.
func (a *AuthState) ControlRBL(ctx *gin.Context) (triggered bool, err error) {
	rbls := a.cfg().GetRBLs()
	if rbls == nil {
		return
	}

	a.Runtime.RBLPolicy = RBLPolicyFact{
		Threshold: rbls.GetThreshold(),
		ListCount: len(rbls.GetLists()),
	}

	if util.IsInNetworkWithCfg(ctx.Request.Context(), a.Cfg(), a.Logger(), rbls.GetIPWhiteList(), a.Runtime.GUID, a.Request.ClientIP) {
		a.logAddMessage(definitions.Whitelisted, definitions.ControlRBL)
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

	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromDNS, definitions.ControlRBL, ctx.FullPath())
	if stopTimer != nil {
		defer stopTimer()
	}

	defer rsp.End()

	return a.evaluateRBLService(ctx, rsp)
}

func (a *AuthState) evaluateRBLService(ctx *gin.Context, span trace.Span) (bool, error) {
	svc := GetRBLService()
	if svc == nil {
		return false, nil
	}

	score, err := a.scoreRBLService(ctx, svc)
	if err != nil {
		span.RecordError(err)

		return false, err
	}

	matched := score >= svc.Threshold()
	span.SetAttributes(
		attribute.Int("score", score),
		attribute.Bool("matched", matched),
	)
	if !matched {
		return false, nil
	}

	a.updateLuaContext(definitions.ControlRBL)

	return true, nil
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

// logEnvironmentControlAllowlisting appends the given environment name and a soft whitelisted message to the additional logs of AuthState.
func (a *AuthState) logEnvironmentControlAllowlisting(environmentName string) {
	a.Runtime.AdditionalLogs = append(a.Runtime.AdditionalLogs, environmentName, definitions.SoftWhitelisted)
}

// checkEnvironmentControlWithAllowlist checks if an environment control is enabled and if a whitelist applies, executes the environment control check function.
// If the environment control is enabled and the whitelist applies, logs the event and returns false.
// Executes the checkFunc when the environment control is enabled and not whitelisted, returning its outcome.
// Returns false if the environment control is not enabled in the configuration.
func (a *AuthState) checkEnvironmentControlWithAllowlist(environmentName string, isWhitelisted func() bool, checkFunc func()) {
	if a.cfg().ShouldRunControl(environmentName, a.Request.NoAuth) {
		if isWhitelisted() {
			a.logEnvironmentControlAllowlisting(environmentName)
		} else {
			checkFunc()
		}
	}
}

// checkLuaEnvironmentSource evaluates Lua environment sources for the given authentication context.
// It determines if an environment control is triggered or if further processing should be aborted.
// It uses a whitelist check and processes environment source actions if the Lua environment source is activated.
// Returns triggered when a Lua environment source triggered and skipRemainingEnvironment when later server environment controls should be skipped.
func (a *AuthState) checkLuaEnvironmentSource(ctx *gin.Context) (triggered bool, skipRemainingEnvironment bool, err error) {
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
		triggered, skipRemainingEnvironment, err = a.EnvironmentLua(ctx)
		if err != nil {
			a.Runtime.EnvironmentName = ""

			return
		}

		if triggered {
			a.processEnvironmentAction(ctx, definitions.ControlLua)
		}

		if skipRemainingEnvironment {
			a.Runtime.EnvironmentName = ""
			skipRemainingEnvironment = true
		}
	}

	a.checkEnvironmentControlWithAllowlist(definitions.ControlLua, func() bool { return false }, checkFunc)

	return
}

// checkTLSEncryptionEnvironment determines if the TLS encryption environment control should be processed for the current authentication state.
// It uses a whitelist check to decide if the environment control action needs to be executed based on the current auth state.
func (a *AuthState) checkTLSEncryptionEnvironment(ctx *gin.Context) (triggered bool) {
	tr := monittrace.New("nauthilus/auth")
	fctx, fspan := tr.Start(ctx.Request.Context(), "auth.environment.tls",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	ctx.Request = ctx.Request.WithContext(fctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(fctx)
	}

	defer fspan.End()

	checkFunc := func() {
		if !a.policyCheckScheduled(ctx, tlsPolicySelector()) {
			return
		}

		if triggered = a.ControlTLSEncryption(ctx); triggered {
			a.processEnvironmentAction(ctx, definitions.ControlTLSEncryption)
		}
	}

	a.checkEnvironmentControlWithAllowlist(definitions.ControlTLSEncryption, func() bool { return false }, checkFunc)

	return
}

// checkRelayDomainsEnvironment evaluates if the relay domains environment control should be activated for the given AuthState instance.
// It checks if the client is whitelisted and processes the environment control action accordingly.
func (a *AuthState) checkRelayDomainsEnvironment(ctx *gin.Context) (triggered bool) {
	tr := monittrace.New("nauthilus/auth")
	fctx, fspan := tr.Start(ctx.Request.Context(), "auth.environment.relay_domains",
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
		if triggered = a.ControlRelayDomains(); triggered {
			a.processEnvironmentAction(ctx, definitions.ControlRelayDomains)
		}
	}

	if a.cfg().ShouldRunControl(definitions.ControlRelayDomains, a.Request.NoAuth) {
		if !a.policyCheckScheduled(ctx, relayDomainsPolicySelector()) {
			return
		}

		if isWhitelisted() {
			a.logEnvironmentControlAllowlisting(definitions.ControlRelayDomains)
			a.Runtime.RelayDomainPolicy = a.relayDomainPolicyFact(a.handleMasterUserMode(), a.cfg().GetRelayDomains(), true)
		} else {
			checkFunc()
		}
	}

	return
}

// checkRBLEnvironment checks if a Real-time Blackhole List (RBL) environment control is triggered for the current request.
// Returns true if the environment control is triggered and processed, otherwise false.
func (a *AuthState) checkRBLEnvironment(ctx *gin.Context) (triggered bool, err error) {
	tr := monittrace.New("nauthilus/auth")
	fctx, fspan := tr.Start(ctx.Request.Context(), "auth.environment.rbl",
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
		triggered, err = a.ControlRBL(ctx)
		if err != nil || !triggered {
			a.Runtime.EnvironmentName = ""

			return
		}

		a.processEnvironmentAction(ctx, definitions.ControlRBL)
	}

	if a.cfg().ShouldRunControl(definitions.ControlRBL, a.Request.NoAuth) {
		if !a.policyCheckScheduled(ctx, rblPolicySelector()) {
			return
		}

		if isWhitelisted() {
			a.logEnvironmentControlAllowlisting(definitions.ControlRBL)
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

// processEnvironmentAction records the triggering environment control for policy-selected obligations.
func (a *AuthState) processEnvironmentAction(ctx *gin.Context, environmentName string) {
	if util.IsHTTPRequestCanceled(a.Logger(), ctx.Request, a.Runtime.GUID, "environment.action") {
		return
	}

	a.Runtime.EnvironmentName = environmentName
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
		disp.Dispatch(a.View(), a.Runtime.EnvironmentName, luaAction)
	}
}

// HandleEnvironment processes multiple environment controls associated with authentication requests and returns the result.
// It checks for various environment controls like TLS encryption, relay domains, RBL, and Lua scripting.
// The method returns an appropriate authentication result based on the environment controls that are triggered or skipped.
func (a *AuthState) HandleEnvironment(ctx *gin.Context) definitions.AuthResult {
	if util.IsHTTPRequestCanceled(a.Logger(), ctx.Request, a.Runtime.GUID, "environment.evaluate") {
		return definitions.AuthResultTempFail
	}

	defer a.completePolicyStage(ctx, policy.StagePreAuth)

	fsp := a.startEnvironmentEvaluation(ctx)
	if a.configuredPreAuthChecksSkipped(ctx) {
		return finishPreAuthEnvironmentOK(fsp, true)
	}

	if !a.cfg().HasRuntimeModule(definitions.ControlBruteForce) {
		a.refreshUserAccount()
	}

	if result, handled := a.handleLuaEnvironmentResult(ctx, fsp); handled {
		return result
	}

	if result, handled := a.handleTLSEnvironmentResult(ctx, fsp); handled {
		return result
	}

	if result, handled := a.handleRelayDomainEnvironmentResult(ctx, fsp); handled {
		return result
	}

	return a.handleRBLEnvironmentResult(ctx, fsp)
}

func (a *AuthState) startEnvironmentEvaluation(ctx *gin.Context) trace.Span {
	tr := monittrace.New("nauthilus/environment")
	fctx, fsp := tr.Start(ctx.Request.Context(), "environment.evaluate",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
		attribute.String("protocol", a.Request.Protocol.Get()),
	)

	// propagate context so any inner call attaches to this span
	ctx.Request = ctx.Request.WithContext(fctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(fctx)
	}

	return fsp
}

func (a *AuthState) handleLuaEnvironmentResult(ctx *gin.Context, span trace.Span) (definitions.AuthResult, bool) {
	if triggered, skipRemainingEnvironment, err := a.checkLuaEnvironmentSource(ctx); err != nil {
		span.RecordError(err)
		if result, handled := a.resolvePreAuthEnvironmentOutcome(ctx, span, preAuthEnvironmentOutcome{
			current:  definitions.AuthResultTempFail,
			decision: environmentDecisionTempFail,
		}); handled {
			return result, true
		}

		return definitions.AuthResultOK, true
	} else if triggered {
		if result, handled := a.resolvePreAuthEnvironmentOutcome(ctx, span, preAuthEnvironmentOutcome{
			current:                 definitions.AuthResultLuaEnvironment,
			decision:                environmentDecisionLua,
			reject:                  true,
			continuePolicyAuthority: true,
			markPolicyContinue:      true,
		}); handled {
			return result, true
		}
	} else if skipRemainingEnvironment {
		if result, handled := a.resolvePreAuthEnvironmentOutcome(ctx, span, preAuthEnvironmentOutcome{
			current:  definitions.AuthResultOK,
			decision: environmentDecisionAbort,
		}); handled {
			return result, true
		}

		return definitions.AuthResultOK, true
	}

	return definitions.AuthResultUnset, false
}

func (a *AuthState) handleTLSEnvironmentResult(ctx *gin.Context, span trace.Span) (definitions.AuthResult, bool) {
	tlsTriggered := a.checkTLSEncryptionEnvironment(ctx)
	a.recordPolicyTLS(ctx, tlsTriggered)

	if tlsTriggered {
		if result, handled := a.resolvePreAuthEnvironmentOutcome(ctx, span, preAuthEnvironmentOutcome{
			current:                 definitions.AuthResultPreAuthTLS,
			decision:                environmentDecisionTLS,
			reject:                  true,
			continuePolicyAuthority: true,
			markPolicyContinue:      true,
		}); handled {
			return result, true
		}
	}

	return definitions.AuthResultUnset, false
}

func (a *AuthState) handleRelayDomainEnvironmentResult(ctx *gin.Context, span trace.Span) (definitions.AuthResult, bool) {
	relayTriggered := a.checkRelayDomainsEnvironment(ctx)
	a.recordPolicyRelayDomains(ctx, relayTriggered)

	if relayTriggered {
		if result, handled := a.resolvePreAuthEnvironmentOutcome(ctx, span, preAuthEnvironmentOutcome{
			current:                 definitions.AuthResultPreAuthRelayDomain,
			decision:                environmentDecisionRelayDomains,
			reject:                  true,
			continuePolicyAuthority: true,
			markPolicyContinue:      true,
		}); handled {
			return result, true
		}
	}

	return definitions.AuthResultUnset, false
}

func (a *AuthState) handleRBLEnvironmentResult(ctx *gin.Context, span trace.Span) definitions.AuthResult {
	triggered, err := a.checkRBLEnvironment(ctx)
	if err != nil {
		a.recordPolicyRBL(ctx, triggered, err)
		span.RecordError(err)
		if result, handled := a.resolvePreAuthEnvironmentOutcome(ctx, span, preAuthEnvironmentOutcome{
			current:            definitions.AuthResultTempFail,
			decision:           environmentDecisionTempFail,
			markPolicyContinue: true,
		}); handled {
			return result
		}

		return definitions.AuthResultOK
	}

	if triggered {
		a.recordPolicyRBL(ctx, triggered, nil)
		if result, handled := a.resolvePreAuthEnvironmentOutcome(ctx, span, preAuthEnvironmentOutcome{
			current:            definitions.AuthResultPreAuthRBL,
			decision:           environmentDecisionRBL,
			reject:             true,
			markPolicyContinue: true,
		}); handled {
			return result
		}

		return definitions.AuthResultOK
	}

	a.recordPolicyRBL(ctx, triggered, nil)

	if result, handled := a.resolvePreAuthEnvironmentOutcome(ctx, span, preAuthEnvironmentOutcome{
		current:  definitions.AuthResultOK,
		decision: environmentDecisionOK,
	}); handled {
		return result
	}

	return definitions.AuthResultOK
}

func (a *AuthState) resolvePreAuthEnvironmentOutcome(
	ctx *gin.Context,
	span trace.Span,
	outcome preAuthEnvironmentOutcome,
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

func finishPreAuthEnvironmentOK(span trace.Span, skipRemaining bool) definitions.AuthResult {
	attributes := []attribute.KeyValue{attribute.String("decision", environmentDecisionOK)}
	if skipRemaining {
		attributes = append(attributes, attribute.Bool(policySkipRemainingAttr, true))
	}

	span.SetAttributes(attributes...)
	span.End()

	return definitions.AuthResultOK
}

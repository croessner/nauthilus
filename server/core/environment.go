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

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/environment"
	"github.com/croessner/nauthilus/v3/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v3/server/lualib/pipeline"
	"github.com/croessner/nauthilus/v3/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v3/server/policy"
	policycollection "github.com/croessner/nauthilus/v3/server/policy/collection"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"

	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	environmentDecisionOK           = "ok"
	environmentDecisionPlugin       = "environment_plugin"
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
	currentEnvironmentControls, exists := a.Runtime.Context.GetExists(definitions.LuaCtxBuiltin)
	if !exists {
		currentEnvironmentControls = nil
	}

	environmentControlSet := environmentControlStringSet(currentEnvironmentControls)

	environmentControlSet.Set(environmentName)

	a.Runtime.Context.Set(definitions.LuaCtxBuiltin, environmentControlSet)
}

// environmentControlStringSet restores the internal set from supported runtime bridge representations.
func environmentControlStringSet(value any) config.StringSet {
	controls := config.NewStringSet()

	switch typed := value.(type) {
	case config.StringSet:
		for control := range typed {
			controls.Set(control)
		}
	case map[string]any:
		for control := range typed {
			controls.Set(control)
		}
	case []string:
		for _, control := range typed {
			controls.Set(control)
		}
	case []any:
		for _, value := range typed {
			if control, ok := value.(string); ok {
				controls.Set(control)
			}
		}
	}

	return controls
}

// EnvironmentLuaSource runs one generation-owned precompiled environment source.
func (a *AuthState) EnvironmentLuaSource(
	ctx *gin.Context,
	name string,
	prototype *lua.FunctionProto,
	pools *vmpool.Manager,
	poolKey vmpool.PoolKey,
	modules *luaseal.Modules,
) (triggered bool, skipRemainingEnvironment bool, err error) {
	if name == "" || prototype == nil || pools == nil || poolKey == "" {
		return false, false, fmt.Errorf("generation-owned Lua environment source is incomplete")
	}

	return a.environmentLuaSource(ctx, &environment.LuaEnvironmentSource{
		Name: name, CompiledScript: prototype, Modules: modules,
		Modes: pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated | pipeline.ModeNoAuth,
	}, pools, poolKey)
}

// environmentLuaSource constructs request state for one generation-owned source.
func (a *AuthState) environmentLuaSource(
	ctx *gin.Context,
	source *environment.LuaEnvironmentSource,
	pools *vmpool.Manager,
	poolKey vmpool.PoolKey,
) (triggered bool, skipRemainingEnvironment bool, err error) {
	resource := util.RequestResource(ctx, ctx.Request, a.Request.Service)
	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromEnvironment, definitions.ControlLua, resource)

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
		Tolerate:             a.deps.Tolerate,
		ScriptRecorder:       policycollection.NewScriptSink(policyCtx),
		PolicyContext:        policyCtx,
	}

	triggered, skipRemainingEnvironment, err = fr.CallEnvironmentLuaSource(
		ctx,
		a.Cfg(),
		a.Logger(),
		a.Redis(),
		source,
		pools,
		poolKey,
	)
	if err != nil {
		return
	}

	a.Security.Logs = fr.Logs
	if fr.StatusMessage != nil {
		a.Runtime.StatusMessage = *fr.StatusMessage
	}

	return
}

// ControlTLSEncryption checks, if the remote client connection was secured.
func (a *AuthState) ControlTLSEncryption(ctx *gin.Context) (triggered bool) {
	if a.Env() != nil && a.Env().GetDevMode() {
		return
	}

	if a.Request.XSSL != "" {
		return
	}

	resource := util.RequestResource(ctx, ctx.Request, a.Request.Service)
	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromEnvironment, definitions.ControlTLSEncryption, resource)

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

	requestScope := a.scopeRequestContext(rctx, ctx)

	defer requestScope.Restore()

	resource := util.RequestResource(ctx, ctx.Request, a.Request.Service)
	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromDNS, definitions.ControlRBL, resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	defer rsp.End()

	return a.evaluateRBLService(ctx, rsp)
}

func (a *AuthState) evaluateRBLService(ctx *gin.Context, span trace.Span) (bool, error) {
	svc := a.deps.HostServices.rbl
	if svc == nil {
		return false, nil
	}

	score, err := a.scoreRBLService(ctx, svc)
	if err != nil {
		span.RecordError(err)

		return false, err
	}

	threshold := 0
	if rbls := a.Cfg().GetRBLs(); rbls != nil {
		threshold = rbls.GetThreshold()
	}

	a.Runtime.RBLPolicy.Threshold = threshold

	matched := score >= threshold
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

// checkTLSEncryptionEnvironment determines if the TLS encryption environment control should be processed for the current authentication state.
// It uses a whitelist check to decide if the environment control action needs to be executed based on the current auth state.
func (a *AuthState) checkTLSEncryptionEnvironment(ctx *gin.Context, record func(bool)) (triggered bool) {
	tr := monittrace.New("nauthilus/auth")
	fctx, fspan := tr.Start(ctx.Request.Context(), "auth.environment.tls",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	requestScope := a.scopeRequestContext(fctx, ctx)

	defer requestScope.Restore()
	defer fspan.End()
	defer func() {
		if record != nil {
			record(triggered)
		}
	}()

	checkFunc := func() {
		if triggered = a.ControlTLSEncryption(ctx); triggered {
			a.processEnvironmentAction(ctx, definitions.ControlTLSEncryption)
		}
	}

	a.checkEnvironmentControlWithAllowlist(definitions.ControlTLSEncryption, func() bool { return false }, checkFunc)

	return
}

// checkRelayDomainsEnvironment evaluates if the relay domains environment control should be activated for the given AuthState instance.
// It checks if the client is whitelisted and processes the environment control action accordingly.
func (a *AuthState) checkRelayDomainsEnvironment(ctx *gin.Context, record func(bool)) (triggered bool) {
	tr := monittrace.New("nauthilus/auth")
	fctx, fspan := tr.Start(ctx.Request.Context(), "auth.environment.relay_domains",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	requestScope := a.scopeRequestContext(fctx, ctx)

	defer requestScope.Restore()
	defer fspan.End()
	defer func() {
		if record != nil {
			record(triggered)
		}
	}()

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

	requestScope := a.scopeRequestContext(fctx, ctx)

	defer requestScope.Restore()
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

type authnEnvironmentProviderPlan struct {
	tls   bool
	relay bool
	rbl   bool
}

// HandleEnvironment processes the complete established environment provider sequence.
func (a *AuthState) HandleEnvironment(ctx *gin.Context) definitions.AuthResult {
	return a.handleEnvironmentProviders(ctx, authnEnvironmentProviderPlan{
		tls:   true,
		relay: true,
		rbl:   true,
	})
}

// handleEnvironmentProviders runs only the providers selected by the captured authn plan.
func (a *AuthState) handleEnvironmentProviders(
	ctx *gin.Context,
	plan authnEnvironmentProviderPlan,
) definitions.AuthResult {
	if util.IsHTTPRequestCanceled(a.Logger(), ctx.Request, a.Runtime.GUID, "environment.evaluate") {
		return definitions.AuthResultTempFail
	}

	defer a.completePolicyStage(ctx, policy.StagePreAuth)

	fsp, requestScope := a.startEnvironmentEvaluation(ctx)

	defer requestScope.Restore()

	if !a.cfg().HasRuntimeModule(definitions.ControlBruteForce) {
		a.refreshUserAccount()
	}

	if plan.tls {
		if result, handled := a.handleTLSEnvironmentResult(ctx, fsp); handled {
			return result
		}
	}

	if plan.relay {
		if result, handled := a.handleRelayDomainEnvironmentResult(ctx, fsp); handled {
			return result
		}
	}

	if plan.rbl {
		return a.handleRBLEnvironmentResult(ctx, fsp)
	}

	return finishPreAuthEnvironmentOK(fsp, false)
}

func (a *AuthState) startEnvironmentEvaluation(ctx *gin.Context) (trace.Span, *requestContextScope) {
	tr := monittrace.New("nauthilus/environment")
	fctx, fsp := tr.Start(ctx.Request.Context(), "environment.evaluate",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
		attribute.String("protocol", a.Request.Protocol.Get()),
	)

	requestScope := a.scopeRequestContext(fctx, ctx)

	return fsp, requestScope
}

func (a *AuthState) handleTLSEnvironmentResult(ctx *gin.Context, span trace.Span) (definitions.AuthResult, bool) {
	return a.handleRecordedRejectingEnvironmentResult(
		ctx,
		span,
		a.checkTLSEncryptionEnvironment,
		a.recordPolicyTLS,
		preAuthEnvironmentOutcome{
			current:                 definitions.AuthResultPreAuthTLS,
			decision:                environmentDecisionTLS,
			reject:                  true,
			continuePolicyAuthority: true,
			markPolicyContinue:      true,
		},
	)
}

func (a *AuthState) handleRelayDomainEnvironmentResult(ctx *gin.Context, span trace.Span) (definitions.AuthResult, bool) {
	return a.handleRecordedRejectingEnvironmentResult(
		ctx,
		span,
		a.checkRelayDomainsEnvironment,
		a.recordPolicyRelayDomains,
		preAuthEnvironmentOutcome{
			current:                 definitions.AuthResultPreAuthRelayDomain,
			decision:                environmentDecisionRelayDomains,
			reject:                  true,
			continuePolicyAuthority: true,
			markPolicyContinue:      true,
		},
	)
}

// handleRecordedRejectingEnvironmentResult evaluates and records one rejecting environment source.
func (a *AuthState) handleRecordedRejectingEnvironmentResult(
	ctx *gin.Context,
	span trace.Span,
	check func(*gin.Context, func(bool)) bool,
	record func(*gin.Context, bool),
	outcome preAuthEnvironmentOutcome,
) (definitions.AuthResult, bool) {
	triggered := check(ctx, func(triggered bool) {
		record(ctx, triggered)
	})
	if triggered {
		return a.resolvePreAuthEnvironmentOutcome(ctx, span, outcome)
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

// resolvePreAuthEnvironmentOutcome records the host result for generation-owned selection.
func (a *AuthState) resolvePreAuthEnvironmentOutcome(
	ctx *gin.Context,
	span trace.Span,
	outcome preAuthEnvironmentOutcome,
) (definitions.AuthResult, bool) {
	span.SetAttributes(attribute.String("decision", outcome.decision))

	if authnCandidateRuntimeOwnsPolicy(ctx) {
		markEnvironmentRejected(ctx, outcome.reject)
		span.End()

		return outcome.current, true
	}

	markEnvironmentRejected(ctx, outcome.reject)
	span.End()

	return outcome.current, true
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

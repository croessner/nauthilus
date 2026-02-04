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
	"github.com/croessner/nauthilus/server/lualib/feature"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
)

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

// FeatureLua runs Lua scripts and returns a trigger result.
func (a *AuthState) FeatureLua(ctx *gin.Context) (triggered bool, abortFeatures bool, err error) {
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

	fr := &feature.Request{
		Session:            a.Runtime.GUID,
		Username:           a.Request.Username,
		Password:           a.Request.Password,
		ClientIP:           a.Request.ClientIP,
		AccountName:        a.GetAccount(),
		UsedBackendPort:    &a.Runtime.UsedBackendPort,
		Logs:               nil,
		Context:            a.Runtime.Context,
		HTTPClientContext:  a.Request.HTTPClientContext,
		HTTPClientRequest:  a.Request.HTTPClientRequest,
		NoAuth:             a.Request.NoAuth,
		BruteForceCounter:  0,
		MasterUserMode:     a.Runtime.MasterUserMode,
		AdditionalFeatures: a.Runtime.AdditionalFeatures,
		CommonRequest:      cr,
	}

	triggered, abortFeatures, err = fr.CallFeatureLua(ctx, a.Cfg(), a.Logger(), a.Redis())

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

	username := handleMasterUserMode(a.cfg(), a)

	if strings.Contains(username, "@") {
		split := strings.Split(username, "@")
		if len(split) != 2 {
			return
		}

		for _, domain := range relayDomains.StaticDomains {
			if strings.EqualFold(domain, split[1]) {
				return
			}
		}

		a.logAddMessage(fmt.Sprintf("%s not our domain", split[1]), definitions.FeatureRelayDomains)
		a.updateLuaContext(definitions.FeatureRelayDomains)

		triggered = true
	}

	return
}

// FeatureRBLs is a method that checks if the client IP address is whitelisted, and then performs an RBL check
// on the client's IP address. If the RBL score exceeds the configured threshold, the 'triggered' flag is set to true.
// It returns the 'triggered' flag and any error that occurred during the check.
func (a *AuthState) FeatureRBLs(ctx *gin.Context) (triggered bool, err error) {
	rbls := a.cfg().GetRBLs()
	if rbls == nil {
		return
	}

	if isLocalOrEmptyIP(a.Request.ClientIP) {
		a.logAddLocalhost(definitions.FeatureRBL)

		return
	}

	if util.IsInNetworkWithCfg(ctx.Request.Context(), a.Cfg(), a.Logger(), rbls.GetIPWhiteList(), a.Runtime.GUID, a.Request.ClientIP) {
		a.logAddMessage(definitions.Whitelisted, definitions.FeatureRBL)

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
		score, e := svc.Score(ctx, a.View())
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

// checkLuaFeature evaluates Lua-based features for the given authentication context.
// It determines if a feature is triggered or if further processing should be aborted.
// It uses a whitelist check and processes feature actions if the Lua feature is activated.
// Returns 'triggered' if a Lua feature is triggered, 'abortFeatures' if further features should be halted.
func (a *AuthState) checkLuaFeature(ctx *gin.Context) (triggered bool, abortFeatures bool, err error) {
	tr := monittrace.New("nauthilus/auth")
	fctx, fspan := tr.Start(ctx.Request.Context(), "auth.features.lua",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	ctx.Request = ctx.Request.WithContext(fctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(fctx)
	}

	defer fspan.End()

	checkFunc := func() {
		triggered, abortFeatures, err = a.FeatureLua(ctx)
		if err != nil {
			a.Runtime.FeatureName = ""

			return
		}

		if triggered {
			a.processFeatureAction(ctx, definitions.FeatureLua, definitions.LuaActionLua, definitions.LuaActionLuaName)
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
			a.processFeatureAction(ctx, definitions.FeatureTLSEncryption, definitions.LuaActionTLS, definitions.LuaActionTLSName)
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
			a.processFeatureAction(ctx, definitions.FeatureRelayDomains, definitions.LuaActionRelayDomains, definitions.LuaActionRelayDomainsName)
		}
	}

	a.checkFeatureWithWhitelist(definitions.FeatureRelayDomains, isWhitelisted, checkFunc)

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

		a.processFeatureAction(ctx, definitions.FeatureRBL, definitions.LuaActionRBL, definitions.LuaActionRBLName)
	}

	a.checkFeatureWithWhitelist(definitions.FeatureRBL, isWhitelisted, checkFunc)

	return
}

// processFeatureAction updates the feature and increments the brute force counter if learning is enabled for the feature.
// It executes a specified Lua action using the provided action name.
func (a *AuthState) processFeatureAction(ctx *gin.Context, featureName string, luaAction definitions.LuaAction, luaActionName string) {
	a.Runtime.FeatureName = featureName

	bruteForce := a.cfg().GetBruteForce()
	if bruteForce != nil && bruteForce.LearnFromFeature(featureName) {
		a.UpdateBruteForceBucketsCounter(ctx)
	}

	a.performAction(luaAction, luaActionName)
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

	if !a.cfg().HasFeature(definitions.FeatureBruteForce) {
		a.refreshUserAccount()
	}

	if triggered, abortFeatures, err := a.checkLuaFeature(ctx); err != nil {
		fsp.RecordError(err)
		fsp.SetAttributes(attribute.String("decision", "tempfail"))
		fsp.End()

		return definitions.AuthResultTempFail
	} else if triggered {
		fsp.SetAttributes(attribute.String("decision", "feature_lua"))
		fsp.End()

		return definitions.AuthResultFeatureLua
	} else if abortFeatures {
		fsp.SetAttributes(attribute.String("decision", "abort_features"))
		fsp.End()

		return definitions.AuthResultOK
	}

	if a.checkTLSEncryptionFeature(ctx) {
		fsp.SetAttributes(attribute.String("decision", "feature_tls"))
		fsp.End()

		return definitions.AuthResultFeatureTLS
	}

	if a.checkRelayDomainsFeature(ctx) {
		fsp.SetAttributes(attribute.String("decision", "feature_relay_domains"))
		fsp.End()

		return definitions.AuthResultFeatureRelayDomain
	}

	if triggered, err := a.checkRBLFeature(ctx); err != nil {
		fsp.RecordError(err)
		fsp.SetAttributes(attribute.String("decision", "tempfail"))
		fsp.End()

		return definitions.AuthResultTempFail
	} else if triggered {
		fsp.SetAttributes(attribute.String("decision", "feature_rbl"))
		fsp.End()

		return definitions.AuthResultFeatureRBL
	}

	fsp.SetAttributes(attribute.String("decision", "ok"))
	fsp.End()

	return definitions.AuthResultOK
}

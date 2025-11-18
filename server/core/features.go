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
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
)

// isLocalOrEmptyIP checks whether the provided IP is empty, an IPv4 localhost, or an IPv6 localhost.
func isLocalOrEmptyIP(ip string) bool {
	return ip == definitions.Localhost4 || ip == definitions.Localhost6 || ip == ""
}

// logAddMessage appends a feature and message to the AdditionalLogs slice of the provided AuthState if it is not nil.
func logAddMessage(auth *AuthState, message, feature string) {
	if auth == nil {
		return
	}

	auth.AdditionalLogs = append(auth.AdditionalLogs, feature)
	auth.AdditionalLogs = append(auth.AdditionalLogs, message)
}

// logAddLocalhost appends feature-specific logs and the "localhost" indicator to the auth state if the auth pointer is valid.
func logAddLocalhost(auth *AuthState, feature string) {
	if auth == nil {
		return
	}

	auth.AdditionalLogs = append(auth.AdditionalLogs, fmt.Sprintf("%s_%s", definitions.LogKeyFeatureName, feature))
	auth.AdditionalLogs = append(auth.AdditionalLogs, definitions.Localhost)
}

// updateLuaContext updates the Lua context with a new feature in the Gin context, ensuring unique entries.
func updateLuaContext(ctx *lualib.Context, feature string) {
	var featureList config.StringSet

	curFeatures, exists := ctx.GetExists(definitions.LuaCtxBuiltin)
	if !exists {
		featureList = config.NewStringSet()
	} else {
		featureList = curFeatures.(config.StringSet)
	}

	featureList.Set(feature)

	ctx.Set(definitions.LuaCtxBuiltin, featureList)
}

// FeatureLua runs Lua scripts and returns a trigger result.
func (a *AuthState) FeatureLua(ctx *gin.Context) (triggered bool, abortFeatures bool, err error) {
	if isLocalOrEmptyIP(a.ClientIP) {
		logAddLocalhost(a, definitions.FeatureLua)

		return
	}

	stopTimer := stats.PrometheusTimer(definitions.PromFeature, definitions.FeatureLua)

	if stopTimer != nil {
		defer stopTimer()
	}

	if engine := GetFeatureEngine(); engine != nil {
		trig, abort, logs, newStatus, evalErr := engine.Evaluate(ctx, a.View())
		if evalErr != nil {
			return false, false, evalErr
		}

		if len(logs) > 0 {
			a.AdditionalLogs = append(a.AdditionalLogs, logs...)
		}

		if newStatus != nil && *newStatus != a.StatusMessage {
			a.StatusMessage = *newStatus
		}

		return trig, abort, nil
	}

	return false, false, nil
}

// FeatureTLSEncryption checks, if the remote client connection was secured.
func (a *AuthState) FeatureTLSEncryption() (triggered bool) {
	if isLocalOrEmptyIP(a.ClientIP) {
		logAddLocalhost(a, definitions.FeatureTLSEncryption)

		return
	}

	if a.XSSL != "" {
		return
	}

	stopTimer := stats.PrometheusTimer(definitions.PromFeature, definitions.FeatureTLSEncryption)

	if stopTimer != nil {
		defer stopTimer()
	}

	if !a.IsInNetwork(config.GetFile().GetClearTextList()) {
		logAddMessage(a, definitions.NoTLS, definitions.FeatureTLSEncryption)
		updateLuaContext(a.Context, definitions.FeatureTLSEncryption)

		triggered = true

		return
	}

	logAddMessage(a, definitions.Whitelisted, definitions.FeatureTLSEncryption)

	return
}

// FeatureRelayDomains triggers if a user sent an email address as a login name and the domain component does not
// match the list of known domains.
func (a *AuthState) FeatureRelayDomains() (triggered bool) {
	relayDomains := config.GetFile().GetRelayDomains()
	if relayDomains == nil {
		return
	}

	if len(relayDomains.StaticDomains) == 0 {
		return
	}

	if isLocalOrEmptyIP(a.ClientIP) {
		logAddLocalhost(a, definitions.FeatureRelayDomains)

		return
	}

	stopTimer := stats.PrometheusTimer(definitions.PromFeature, definitions.FeatureRelayDomains)

	if stopTimer != nil {
		defer stopTimer()
	}

	username := handleMasterUserMode(a)

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

		logAddMessage(a, fmt.Sprintf("%s not our domain", split[1]), definitions.FeatureRelayDomains)
		updateLuaContext(a.Context, definitions.FeatureRelayDomains)

		triggered = true
	}

	return
}

// FeatureRBLs is a method that checks if the client IP address is whitelisted, and then performs an RBL check
// on the client's IP address. If the RBL score exceeds the configured threshold, the 'triggered' flag is set to true.
// It returns the 'triggered' flag and any error that occurred during the check.
func (a *AuthState) FeatureRBLs(ctx *gin.Context) (triggered bool, err error) {
	rbls := config.GetFile().GetRBLs()
	if rbls == nil {
		return
	}

	if isLocalOrEmptyIP(a.ClientIP) {
		logAddLocalhost(a, definitions.FeatureRBL)

		return
	}

	if a.IsInNetwork(rbls.GetIPWhiteList()) {
		logAddMessage(a, definitions.Whitelisted, definitions.FeatureRBL)

		return
	}

	stopTimer := stats.PrometheusTimer(definitions.PromDNS, definitions.FeatureRBL)
	if stopTimer != nil {
		defer stopTimer()
	}

	if svc := GetRBLService(); svc != nil {
		score, e := svc.Score(ctx, a.View())
		if e != nil {
			return false, e
		}

		if score >= svc.Threshold() {
			updateLuaContext(a.Context, definitions.FeatureRBL)
			return true, nil
		}
	}

	return false, nil
}

// initializeAccountName initializes the account name if it is not already set by calling refreshUserAccount.
func (a *AuthState) initializeAccountName() {
	if a.refreshUserAccount() == "" {
		a.refreshUserAccount()
	}
}

// logFeatureWhitelisting appends the given feature name and a soft whitelisted message to the additional logs of AuthState.
func (a *AuthState) logFeatureWhitelisting(featureName string) {
	a.AdditionalLogs = append(a.AdditionalLogs, featureName, definitions.SoftWhitelisted)
}

// checkFeatureWithWhitelist checks if a feature is enabled and if a whitelist applies, executes the feature check function.
// If the feature is enabled and the whitelist applies, logs the event and returns false.
// Executes the checkFunc when the feature is enabled and not whitelisted, returning its outcome.
// Returns false if the feature is not enabled in the configuration.
func (a *AuthState) checkFeatureWithWhitelist(featureName string, isWhitelisted func() bool, checkFunc func()) {
	if config.GetFile().HasFeature(featureName) {
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
	checkFunc := func() {
		triggered, abortFeatures, err = a.FeatureLua(ctx)
		if err != nil {
			a.FeatureName = ""

			return
		}

		if triggered {
			a.processFeatureAction(ctx, definitions.FeatureLua, definitions.LuaActionLua, definitions.LuaActionLuaName)
		}

		if abortFeatures {
			a.FeatureName = ""
			abortFeatures = true
		}
	}

	a.checkFeatureWithWhitelist(definitions.FeatureLua, func() bool { return false }, checkFunc)

	return
}

// checkTLSEncryptionFeature determines if the TLS encryption feature should be processed for the current authentication state.
// It uses a whitelist check to decide if the feature action needs to be executed based on the current auth state.
func (a *AuthState) checkTLSEncryptionFeature(ctx *gin.Context) (triggered bool) {
	checkFunc := func() {
		if triggered = a.FeatureTLSEncryption(); triggered {
			a.processFeatureAction(ctx, definitions.FeatureTLSEncryption, definitions.LuaActionTLS, definitions.LuaActionTLSName)
		}
	}

	a.checkFeatureWithWhitelist(definitions.FeatureTLSEncryption, func() bool { return false }, checkFunc)

	return
}

// checkRelayDomainsFeature evaluates if the relay domains feature should be activated for the given AuthState instance.
// It checks if the client is whitelisted and processes the feature action accordingly.
func (a *AuthState) checkRelayDomainsFeature(ctx *gin.Context) (triggered bool) {
	isWhitelisted := func() bool {
		relayDomains := config.GetFile().GetRelayDomains()
		if relayDomains == nil {
			return false
		}

		return relayDomains.HasSoftWhitelist() &&
			util.IsSoftWhitelisted(a.Username, a.ClientIP, a.GUID, relayDomains.SoftWhitelist)
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
	isWhitelisted := func() bool {
		rbls := config.GetFile().GetRBLs()
		if rbls == nil {
			return false
		}

		return rbls.HasSoftWhitelist() &&
			util.IsSoftWhitelisted(a.Username, a.ClientIP, a.GUID, rbls.SoftWhitelist)
	}

	checkFunc := func() {
		triggered, err = a.FeatureRBLs(ctx)
		if err != nil || !triggered {
			a.FeatureName = ""

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
	a.FeatureName = featureName

	bruteForce := config.GetFile().GetBruteForce()
	if bruteForce != nil && bruteForce.LearnFromFeature(featureName) {
		a.UpdateBruteForceBucketsCounter(ctx)
	}

	a.performAction(luaAction, luaActionName)
}

// performAction triggers the execution of a specified Lua action if Lua actions are enabled in the configuration.
// It initializes an account name if absent, sends the action request to the RequestChan channel,
// and waits for the action to complete.
func (a *AuthState) performAction(luaAction definitions.LuaAction, luaActionName string) {
	if !config.GetFile().HaveLuaActions() {
		return
	}

	stopTimer := stats.PrometheusTimer(definitions.PromAction, luaActionName)
	if stopTimer != nil {
		defer stopTimer()
	}

	if a.GetAccount() == "" {
		a.initializeAccountName()
	}

	if disp := GetActionDispatcher(); disp != nil {
		disp.Dispatch(a.View(), a.FeatureName, luaAction)
	}
}

// HandleFeatures processes multiple security features associated with authentication requests and returns the result.
// It checks for various features like TLS encryption, relay domains, RBL, and Lua scripting.
// The method returns an appropriate authentication result based on the features that are triggered or aborted.
func (a *AuthState) HandleFeatures(ctx *gin.Context) definitions.AuthResult {
	if !config.GetFile().HasFeature(definitions.FeatureBruteForce) {
		a.initializeAccountName()
	}

	if triggered, abortFeatures, err := a.checkLuaFeature(ctx); err != nil {
		return definitions.AuthResultTempFail
	} else if triggered {
		return definitions.AuthResultFeatureLua
	} else if abortFeatures {
		return definitions.AuthResultOK
	}

	if a.checkTLSEncryptionFeature(ctx) {
		return definitions.AuthResultFeatureTLS
	}

	if a.checkRelayDomainsFeature(ctx) {
		return definitions.AuthResultFeatureRelayDomain
	}

	if triggered, err := a.checkRBLFeature(ctx); err != nil {
		return definitions.AuthResultTempFail
	} else if triggered {
		return definitions.AuthResultFeatureRBL
	}

	return definitions.AuthResultOK
}

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
	"sync"
	"sync/atomic"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/lualib/feature"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
)

// isLocalOrEmptyIP checks if the given IP address is localhost or an empty string.
//
// It returns true if the IP address is localhost (either IPv4 or IPv6) or an empty string,
// and false otherwise.
//
// Parameters:
//   - ip: The IP address to check.
//
// Returns:
//   - bool: True if the IP address is localhost or empty, false otherwise.
func isLocalOrEmptyIP(ip string) bool {
	return ip == definitions.Localhost4 || ip == definitions.Localhost6 || ip == ""
}

// logAddMessage logs a message with the specified parameters using the global logger. It is intended to be a handleAuthentication logging function.
//
// Parameters:
//   - auth: Pointer to AuthState
//   - message: The message to log.
//   - feature: The feature name.
//
// Example usage:
//
//	logAddMessage("This is a log message", "12345", "feature", "192.168.0.1")
func logAddMessage(auth *AuthState, message, feature string) {
	if auth == nil {
		return
	}

	auth.AdditionalLogs = append(auth.AdditionalLogs, feature)
	auth.AdditionalLogs = append(auth.AdditionalLogs, message)
}

// logAddLocalhost adds the given feature to the whitelist of additional logs
// in the AuthState struct. It appends the feature name and "localhost" to the
// AdditionalLogs slice.
//
// Parameters:
//   - a: A pointer to an AuthState instance.
//   - feature: The name of the feature to be added to the whitelist.
//
// Returns:
//   - None.
func logAddLocalhost(auth *AuthState, feature string) {
	if auth == nil {
		return
	}

	auth.AdditionalLogs = append(auth.AdditionalLogs, fmt.Sprintf("%s_%s", definitions.LogKeyFeatureName, feature))
	auth.AdditionalLogs = append(auth.AdditionalLogs, definitions.Localhost)
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

	accountName := a.GetAccount()

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()
	// Set the fields
	commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Repeating = false // unavailable
	commonRequest.UserFound = func() bool { return accountName != "" }()
	commonRequest.Authenticated = false // unavailable
	commonRequest.NoAuth = a.NoAuth
	commonRequest.BruteForceCounter = 0 // unavailable
	commonRequest.Service = a.Service
	commonRequest.Session = *a.GUID
	commonRequest.ClientIP = a.ClientIP
	commonRequest.ClientPort = a.XClientPort
	commonRequest.ClientNet = "" // unavailable
	commonRequest.ClientHost = a.ClientHost
	commonRequest.ClientID = a.XClientID
	commonRequest.UserAgent = *a.UserAgent
	commonRequest.LocalIP = a.XLocalIP
	commonRequest.LocalPort = a.XPort
	commonRequest.Username = a.Username
	commonRequest.Account = accountName
	commonRequest.AccountField = a.GetAccountField()
	commonRequest.UniqueUserID = "" // unavailable
	commonRequest.DisplayName = ""  // unavailable
	commonRequest.Password = a.Password
	commonRequest.Protocol = a.Protocol.String()
	commonRequest.OIDCCID = a.OIDCCID
	commonRequest.BruteForceName = "" // unavailable
	commonRequest.FeatureName = ""    // unavailable
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

	featureRequest := feature.Request{
		Context:       a.Context,
		CommonRequest: commonRequest,
	}

	triggered, abortFeatures, err = featureRequest.CallFeatureLua(ctx)

	if featureRequest.Logs != nil {
		for index := range *featureRequest.Logs {
			a.AdditionalLogs = append(a.AdditionalLogs, (*featureRequest.Logs)[index])
		}
	}

	if statusMessage := featureRequest.StatusMessage; *statusMessage != a.StatusMessage {
		a.StatusMessage = *statusMessage
	}

	// Return the CommonRequest to the pool
	lualib.PutCommonRequest(commonRequest)

	return
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

		triggered = true

		return
	}

	logAddMessage(a, definitions.Whitelisted, definitions.FeatureTLSEncryption)

	return
}

// FeatureRelayDomains triggers if a user sent an email address as a login name and the domain component does not
// match the list of known domains.
func (a *AuthState) FeatureRelayDomains() (triggered bool) {
	if config.GetFile().GetRelayDomains() == nil {
		return
	}

	if len(config.GetFile().GetRelayDomains().StaticDomains) == 0 {
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

		for _, domain := range config.GetFile().GetRelayDomains().StaticDomains {
			if strings.EqualFold(domain, split[1]) {
				return
			}
		}

		logAddMessage(a, fmt.Sprintf("%s not our domain", split[1]), definitions.FeatureRelayDomains)

		triggered = true
	}

	return
}

// processRBL processes the given RBL (Real-time Blackhole BlockedIPAddresses) by checking if the IP address is listed.
// It uses the isListed method to check if the IP address is listed in the RBL.
// If an error occurs while checking the RBL, handleRBLError is called to handle the error.
// If the IP address is listed in the RBL, it logs the matched RBL and returns the weight associated with the RBL.
// If the IP address is not listed in the RBL, it returns 0 as the weight.
// The method runs concurrently using goroutines and waits for all goroutines to finish using a wait group.
//
// Parameters:
//
//	ctx - is a Gin context
//	rbl - is the RBL configuration
//	rblChan - is the channel to send the RBL weight
//	waitGroup - is used to synchronize the goroutines
//
// dnsResolverErr - is an atomic boolean to indicate if a DNS resolver error occurred
func (a *AuthState) processRBL(ctx *gin.Context, rbl *config.RBL, rblChan chan int, waitGroup *sync.WaitGroup, dnsResolverErr *atomic.Bool) {
	isListed, rblName, rblErr := a.isListed(ctx, rbl)
	if rblErr != nil {
		handleRBLError(*a.GUID, rblErr, rbl, dnsResolverErr)
		handleRBLOutcome(waitGroup, rblChan, 0)

		return
	}

	if isListed {
		stats.GetMetrics().GetRblRejected().WithLabelValues(rblName).Inc()
		logMatchedRBL(a, rblName, rbl.Weight)
		handleRBLOutcome(waitGroup, rblChan, rbl.Weight)

		return
	}

	handleRBLOutcome(waitGroup, rblChan, 0)
}

// handleRBLOutcome handles the outcome of the RBL processing by sending the weight to the rblChan channel.
// It decreases the wait group counter by calling the Done() method on the wait group.
//
// Parameters:
//
//	waitGroup - is used to synchronize the goroutines by decreasing the counter
//	rblChan - is the channel to send the RBL weight
//	weight - is the weight associated with the RBL
//
// Usage example:
//
//	handleRBLOutcome(waitGroup, rblChan, rbl.Weight)
func handleRBLOutcome(waitGroup *sync.WaitGroup, rblChan chan int, weight int) {
	waitGroup.Done()

	rblChan <- weight
}

// handleRBLError handles errors that occur during RBL processing.
// If the error is a network DNS error with "no such host" message, it logs the error in debug mode.
// Otherwise, if AllowFailure is false, it sets dnsResolverErr to true.
// Finally, it logs the error at the error level.
func handleRBLError(guid string, err error, rbl *config.RBL, dnsResolverErr *atomic.Bool) {
	if strings.Contains(err.Error(), "no such host") {
		util.DebugModule(definitions.DbgRBL, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)
	} else {
		if !rbl.AllowFailure {
			dnsResolverErr.Store(true)
		}

		level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)
	}
}

// logMatchedRBL logs the matched RBL information.
//
// Parameters:
//
//	 auth - pointer to AuthState
//		rblName - the name of the RBL that was matched
//		weight - the weight associated with the RBL
func logMatchedRBL(auth *AuthState, rblName string, weight int) {
	if auth == nil {
		return
	}

	auth.AdditionalLogs = append(auth.AdditionalLogs, "rbl "+rblName)
	auth.AdditionalLogs = append(auth.AdditionalLogs, weight)
}

// checkRBLs checks the remote client IP address against a list of realtime blocklists.
func (a *AuthState) checkRBLs(ctx *gin.Context) (totalRBLScore int, err error) {
	var (
		dnsResolverErr atomic.Bool
	)

	waitGroup := &sync.WaitGroup{}

	dnsResolverErr.Store(false)
	rblChan := make(chan int)
	numberOfRBLs := len(config.GetFile().GetRBLs().Lists)

	for _, rbl := range config.GetFile().GetRBLs().Lists {
		waitGroup.Add(1)

		go a.processRBL(ctx, &rbl, rblChan, waitGroup, &dnsResolverErr)
	}

	waitGroup.Wait()

	if dnsResolverErr.Load() {
		err = errors.ErrDNSResolver

		return
	}

	for rblScore := range rblChan {
		totalRBLScore += rblScore
		numberOfRBLs--

		if numberOfRBLs == 0 {
			break
		}
	}

	return
}

// FeatureRBLs is a method that checks if the client IP address is whitelisted, and then performs an RBL check
// on the client's IP address. If the RBL score exceeds the configured threshold, the 'triggered' flag is set to true.
// It returns the 'triggered' flag and any error that occurred during the check.
func (a *AuthState) FeatureRBLs(ctx *gin.Context) (triggered bool, err error) {
	var (
		totalRBLScore int
	)

	if config.GetFile().GetRBLs() == nil {
		return
	}

	if isLocalOrEmptyIP(a.ClientIP) {
		logAddLocalhost(a, definitions.FeatureRBL)

		return
	}

	if a.IsInNetwork(config.GetFile().GetRBLs().IPWhiteList) {
		logAddMessage(a, definitions.Whitelisted, definitions.FeatureRBL)

		return
	}

	stopTimer := stats.PrometheusTimer(definitions.PromDNS, definitions.FeatureRBL)

	if stopTimer != nil {
		defer stopTimer()
	}

	totalRBLScore, err = a.checkRBLs(ctx)
	if err != nil {
		return
	}

	if totalRBLScore >= config.GetFile().GetRBLs().Threshold {
		triggered = true
	}

	return
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
			a.processFeatureAction(definitions.FeatureLua, definitions.LuaActionLua, definitions.LuaActionLuaName)
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
func (a *AuthState) checkTLSEncryptionFeature() (triggered bool) {
	checkFunc := func() {
		if triggered = a.FeatureTLSEncryption(); triggered {
			a.processFeatureAction(definitions.FeatureTLSEncryption, definitions.LuaActionTLS, definitions.LuaActionTLSName)
		}
	}

	a.checkFeatureWithWhitelist(definitions.FeatureTLSEncryption, func() bool { return false }, checkFunc)

	return
}

// checkRelayDomainsFeature evaluates if the relay domains feature should be activated for the given AuthState instance.
// It checks if the client is whitelisted and processes the feature action accordingly.
func (a *AuthState) checkRelayDomainsFeature() (triggered bool) {
	isWhitelisted := func() bool {
		return config.GetFile().GetRelayDomains().HasSoftWhitelist() &&
			util.IsSoftWhitelisted(a.Username, a.ClientIP, *a.GUID, config.GetFile().GetRelayDomains().SoftWhitelist)
	}

	checkFunc := func() {
		if triggered = a.FeatureRelayDomains(); triggered {
			a.processFeatureAction(definitions.FeatureRelayDomains, definitions.LuaActionRelayDomains, definitions.LuaActionRelayDomainsName)
		}
	}

	a.checkFeatureWithWhitelist(definitions.FeatureRelayDomains, isWhitelisted, checkFunc)

	return
}

// checkRBLFeature checks if a Real-time Blackhole List (RBL) feature is triggered for the current request.
// Returns true if the feature is triggered and processed, otherwise false.
func (a *AuthState) checkRBLFeature(ctx *gin.Context) (triggered bool, err error) {
	isWhitelisted := func() bool {
		return config.GetFile().GetRBLs().HasSoftWhitelist() &&
			util.IsSoftWhitelisted(a.Username, a.ClientIP, *a.GUID, config.GetFile().GetRBLs().SoftWhitelist)
	}

	checkFunc := func() {
		triggered, err = a.FeatureRBLs(ctx)
		if err != nil || !triggered {
			a.FeatureName = ""

			return
		}

		a.processFeatureAction(definitions.FeatureRBL, definitions.LuaActionRBL, definitions.LuaActionRBLName)
	}

	a.checkFeatureWithWhitelist(definitions.FeatureRBL, isWhitelisted, checkFunc)

	return
}

// processFeatureAction updates the feature and increments the brute force counter if learning is enabled for the feature.
// It executes a specified Lua action using the provided action name.
func (a *AuthState) processFeatureAction(featureName string, luaAction definitions.LuaAction, luaActionName string) {
	a.FeatureName = featureName

	if config.GetFile().GetBruteForce().LearnFromFeature(featureName) {
		a.UpdateBruteForceBucketsCounter()
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

	finished := make(chan action.Done)

	if a.GetAccount() == "" {
		a.initializeAccountName()
	}

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()
	// Set the fields
	commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.UserFound = func() bool { return a.GetAccount() != "" }()
	commonRequest.NoAuth = a.NoAuth
	commonRequest.Service = a.Service
	commonRequest.Session = *a.GUID
	commonRequest.ClientIP = a.ClientIP
	commonRequest.ClientPort = a.XClientPort
	commonRequest.ClientHost = a.ClientHost
	commonRequest.ClientID = a.XClientID
	commonRequest.LocalIP = a.XLocalIP
	commonRequest.LocalPort = a.XPort
	commonRequest.UserAgent = *a.UserAgent
	commonRequest.Username = a.Username
	commonRequest.Account = a.GetAccount()
	commonRequest.AccountField = a.GetAccountField()
	commonRequest.Password = a.Password
	commonRequest.Protocol = a.Protocol.Get()
	commonRequest.OIDCCID = a.OIDCCID
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
		LuaAction:     luaAction,
		Context:       a.Context,
		FinishedChan:  finished,
		HTTPRequest:   a.HTTPClientContext.Request,
		CommonRequest: commonRequest,
	}

	<-finished

	// Return the CommonRequest to the pool
	lualib.PutCommonRequest(commonRequest)
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

	if a.checkTLSEncryptionFeature() {
		return definitions.AuthResultFeatureTLS
	}

	if a.checkRelayDomainsFeature() {
		return definitions.AuthResultFeatureRelayDomain
	}

	if triggered, err := a.checkRBLFeature(ctx); err != nil {
		return definitions.AuthResultTempFail
	} else if triggered {
		return definitions.AuthResultFeatureRBL
	}

	return definitions.AuthResultOK
}

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
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/bruteforce/ml"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/lualib/feature"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
)

// handleBruteForceLuaAction handles the brute force Lua action based on the provided authentication state and rule config.
func (a *AuthState) handleBruteForceLuaAction(alreadyTriggered bool, rule *config.BruteForceRule, network *net.IPNet) {
	if config.GetFile().HaveLuaActions() {
		finished := make(chan action.Done)
		accountName := a.GetAccount()

		// Get a CommonRequest from the pool
		commonRequest := lualib.GetCommonRequest()

		// Set the fields
		commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
		commonRequest.Repeating = alreadyTriggered
		commonRequest.UserFound = func() bool { return accountName != "" }()
		commonRequest.Authenticated = false // unavailable
		commonRequest.NoAuth = a.NoAuth
		commonRequest.BruteForceCounter = a.BruteForceCounter[rule.Name]
		commonRequest.Service = a.Service
		commonRequest.Session = *a.GUID
		commonRequest.ClientIP = a.ClientIP
		commonRequest.ClientPort = a.XClientPort
		commonRequest.ClientNet = network.String()
		commonRequest.ClientHost = a.ClientHost
		commonRequest.ClientID = a.XClientID
		commonRequest.LocalIP = a.XLocalIP
		commonRequest.LocalPort = a.XPort
		commonRequest.UserAgent = *a.UserAgent
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
			HTTPRequest:   nil, // We don't have access to the gin.Context here, so we can't use its Request
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
		definitions.LogKeyGUID, *auth.GUID,
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

// CheckBruteForce checks if a client is triggering brute force detection based on predefined rules and configurations.
// It evaluates conditions like authentication state, IP whitelisting, protocol enforcement, and bucket rate limits.
// Returns true if brute force detection is triggered, and false otherwise.
func (a *AuthState) CheckBruteForce(ctx *gin.Context) (blockClientIP bool) {
	var (
		ruleTriggered bool
		message       string
		bm            bruteforce.BucketManager
	)

	if a.NoAuth || a.ListAccounts {
		return false
	}

	if !config.GetFile().HasFeature(definitions.FeatureBruteForce) {
		return false
	}

	stopTimer := stats.PrometheusTimer(definitions.PromBruteForce, "brute_force_check_request_total")

	if stopTimer != nil {
		defer stopTimer()
	}

	// All rules
	rules := config.GetFile().GetBruteForceRules()

	if len(rules) == 0 {
		return false
	}

	logBruteForceDebug(a)

	if isLocalOrEmptyIP(a.ClientIP) {
		a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyBruteForce)
		a.AdditionalLogs = append(a.AdditionalLogs, definitions.Localhost)

		return false
	}

	if config.GetFile().GetBruteForce().HasSoftWhitelist() {
		if util.IsSoftWhitelisted(a.Username, a.ClientIP, *a.GUID, config.GetFile().GetBruteForce().SoftWhitelist) {
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyBruteForce)
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.SoftWhitelisted)

			return false
		}
	}

	if len(config.GetFile().GetBruteForce().IPWhitelist) > 0 {
		if a.IsInNetwork(config.GetFile().GetBruteForce().IPWhitelist) {
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyBruteForce)
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.Whitelisted)

			return false
		}
	}

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

	if config.GetEnvironment().GetExperimentalML() {
		// Collect additional features from Lua scripts before creating the ML bucket manager
		if config.GetFile().HaveLuaFeatures() {
			// Get a CommonRequest from the pool
			commonRequest := lualib.GetCommonRequest()

			// Set the fields
			commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
			commonRequest.Repeating = false     // unavailable
			commonRequest.UserFound = false     // unavailable,
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
			commonRequest.Account = ""      // unavailable
			commonRequest.AccountField = "" // unavailable
			commonRequest.UniqueUserID = "" // unavailable
			commonRequest.DisplayName = ""  // unavailable
			commonRequest.Password = a.Password
			commonRequest.Protocol = a.Protocol.String()
			commonRequest.OIDCCID = a.OIDCCID
			commonRequest.BruteForceName = "" // unavailable
			commonRequest.FeatureName = "brute_force"
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

			// Collect additional features
			err := featureRequest.CollectAdditionalFeatures(ctx)
			if err != nil {
				level.Warn(log.Logger).Log(
					definitions.LogKeyGUID, a.GUID,
					definitions.LogKeyBruteForce, "Failed to collect additional features",
					"error", err)
			}

			if featureRequest.Logs != nil {
				for index := range *featureRequest.Logs {
					a.AdditionalLogs = append(a.AdditionalLogs, (*featureRequest.Logs)[index])
				}
			}

			// Return the CommonRequest to the pool
			lualib.PutCommonRequest(commonRequest)
		}

		bm = ml.NewMLBucketManager(ctx, *a.GUID, a.ClientIP).WithUsername(a.Username)

		// Set NoAuth flag
		if mlBM, ok := bm.(*ml.MLBucketManager); ok {
			mlBM.SetNoAuth(a.NoAuth)
		}

		// Check if additional features are available from the Context
		if features := lualib.GetAdditionalFeatures(ctx); features != nil {
			bm = bm.WithAdditionalFeatures(features)
		}
	} else {
		bm = bruteforce.NewBucketManager(ctx, *a.GUID, a.ClientIP)
	}

	// Set the protocol on the bucket manager
	if a.Protocol != nil && a.Protocol.Get() != "" {
		bm = bm.WithProtocol(a.Protocol.Get())
	}

	// Set the OIDC Client ID on the bucket manager
	if a.OIDCCID != "" {
		bm = bm.WithOIDCCID(a.OIDCCID)
	}

	defer func() {
		if mlBM, ok := bm.(*ml.MLBucketManager); ok {
			// Add ML probability to additional logs if ML is activated
			if config.GetEnvironment().GetExperimentalML() {
				mlProb := mlBM.GetMLProbability()
				if mlProb > 0 {
					a.AdditionalLogs = append(a.AdditionalLogs, "ml_probability")
					a.AdditionalLogs = append(a.AdditionalLogs, fmt.Sprintf("%.2f", mlProb))
				}
			}

			mlBM.Close()
		}
	}()

	network := &net.IPNet{}

	abort, alreadyTriggered, ruleNumber := bm.CheckRepeatingBruteForcer(rules, &network, &message)
	if abort {
		return false
	}

	if !alreadyTriggered {
		abort, ruleTriggered, ruleNumber = bm.CheckBucketOverLimit(rules, &network, &message)
		if abort {
			return false
		}
	}

	accountName := backend.GetUserAccountFromCache(ctx, a.Username, *a.GUID)

	bm.WithPassword(a.Password).WithAccountName(accountName)

	triggered := bm.ProcessBruteForce(ruleTriggered, alreadyTriggered, &rules[ruleNumber], network, message, func() {
		a.FeatureName = bm.GetFeatureName()
		a.BruteForceName = bm.GetBruteForceName()
		a.BruteForceCounter = bm.GetBruteForceCounter()
		a.LoginAttempts = bm.GetLoginAttempts()
		a.PasswordHistory = bm.GetPasswordHistory()
	})

	if triggered {
		a.handleBruteForceLuaAction(alreadyTriggered, &rules[ruleNumber], network)
	}

	return triggered
}

// UpdateBruteForceBucketsCounter updates brute force protection rules based on client and protocol details.
func (a *AuthState) UpdateBruteForceBucketsCounter(ctx *gin.Context) {
	var bm bruteforce.BucketManager

	if !config.GetFile().HasFeature(definitions.FeatureBruteForce) {
		return
	}

	if config.GetFile().GetBruteForce() == nil {
		return
	}

	util.DebugModule(
		definitions.DbgBf,
		definitions.LogKeyGUID, *a.GUID,
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

		break
	}

	if config.GetEnvironment().GetExperimentalML() {
		bm = ml.NewMLBucketManager(ctx, *a.GUID, a.ClientIP).
			WithUsername(a.Username).WithPassword(a.Password)

		// Set NoAuth flag
		if mlManager, ok := bm.(*ml.MLBucketManager); ok {
			mlManager.SetNoAuth(a.NoAuth)
		}

		// Set the protocol if available
		if a.Protocol != nil && a.Protocol.Get() != "" {
			bm = bm.WithProtocol(a.Protocol.Get())
		}

		// Set the OIDC Client ID if available
		if a.OIDCCID != "" {
			bm = bm.WithOIDCCID(a.OIDCCID)
		}

		// Check if additional features are available from the Context
		if features := lualib.GetAdditionalFeatures(ctx); features != nil {
			bm = bm.WithAdditionalFeatures(features)
		}

		// Record the login attempt for ML training when a feature is triggered
		if mlManager, ok := bm.(*ml.MLBucketManager); ok {
			mlManager.RecordLoginFeature()
		}
	} else {
		bm = bruteforce.NewBucketManager(ctx, *a.GUID, a.ClientIP)

		// Set the protocol if available
		if a.Protocol != nil && a.Protocol.Get() != "" {
			bm = bm.WithProtocol(a.Protocol.Get())
		}

		// Set the OIDC Client ID if available
		if a.OIDCCID != "" {
			bm = bm.WithOIDCCID(a.OIDCCID)
		}
	}

	for _, rule := range config.GetFile().GetBruteForceRules() {
		// Skip if the rule has FilterByProtocol specified and the current protocol is not in the list
		if len(rule.FilterByProtocol) > 0 && a.Protocol != nil && a.Protocol.Get() != "" {
			protocolMatched := false
			for _, p := range rule.FilterByProtocol {
				if p == a.Protocol.Get() {
					protocolMatched = true

					break
				}
			}

			if !protocolMatched {
				continue
			}
		}

		// Skip if the rule has FilterByOIDCCID specified and the current OIDC Client ID is not in the list
		if len(rule.FilterByOIDCCID) > 0 && a.OIDCCID != "" {
			oidcCIDMatched := false
			for _, cid := range rule.FilterByOIDCCID {
				if cid == a.OIDCCID {
					oidcCIDMatched = true

					break
				}
			}

			if !oidcCIDMatched {
				continue
			}
		}

		if matchedPeriod == 0 || rule.Period.Round(time.Second) >= matchedPeriod {
			bm.SaveBruteForceBucketCounterToRedis(&rule)
		}
	}
}

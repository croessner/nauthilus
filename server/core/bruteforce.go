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
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
)

// handleBruteForceLuaAction handles the brute force Lua action based on the provided authentication state and rule config.
func (a *AuthState) handleBruteForceLuaAction(alreadyTriggered bool, rule *config.BruteForceRule, network *net.IPNet) {
	if config.GetFile().HaveLuaActions() {
		finished := make(chan action.Done)
		accountName := a.GetAccount()

		action.RequestChan <- &action.Action{
			LuaAction:    definitions.LuaActionBruteForce,
			Context:      a.Context,
			FinishedChan: finished,
			HTTPRequest:  a.HTTPClientContext.Request,
			CommonRequest: &lualib.CommonRequest{
				Debug:               config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug,
				Repeating:           alreadyTriggered,
				UserFound:           func() bool { return accountName != "" }(),
				Authenticated:       false, // unavailable
				NoAuth:              a.NoAuth,
				BruteForceCounter:   a.BruteForceCounter[rule.Name],
				Service:             a.Service,
				Session:             *a.GUID,
				ClientIP:            a.ClientIP,
				ClientPort:          a.XClientPort,
				ClientNet:           network.String(),
				ClientHost:          a.ClientHost,
				ClientID:            a.XClientID,
				LocalIP:             a.XLocalIP,
				LocalPort:           a.XPort,
				UserAgent:           *a.UserAgent,
				Username:            a.Username,
				Account:             accountName,
				AccountField:        a.GetAccountField(),
				UniqueUserID:        "", // unavailable
				DisplayName:         "", // unavailable
				Password:            a.Password,
				Protocol:            a.Protocol.Get(),
				BruteForceName:      rule.Name,
				FeatureName:         a.FeatureName,
				StatusMessage:       &a.StatusMessage,
				XSSL:                a.XSSL,
				XSSLSessionID:       a.XSSLSessionID,
				XSSLClientVerify:    a.XSSLClientVerify,
				XSSLClientDN:        a.XSSLClientDN,
				XSSLClientCN:        a.XSSLClientCN,
				XSSLIssuer:          a.XSSLIssuer,
				XSSLClientNotBefore: a.XSSLClientNotBefore,
				XSSLClientNotAfter:  a.XSSLClientNotAfter,
				XSSLSubjectDN:       a.XSSLSubjectDN,
				XSSLIssuerDN:        a.XSSLIssuerDN,
				XSSLClientSubjectDN: a.XSSLClientSubjectDN,
				XSSLClientIssuerDN:  a.XSSLClientIssuerDN,
				XSSLProtocol:        a.XSSLProtocol,
				XSSLCipher:          a.XSSLCipher,
				SSLSerial:           a.SSLSerial,
				SSLFingerprint:      a.SSLFingerprint,
			},
		}

		<-finished
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
func (a *AuthState) CheckBruteForce() (blockClientIP bool) {
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
		bm = ml.NewMLBucketManager(a.HTTPClientContext, *a.GUID, a.ClientIP)
	} else {
		bm = bruteforce.NewBucketManager(a.HTTPClientContext, *a.GUID, a.ClientIP)
	}

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

	accountName := backend.GetUserAccountFromCache(a.HTTPClientContext, a.Username, *a.GUID)

	bm.WithUsername(a.Username).WithPassword(a.Password).WithAccountName(accountName)

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
func (a *AuthState) UpdateBruteForceBucketsCounter() {
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
		bm = ml.NewMLBucketManager(a.HTTPClientContext, *a.GUID, a.ClientIP)
	} else {
		bm = bruteforce.NewBucketManager(a.HTTPClientContext, *a.GUID, a.ClientIP)
	}

	for _, rule := range config.GetFile().GetBruteForceRules() {
		if matchedPeriod == 0 || rule.Period.Round(time.Second) >= matchedPeriod {
			bm.SaveBruteForceBucketCounterToRedis(&rule)
		}
	}
}

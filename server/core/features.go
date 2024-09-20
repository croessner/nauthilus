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
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
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
	return ip == global.Localhost4 || ip == global.Localhost6 || ip == ""
}

// logAddMessage logs a message with the specified parameters using the global logger. It is intended to be a generic logging function.
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

	auth.AdditionalLogs = append(auth.AdditionalLogs, fmt.Sprintf("%s_%s", global.LogKeyFeatureName, feature))
	auth.AdditionalLogs = append(auth.AdditionalLogs, global.Localhost)
}

// featureLua runs Lua scripts and returns a trigger result.
func (a *AuthState) featureLua(ctx *gin.Context) (triggered bool, abortFeatures bool, err error) {
	if isLocalOrEmptyIP(a.ClientIP) {
		logAddLocalhost(a, global.FeatureLua)

		return
	}

	stopTimer := stats.PrometheusTimer(global.PromFeature, global.FeatureLua)

	defer stopTimer()

	featureRequest := feature.Request{
		Context: a.Context,
		CommonRequest: &lualib.CommonRequest{
			Debug:               config.LoadableConfig.Server.Log.Level.Level() == global.LogLevelDebug,
			Repeating:           false, // unavailable
			UserFound:           false, // unavailable
			Authenticated:       false, // unavailable
			NoAuth:              a.NoAuth,
			BruteForceCounter:   0, // unavailable
			Service:             a.Service,
			Session:             *a.GUID,
			ClientIP:            a.ClientIP,
			ClientPort:          a.XClientPort,
			ClientNet:           "", // unavailable
			ClientHost:          a.ClientHost,
			ClientID:            a.XClientID,
			UserAgent:           *a.UserAgent,
			LocalIP:             a.XLocalIP,
			LocalPort:           a.XPort,
			Username:            a.Username,
			Account:             "", // unavailable
			AccountField:        "", // unavailable
			UniqueUserID:        "", // unavailable
			DisplayName:         "", // unavailable
			Password:            a.Password,
			Protocol:            a.Protocol.String(),
			BruteForceName:      "", // unavailable
			FeatureName:         "", // unavailable
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

	triggered, abortFeatures, err = featureRequest.CallFeatureLua(ctx)

	for index := range *featureRequest.Logs {
		a.AdditionalLogs = append(a.AdditionalLogs, (*featureRequest.Logs)[index])
	}

	if statusMessage := featureRequest.StatusMessage; *statusMessage != a.StatusMessage {
		a.StatusMessage = *statusMessage
	}

	return
}

// featureTLSEncryption checks, if the remote client connection was secured.
func (a *AuthState) featureTLSEncryption() (triggered bool) {
	if isLocalOrEmptyIP(a.ClientIP) {
		logAddLocalhost(a, global.FeatureTLSEncryption)

		return
	}

	if a.XSSL != "" {
		return
	}

	stopTimer := stats.PrometheusTimer(global.PromFeature, global.FeatureTLSEncryption)

	defer stopTimer()

	if a.isInNetwork(config.LoadableConfig.ClearTextList) {
		logAddMessage(a, global.NoTLS, global.FeatureTLSEncryption)

		triggered = true

		return
	}

	logAddMessage(a, global.Whitelisted, global.FeatureTLSEncryption)

	return
}

// featureRelayDomains triggers if a user sent an email address as a login name and the domain component does not
// match the list of known domains.
func (a *AuthState) featureRelayDomains() (triggered bool) {
	if config.LoadableConfig.RelayDomains == nil {
		return
	}

	if len(config.LoadableConfig.RelayDomains.StaticDomains) == 0 {
		return
	}

	if isLocalOrEmptyIP(a.ClientIP) {
		logAddLocalhost(a, global.FeatureRelayDomains)

		return
	}

	stopTimer := stats.PrometheusTimer(global.PromFeature, global.FeatureRelayDomains)

	defer stopTimer()

	username := handleMasterUserMode(a)

	if strings.Contains(username, "@") {
		split := strings.Split(username, "@")
		if len(split) != 2 {
			return
		}

		for _, domain := range config.LoadableConfig.RelayDomains.StaticDomains {
			if strings.EqualFold(domain, split[1]) {
				return
			}
		}

		logAddMessage(a, fmt.Sprintf("%s not our domain", split[1]), global.FeatureRelayDomains)

		triggered = true
	}

	return
}

// processRBL processes the given RBL (Real-time Blackhole List) by checking if the IP address is listed.
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
		util.DebugModule(global.DbgRBL, global.LogKeyGUID, guid, global.LogKeyMsg, err)
	} else {
		if !rbl.AllowFailure {
			dnsResolverErr.Store(true)
		}

		level.Error(log.Logger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)
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
	numberOfRBLs := len(config.LoadableConfig.RBLs.Lists)

	for _, rbl := range config.LoadableConfig.RBLs.Lists {
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

// featureRBLs is a method that checks if the client IP address is whitelisted, and then performs an RBL check
// on the client's IP address. If the RBL score exceeds the configured threshold, the 'triggered' flag is set to true.
// It returns the 'triggered' flag and any error that occurred during the check.
func (a *AuthState) featureRBLs(ctx *gin.Context) (triggered bool, err error) {
	var (
		totalRBLScore int
	)

	if config.LoadableConfig.RBLs == nil {
		return
	}

	if isLocalOrEmptyIP(a.ClientIP) {
		logAddLocalhost(a, global.FeatureRBL)

		return
	}

	stopTimer := stats.PrometheusTimer(global.PromDNS, global.FeatureRBL)

	defer stopTimer()

	if a.isInNetwork(config.LoadableConfig.RBLs.IPWhiteList) {
		logAddMessage(a, global.Whitelisted, global.FeatureRBL)

		return
	}

	totalRBLScore, err = a.checkRBLs(ctx)
	if err != nil {
		return
	}

	if totalRBLScore >= config.LoadableConfig.RBLs.Threshold {
		triggered = true
	}

	return
}

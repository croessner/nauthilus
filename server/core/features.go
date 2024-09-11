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
	stderrors "errors"
	"fmt"
	"net"
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

// logMessage logs a message with the specified parameters using the global logger. It is intended to be a generic logging function.
//
// Parameters:
//   - message: The message to log.
//   - guid: The session identifier used in log entries.
//   - feature: The feature name.
//   - clientIP: The IP address of the client.
//
// Example usage:
//
//	logMessage("This is a log message", "12345", "feature", "192.168.0.1")
func logMessage(message, guid, feature, clientIP string) {
	level.Info(log.Logger).Log(global.LogKeyGUID, guid, feature, message, global.LogKeyClientIP, clientIP)
}

// featureLua runs Lua scripts and returns a trigger result.
func (a *AuthState) featureLua(ctx *gin.Context) (triggered bool, abortFeatures bool, err error) {
	if isLocalOrEmptyIP(a.ClientIP) {
		logMessage(global.Localhost, *a.GUID, global.FeatureLua, a.ClientIP)

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
		logMessage(global.Localhost, *a.GUID, global.FeatureTLSEncryption, a.ClientIP)

		return
	}

	if a.XSSL != global.NotAvailable {
		return
	}

	stopTimer := stats.PrometheusTimer(global.PromFeature, global.FeatureTLSEncryption)

	defer stopTimer()

	if a.isInNetwork(config.LoadableConfig.ClearTextList) {
		logMessage("Client has no transport security", *a.GUID, global.FeatureTLSEncryption, a.ClientIP)

		triggered = true

		return
	}

	logMessage("Client is whitelisted", *a.GUID, global.FeatureTLSEncryption, a.ClientIP)

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
		logMessage(global.Localhost, *a.GUID, global.FeatureRelayDomains, a.ClientIP)

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

		logMessage(fmt.Sprintf("%s not our domain", split[1]), *a.GUID, global.FeatureRelayDomains, a.ClientIP)

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
	defer waitGroup.Done()

	isListed, rblName, errRBL := a.isListed(ctx, rbl)

	if errRBL != nil {
		handleRBLError(*a.GUID, errRBL, rbl, dnsResolverErr)

		rblChan <- 0

		return
	}

	if isListed {
		logMatchedRBL(*a.GUID, a.ClientIP, rblName, rbl.Weight)

		rblChan <- rbl.Weight

		return
	}

	rblChan <- 0
}

// handleRBLError handles errors that occur during RBL processing.
// If the error is a network DNS error with "no such host" message, it logs the error in debug mode.
// Otherwise, if AllowFailure is false, it sets dnsResolverErr to true.
// Finally, it logs the error at the error level.
func handleRBLError(guid string, err error, rbl *config.RBL, dnsResolverErr *atomic.Bool) {
	if stderrors.Is(err, &net.DNSError{}) && strings.Contains(err.Error(), "no such host") {
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
//	guid - the session identifier
//	clientIP - the IP address of the client
//	rblName - the name of the RBL that was matched
//	weight - the weight associated with the RBL
func logMatchedRBL(guid, clientIP, rblName string, weight int) {
	level.Info(log.Logger).Log(
		global.LogKeyGUID, guid,
		global.FeatureRBL, "RBL matched",
		global.LogKeyClientIP, clientIP,
		"rbl_name", rblName,
		"weight", weight,
	)
}

// checkRBLs checks the remote client IP address against a list of realtime blocklists.
func (a *AuthState) checkRBLs(ctx *gin.Context) (totalRBLScore int, err error) {
	var (
		waitGroup      sync.WaitGroup
		dnsResolverErr atomic.Bool
	)

	dnsResolverErr.Store(false)
	rblChan := make(chan int)
	numberOfRBLs := len(config.LoadableConfig.RBLs.Lists)

	for _, rbl := range config.LoadableConfig.RBLs.Lists {
		waitGroup.Add(1)

		go a.processRBL(ctx, &rbl, rblChan, &waitGroup, &dnsResolverErr)
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
		logMessage(global.Localhost, *a.GUID, global.FeatureRBL, a.ClientIP)

		return
	}

	stopTimer := stats.PrometheusTimer(global.PromDNS, global.FeatureRBL)

	defer stopTimer()

	if a.isInNetwork(config.LoadableConfig.RBLs.IPWhiteList) {
		level.Info(log.Logger).Log(
			global.LogKeyGUID, a.GUID, global.FeatureRBL, "Client is whitelisted", global.LogKeyClientIP, a.ClientIP,
		)
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

// Copyright (C) 2024-2025 Christian Rößner
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

package auth

import (
	stderrors "errors"
	"fmt"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/filter"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

// DefaultLuaFilter mirrors the previous AuthState.FilterLua behavior.
// Implemented in subpackage to avoid import cycles; registered via core.RegisterLuaFilter.
//
//goland:nointerface
type DefaultLuaFilter struct{}

// DefaultPostAction mirrors the previous AuthState.PostLuaAction behavior.
//
//goland:nointerface
type DefaultPostAction struct{}

// Filter implements the Lua filter logic with identical behavior to the legacy inline method.
func (DefaultLuaFilter) Filter(ctx *gin.Context, view *core.StateView, passDBResult *core.PassDBResult) definitions.AuthResult {
	auth := view.Auth()

	if !config.GetFile().HaveLuaFilters() {
		// No filters configured → treat as authorized
		auth.Authorized = true

		if passDBResult.Authenticated {
			return definitions.AuthResultOK
		}

		return definitions.AuthResultFail
	}

	stopTimer := stats.PrometheusTimer(definitions.PromFilter, "lua_filter_request_total")
	if stopTimer != nil {
		defer stopTimer()
	}

	backendServers := core.ListBackendServers()
	util.DebugModule(definitions.DbgFeature, definitions.LogKeyMsg, fmt.Sprintf("Active backend servers: %d", len(backendServers)))

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	// Set the fields (intentionally identical to previous inline code)
	commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Repeating = false // unavailable
	commonRequest.UserFound = passDBResult.UserFound
	commonRequest.Authenticated = passDBResult.Authenticated
	commonRequest.NoAuth = auth.NoAuth
	commonRequest.BruteForceCounter = 0 // unavailable
	commonRequest.Service = auth.Service
	commonRequest.Session = auth.GUID
	commonRequest.ClientIP = auth.ClientIP
	commonRequest.ClientPort = auth.XClientPort
	commonRequest.ClientNet = "" // unavailable
	commonRequest.ClientHost = auth.ClientHost
	commonRequest.ClientID = auth.XClientID
	commonRequest.UserAgent = auth.UserAgent
	commonRequest.LocalIP = auth.XLocalIP
	commonRequest.LocalPort = auth.XPort
	commonRequest.Username = auth.Username
	commonRequest.Account = auth.GetAccount()
	commonRequest.AccountField = auth.GetAccountField()
	commonRequest.UniqueUserID = auth.GetUniqueUserID()
	commonRequest.DisplayName = auth.GetDisplayName()
	commonRequest.Password = auth.Password
	commonRequest.Protocol = auth.Protocol.String()
	commonRequest.OIDCCID = auth.OIDCCID
	commonRequest.BruteForceName = "" // unavailable
	commonRequest.FeatureName = ""    // unavailable
	commonRequest.StatusMessage = &auth.StatusMessage
	commonRequest.XSSL = auth.XSSL
	commonRequest.XSSLSessionID = auth.XSSLSessionID
	commonRequest.XSSLClientVerify = auth.XSSLClientVerify
	commonRequest.XSSLClientDN = auth.XSSLClientDN
	commonRequest.XSSLClientCN = auth.XSSLClientCN
	commonRequest.XSSLIssuer = auth.XSSLIssuer
	commonRequest.XSSLClientNotBefore = auth.XSSLClientNotBefore
	commonRequest.XSSLClientNotAfter = auth.XSSLClientNotAfter
	commonRequest.XSSLSubjectDN = auth.XSSLSubjectDN
	commonRequest.XSSLIssuerDN = auth.XSSLIssuerDN
	commonRequest.XSSLClientSubjectDN = auth.XSSLClientSubjectDN
	commonRequest.XSSLClientIssuerDN = auth.XSSLClientIssuerDN
	commonRequest.XSSLProtocol = auth.XSSLProtocol
	commonRequest.XSSLCipher = auth.XSSLCipher
	commonRequest.SSLSerial = auth.SSLSerial
	commonRequest.SSLFingerprint = auth.SSLFingerprint

	filterRequest := &filter.Request{
		BackendServers:     backendServers,
		UsedBackendAddress: &auth.UsedBackendIP,
		UsedBackendPort:    &auth.UsedBackendPort,
		Logs:               nil,
		Context:            auth.Context,
		CommonRequest:      commonRequest,
	}

	filterResult, luaBackendResult, removeAttributes, err := filterRequest.CallFilterLua(ctx)
	if err != nil {
		if !stderrors.Is(err, errors.ErrNoFiltersDefined) {
			// Include Lua stacktrace when available
			var ae *lua.ApiError
			if stderrors.As(err, &ae) && ae != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyGUID, auth.GUID,
					definitions.LogKeyMsg, "Error calling Lua filter",
					definitions.LogKeyError, ae.Error(),
					"stacktrace", ae.StackTrace,
				)
			}

			// Return the CommonRequest to the pool even if there's an error
			lualib.PutCommonRequest(commonRequest)

			// error during filter execution → not authorized
			auth.Authorized = false

			return definitions.AuthResultTempFail
		}

		// Explicitly authorized when no filters are defined
		auth.Authorized = true
	} else {
		if filterRequest.Logs != nil && len(*filterRequest.Logs) > 0 {
			// Pre-allocate the AdditionalLogs slice to avoid continuous reallocation
			additionalLogsLen := len(auth.AdditionalLogs)
			newAdditionalLogs := make([]any, additionalLogsLen+len(*filterRequest.Logs))
			copy(newAdditionalLogs, auth.AdditionalLogs)
			auth.AdditionalLogs = newAdditionalLogs[:additionalLogsLen]

			for index := range *filterRequest.Logs {
				auth.AdditionalLogs = append(auth.AdditionalLogs, (*filterRequest.Logs)[index])
			}
		}

		if statusMessage := filterRequest.StatusMessage; *statusMessage != auth.StatusMessage {
			auth.StatusMessage = *statusMessage
		}

		for _, attributeName := range removeAttributes {
			auth.DeleteAttribute(attributeName)
		}

		if luaBackendResult != nil {
			// XXX: We currently only support changing attributes from the AuthState object.
			if (*luaBackendResult).Attributes != nil {
				for key, value := range (*luaBackendResult).Attributes {
					if keyName, assertOk := key.(string); assertOk {
						auth.SetAttributeIfAbsent(keyName, value)
					}
				}
			}
		}

		if filterResult {
			auth.Authorized = false

			// Return the CommonRequest to the pool before returning
			lualib.PutCommonRequest(commonRequest)

			return definitions.AuthResultFail
		}

		// filters accepted → authorized
		auth.Authorized = true

		auth.UsedBackendIP = *filterRequest.UsedBackendAddress
		auth.UsedBackendPort = *filterRequest.UsedBackendPort
	}

	// Return the CommonRequest to the pool
	lualib.PutCommonRequest(commonRequest)

	if passDBResult.Authenticated {
		return definitions.AuthResultOK
	}

	return definitions.AuthResultFail
}

// Run implements the Lua post action dispatch with identical behavior to the legacy inline method.
func (DefaultPostAction) Run(input core.PostActionInput) {
	auth := input.View.Auth()
	passDBResult := input.Result

	if !config.GetFile().HaveLuaActions() {
		return
	}

	// Make sure we have all the required values and they're not nil
	if auth.Protocol == nil || auth.HTTPClientRequest == nil || auth.Context == nil {
		return
	}

	// Get account name and check if user was found
	accountName := auth.GetAccount()
	userFound := passDBResult.UserFound || accountName != ""

	// Make a copy of the status message
	statusMessageCopy := auth.StatusMessage

	args := core.PostActionArgs{
		Context:       auth.Context,
		HTTPRequest:   auth.HTTPClientRequest,
		StatusMessage: statusMessageCopy,
		Request: lualib.CommonRequest{
			Debug:               config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug,
			Repeating:           auth.BFRepeating,
			UserFound:           userFound,
			Authenticated:       passDBResult.Authenticated,
			NoAuth:              auth.NoAuth,
			BruteForceCounter:   0,
			Service:             auth.Service,
			Session:             auth.GUID,
			ClientIP:            auth.ClientIP,
			ClientPort:          auth.XClientPort,
			ClientNet:           auth.BFClientNet,
			ClientHost:          auth.ClientHost,
			ClientID:            auth.XClientID,
			LocalIP:             auth.XLocalIP,
			LocalPort:           auth.XPort,
			UserAgent:           auth.UserAgent,
			Username:            auth.Username,
			Account:             accountName,
			AccountField:        auth.GetAccountField(),
			UniqueUserID:        auth.GetUniqueUserID(),
			DisplayName:         auth.GetDisplayName(),
			Password:            auth.Password,
			Protocol:            auth.Protocol.Get(),
			OIDCCID:             auth.OIDCCID,
			BruteForceName:      auth.BruteForceName,
			FeatureName:         auth.FeatureName,
			XSSL:                auth.XSSL,
			XSSLSessionID:       auth.XSSLSessionID,
			XSSLClientVerify:    auth.XSSLClientVerify,
			XSSLClientDN:        auth.XSSLClientDN,
			XSSLClientCN:        auth.XSSLClientCN,
			XSSLIssuer:          auth.XSSLIssuer,
			XSSLClientNotBefore: auth.XSSLClientNotBefore,
			XSSLClientNotAfter:  auth.XSSLClientNotAfter,
			XSSLSubjectDN:       auth.XSSLSubjectDN,
			XSSLIssuerDN:        auth.XSSLIssuerDN,
			XSSLClientSubjectDN: auth.XSSLClientSubjectDN,
			XSSLClientIssuerDN:  auth.XSSLClientIssuerDN,
			XSSLProtocol:        auth.XSSLProtocol,
			XSSLCipher:          auth.XSSLCipher,
			SSLSerial:           auth.SSLSerial,
			SSLFingerprint:      auth.SSLFingerprint,
		},
	}

	go core.RunLuaPostAction(args)
}

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

package core

import (
	stderrors "errors"
	"fmt"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/filter"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
)

// LuaFilter encapsulates the Lua filter pipeline and returns an AuthResult.
//
//goland:nointerface
type LuaFilter interface {
	Filter(ctx *gin.Context, view *StateView, result *PassDBResult) definitions.AuthResult
}

// PostActionInput aggregates the minimal inputs required for the Lua post action.
// It deliberately reduces dozens of parameters to a compact value object.
type PostActionInput struct {
	View   *StateView
	Result *PassDBResult
}

// PostAction encapsulates the asynchronous post-action dispatch to the Lua worker.
//
//goland:nointerface
type PostAction interface {
	Run(input PostActionInput)
}

// DefaultLuaFilter mirrors the previous AuthState.FilterLua behavior.
// It lives in the same package to access internal state without changing visibility.
type DefaultLuaFilter struct{}

// DefaultPostAction mirrors the previous AuthState.PostLuaAction behavior.
type DefaultPostAction struct{}

var (
	defaultLuaFilter  LuaFilter  = DefaultLuaFilter{}
	defaultPostAction PostAction = DefaultPostAction{}
)

// Filter implements the Lua filter logic with identical behavior to the legacy inline method.
func (DefaultLuaFilter) Filter(ctx *gin.Context, view *StateView, passDBResult *PassDBResult) definitions.AuthResult {
	a := view.auth

	if !config.GetFile().HaveLuaFilters() {
		// No filters configured → treat as authorized
		a.Authorized = true

		if passDBResult.Authenticated {
			return definitions.AuthResultOK
		}

		return definitions.AuthResultFail
	}

	stopTimer := stats.PrometheusTimer(definitions.PromFilter, "lua_filter_request_total")
	if stopTimer != nil {
		defer stopTimer()
	}

	BackendServers.mu.RLock()
	backendServers := BackendServers.backendServer
	util.DebugModule(definitions.DbgFeature, definitions.LogKeyMsg, fmt.Sprintf("Active backend servers: %d", len(backendServers)))
	BackendServers.mu.RUnlock()

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	// Set the fields (intentionally identical to previous inline code)
	commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Repeating = false // unavailable
	commonRequest.UserFound = passDBResult.UserFound
	commonRequest.Authenticated = passDBResult.Authenticated
	commonRequest.NoAuth = a.NoAuth
	commonRequest.BruteForceCounter = 0 // unavailable
	commonRequest.Service = a.Service
	commonRequest.Session = a.GUID
	commonRequest.ClientIP = a.ClientIP
	commonRequest.ClientPort = a.XClientPort
	commonRequest.ClientNet = "" // unavailable
	commonRequest.ClientHost = a.ClientHost
	commonRequest.ClientID = a.XClientID
	commonRequest.UserAgent = a.UserAgent
	commonRequest.LocalIP = a.XLocalIP
	commonRequest.LocalPort = a.XPort
	commonRequest.Username = a.Username
	commonRequest.Account = a.GetAccount()
	commonRequest.AccountField = a.GetAccountField()
	commonRequest.UniqueUserID = a.GetUniqueUserID()
	commonRequest.DisplayName = a.GetDisplayName()
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

	filterRequest := &filter.Request{
		BackendServers:     backendServers,
		UsedBackendAddress: &a.UsedBackendIP,
		UsedBackendPort:    &a.UsedBackendPort,
		Logs:               nil,
		Context:            a.Context,
		CommonRequest:      commonRequest,
	}

	filterResult, luaBackendResult, removeAttributes, err := filterRequest.CallFilterLua(ctx)
	if err != nil {
		if !stderrors.Is(err, errors.ErrNoFiltersDefined) {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, a.GUID,
				definitions.LogKeyMsg, "Error calling Lua filter",
				definitions.LogKeyError, err,
			)

			// Return the CommonRequest to the pool even if there's an error
			lualib.PutCommonRequest(commonRequest)

			// error during filter execution → not authorized
			a.Authorized = false

			return definitions.AuthResultTempFail
		}

		// Explicitly authorized when no filters are defined
		a.Authorized = true
	} else {
		if filterRequest.Logs != nil && len(*filterRequest.Logs) > 0 {
			// Pre-allocate the AdditionalLogs slice to avoid continuous reallocation
			additionalLogsLen := len(a.AdditionalLogs)
			newAdditionalLogs := make([]any, additionalLogsLen+len(*filterRequest.Logs))
			copy(newAdditionalLogs, a.AdditionalLogs)
			a.AdditionalLogs = newAdditionalLogs[:additionalLogsLen]

			for index := range *filterRequest.Logs {
				a.AdditionalLogs = append(a.AdditionalLogs, (*filterRequest.Logs)[index])
			}
		}

		if statusMessage := filterRequest.StatusMessage; *statusMessage != a.StatusMessage {
			a.StatusMessage = *statusMessage
		}

		for _, attributeName := range removeAttributes {
			delete(a.Attributes, attributeName)
		}

		if luaBackendResult != nil {
			// XXX: We currently only support changing attributes from the AuthState object.
			if (*luaBackendResult).Attributes != nil {
				for key, value := range (*luaBackendResult).Attributes {
					if keyName, assertOk := key.(string); assertOk {
						if _, okay := a.Attributes[keyName]; !okay {
							a.Attributes[keyName] = []any{value}
						}
					}
				}
			}
		}

		if filterResult {
			a.Authorized = false

			// Return the CommonRequest to the pool before returning
			lualib.PutCommonRequest(commonRequest)

			return definitions.AuthResultFail
		}

		// filters accepted → authorized
		a.Authorized = true

		a.UsedBackendIP = *filterRequest.UsedBackendAddress
		a.UsedBackendPort = *filterRequest.UsedBackendPort
	}

	// Return the CommonRequest to the pool
	lualib.PutCommonRequest(commonRequest)

	if passDBResult.Authenticated {
		return definitions.AuthResultOK
	}

	return definitions.AuthResultFail
}

// Run implements the Lua post action dispatch with identical behavior to the legacy inline method.
func (DefaultPostAction) Run(input PostActionInput) {
	a := input.View.auth
	passDBResult := input.Result

	if !config.GetFile().HaveLuaActions() {
		return
	}

	// Make sure we have all the required values and they're not nil
	if a.Protocol == nil || a.HTTPClientRequest == nil || a.Context == nil {
		return
	}

	// Get account name and check if user was found
	accountName := a.GetAccount()
	userFound := passDBResult.UserFound || accountName != ""

	// Make a copy of the status message
	statusMessageCopy := a.StatusMessage

	// Start a goroutine with copies of all necessary values (unchanged)
	go executeLuaPostAction(
		a.Context,
		a.HTTPClientRequest,
		a.GUID,
		a.NoAuth,
		a.Service,
		a.ClientIP,
		a.XClientPort,
		a.ClientHost,
		a.XClientID,
		a.XLocalIP,
		a.XPort,
		a.UserAgent,
		a.Username,
		accountName,
		a.GetAccountField(),
		a.GetUniqueUserID(),
		a.GetDisplayName(),
		a.Password,
		a.Protocol.Get(),
		a.OIDCCID,
		a.BruteForceName,
		a.FeatureName,
		statusMessageCopy,
		a.XSSL,
		a.XSSLSessionID,
		a.XSSLClientVerify,
		a.XSSLClientDN,
		a.XSSLClientCN,
		a.XSSLIssuer,
		a.XSSLClientNotBefore,
		a.XSSLClientNotAfter,
		a.XSSLSubjectDN,
		a.XSSLIssuerDN,
		a.XSSLClientSubjectDN,
		a.XSSLClientIssuerDN,
		a.XSSLProtocol,
		a.XSSLCipher,
		a.SSLSerial,
		a.SSLFingerprint,
		userFound,
		passDBResult.Authenticated,
		a.BFClientNet,
		a.BFRepeating,
	)
}

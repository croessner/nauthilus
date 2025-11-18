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
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
)

type DefaultActionDispatcher struct{}

// Dispatch sends an action to the Lua execution pipeline, initializing context and preparing authentication details.
// It blocks until the action is completed and ensures proper resource cleanup.
func (DefaultActionDispatcher) Dispatch(view *core.StateView, featureName string, luaAction definitions.LuaAction) {
	auth := view.Auth()

	if !config.GetFile().HaveLuaActions() {
		return
	}

	finished := make(chan action.Done)

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	// Populate fields exactly like the previous performAction implementation
	commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.UserFound = auth.GetAccount() != ""
	commonRequest.NoAuth = auth.NoAuth
	commonRequest.Service = auth.Service
	commonRequest.Session = auth.GUID
	commonRequest.ClientIP = auth.ClientIP
	commonRequest.ClientPort = auth.XClientPort
	commonRequest.ClientHost = auth.ClientHost
	commonRequest.ClientID = auth.XClientID
	commonRequest.LocalIP = auth.XLocalIP
	commonRequest.LocalPort = auth.XPort
	commonRequest.UserAgent = auth.UserAgent
	commonRequest.Username = auth.Username
	commonRequest.Account = auth.GetAccount()
	commonRequest.AccountField = auth.GetAccountField()
	commonRequest.Password = auth.Password
	commonRequest.Protocol = auth.Protocol.Get()
	commonRequest.OIDCCID = auth.OIDCCID
	commonRequest.FeatureName = featureName
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

	action.RequestChan <- &action.Action{
		LuaAction:     luaAction,
		Context:       auth.Context,
		FinishedChan:  finished,
		HTTPRequest:   auth.HTTPClientRequest,
		HTTPContext:   auth.HTTPClientContext,
		CommonRequest: commonRequest,
	}

	<-finished

	lualib.PutCommonRequest(commonRequest)
}

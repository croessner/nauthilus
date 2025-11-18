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
	"github.com/croessner/nauthilus/server/lualib/feature"
	"github.com/gin-gonic/gin"
)

// DefaultFeatureEngine implements the Lua feature evaluation analogous to the previous AuthState.FeatureLua
// (excluding the localhost/whitelist shortcuts; those remain in the orchestrator in core/features.go).
//
//goland:nointerface
type DefaultFeatureEngine struct{}

func (DefaultFeatureEngine) Evaluate(ctx *gin.Context, view *core.StateView) (bool, bool, []any, *string, error) {
	auth := view.Auth()

	accountName := auth.GetAccount()

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	// Populate fields (identical to the previous inline code in FeatureLua)
	commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Repeating = false // unavailable
	commonRequest.UserFound = accountName != ""
	commonRequest.Authenticated = false // unavailable
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
	commonRequest.Account = accountName
	commonRequest.AccountField = auth.GetAccountField()
	commonRequest.UniqueUserID = "" // unavailable
	commonRequest.DisplayName = ""  // unavailable
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

	featReq := feature.Request{
		Context:       auth.Context,
		CommonRequest: commonRequest,
	}

	triggered, abort, err := featReq.CallFeatureLua(ctx)

	// Provide logs and status
	var logs []any
	if featReq.Logs != nil {
		for i := range *featReq.Logs {
			logs = append(logs, (*featReq.Logs)[i])
		}
	}

	newStatus := featReq.StatusMessage

	// Return CommonRequest to the pool
	lualib.PutCommonRequest(commonRequest)

	return triggered, abort, logs, newStatus, err
}

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
	"context"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/localcache"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/model/mfa"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/svcctx"
	"go.opentelemetry.io/otel/attribute"
)

// luaManagerImpl provides an implementation for managing Lua connections and operations using a specific connection backend.
type luaManagerImpl struct {
	backendName string
	deps        AuthDeps
}

// PassDB implements the Lua password database backend.
func (lm *luaManagerImpl) PassDB(auth *AuthState) (passDBResult *PassDBResult, err error) {
	// Tracing: Lua backend password DB
	tr := monittrace.New("nauthilus/lua_backend")
	lctx, lsp := tr.Start(auth.Ctx(), "lua.passdb",
		attribute.String("backend_name", lm.backendName),
		attribute.String("service", auth.Service),
		attribute.String("username", auth.Username),
		attribute.String("protocol", auth.Protocol.Get()),
	)

	_ = lctx

	defer lsp.End()

	var (
		luaBackendResult *lualib.LuaBackendResult
		protocol         *config.LuaSearchProtocol
	)

	stopTimer := stats.PrometheusTimer(definitions.PromBackend, "lua_backend_request_total")

	if stopTimer != nil {
		defer stopTimer()
	}

	if protocol, err = config.GetFile().GetLuaSearchProtocol(auth.Protocol.Get(), lm.backendName); protocol == nil || err != nil {
		if err != nil {
			lsp.RecordError(err)
		}

		return
	}

	passDBResult = GetPassDBResultFromPool()

	luaReplyChan := make(chan *lualib.LuaBackendResult)

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	// Set the fields
	commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Repeating = false     // unavailable
	commonRequest.UserFound = false     // set by backend_result
	commonRequest.Authenticated = false // set by backend_result
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
	commonRequest.Account = ""      // set by nauthilus_backend_result
	commonRequest.AccountField = "" // set by nauthilus_backend_result
	commonRequest.UniqueUserID = "" // set by nauthilus_backend_result
	commonRequest.DisplayName = ""  // set by nauthilus_backend_result
	commonRequest.Password = auth.Password
	commonRequest.Protocol = auth.Protocol.Get()
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

	// Derive a timeout context for Lua backend work
	dLua := config.GetFile().GetServer().GetTimeouts().GetLuaBackend()
	ctxLua, cancelLua := context.WithTimeout(auth.Ctx(), dLua)
	defer cancelLua()

	luaRequest := &bktype.LuaRequest{
		Function:          definitions.LuaCommandPassDB,
		BackendName:       lm.backendName,
		Service:           auth.Service,
		Protocol:          auth.Protocol,
		Context:           auth.Context,
		LuaReplyChan:      luaReplyChan,
		HTTPClientRequest: auth.HTTPClientRequest,
		HTTPClientContext: ctxLua,
		CommonRequest:     commonRequest,
	}

	// Determine priority based on NoAuth flag and whether the user is already authenticated
	priority := priorityqueue.PriorityLow
	if !auth.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	if localcache.AuthCache.IsAuthenticated(auth.Username) {
		priority = priorityqueue.PriorityHigh
	}

	// Use priority queue instead of channel
	priorityqueue.LuaQueue.Push(luaRequest, priority)

	luaBackendResult = <-luaReplyChan

	if luaBackendResult.Logs != nil && len(*luaBackendResult.Logs) > 0 {
		// Pre-allocate the AdditionalLogs slice to avoid continuous reallocation
		additionalLogsLen := len(auth.AdditionalLogs)
		newAdditionalLogs := make([]any, additionalLogsLen+len(*luaBackendResult.Logs))
		copy(newAdditionalLogs, auth.AdditionalLogs)
		auth.AdditionalLogs = newAdditionalLogs[:additionalLogsLen]

		for index := range *luaBackendResult.Logs {
			auth.AdditionalLogs = append(auth.AdditionalLogs, (*luaBackendResult.Logs)[index])
		}
	}

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err

		lsp.RecordError(err)

		return
	}

	if statusMessage := luaRequest.StatusMessage; *statusMessage != auth.StatusMessage {
		auth.StatusMessage = *statusMessage
	}

	accountField := luaBackendResult.AccountField
	if accountField == "" {
		// Harden: explicit negative result to avoid OK without attributes
		passDBResult.Authenticated = false
		passDBResult.UserFound = false

		return
	}

	totpSecretField := luaBackendResult.TOTPSecretField
	uniqueUserIDField := luaBackendResult.UniqueUserIDField
	displayName := luaBackendResult.DisplayNameField

	passDBResult.Authenticated = luaBackendResult.Authenticated
	passDBResult.UserFound = luaBackendResult.UserFound
	passDBResult.AccountField = accountField

	// Update the authentication cache if the user is authenticated
	if passDBResult.Authenticated {
		localcache.AuthCache.Set(auth.Username, true)
	}

	if luaBackendResult.UserFound {
		passDBResult.BackendName = lm.backendName
	}

	if totpSecretField != "" {
		passDBResult.TOTPSecretField = totpSecretField
	}

	if uniqueUserIDField != "" {
		passDBResult.UniqueUserIDField = uniqueUserIDField
	}

	if displayName != "" {
		passDBResult.DisplayNameField = displayName
	}

	if luaBackendResult.UserFound {
		passDBResult.Backend = definitions.BackendLua
	}

	if luaBackendResult.Attributes != nil {
		passDBResult.Attributes = make(bktype.AttributeMapping)

		for key, value := range luaBackendResult.Attributes {
			if keyName, assertOk := key.(string); assertOk {
				passDBResult.Attributes[keyName] = []any{value}
			}
		}
	}

	// Outcome attributes
	lsp.SetAttributes(
		attribute.Bool("user_found", luaBackendResult.UserFound),
		attribute.Bool("authenticated", luaBackendResult.Authenticated),
	)

	// Return the CommonRequest to the pool
	lualib.PutCommonRequest(commonRequest)

	return
}

// AccountDB implements the list-account mode and returns all known users from a Lua backend logic.
func (lm *luaManagerImpl) AccountDB(auth *AuthState) (accounts AccountList, err error) {
	// Tracing: Lua backend account listing
	tr := monittrace.New("nauthilus/lua_backend")
	actx, asp := tr.Start(auth.Ctx(), "lua.accountdb",
		attribute.String("backend_name", lm.backendName),
		attribute.String("service", auth.Service),
		attribute.String("protocol", auth.Protocol.Get()),
	)

	_ = actx

	defer asp.End()

	var (
		luaBackendResult *lualib.LuaBackendResult
		protocol         *config.LuaSearchProtocol
	)

	stopTimer := stats.PrometheusTimer(definitions.PromAccount, "lua_account_request_total")

	if stopTimer != nil {
		defer stopTimer()
	}

	if protocol, err = config.GetFile().GetLuaSearchProtocol(auth.Protocol.Get(), lm.backendName); protocol == nil || err != nil {
		if err != nil {
			asp.RecordError(err)
		}

		return
	}

	luaReplyChan := make(chan *lualib.LuaBackendResult)

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	// Set the fields
	commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Service = auth.Service
	commonRequest.Session = auth.GUID
	commonRequest.ClientIP = auth.ClientIP
	commonRequest.ClientPort = auth.XClientPort
	commonRequest.LocalIP = auth.XLocalIP
	commonRequest.LocalPort = auth.XPort
	commonRequest.OIDCCID = auth.OIDCCID

	// Derive a timeout context for Lua backend work (list accounts) using service-scoped context
	dLua := config.GetFile().GetServer().GetTimeouts().GetLuaBackend()
	ctxLua, cancelLua := context.WithTimeout(svcctx.Get(), dLua)
	defer cancelLua()

	luaRequest := &bktype.LuaRequest{
		Function:          definitions.LuaCommandListAccounts,
		BackendName:       lm.backendName,
		Protocol:          auth.Protocol,
		HTTPClientRequest: auth.HTTPClientRequest,
		HTTPClientContext: ctxLua,
		LuaReplyChan:      luaReplyChan,
		CommonRequest:     commonRequest,
	}

	priorityqueue.LuaQueue.Push(luaRequest, priorityqueue.PriorityMedium)

	luaBackendResult = <-luaReplyChan

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err
		asp.RecordError(err)

		return
	}

	accountSet := config.NewStringSet()

	if luaBackendResult.Attributes != nil {
		for _, value := range luaBackendResult.Attributes {
			if valueName, assertOk := value.(string); assertOk {
				accountSet.Set(valueName)
			}
		}
	}

	// Return the CommonRequest to the pool
	lualib.PutCommonRequest(commonRequest)

	accounts = accountSet.GetStringSlice()

	if len(accounts) == 0 {
		level.Warn(log.Logger).Log(
			definitions.LogKeyGUID, auth.GUID,
			definitions.LogKeyMsg, "No accounts found in Lua backend",
		)
	}

	asp.SetAttributes(attribute.Int("accounts", len(accounts)))

	return accounts, nil
}

// AddTOTPSecret sends a newly generated TOTP secret to a Lua backend logic.
func (lm *luaManagerImpl) AddTOTPSecret(auth *AuthState, totp *mfa.TOTPSecret) (err error) {
	// Tracing: Lua backend add TOTP
	tr := monittrace.New("nauthilus/lua_backend")
	mctx, msp := tr.Start(auth.Ctx(), "lua.add_totp",
		attribute.String("backend_name", lm.backendName),
		attribute.String("service", auth.Service),
		attribute.String("protocol", auth.Protocol.Get()),
	)

	_ = mctx

	defer func() {
		if err != nil {
			msp.RecordError(err)
		}

		msp.End()
	}()

	var (
		luaBackendResult *lualib.LuaBackendResult
		protocol         *config.LuaSearchProtocol
	)

	stopTimer := stats.PrometheusTimer(definitions.PromStoreTOTP, "lua_store_totp_request_total")

	if stopTimer != nil {
		defer stopTimer()
	}

	if protocol, err = config.GetFile().GetLuaSearchProtocol(auth.Protocol.Get(), lm.backendName); protocol == nil || err != nil {
		return
	}

	luaReplyChan := make(chan *lualib.LuaBackendResult)

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	// Set the fields
	commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Service = auth.Service
	commonRequest.Session = auth.GUID
	commonRequest.Username = auth.Username
	commonRequest.ClientIP = auth.ClientIP
	commonRequest.ClientPort = auth.XClientPort
	commonRequest.LocalIP = auth.XLocalIP
	commonRequest.LocalPort = auth.XPort
	commonRequest.OIDCCID = auth.OIDCCID

	// Derive a timeout context for Lua backend work (add TOTP)
	dLua := config.GetFile().GetServer().GetTimeouts().GetLuaBackend()
	ctxLua, cancelLua := context.WithTimeout(auth.Ctx(), dLua)
	defer cancelLua()

	luaRequest := &bktype.LuaRequest{
		Function:          definitions.LuaCommandAddMFAValue,
		BackendName:       lm.backendName,
		Protocol:          auth.Protocol,
		TOTPSecret:        totp.GetValue(),
		HTTPClientRequest: auth.HTTPClientRequest,
		HTTPClientContext: ctxLua,
		LuaReplyChan:      luaReplyChan,
		CommonRequest:     commonRequest,
	}

	// Determine priority based on NoAuth flag and whether the user is already authenticated
	priority := priorityqueue.PriorityLow
	if !auth.NoAuth {
		priority = priorityqueue.PriorityMedium
	}
	if localcache.AuthCache.IsAuthenticated(auth.Username) {
		priority = priorityqueue.PriorityHigh
	}

	// Use priority queue instead of channel
	priorityqueue.LuaQueue.Push(luaRequest, priority)

	luaBackendResult = <-luaReplyChan

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err

		// Return the CommonRequest to the pool even if there's an error
		lualib.PutCommonRequest(commonRequest)

		return
	}

	// Return the CommonRequest to the pool
	lualib.PutCommonRequest(commonRequest)

	return
}

var _ BackendManager = &luaManagerImpl{}

// NewLuaManager initializes and returns a new LuaManager instance with the specified backend name.
func NewLuaManager(backendName string, deps AuthDeps) BackendManager {
	return &luaManagerImpl{
		backendName: backendName,
		deps:        deps,
	}
}

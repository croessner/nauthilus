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
	"log/slog"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/localcache"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/svcctx"
	"github.com/croessner/nauthilus/v3/server/util"
	"go.opentelemetry.io/otel/attribute"
)

// luaManagerImpl provides an implementation for managing Lua connections and operations using a specific connection backend.
type luaManagerImpl struct {
	backendName string
	deps        AuthDeps
}

type luaMFACommandInput struct {
	spanName   string
	promLabel  string
	promMetric string
	totpSecret string
	command    definitions.LuaCommand
}

type luaRequestHandle struct {
	request   *bktype.LuaRequest
	replyChan chan *lualib.LuaBackendResult
	cleanup   func()
}

func (lm *luaManagerImpl) effectiveCfg() config.File {
	return lm.deps.Cfg
}

func (lm *luaManagerImpl) effectiveLogger() *slog.Logger {
	return lm.deps.Logger
}

// luaPriority derives the queue priority from no-auth state and the local authentication cache.
func (lm *luaManagerImpl) luaPriority(auth *AuthState) int {
	priority := priorityqueue.PriorityLow
	if !auth.Request.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	if localcache.AuthCache.IsAuthenticated(auth.Request.Username) {
		priority = priorityqueue.PriorityHigh
	}

	return priority
}

// runLuaMFACommand executes a Lua MFA mutation command with shared tracing and request setup.
func (lm *luaManagerImpl) runLuaMFACommand(auth *AuthState, input luaMFACommandInput) (err error) {
	tr := monittrace.New("nauthilus/lua_backend")
	mctx, msp := tr.Start(auth.Ctx(), input.spanName,
		attribute.String("backend_name", lm.backendName),
		attribute.String("service", auth.Request.Service),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	_ = mctx

	defer func() {
		if err != nil {
			msp.RecordError(err)
		}

		msp.End()
	}()

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.backendName)

	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), input.promLabel, input.promMetric, resource)
	if stopTimer != nil {
		defer stopTimer()
	}

	protocol, err := lm.effectiveCfg().GetLuaSearchProtocol(auth.Request.Protocol.Get(), lm.backendName)
	if protocol == nil || err != nil {
		return err
	}

	luaReplyChan := make(chan *lualib.LuaBackendResult)

	commonRequest := lualib.GetCommonRequest()
	defer lualib.PutCommonRequest(commonRequest)

	lm.fillLuaMFACommonRequest(commonRequest, auth)

	dLua := lm.effectiveCfg().GetServer().GetTimeouts().GetLuaBackend()

	ctxLua, cancelLua := context.WithTimeout(auth.Ctx(), dLua)
	defer cancelLua()

	luaRequest := &bktype.LuaRequest{
		Command:           input.command,
		BackendName:       lm.backendName,
		Protocol:          auth.Request.Protocol,
		Context:           auth.Runtime.Context,
		TOTPSecret:        input.totpSecret,
		HTTPClientRequest: auth.Request.HTTPClientRequest,
		HTTPClientContext: ctxLua,
		LuaReplyChan:      luaReplyChan,
		CommonRequest:     commonRequest,
	}

	priorityqueue.LuaQueue.Push(luaRequest, lm.luaPriority(auth))

	return (<-luaReplyChan).Err
}

// fillLuaCommonBase copies fields shared by all Lua backend commands.
func (lm *luaManagerImpl) fillLuaCommonBase(commonRequest *lualib.CommonRequest, auth *AuthState) {
	commonRequest.Debug = lm.effectiveCfg().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Service = auth.Request.Service
	commonRequest.Session = auth.Runtime.GUID
	commonRequest.ExternalSessionID = auth.Request.ExternalSessionID
	commonRequest.ClientIP = auth.Request.ClientIP
	commonRequest.ClientPort = auth.Request.XClientPort
	commonRequest.LocalIP = auth.Request.XLocalIP
	commonRequest.LocalPort = auth.Request.XPort
	commonRequest.OIDCCID = auth.Request.OIDCCID
}

// fillLuaCommonRequestContext copies request identity and connection details for Lua commands.
func fillLuaCommonRequestContext(commonRequest *lualib.CommonRequest, auth *AuthState) {
	commonRequest.NoAuth = auth.Request.NoAuth
	commonRequest.ClientHost = auth.Request.ClientHost
	commonRequest.ClientID = auth.Request.XClientID
	commonRequest.UserAgent = auth.Request.UserAgent
	commonRequest.Username = auth.Request.Username
	commonRequest.Account = auth.GetAccount()
	commonRequest.Protocol = auth.Request.Protocol.Get()
	commonRequest.AuthLoginAttempt = auth.Request.AuthLoginAttempt
	commonRequest.StatusMessage = &auth.Runtime.StatusMessage
}

// fillLuaCommonTLS copies TLS-derived request details for Lua commands.
func fillLuaCommonTLS(commonRequest *lualib.CommonRequest, auth *AuthState) {
	commonRequest.XSSL = auth.Request.XSSL
	commonRequest.XSSLSessionID = auth.Request.XSSLSessionID
	commonRequest.XSSLClientVerify = auth.Request.XSSLClientVerify
	commonRequest.XSSLClientDN = auth.Request.XSSLClientDN
	commonRequest.XSSLClientCN = auth.Request.XSSLClientCN
	commonRequest.XSSLIssuer = auth.Request.XSSLIssuer
	commonRequest.XSSLClientNotBefore = auth.Request.XSSLClientNotBefore
	commonRequest.XSSLClientNotAfter = auth.Request.XSSLClientNotAfter
	commonRequest.XSSLSubjectDN = auth.Request.XSSLSubjectDN
	commonRequest.XSSLIssuerDN = auth.Request.XSSLIssuerDN
	commonRequest.XSSLClientSubjectDN = auth.Request.XSSLClientSubjectDN
	commonRequest.XSSLClientIssuerDN = auth.Request.XSSLClientIssuerDN
	commonRequest.XSSLProtocol = auth.Request.XSSLProtocol
	commonRequest.XSSLCipher = auth.Request.XSSLCipher
	commonRequest.SSLSerial = auth.Request.SSLSerial
	commonRequest.SSLFingerprint = auth.Request.SSLFingerprint
}

// fillLuaPassDBCommonRequest prepares the CommonRequest shape expected by Lua PassDB scripts.
func (lm *luaManagerImpl) fillLuaPassDBCommonRequest(commonRequest *lualib.CommonRequest, auth *AuthState) {
	lm.fillLuaCommonBase(commonRequest, auth)
	fillLuaCommonRequestContext(commonRequest, auth)
	fillLuaCommonTLS(commonRequest, auth)

	commonRequest.Repeating = false     // unavailable
	commonRequest.UserFound = false     // set by backend_result
	commonRequest.Authenticated = false // set by backend_result
	commonRequest.BruteForceCounter = 0 // unavailable
	commonRequest.ClientNet = ""        // unavailable
	commonRequest.Account = ""          // set by nauthilus_backend_result
	commonRequest.AccountField = ""     // set by nauthilus_backend_result
	commonRequest.UniqueUserID = ""     // set by nauthilus_backend_result
	commonRequest.DisplayName = ""      // set by nauthilus_backend_result
	commonRequest.Password = auth.passwordBytes()
	commonRequest.BruteForceName = ""  // unavailable
	commonRequest.EnvironmentName = "" // unavailable
}

// fillLuaMFACommonRequest prepares CommonRequest fields shared by Lua MFA mutation commands.
func (lm *luaManagerImpl) fillLuaMFACommonRequest(commonRequest *lualib.CommonRequest, auth *AuthState) {
	lm.fillLuaCommonBase(commonRequest, auth)
	commonRequest.Username = auth.Request.Username
}

// fillLuaRecoveryCommonRequest prepares CommonRequest fields for Lua TOTP recovery mutations.
func (lm *luaManagerImpl) fillLuaRecoveryCommonRequest(commonRequest *lualib.CommonRequest, auth *AuthState) {
	commonRequest.Debug = lm.effectiveCfg().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.UserFound = true
	commonRequest.Authenticated = true
	commonRequest.NoAuth = auth.Request.NoAuth
	commonRequest.Service = auth.Request.Service
	commonRequest.Session = auth.Runtime.GUID
	commonRequest.ExternalSessionID = auth.Request.ExternalSessionID
	commonRequest.ClientIP = auth.Request.ClientIP
	commonRequest.ClientPort = auth.Request.XClientPort
	commonRequest.ClientHost = auth.Request.ClientHost
	commonRequest.ClientID = auth.Request.XClientID
	commonRequest.UserAgent = auth.Request.UserAgent
	commonRequest.LocalIP = auth.Request.XLocalIP
	commonRequest.LocalPort = auth.Request.XPort
	commonRequest.Username = auth.Request.Username
	commonRequest.Account = auth.GetAccount()
}

// appendLuaBackendLogs appends backend-provided log fields while preserving existing entries.
func appendLuaBackendLogs(auth *AuthState, luaBackendResult *lualib.LuaBackendResult) {
	if luaBackendResult.Logs == nil || len(*luaBackendResult.Logs) == 0 {
		return
	}

	additionalLogsLen := len(auth.Runtime.AdditionalLogs)
	newAdditionalLogs := make([]any, additionalLogsLen+len(*luaBackendResult.Logs))
	copy(newAdditionalLogs, auth.Runtime.AdditionalLogs)
	auth.Runtime.AdditionalLogs = newAdditionalLogs[:additionalLogsLen]

	for index := range *luaBackendResult.Logs {
		auth.Runtime.AdditionalLogs = append(auth.Runtime.AdditionalLogs, (*luaBackendResult.Logs)[index])
	}
}

// syncLuaStatusMessage copies a Lua-updated status message back into the AuthState.
func syncLuaStatusMessage(auth *AuthState, luaRequest *bktype.LuaRequest) {
	if statusMessage := luaRequest.StatusMessage; *statusMessage != auth.Runtime.StatusMessage {
		auth.Runtime.StatusMessage = *statusMessage
	}
}

// applyLuaPassDBResult copies Lua backend data into the pooled PassDB result.
func (lm *luaManagerImpl) applyLuaPassDBResult(auth *AuthState, passDBResult *PassDBResult, luaBackendResult *lualib.LuaBackendResult) bool {
	accountField := luaBackendResult.AccountField
	if accountField == "" {
		passDBResult.Authenticated = false
		passDBResult.UserFound = false

		return false
	}

	passDBResult.Authenticated = luaBackendResult.Authenticated
	passDBResult.UserFound = luaBackendResult.UserFound
	passDBResult.AccountField = accountField

	if passDBResult.Authenticated {
		localcache.AuthCache.Set(auth.Request.Username, true)
	}

	lm.applyOptionalLuaPassDBFields(passDBResult, luaBackendResult)

	return true
}

// applyOptionalLuaPassDBFields copies optional Lua backend fields when they are present.
func (lm *luaManagerImpl) applyOptionalLuaPassDBFields(passDBResult *PassDBResult, luaBackendResult *lualib.LuaBackendResult) {
	if luaBackendResult.UserFound {
		passDBResult.BackendName = lm.backendName
		passDBResult.Backend = definitions.BackendLua
	}

	if luaBackendResult.TOTPSecretField != "" {
		passDBResult.TOTPSecretField = luaBackendResult.TOTPSecretField
	}

	if luaBackendResult.UniqueUserIDField != "" {
		passDBResult.UniqueUserIDField = luaBackendResult.UniqueUserIDField
	}

	if luaBackendResult.DisplayNameField != "" {
		passDBResult.DisplayNameField = luaBackendResult.DisplayNameField
	}

	if luaBackendResult.Attributes != nil {
		passDBResult.Attributes, passDBResult.Groups, passDBResult.GroupDistinguishedNames = buildAttributeMappingFromLua(luaBackendResult.Attributes)
	}

	if len(luaBackendResult.Groups) > 0 || len(luaBackendResult.GroupDistinguishedNames) > 0 {
		passDBResult.Groups = mergeNormalizedStringSlices(passDBResult.Groups, luaBackendResult.Groups)
		passDBResult.GroupDistinguishedNames = mergeNormalizedStringSlices(passDBResult.GroupDistinguishedNames, luaBackendResult.GroupDistinguishedNames)
	}
}

// newLuaPassDBRequest creates a queued Lua PassDB request with pooled request state.
func (lm *luaManagerImpl) newLuaPassDBRequest(auth *AuthState) luaRequestHandle {
	luaReplyChan := make(chan *lualib.LuaBackendResult)
	commonRequest := lualib.GetCommonRequest()
	lm.fillLuaPassDBCommonRequest(commonRequest, auth)

	dLua := lm.effectiveCfg().GetServer().GetTimeouts().GetLuaBackend()
	ctxLua, cancelLua := context.WithTimeout(auth.Ctx(), dLua)

	return luaRequestHandle{
		replyChan: luaReplyChan,
		cleanup: func() {
			cancelLua()
			lualib.PutCommonRequest(commonRequest)
		},
		request: &bktype.LuaRequest{
			Command:           definitions.LuaCommandPassDB,
			BackendName:       lm.backendName,
			Service:           auth.Request.Service,
			Protocol:          auth.Request.Protocol,
			Context:           auth.Runtime.Context,
			LuaReplyChan:      luaReplyChan,
			HTTPClientRequest: auth.Request.HTTPClientRequest,
			HTTPClientContext: ctxLua,
			PolicyContext:     auth.requestPolicyContext(auth.Request.HTTPClientContext),
			CommonRequest:     commonRequest,
		},
	}
}

// newLuaAccountRequest creates a queued Lua account-list request with pooled request state.
func (lm *luaManagerImpl) newLuaAccountRequest(auth *AuthState) luaRequestHandle {
	luaReplyChan := make(chan *lualib.LuaBackendResult)
	commonRequest := lualib.GetCommonRequest()
	lm.fillLuaCommonBase(commonRequest, auth)

	dLua := lm.effectiveCfg().GetServer().GetTimeouts().GetLuaBackend()
	ctxLua, cancelLua := context.WithTimeout(svcctx.Get(), dLua)

	return luaRequestHandle{
		replyChan: luaReplyChan,
		cleanup: func() {
			cancelLua()
			lualib.PutCommonRequest(commonRequest)
		},
		request: &bktype.LuaRequest{
			Command:           definitions.LuaCommandListAccounts,
			BackendName:       lm.backendName,
			Protocol:          auth.Request.Protocol,
			Context:           auth.Runtime.Context,
			HTTPClientRequest: auth.Request.HTTPClientRequest,
			HTTPClientContext: ctxLua,
			LuaReplyChan:      luaReplyChan,
			CommonRequest:     commonRequest,
		},
	}
}

// accountsFromLuaBackendResult converts Lua account attributes into a stable account list.
func accountsFromLuaBackendResult(luaBackendResult *lualib.LuaBackendResult) AccountList {
	accountSet := config.NewStringSet()

	if luaBackendResult.Attributes != nil {
		for _, value := range luaBackendResult.Attributes {
			if valueName, assertOk := value.(string); assertOk {
				accountSet.Set(valueName)
			}
		}
	}

	return accountSet.GetStringSlice()
}

// PassDB implements the Lua password database backend.
func (lm *luaManagerImpl) PassDB(auth *AuthState) (passDBResult *PassDBResult, err error) {
	tr := monittrace.New("nauthilus/lua_backend")
	lctx, lsp := tr.Start(auth.Ctx(), "lua.passdb",
		attribute.String("backend_name", lm.backendName),
		attribute.String("service", auth.Request.Service),
		attribute.String("username", auth.Request.Username),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	_ = lctx

	defer lsp.End()

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.backendName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromBackend, "lua_backend_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	protocol, protocolErr := lm.effectiveCfg().GetLuaSearchProtocol(auth.Request.Protocol.Get(), lm.backendName)
	if protocol == nil || protocolErr != nil {
		if protocolErr != nil {
			lsp.RecordError(protocolErr)
		}

		return passDBResult, protocolErr
	}

	passDBResult = GetPassDBResultFromPool()

	requestHandle := lm.newLuaPassDBRequest(auth)
	defer requestHandle.cleanup()

	priorityqueue.LuaQueue.Push(requestHandle.request, lm.luaPriority(auth))

	luaBackendResult := <-requestHandle.replyChan

	appendLuaBackendLogs(auth, luaBackendResult)

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err

		lsp.RecordError(err)

		return
	}

	syncLuaStatusMessage(auth, requestHandle.request)

	if !lm.applyLuaPassDBResult(auth, passDBResult, luaBackendResult) {
		return
	}

	lsp.SetAttributes(
		attribute.Bool("user_found", luaBackendResult.UserFound),
		attribute.Bool("authenticated", luaBackendResult.Authenticated),
	)

	return
}

// AccountDB implements the list-account mode and returns all known users from a Lua backend logic.
func (lm *luaManagerImpl) AccountDB(auth *AuthState) (accounts AccountList, err error) {
	// Tracing: Lua backend account listing
	tr := monittrace.New("nauthilus/lua_backend")
	actx, asp := tr.Start(auth.Ctx(), "lua.accountdb",
		attribute.String("backend_name", lm.backendName),
		attribute.String("service", auth.Request.Service),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	_ = actx

	defer asp.End()

	var (
		luaBackendResult *lualib.LuaBackendResult
		protocol         *config.LuaSearchProtocol
	)

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.backendName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromAccount, "lua_account_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	if protocol, err = lm.effectiveCfg().GetLuaSearchProtocol(auth.Request.Protocol.Get(), lm.backendName); protocol == nil || err != nil {
		if err != nil {
			asp.RecordError(err)
		}

		return
	}

	requestHandle := lm.newLuaAccountRequest(auth)
	defer requestHandle.cleanup()

	priorityqueue.LuaQueue.Push(requestHandle.request, priorityqueue.PriorityMedium)

	luaBackendResult = <-requestHandle.replyChan

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err
		asp.RecordError(err)

		return
	}

	accounts = accountsFromLuaBackendResult(luaBackendResult)

	if len(accounts) == 0 {
		level.Warn(lm.effectiveLogger()).Log(
			definitions.LogKeyGUID, auth.Runtime.GUID,
			definitions.LogKeyMsg, "No accounts found in Lua backend",
		)
	}

	asp.SetAttributes(attribute.Int("accounts", len(accounts)))

	return accounts, nil
}

// AddTOTPSecret sends a newly generated TOTP secret to a Lua backend logic.
func (lm *luaManagerImpl) AddTOTPSecret(auth *AuthState, totp *mfa.TOTPSecret) (err error) {
	return lm.runLuaMFACommand(auth, luaMFACommandInput{
		spanName:   "lua.add_totp",
		promLabel:  definitions.PromStoreTOTP,
		promMetric: "lua_store_totp_request_total",
		totpSecret: totp.GetValue(),
		command:    definitions.LuaCommandAddMFAValue,
	})
}

// DeleteTOTPSecret removes the TOTP secret from a Lua backend logic.
func (lm *luaManagerImpl) DeleteTOTPSecret(auth *AuthState) (err error) {
	return lm.runLuaMFACommand(auth, luaMFACommandInput{
		spanName:   "lua.delete_totp",
		promLabel:  definitions.PromDeleteTOTP,
		promMetric: "lua_delete_totp_request_total",
		command:    definitions.LuaCommandDeleteMFAValue,
	})
}

// AddTOTPRecoveryCodes adds the specified TOTP recovery codes to the user's authentication state in the Lua backend.
func (lm *luaManagerImpl) AddTOTPRecoveryCodes(auth *AuthState, recovery *mfa.TOTPRecovery) (err error) {
	tr := monittrace.New("nauthilus/lua_backend")
	lctx, lsp := tr.Start(auth.Ctx(), "lua.add_totp_recovery",
		attribute.String("backend_name", lm.backendName),
		attribute.String("service", auth.Request.Service),
		attribute.String("username", auth.Request.Username),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	_ = lctx

	defer lsp.End()

	var luaBackendResult *lualib.LuaBackendResult

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.backendName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromStoreTOTPRecovery, "lua_store_totp_recovery_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	luaReplyChan := make(chan *lualib.LuaBackendResult)

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	defer lualib.PutCommonRequest(commonRequest)

	lm.fillLuaRecoveryCommonRequest(commonRequest, auth)
	commonRequest.TOTPRecoveryCodes = recovery.GetCodes()

	luaRequest := &bktype.LuaRequest{
		Command:       definitions.LuaCommandAddTOTPRecoveryCodes,
		BackendName:   lm.backendName,
		Context:       auth.Runtime.Context,
		LuaReplyChan:  luaReplyChan,
		CommonRequest: commonRequest,
	}

	priorityqueue.LuaQueue.Push(luaRequest, lm.luaPriority(auth))

	_, wSpan := tr.Start(lctx, "lua.add_totp_recovery.wait")
	luaBackendResult = <-luaReplyChan

	wSpan.End()

	if luaBackendResult.Err != nil {
		lsp.RecordError(luaBackendResult.Err)
	}

	return luaBackendResult.Err
}

// DeleteTOTPRecoveryCodes removes all TOTP recovery codes for the user in the Lua backend.
func (lm *luaManagerImpl) DeleteTOTPRecoveryCodes(auth *AuthState) (err error) {
	tr := monittrace.New("nauthilus/lua_backend")
	lctx, lsp := tr.Start(auth.Ctx(), "lua.delete_totp_recovery",
		attribute.String("backend_name", lm.backendName),
		attribute.String("service", auth.Request.Service),
		attribute.String("username", auth.Request.Username),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	_ = lctx

	defer lsp.End()

	var luaBackendResult *lualib.LuaBackendResult

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.backendName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromDeleteTOTPRecovery, "lua_delete_totp_recovery_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	luaReplyChan := make(chan *lualib.LuaBackendResult)

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	defer lualib.PutCommonRequest(commonRequest)

	lm.fillLuaRecoveryCommonRequest(commonRequest, auth)

	luaRequest := &bktype.LuaRequest{
		Command:       definitions.LuaCommandDeleteTOTPRecoveryCodes,
		BackendName:   lm.backendName,
		Context:       auth.Runtime.Context,
		LuaReplyChan:  luaReplyChan,
		CommonRequest: commonRequest,
	}

	priorityqueue.LuaQueue.Push(luaRequest, lm.luaPriority(auth))

	_, wSpan := tr.Start(lctx, "lua.delete_totp_recovery.wait")
	luaBackendResult = <-luaReplyChan

	wSpan.End()

	if luaBackendResult.Err != nil {
		lsp.RecordError(luaBackendResult.Err)
	}

	return luaBackendResult.Err
}

var _ BackendManager = &luaManagerImpl{}

// NewLuaManager initializes and returns a new LuaManager instance with the specified backend name.
func NewLuaManager(backendName string, deps AuthDeps) BackendManager {
	return &luaManagerImpl{
		backendName: backendName,
		deps:        deps,
	}
}

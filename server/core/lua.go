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
	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/stats"
)

// luaPassDB implements the Lua password database backend.
func luaPassDB(auth *AuthState) (passDBResult *PassDBResult, err error) {
	var luaBackendResult *lualib.LuaBackendResult

	stopTimer := stats.PrometheusTimer(global.PromBackend, "lua_backend_request_total")

	defer stopTimer()

	passDBResult = &PassDBResult{}

	luaReplyChan := make(chan *lualib.LuaBackendResult)

	defer close(luaReplyChan)

	luaRequest := &backend.LuaRequest{
		Function:          global.LuaCommandPassDB,
		Service:           auth.Service,
		Protocol:          auth.Protocol,
		Context:           auth.Context,
		LuaReplyChan:      luaReplyChan,
		HTTPClientContext: auth.HTTPClientContext,
		CommonRequest: &lualib.CommonRequest{
			Debug:               config.LoadableConfig.Server.Log.Level.Level() == global.LogLevelDebug,
			Repeating:           false, // unavailable
			UserFound:           false, // set by backend_result
			Authenticated:       false, // set by backend_result
			NoAuth:              auth.NoAuth,
			BruteForceCounter:   0, // unavailable
			Service:             auth.Service,
			Session:             *auth.GUID,
			ClientIP:            auth.ClientIP,
			ClientPort:          auth.XClientPort,
			ClientNet:           "", // unavailable
			ClientHost:          auth.ClientHost,
			ClientID:            auth.XClientID,
			UserAgent:           *auth.UserAgent,
			LocalIP:             auth.XLocalIP,
			LocalPort:           auth.XPort,
			Username:            auth.Username,
			Account:             "", // set by backend_result
			UniqueUserID:        "", // set by backend_result
			DisplayName:         "", // set by backend_result
			Password:            auth.Password,
			Protocol:            auth.Protocol.Get(),
			BruteForceName:      "", // unavailable
			FeatureName:         "", // unavailable
			StatusMessage:       &auth.StatusMessage,
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
		},
	}

	select {
	case backend.LuaRequestChan <- luaRequest:
	default:
		return passDBResult, errors.ErrClosedChannel
	}

	luaBackendResult = <-luaReplyChan

	for index := range *luaBackendResult.Logs {
		auth.AdditionalLogs = append(auth.AdditionalLogs, (*luaBackendResult.Logs)[index])
	}

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err

		return
	}

	if statusMessage := luaRequest.StatusMessage; *statusMessage != auth.StatusMessage {
		auth.StatusMessage = *statusMessage
	}

	accountField := luaBackendResult.AccountField
	if accountField == "" {
		return
	}

	totpSecretField := luaBackendResult.TOTPSecretField
	uniqueUserIDField := luaBackendResult.UniqueUserIDField
	displayName := luaBackendResult.DisplayNameField

	passDBResult.Authenticated = luaBackendResult.Authenticated
	passDBResult.UserFound = luaBackendResult.UserFound
	passDBResult.AccountField = &accountField

	if totpSecretField != "" {
		passDBResult.TOTPSecretField = &totpSecretField
	}

	if uniqueUserIDField != "" {
		passDBResult.UniqueUserIDField = &uniqueUserIDField
	}

	if displayName != "" {
		passDBResult.DisplayNameField = &displayName
	}

	if luaBackendResult.UserFound {
		passDBResult.Backend = global.BackendLua
	}

	if luaBackendResult.Attributes != nil {
		passDBResult.Attributes = make(backend.DatabaseResult)

		for key, value := range luaBackendResult.Attributes {
			if keyName, assertOk := key.(string); assertOk {
				passDBResult.Attributes[keyName] = []any{value}
			}
		}
	}

	return
}

// luaAccountDB implements the list-account mode and returns all known users from a Lua backend logic.
func luaAccountDB(auth *AuthState) (accounts AccountList, err error) {
	var luaBackendResult *lualib.LuaBackendResult

	stopTimer := stats.PrometheusTimer(global.PromAccount, "lua_account_request_total")

	defer stopTimer()

	luaReplyChan := make(chan *lualib.LuaBackendResult)

	defer close(luaReplyChan)

	luaRequest := &backend.LuaRequest{
		Function:          global.LuaCommandListAccounts,
		Protocol:          auth.Protocol,
		HTTPClientContext: auth.HTTPClientContext,
		LuaReplyChan:      luaReplyChan,
		CommonRequest: &lualib.CommonRequest{
			Debug:      config.LoadableConfig.Server.Log.Level.Level() == global.LogLevelDebug,
			Service:    auth.Service,
			Session:    *auth.GUID,
			ClientIP:   auth.ClientIP,
			ClientPort: auth.XClientPort,
			LocalIP:    auth.XLocalIP,
			LocalPort:  auth.XPort,
		},
	}

	select {
	case backend.LuaRequestChan <- luaRequest:
	default:
		return accounts, errors.ErrClosedChannel
	}

	luaBackendResult = <-luaReplyChan

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err

		return
	}

	accountSet := config.NewStringSet()
	_ = accountSet

	if luaBackendResult.Attributes != nil {
		for _, value := range luaBackendResult.Attributes {
			if valueName, assertOk := value.(string); assertOk {
				accountSet.Set(valueName)
			}
		}
	}

	return accountSet.GetStringSlice(), nil
}

// luaAddTOTPSecret sends a newly generated TOTP secret to a Lua backend logic.
func luaAddTOTPSecret(auth *AuthState, totp *TOTPSecret) (err error) {
	var luaBackendResult *lualib.LuaBackendResult

	stopTimer := stats.PrometheusTimer(global.PromStoreTOTP, "lua_store_totp_request_total")

	defer stopTimer()

	luaReplyChan := make(chan *lualib.LuaBackendResult)

	defer close(luaReplyChan)

	luaRequest := &backend.LuaRequest{
		Function:          global.LuaCommandAddMFAValue,
		Protocol:          auth.Protocol,
		TOTPSecret:        totp.getValue(),
		HTTPClientContext: auth.HTTPClientContext,
		LuaReplyChan:      luaReplyChan,
		CommonRequest: &lualib.CommonRequest{
			Debug:      config.LoadableConfig.Server.Log.Level.Level() == global.LogLevelDebug,
			Service:    auth.Service,
			Session:    *auth.GUID,
			Username:   auth.Username,
			ClientIP:   auth.ClientIP,
			ClientPort: auth.XClientPort,
			LocalIP:    auth.XLocalIP,
			LocalPort:  auth.XPort,
		},
	}

	select {
	case backend.LuaRequestChan <- luaRequest:
	default:
		return errors.ErrClosedChannel
	}

	luaBackendResult = <-luaReplyChan

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err

		return
	}

	return
}

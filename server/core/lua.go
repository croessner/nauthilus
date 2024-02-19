package core

import (
	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/prometheus/client_golang/prometheus"
)

// luaPassDB implements the Lua password database backend.
func luaPassDB(auth *Authentication) (passDBResult *PassDBResult, err error) {
	var luaBackendResult *backend.LuaBackendResult

	timer := prometheus.NewTimer(stats.FunctionDuration.WithLabelValues("Authentication", "luaPassDB"))

	defer timer.ObserveDuration()

	passDBResult = &PassDBResult{}

	luaReplyChan := make(chan *backend.LuaBackendResult)

	defer close(luaReplyChan)

	luaRequest := &backend.LuaRequest{
		Function:     global.LuaCommandPassDB,
		Service:      auth.Service,
		Protocol:     auth.Protocol,
		Context:      auth.Context,
		LuaReplyChan: luaReplyChan,
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

	backend.LuaRequestChan <- luaRequest

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
func luaAccountDB(auth *Authentication) (accounts AccountList, err error) {
	var luaBackendResult *backend.LuaBackendResult

	timer := prometheus.NewTimer(stats.FunctionDuration.WithLabelValues("Account", "luaAccountDB"))

	defer timer.ObserveDuration()

	luaReplyChan := make(chan *backend.LuaBackendResult)

	defer close(luaReplyChan)

	luaRequest := &backend.LuaRequest{
		Function:     global.LuaCommandListAccounts,
		Protocol:     auth.Protocol,
		LuaReplyChan: luaReplyChan,
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

	backend.LuaRequestChan <- luaRequest

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
func luaAddTOTPSecret(auth *Authentication, totp *TOTPSecret) (err error) {
	var luaBackendResult *backend.LuaBackendResult

	timer := prometheus.NewTimer(stats.FunctionDuration.WithLabelValues("StoreTOTP", "luaAddTOTPSecret"))

	defer timer.ObserveDuration()

	luaReplyChan := make(chan *backend.LuaBackendResult)

	defer close(luaReplyChan)

	luaRequest := &backend.LuaRequest{
		Function:     global.LuaCommandAddMFAValue,
		Protocol:     auth.Protocol,
		TOTPSecret:   totp.getValue(),
		LuaReplyChan: luaReplyChan,
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

	backend.LuaRequestChan <- luaRequest

	luaBackendResult = <-luaReplyChan

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err

		return
	}

	return
}

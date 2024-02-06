package core

import (
	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/global"
	"github.com/prometheus/client_golang/prometheus"
)

// luaPassDB implements the Lua password database backend.
func luaPassDB(auth *Authentication) (passDBResult *PassDBResult, err error) {
	var luaBackendResult *backend.LuaBackendResult

	timer := prometheus.NewTimer(functionDuration.WithLabelValues("Authentication", "luaPassDB"))

	defer timer.ObserveDuration()

	passDBResult = &PassDBResult{}

	luaReplyChan := make(chan *backend.LuaBackendResult)

	defer close(luaReplyChan)

	luaRequest := &backend.LuaRequest{
		Debug:               config.EnvConfig.Verbosity.Level() == global.LogLevelDebug,
		NoAuth:              auth.NoAuth,
		Function:            global.LuaCommandPassDB,
		Session:             auth.GUID,
		Username:            auth.Username,
		Password:            auth.Password,
		ClientIP:            auth.ClientIP,
		ClientPort:          auth.XClientPort,
		ClientHost:          auth.ClientHost,
		LocalIP:             auth.XLocalIP,
		LocalPprt:           auth.XPort,
		ClientID:            auth.XClientID,
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
		UserAgent:           *auth.UserAgent,
		Service:             auth.Service,
		Protocol:            auth.Protocol,
		Context:             auth.Context,
		LuaReplyChan:        luaReplyChan,
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

	timer := prometheus.NewTimer(functionDuration.WithLabelValues("Account", "luaAccountDB"))

	defer timer.ObserveDuration()

	luaReplyChan := make(chan *backend.LuaBackendResult)

	defer close(luaReplyChan)

	luaRequest := &backend.LuaRequest{
		Debug:        config.EnvConfig.Verbosity.Level() == global.LogLevelDebug,
		Session:      auth.GUID,
		ClientIP:     auth.ClientIP,
		ClientPort:   auth.XClientPort,
		LocalIP:      auth.XLocalIP,
		LocalPprt:    auth.XPort,
		Protocol:     auth.Protocol,
		LuaReplyChan: luaReplyChan,
		Function:     global.LuaCommandListAccounts,
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

	timer := prometheus.NewTimer(functionDuration.WithLabelValues("StoreTOTP", "luaAddTOTPSecret"))

	defer timer.ObserveDuration()

	luaReplyChan := make(chan *backend.LuaBackendResult)

	defer close(luaReplyChan)

	luaRequest := &backend.LuaRequest{
		Debug:        config.EnvConfig.Verbosity.Level() == global.LogLevelDebug,
		Session:      auth.GUID,
		Username:     auth.Username,
		ClientIP:     auth.ClientIP,
		ClientPort:   auth.XClientPort,
		LocalIP:      auth.XLocalIP,
		LocalPprt:    auth.XPort,
		Protocol:     auth.Protocol,
		TOTPSecret:   totp.getValue(),
		LuaReplyChan: luaReplyChan,
		Function:     global.LuaCommandAddMFAValue,
	}

	backend.LuaRequestChan <- luaRequest

	luaBackendResult = <-luaReplyChan

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err

		return
	}

	return
}

package core

import (
	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
)

// LuaPassDB implements the Lua password database backend.
func LuaPassDB(auth *Authentication) (passDBResult *PassDBResult, err error) {
	var luaBackendResult *backend.LuaBackendResult

	passDBResult = &PassDBResult{}

	luaReplyChan := make(chan *backend.LuaBackendResult)

	luaRequest := &backend.LuaRequest{
		Debug:               config.EnvConfig.Verbosity.Level() == decl.LogLevelDebug,
		NoAuth:              auth.NoAuth,
		Function:            decl.LuaCommandPassDB,
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
		passDBResult.Backend = decl.BackendLua
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

// LuaAccountDB implements the list-account mode and returns all known users from a Lua backend logic.
func LuaAccountDB(auth *Authentication) (accounts AccountList, err error) {
	var luaBackendResult *backend.LuaBackendResult

	luaReplyChan := make(chan *backend.LuaBackendResult)

	luaRequest := &backend.LuaRequest{
		Debug:        config.EnvConfig.Verbosity.Level() == decl.LogLevelDebug,
		Session:      auth.GUID,
		ClientIP:     auth.ClientIP,
		ClientPort:   auth.XClientPort,
		LocalIP:      auth.XLocalIP,
		LocalPprt:    auth.XPort,
		Protocol:     auth.Protocol,
		LuaReplyChan: luaReplyChan,
		Function:     decl.LuaCommandListAccounts,
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

// LuaAddTOTPSecret sends a newly generated TOTP secret to a Lua backend logic.
func LuaAddTOTPSecret(auth *Authentication, totp *TOTPSecret) (err error) {
	var luaBackendResult *backend.LuaBackendResult

	luaReplyChan := make(chan *backend.LuaBackendResult)

	luaRequest := &backend.LuaRequest{
		Debug:        config.EnvConfig.Verbosity.Level() == decl.LogLevelDebug,
		Session:      auth.GUID,
		Username:     auth.Username,
		ClientIP:     auth.ClientIP,
		ClientPort:   auth.XClientPort,
		LocalIP:      auth.XLocalIP,
		LocalPprt:    auth.XPort,
		Protocol:     auth.Protocol,
		TOTPSecret:   totp.GetValue(),
		LuaReplyChan: luaReplyChan,
		Function:     decl.LuaCommandAddMFAValue,
	}

	backend.LuaRequestChan <- luaRequest

	luaBackendResult = <-luaReplyChan

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err

		return
	}

	return
}

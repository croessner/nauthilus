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
	"encoding/json"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/localcache"
	"github.com/croessner/nauthilus/server/lualib"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/go-webauthn/webauthn/webauthn"
	"go.opentelemetry.io/otel/attribute"
)

// GetWebAuthnCredentials retrieves WebAuthn credentials for the user in the Lua backend.
func (lm *luaManagerImpl) GetWebAuthnCredentials(auth *AuthState) (credentials []webauthn.Credential, err error) {
	tr := monittrace.New("nauthilus/lua_backend")
	lctx, lsp := tr.Start(auth.Ctx(), "lua.get_webauthn_credentials",
		attribute.String("backend_name", lm.backendName),
		attribute.String("username", auth.Request.Username),
	)
	defer lsp.End()

	var luaBackendResult *lualib.LuaBackendResult

	luaReplyChan := make(chan *lualib.LuaBackendResult)

	commonRequest := lualib.GetCommonRequest()
	defer lualib.PutCommonRequest(commonRequest)

	commonRequest.Debug = lm.effectiveCfg().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Username = auth.Request.Username
	commonRequest.Service = auth.Request.Service
	commonRequest.Session = auth.Runtime.GUID

	dLua := lm.effectiveCfg().GetServer().GetTimeouts().GetLuaBackend()
	ctxLua, cancelLua := context.WithTimeout(lctx, dLua)
	defer cancelLua()

	luaRequest := &bktype.LuaRequest{
		Command:           definitions.LuaCommandGetWebAuthnCredentials,
		BackendName:       lm.backendName,
		Service:           auth.Request.Service,
		Protocol:          auth.Request.Protocol,
		Context:           auth.Runtime.Context,
		LuaReplyChan:      luaReplyChan,
		HTTPClientContext: ctxLua,
		CommonRequest:     commonRequest,
	}

	priority := priorityqueue.PriorityLow
	if localcache.AuthCache.IsAuthenticated(auth.Request.Username) {
		priority = priorityqueue.PriorityHigh
	}

	priorityqueue.LuaQueue.Push(luaRequest, priority)

	luaBackendResult = <-luaReplyChan

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err
		lsp.RecordError(err)
		return
	}

	for _, credStr := range luaBackendResult.Attributes {
		if str, ok := credStr.(string); ok {
			var cred webauthn.Credential
			if err = json.Unmarshal([]byte(str), &cred); err == nil {
				credentials = append(credentials, cred)
			}
		}
	}

	return
}

// SaveWebAuthnCredential saves a WebAuthn credential for the user in the Lua backend.
func (lm *luaManagerImpl) SaveWebAuthnCredential(auth *AuthState, credential *webauthn.Credential) (err error) {
	tr := monittrace.New("nauthilus/lua_backend")
	lctx, lsp := tr.Start(auth.Ctx(), "lua.save_webauthn_credential",
		attribute.String("backend_name", lm.backendName),
		attribute.String("username", auth.Request.Username),
	)
	defer lsp.End()

	var (
		luaBackendResult *lualib.LuaBackendResult
		credBytes        []byte
	)

	if credBytes, err = json.Marshal(credential); err != nil {
		lsp.RecordError(err)
		return
	}

	luaReplyChan := make(chan *lualib.LuaBackendResult)

	commonRequest := lualib.GetCommonRequest()
	defer lualib.PutCommonRequest(commonRequest)

	commonRequest.Debug = lm.effectiveCfg().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Username = auth.Request.Username
	commonRequest.Service = auth.Request.Service
	commonRequest.Session = auth.Runtime.GUID

	dLua := lm.effectiveCfg().GetServer().GetTimeouts().GetLuaBackend()
	ctxLua, cancelLua := context.WithTimeout(lctx, dLua)
	defer cancelLua()

	luaRequest := &bktype.LuaRequest{
		Command:            definitions.LuaCommandSaveWebAuthnCredential,
		BackendName:        lm.backendName,
		Service:            auth.Request.Service,
		Protocol:           auth.Request.Protocol,
		Context:            auth.Runtime.Context,
		WebAuthnCredential: string(credBytes),
		LuaReplyChan:       luaReplyChan,
		HTTPClientContext:  ctxLua,
		CommonRequest:      commonRequest,
	}

	priority := priorityqueue.PriorityMedium
	if localcache.AuthCache.IsAuthenticated(auth.Request.Username) {
		priority = priorityqueue.PriorityHigh
	}

	priorityqueue.LuaQueue.Push(luaRequest, priority)

	luaBackendResult = <-luaReplyChan

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err
		lsp.RecordError(err)
		return
	}

	return
}

// DeleteWebAuthnCredential removes a WebAuthn credential for the user in the Lua backend.
func (lm *luaManagerImpl) DeleteWebAuthnCredential(auth *AuthState, credential *webauthn.Credential) (err error) {
	tr := monittrace.New("nauthilus/lua_backend")
	lctx, lsp := tr.Start(auth.Ctx(), "lua.delete_webauthn_credential",
		attribute.String("backend_name", lm.backendName),
		attribute.String("username", auth.Request.Username),
	)
	defer lsp.End()

	var (
		luaBackendResult *lualib.LuaBackendResult
		credBytes        []byte
	)

	if credBytes, err = json.Marshal(credential); err != nil {
		lsp.RecordError(err)
		return
	}

	luaReplyChan := make(chan *lualib.LuaBackendResult)

	commonRequest := lualib.GetCommonRequest()
	defer lualib.PutCommonRequest(commonRequest)

	commonRequest.Debug = lm.effectiveCfg().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Username = auth.Request.Username
	commonRequest.Service = auth.Request.Service
	commonRequest.Session = auth.Runtime.GUID

	dLua := lm.effectiveCfg().GetServer().GetTimeouts().GetLuaBackend()
	ctxLua, cancelLua := context.WithTimeout(lctx, dLua)
	defer cancelLua()

	luaRequest := &bktype.LuaRequest{
		Command:            definitions.LuaCommandDeleteWebAuthnCredential,
		BackendName:        lm.backendName,
		Service:            auth.Request.Service,
		Protocol:           auth.Request.Protocol,
		Context:            auth.Runtime.Context,
		WebAuthnCredential: string(credBytes),
		LuaReplyChan:       luaReplyChan,
		HTTPClientContext:  ctxLua,
		CommonRequest:      commonRequest,
	}

	priority := priorityqueue.PriorityMedium
	if localcache.AuthCache.IsAuthenticated(auth.Request.Username) {
		priority = priorityqueue.PriorityHigh
	}

	priorityqueue.LuaQueue.Push(luaRequest, priority)

	luaBackendResult = <-luaReplyChan

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err
		lsp.RecordError(err)
		return
	}

	return
}

// UpdateWebAuthnCredential updates an existing WebAuthn credential for the user in the Lua backend.
func (lm *luaManagerImpl) UpdateWebAuthnCredential(auth *AuthState, oldCredential *webauthn.Credential, newCredential *webauthn.Credential) (err error) {
	tr := monittrace.New("nauthilus/lua_backend")
	lctx, lsp := tr.Start(auth.Ctx(), "lua.update_webauthn_credential",
		attribute.String("backend_name", lm.backendName),
		attribute.String("username", auth.Request.Username),
	)
	defer lsp.End()

	var (
		luaBackendResult *lualib.LuaBackendResult
		newCredBytes     []byte
		oldCredBytes     []byte
	)

	if newCredBytes, err = json.Marshal(newCredential); err != nil {
		lsp.RecordError(err)
		return
	}

	if oldCredBytes, err = json.Marshal(oldCredential); err != nil {
		lsp.RecordError(err)
		return
	}

	luaReplyChan := make(chan *lualib.LuaBackendResult)

	commonRequest := lualib.GetCommonRequest()
	defer lualib.PutCommonRequest(commonRequest)

	commonRequest.Debug = lm.effectiveCfg().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Username = auth.Request.Username
	commonRequest.Service = auth.Request.Service
	commonRequest.Session = auth.Runtime.GUID
	commonRequest.WebAuthnCredential = string(newCredBytes)
	commonRequest.WebAuthnOldCredential = string(oldCredBytes)

	dLua := lm.effectiveCfg().GetServer().GetTimeouts().GetLuaBackend()
	ctxLua, cancelLua := context.WithTimeout(lctx, dLua)
	defer cancelLua()

	luaRequest := &bktype.LuaRequest{
		Command:               definitions.LuaCommandUpdateWebAuthnCredential,
		BackendName:           lm.backendName,
		Service:               auth.Request.Service,
		Protocol:              auth.Request.Protocol,
		Context:               auth.Runtime.Context,
		WebAuthnCredential:    string(newCredBytes),
		WebAuthnOldCredential: string(oldCredBytes),
		LuaReplyChan:          luaReplyChan,
		HTTPClientContext:     ctxLua,
		CommonRequest:         commonRequest,
	}

	priority := priorityqueue.PriorityMedium
	if localcache.AuthCache.IsAuthenticated(auth.Request.Username) {
		priority = priorityqueue.PriorityHigh
	}

	priorityqueue.LuaQueue.Push(luaRequest, priority)

	luaBackendResult = <-luaReplyChan

	if luaBackendResult.Err != nil {
		err = luaBackendResult.Err
		lsp.RecordError(err)
		return
	}

	return
}

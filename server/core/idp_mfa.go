// Copyright (C) 2025 Christian Rößner
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
	"bytes"
	"net"
	"net/http"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/idp/flow"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"
)

// StoreCompletedIDPMFASession replaces the temporary MFA state with the final
// authenticated IdP session while preserving the completed MFA metadata.
func StoreCompletedIDPMFASession(mgr cookie.Manager, user *backend.User, method string) {
	if mgr == nil || user == nil {
		return
	}

	protocol := mgr.GetString(definitions.SessionKeyProtocol, "")
	if protocol == "" {
		protocol = mgr.GetString(definitions.SessionKeyIdPFlowType, definitions.ProtoIDP)
	}

	rememberMeTTL := mgr.GetInt(definitions.SessionKeyRememberTTL, 0)

	flow.CleanupMFAState(mgr)

	mgr.Set(definitions.SessionKeyAccount, user.Name)
	mgr.Set(definitions.SessionKeyUniqueUserID, user.Id)
	mgr.Set(definitions.SessionKeyDisplayName, user.DisplayName)
	mgr.Set(definitions.SessionKeySubject, user.Id)
	mgr.Set(definitions.SessionKeyProtocol, protocol)
	mgr.Set(definitions.SessionKeyMFACompleted, true)

	if method != "" {
		mgr.Set(definitions.SessionKeyMFAMethod, method)
	}

	if rememberMeTTL > 0 {
		mgr.SetMaxAge(rememberMeTTL)
		mgr.Delete(definitions.SessionKeyRememberTTL)
	}
}

// QueueCompletedIDPMFAPostAction dispatches a dedicated Lua post action after a
// successful second factor so Lua actions can observe the final MFA state.
func QueueCompletedIDPMFAPostAction(ctx *gin.Context, deps AuthDeps, user *backend.User) bool {
	if ctx == nil || ctx.Request == nil || user == nil || deps.Cfg == nil || !deps.Cfg.HaveLuaActions() {
		return false
	}

	auth := newCompletedIDPMFAPostActionAuth(ctx, deps, user)
	if auth == nil {
		return false
	}

	requestCopy := completedIDPMFAPostActionRequest(auth, user)

	go auth.RunLuaPostAction(PostActionArgs{
		Context:       auth.Runtime.Context,
		HTTPRequest:   util.DetachedHTTPRequest(ctx.Request, nil),
		ParentSpan:    trace.SpanContextFromContext(ctx.Request.Context()),
		StatusMessage: "OK",
		Request:       requestCopy,
	})

	return true
}

func newCompletedIDPMFAPostActionAuth(ctx *gin.Context, deps AuthDeps, user *backend.User) *AuthState {
	authRaw := NewAuthStateFromContextWithDeps(ctx, deps)
	auth, ok := authRaw.(*AuthState)
	if !ok || auth == nil {
		return nil
	}

	service := ctx.GetString(definitions.CtxServiceKey)
	if service == "" {
		service = definitions.ServIdP
	}

	protocolName, oidcClientID, samlEntityID := idpPostActionSessionState(ctx)

	auth.Request.Service = service
	auth.Request.ClientIP = ctx.ClientIP()
	auth.Request.UserAgent = ctx.Request.UserAgent()
	auth.Request.XClientPort = detachedRequestPort(ctx.Request.RemoteAddr)
	auth.Runtime.GUID = ctx.GetString(definitions.CtxGUIDKey)
	auth.Runtime.Context = idpPostActionLuaContext(ctx)
	auth.Runtime.Authenticated = true
	auth.Runtime.UserFound = true
	auth.SetStatusCodes(service)
	auth.SetUsername(user.Name)
	auth.SetAccount(user.Name)
	auth.SetOIDCCID(oidcClientID)
	auth.SetSAMLEntityID(samlEntityID)
	auth.SetProtocol(config.NewProtocol(protocolName))
	auth.ReplaceAllAttributes(user.Attributes)

	return auth
}

func idpPostActionSessionState(ctx *gin.Context) (protocolName, oidcClientID, samlEntityID string) {
	protocolName = definitions.ProtoIDP

	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		return protocolName, "", ""
	}

	protocolName = mgr.GetString(definitions.SessionKeyProtocol, "")
	if protocolName == "" {
		protocolName = mgr.GetString(definitions.SessionKeyIdPFlowType, definitions.ProtoIDP)
	}

	return protocolName,
		mgr.GetString(definitions.SessionKeyIdPClientID, ""),
		mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, "")
}

func completedIDPMFAPostActionRequest(auth *AuthState, user *backend.User) lualib.CommonRequest {
	requestCopy := lualib.CommonRequest{}
	auth.FillCommonRequest(&requestCopy)
	requestCopy.UserFound = true
	requestCopy.Authenticated = true
	requestCopy.HTTPStatus = http.StatusOK

	if requestCopy.Account == "" {
		requestCopy.Account = user.Name
	}

	if requestCopy.UniqueUserID == "" {
		requestCopy.UniqueUserID = user.Id
	}

	if requestCopy.DisplayName == "" {
		requestCopy.DisplayName = user.DisplayName
	}

	if len(requestCopy.Password) > 0 {
		requestCopy.Password = bytes.Clone(requestCopy.Password)
	}

	return requestCopy
}

func idpPostActionLuaContext(ctx *gin.Context) *lualib.Context {
	if ctx == nil {
		return lualib.NewContext()
	}

	luaCtx, ok := ctx.Get(definitions.CtxDataExchangeKey)
	contextData, _ := luaCtx.(*lualib.Context)
	if !ok || contextData == nil {
		return lualib.NewContext()
	}

	return contextData
}

func detachedRequestPort(remoteAddr string) string {
	_, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return ""
	}

	return port
}

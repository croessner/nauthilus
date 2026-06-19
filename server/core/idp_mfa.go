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
	"context"
	"net"
	"net/http"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"
)

// StoreCompletedIDPMFASession replaces the temporary MFA state with the final
// authenticated IDP session while preserving the completed MFA metadata.
func StoreCompletedIDPMFASession(mgr cookie.Manager, user *backend.User, method string) {
	if mgr == nil || user == nil {
		return
	}

	finalUser := ResolveCompletedIDPMFAUser(mgr, user)

	protocol := mgr.GetString(definitions.SessionKeyProtocol, "")
	if protocol == "" {
		protocol = mgr.GetString(definitions.SessionKeyIDPFlowType, definitions.ProtoIDP)
	}

	rememberMeTTL := mgr.GetInt(definitions.SessionKeyRememberTTL, 0)

	flow.CleanupMFAState(mgr)

	mgr.Set(definitions.SessionKeyAccount, finalUser.Name)
	mgr.Set(definitions.SessionKeyUniqueUserID, finalUser.ID)
	mgr.Set(definitions.SessionKeyDisplayName, finalUser.DisplayName)
	mgr.Set(definitions.SessionKeySubject, finalUser.ID)
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

// ResolveCompletedIDPMFAUser returns the user identity that should be visible
// after MFA, falling back to the factor user when no pending target identity exists.
func ResolveCompletedIDPMFAUser(mgr cookie.Manager, user *backend.User) *backend.User {
	if user == nil {
		return nil
	}

	finalUser := completedIDPMFAUser(mgr, user)

	return &finalUser
}

// StorePendingIDPMFAIdentity records the canonical user identity that should
// become the final IDP session after a successful MFA verification.
func StorePendingIDPMFAIdentity(mgr cookie.Manager, user *backend.User) {
	storePendingIDPMFAUser(
		mgr,
		user,
		definitions.SessionKeyMFAAccount,
		definitions.SessionKeyUniqueUserID,
		definitions.SessionKeyMFADisplayName,
	)
}

// StorePendingIDPMFAFactor records the account whose second factor must be verified.
func StorePendingIDPMFAFactor(mgr cookie.Manager, user *backend.User) {
	storePendingIDPMFAUser(
		mgr,
		user,
		definitions.SessionKeyMFAFactorAccount,
		definitions.SessionKeyMFAFactorUniqueUserID,
		definitions.SessionKeyMFAFactorDisplayName,
	)
}

// storePendingIDPMFAUser writes a user identity into the provided MFA session keys.
func storePendingIDPMFAUser(mgr cookie.Manager, user *backend.User, accountKey string, uniqueUserIDKey string, displayNameKey string) {
	if mgr == nil || user == nil {
		return
	}

	if user.Name != "" {
		mgr.Set(accountKey, user.Name)
	}

	if user.ID != "" {
		mgr.Set(uniqueUserIDKey, user.ID)
	}

	if user.DisplayName != "" {
		mgr.Set(displayNameKey, user.DisplayName)
	}
}

// completedIDPMFAUser resolves the final session identity from MFA session
// state while keeping the submitted login available for factor verification.
func completedIDPMFAUser(mgr cookie.Manager, user *backend.User) backend.User {
	finalUser := *user

	if account := mgr.GetString(definitions.SessionKeyMFAAccount, ""); account != "" {
		finalUser.Name = account
	}

	if uniqueUserID := mgr.GetString(definitions.SessionKeyUniqueUserID, ""); uniqueUserID != "" {
		finalUser.ID = uniqueUserID
	}

	if displayName := mgr.GetString(definitions.SessionKeyMFADisplayName, ""); displayName != "" {
		finalUser.DisplayName = displayName
	}

	return finalUser
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
		HTTPRequest:   util.DetachedHTTPRequest(context.TODO(), ctx.Request),
		ParentSpan:    trace.SpanContextFromContext(ctx.Request.Context()),
		StatusMessage: authStatusMessageOK,
		Request:       requestCopy,
	})

	return true
}

// LogIDPMFAuthResult writes a Notice log for the result of a second-factor verification
// during the IDP login flow. It is intentionally not gated behind debug modules.
func LogIDPMFAuthResult(ctx *gin.Context, deps AuthDeps, username, method, statusMessage string, successful bool) {
	if ctx == nil || ctx.Request == nil || deps.Cfg == nil || deps.Logger == nil {
		return
	}

	authStateRaw := NewAuthStateFromContextWithDeps(ctx, deps)

	auth, ok := authStateRaw.(*AuthState)
	if !ok || auth == nil {
		return
	}

	auth.WithClientInfo(ctx)
	auth.WithLocalInfo(ctx)
	auth.WithUserAgent(ctx)
	auth.WithXSSL(ctx)

	auth.Runtime.GUID = ctx.GetString(definitions.CtxGUIDKey)

	auth.Request.Service = ctx.GetString(definitions.CtxServiceKey)
	if auth.Request.Service == "" {
		auth.Request.Service = definitions.ServIDP
	}

	protocolName, oidcClientID, samlEntityID := idpPostActionSessionState(ctx)
	auth.SetProtocol(config.NewProtocol(protocolName))
	auth.SetOIDCCID(oidcClientID)
	auth.SetSAMLEntityID(samlEntityID)
	auth.SetUsername(username)

	logMethod := normalizeMFAMethodForLogging(method)
	auth.SetMethod(logMethod)
	auth.Runtime.Authenticated = successful
	auth.Runtime.UserFound = username != ""

	if statusMessage != "" {
		auth.Runtime.StatusMessage = statusMessage
	}

	status := "fail"
	message := "Second-factor authentication has failed"

	if successful {
		status = environmentDecisionOK
		message = "Second-factor authentication was successful"
	}

	keyvals := getLogSlice()

	defer putLogSlice(keyvals)

	keyvals = auth.fillLogLineTemplate(keyvals, status, ctx.Request.URL.Path)
	keyvals = append(
		keyvals,
		definitions.LogKeyMsg, message,
		definitions.SessionKeyMFAMethod, logMethod,
	)

	_ = level.Notice(auth.Logger()).WithContext(ctx).Log(keyvals...)
}

func normalizeMFAMethodForLogging(method string) string {
	switch method {
	case "recovery":
		return definitions.MFAMethodRecoveryCodes
	case "":
		return method
	default:
		return method
	}
}

// newCompletedIDPMFAPostActionAuth builds the authenticated request state used
// by Lua post-actions after a successful IDP MFA challenge.
func newCompletedIDPMFAPostActionAuth(ctx *gin.Context, deps AuthDeps, user *backend.User) *AuthState {
	authRaw := NewAuthStateFromContextWithDeps(ctx, deps)

	auth, ok := authRaw.(*AuthState)
	if !ok || auth == nil {
		return nil
	}

	service := ctx.GetString(definitions.CtxServiceKey)
	if service == "" {
		service = definitions.ServIDP
	}

	protocolName, oidcClientID, samlEntityID := idpPostActionSessionState(ctx)

	auth.Request.Service = service
	auth.WithClientInfo(ctx)
	auth.WithUserAgent(ctx)

	if auth.Request.XClientPort == "" {
		auth.Request.XClientPort = detachedRequestPort(ctx.Request.RemoteAddr)
	}

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
	auth.SetResolvedGroups(user.Groups, user.GroupDistinguishedNames)

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
		protocolName = mgr.GetString(definitions.SessionKeyIDPFlowType, definitions.ProtoIDP)
	}

	return protocolName,
		mgr.GetString(definitions.SessionKeyIDPClientID, ""),
		mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, "")
}

func completedIDPMFAPostActionRequest(auth *AuthState, user *backend.User) lualib.CommonRequest {
	requestCopy := lualib.CommonRequest{}
	auth.FillCommonRequest(&requestCopy)
	requestCopy.UserFound = true
	requestCopy.Authenticated = true
	requestCopy.EnvironmentStageExpected = false
	requestCopy.SubjectStageExpected = false
	requestCopy.HTTPStatus = http.StatusOK

	if requestCopy.Account == "" {
		requestCopy.Account = user.Name
	}

	if requestCopy.UniqueUserID == "" {
		requestCopy.UniqueUserID = user.ID
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

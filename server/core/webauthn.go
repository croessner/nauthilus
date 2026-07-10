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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	jsoniter "github.com/json-iterator/go"
	"go.opentelemetry.io/otel/attribute"
)

var webAuthn *webauthn.WebAuthn

// jsonIter is a package-level variable for jsoniter with standard configuration
var jsonIter = jsoniter.ConfigFastest

// webAuthnLoginIdentity carries the account identity used for login assertions.
type webAuthnLoginIdentity struct {
	userName     string
	uniqueUserID string
	displayName  string
}

type webAuthnLoginSession struct {
	identity    webAuthnLoginIdentity
	sessionData *webauthn.SessionData
}

type webAuthnLoginAssertion struct {
	credential          *webauthn.Credential
	existingCredentials []mfa.PersistentCredential
}

type webAuthnSignCountAudit struct {
	oldSignCount       *uint32
	credentialIDHash   string
	aaguid             string
	isResidentKey      bool
	signCountZero      bool
	signCountMonotonic bool
	newSignCount       uint32
}

type webAuthnTraceSpan interface {
	SetAttributes(...attribute.KeyValue)
}

// sessionWebAuthnLoginIdentity resolves the MFA factor identity for WebAuthn login.
func sessionWebAuthnLoginIdentity(mgr cookie.Manager) webAuthnLoginIdentity {
	if mgr == nil {
		return webAuthnLoginIdentity{}
	}

	identity := webAuthnLoginIdentity{
		userName:     mgr.GetString(definitions.SessionKeyMFAFactorAccount, ""),
		uniqueUserID: mgr.GetString(definitions.SessionKeyMFAFactorUniqueUserID, ""),
		displayName:  mgr.GetString(definitions.SessionKeyMFAFactorDisplayName, ""),
	}

	if identity.userName == "" {
		identity.userName = mgr.GetString(definitions.SessionKeyUsername, "")
	}

	if identity.uniqueUserID == "" {
		identity.uniqueUserID = mgr.GetString(definitions.SessionKeyUniqueUserID, "")
	}

	return identity
}

// webAuthnBackendLookupUsername selects the identity used for backend credential operations.
func webAuthnBackendLookupUsername(userName string, uniqueUserID string) string {
	if userName != "" {
		return userName
	}

	return uniqueUserID
}

// webAuthnProtocolName resolves the request protocol for WebAuthn backend lookups.
func (a *AuthState) webAuthnProtocolName(mgr cookie.Manager) string {
	protocolName := ""
	if a.Request.HTTPClientContext != nil {
		protocolName = a.Request.HTTPClientContext.Query("protocol")
	}

	if protocolName == "" && mgr != nil {
		protocolName = mgr.GetString(definitions.SessionKeyProtocol, "")
	}

	if protocolName == "" {
		protocolName = definitions.ProtoIDP
	}

	return protocolName
}

// ensureWebAuthnRequestProtocol sets the request protocol when it is missing.
func (a *AuthState) ensureWebAuthnRequestProtocol(protocolName string) {
	if a.Request.Protocol == nil {
		a.Request.Protocol = config.NewProtocol(protocolName)

		return
	}

	if a.Request.Protocol.Get() == "" {
		a.Request.Protocol.Set(protocolName)
	}
}

// sessionWebAuthnCredentials loads credentials from the backend stored in the session.
func (a *AuthState) sessionWebAuthnCredentials(mgr cookie.Manager) (definitions.Backend, []mfa.PersistentCredential, error) {
	if mgr == nil {
		return definitions.BackendUnknown, nil, nil
	}

	cookieValue := mgr.GetUint8(definitions.SessionKeyUserBackend, 0)
	if cookieValue == 0 {
		return definitions.BackendUnknown, nil, nil
	}

	passDB := definitions.Backend(cookieValue)
	backendName := mgr.GetString(definitions.SessionKeyUserBackendName, "")

	backendMgr := a.GetBackendManager(passDB, backendName)
	if backendMgr == nil {
		return passDB, nil, nil
	}

	credentials, err := backendMgr.GetWebAuthnCredentials(a)

	return passDB, credentials, err
}

// configuredWebAuthnCredentials searches configured backends for WebAuthn credentials.
func (a *AuthState) configuredWebAuthnCredentials() ([]mfa.PersistentCredential, error) {
	for _, backendType := range a.Cfg().GetServer().GetBackends() {
		mgr := a.GetBackendManager(backendType.Get(), backendType.GetName())
		if mgr == nil {
			continue
		}

		credentials, err := mgr.GetWebAuthnCredentials(a)
		if err != nil {
			if stderrors.Is(err, errors.ErrLDAPConfig) {
				continue
			}

			return nil, err
		}

		if len(credentials) > 0 {
			return credentials, nil
		}
	}

	return nil, nil
}

// webAuthnUserFromCredentials builds a backend user when credentials were found.
func webAuthnUserFromCredentials(userName string, uniqueUserID string, displayName string, credentials []mfa.PersistentCredential) *backend.User {
	if len(credentials) == 0 {
		return nil
	}

	return &backend.User{
		ID:          uniqueUserID,
		Name:        userName,
		DisplayName: displayName,
		Credentials: credentials,
	}
}

// getUser retrieves a User object with all their current credentials. This is Database depended. Which backend was used
// can be gotten from the session cookie.
func (a *AuthState) getUser(userName string, uniqueUserID string, displayName string) (*backend.User, error) {
	mgr := cookie.GetManager(a.Request.HTTPClientContext)
	a.ensureWebAuthnRequestProtocol(a.webAuthnProtocolName(mgr))

	a.Request.Username = webAuthnBackendLookupUsername(userName, uniqueUserID)

	a.restoreRemoteBackendRefFromSession(mgr)

	util.DebugModuleWithCfg(
		a.Ctx(),
		a.Cfg(),
		a.Logger(),
		definitions.DbgWebAuthn,
		definitions.LogKeyGUID, a.Runtime.GUID,
		definitions.LogKeyMsg, "WebAuthn getUser input",
		"account", userName,
		"unique_user_id", uniqueUserID,
		"display_name", displayName,
		"request_username", a.Request.Username,
	)

	passDB, credentials, err := a.sessionWebAuthnCredentials(mgr)
	if err != nil {
		return nil, err
	}

	if passDB == definitions.BackendUnknown || len(credentials) == 0 {
		credentials, err = a.configuredWebAuthnCredentials()
		if err != nil {
			return nil, err
		}
	}

	user := webAuthnUserFromCredentials(userName, uniqueUserID, displayName, credentials)
	if user == nil {
		if user, err = backend.GetWebAuthnFromRedis(a.Ctx(), a.Cfg(), a.Logger(), a.Redis(), uniqueUserID); err != nil {
			return nil, err
		}
	}

	return user, nil
}

// putUser stores the initial WebAuthn user cache entry for registration.
func (a *AuthState) putUser(user *backend.User) error {
	return backend.SaveWebAuthnToRedis(a.Ctx(), a.Logger(), a.Cfg(), a.Redis(), user, a.Cfg().GetServer().Redis.PosCacheTTL)
}

// updateUser refreshes the WebAuthn user cache after credential changes.
func (a *AuthState) updateUser(user *backend.User) error {
	return backend.SaveWebAuthnToRedis(a.Ctx(), a.Logger(), a.Cfg(), a.Redis(), user, a.Cfg().GetServer().Redis.PosCacheTTL)
}

func isWebAuthnRegistrationAuthenticated(mgr cookie.Manager) bool {
	authResult := mgr.GetUint8(definitions.SessionKeyAuthResult, 0)
	if authResult != 0 {
		return definitions.AuthResult(authResult) == definitions.AuthResultOK
	}

	account := mgr.GetString(definitions.SessionKeyAccount, "")

	return account != ""
}

func resolveWebAuthnDisplayName(mgr cookie.Manager, userName string) (string, bool) {
	displayName := mgr.GetString(definitions.SessionKeyDisplayName, "")
	if displayName != "" {
		return displayName, false
	}

	if userName == "" {
		return "", false
	}

	mgr.Set(definitions.SessionKeyDisplayName, userName)

	return userName, true
}

func webAuthnRegistrationUserName(mgr cookie.Manager) string {
	if mgr == nil {
		return ""
	}

	userName := mgr.GetString(definitions.SessionKeyAccount, "")
	if userName != "" {
		return userName
	}

	return mgr.GetString(definitions.SessionKeyUsername, "")
}

func restoreWebAuthnRegistrationIdentityFromFlow(ctx *gin.Context, deps AuthDeps, mgr cookie.Manager) {
	if ctx == nil || deps.Cfg == nil || deps.Redis == nil || deps.Redis.GetWriteHandle() == nil || mgr == nil {
		return
	}

	flowID := webAuthnRegistrationFlowIDFromSession(mgr)
	if flowID == "" {
		return
	}

	store := flow.NewRedisStore(deps.Redis.GetWriteHandle(), deps.Cfg.GetServer().GetRedis().GetPrefix()+"idp:flow", 0)

	state, err := store.Load(ctx.Request.Context(), flowID)
	if err != nil {
		return
	}

	restoreWebAuthnRegistrationIdentityFromState(mgr, state)
}

func webAuthnRegistrationFlowIDFromSession(mgr cookie.Manager) string {
	if mgr == nil {
		return ""
	}

	flowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if flowID != "" {
		return flowID
	}

	if mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
		return flow.NewRequireMFAFlowID(mgr.GetString(definitions.SessionKeyRequireMFAParentFlowID, ""))
	}

	return ""
}

func restoreWebAuthnRegistrationIdentityFromState(mgr cookie.Manager, state *flow.State) {
	if mgr == nil || state == nil || state.Type != flow.FlowTypeRequireMFA || state.Metadata == nil {
		return
	}

	if mgr.GetString(definitions.SessionKeyAccount, "") == "" {
		if account := state.Metadata[flow.FlowMetadataAccount]; account != "" {
			mgr.Set(definitions.SessionKeyAccount, account)
		}
	}

	if mgr.GetString(definitions.SessionKeyUniqueUserID, "") == "" {
		if uniqueUserID := state.Metadata[flow.FlowMetadataUniqueUserID]; uniqueUserID != "" {
			mgr.Set(definitions.SessionKeyUniqueUserID, uniqueUserID)
		}
	}

	if mgr.GetString(definitions.SessionKeyDisplayName, "") == "" {
		if displayName := state.Metadata[flow.FlowMetadataDisplayName]; displayName != "" {
			mgr.Set(definitions.SessionKeyDisplayName, displayName)
		}
	}
}

type webAuthnRegistrationIdentity struct {
	mgr          cookie.Manager
	userName     string
	uniqueUserID string
	displayName  string
}

// registrationIdentityFromSession validates the session and resolves the WebAuthn registration identity.
func registrationIdentityFromSession(ctx *gin.Context, deps AuthDeps, mgr cookie.Manager) (webAuthnRegistrationIdentity, bool) {
	identity := webAuthnRegistrationIdentity{mgr: mgr}

	if mgr == nil {
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "fail").Inc()
		ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())
		SessionCleaner(ctx)

		return identity, false
	}

	if !isWebAuthnRegistrationAuthenticated(mgr) {
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "fail").Inc()
		ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())
		SessionCleaner(ctx)

		return identity, false
	}

	restoreWebAuthnRegistrationIdentityFromFlow(ctx, deps, mgr)

	identity.userName = webAuthnRegistrationUserName(mgr)
	if identity.userName == "" {
		ctx.JSON(http.StatusInternalServerError, errors.ErrNotLoggedIn.Error())
		SessionCleaner(ctx)

		return identity, false
	}

	identity.uniqueUserID = mgr.GetString(definitions.SessionKeyUniqueUserID, "")
	if identity.uniqueUserID == "" {
		ctx.JSON(http.StatusInternalServerError, errors.ErrNotLoggedIn.Error())
		SessionCleaner(ctx)

		return identity, false
	}

	identity.displayName, _ = resolveWebAuthnDisplayName(mgr, identity.userName)
	if identity.displayName == "" {
		ctx.JSON(http.StatusBadRequest, errors.ErrNoDisplayName.Error())
		SessionCleaner(ctx)

		return identity, false
	}

	return identity, true
}

// registrationUser returns an existing WebAuthn user or creates the initial backend cache entry.
func registrationUser(ctx *gin.Context, deps AuthDeps, identity webAuthnRegistrationIdentity) (*backend.User, bool) {
	auth := NewAuthStateFromContextWithDeps(ctx, deps)
	auth.WithDefaults(ctx)

	authState := auth.(*AuthState)

	user, err := authState.getUser(identity.userName, identity.uniqueUserID, identity.displayName)
	if err == nil {
		return user, true
	}

	user = backend.NewUser(identity.userName, identity.displayName, identity.uniqueUserID)
	if err = authState.putUser(user); err != nil {
		level.Error(deps.Logger).Log(
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Failed to persist initial WebAuthn user cache",
			definitions.LogKeyError, err,
		)
		ctx.JSON(http.StatusInternalServerError, err.Error())

		return nil, false
	}

	return user, true
}

// beginRegistrationOptions starts the WebAuthn registration ceremony.
func beginRegistrationOptions(deps AuthDeps, user *backend.User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return webAuthn.BeginRegistration(
		user,
		webauthn.WithAuthenticatorSelection(buildAuthenticatorSelection(deps.Cfg)),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
}

// saveRegistrationSession stores WebAuthn session data in the encrypted session cookie.
func saveRegistrationSession(ctx *gin.Context, deps AuthDeps, mgr cookie.Manager, sessionData *webauthn.SessionData) bool {
	sessionDataJSON, err := jsonIter.Marshal(*sessionData)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, err)
		SessionCleaner(ctx)

		return false
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		deps.Cfg,
		deps.Logger,
		definitions.DbgWebAuthn,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "session data begin",
		"content", fmt.Sprintf("%#v", sessionData),
	)

	mgr.Set(definitions.SessionKeyRegistration, sessionDataJSON)

	if err = mgr.Save(ctx); err != nil {
		ctx.JSON(http.StatusInternalServerError, err)
		SessionCleaner(ctx)

		return false
	}

	return true
}

// loginBeginUser resolves the optional session-bound WebAuthn user for login.
func loginBeginUser(ctx *gin.Context, deps AuthDeps, mgr cookie.Manager) (*backend.User, bool) {
	if mgr == nil {
		return nil, true
	}

	identity := sessionWebAuthnLoginIdentity(mgr)
	if identity.userName == "" {
		return nil, true
	}

	auth := NewAuthStateFromContextWithDeps(ctx, deps)

	user, err := auth.(*AuthState).getUser(identity.userName, identity.uniqueUserID, identity.displayName)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, err.Error())

		return nil, false
	}

	if user == nil || len(user.Credentials) == 0 {
		ctx.JSON(http.StatusBadRequest, "No WebAuthn credentials found")

		return nil, false
	}

	return user, true
}

// beginWebAuthnLoginOptions starts either discoverable or user-bound login.
func beginWebAuthnLoginOptions(user *backend.User) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	if user == nil {
		return webAuthn.BeginDiscoverableLogin()
	}

	return webAuthn.BeginLogin(user)
}

// saveLoginSession stores WebAuthn login session data when a session manager exists.
func saveLoginSession(ctx *gin.Context, mgr cookie.Manager, sessionData *webauthn.SessionData) bool {
	sessionDataJSON, err := jsonIter.Marshal(*sessionData)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, err.Error())

		return false
	}

	if mgr == nil {
		return true
	}

	mgr.Set(definitions.SessionKeyRegistration, sessionDataJSON)

	if err = mgr.Save(ctx); err != nil {
		ctx.JSON(http.StatusInternalServerError, err.Error())

		return false
	}

	return true
}

// finishRegistrationIdentityFromSession validates the finish-registration session identity.
func finishRegistrationIdentityFromSession(ctx *gin.Context, deps AuthDeps, mgr cookie.Manager) (webAuthnRegistrationIdentity, bool) {
	identity := webAuthnRegistrationIdentity{mgr: mgr}
	if mgr == nil {
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "fail").Inc()
		ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())

		return identity, false
	}

	if !isWebAuthnRegistrationAuthenticated(mgr) {
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "fail").Inc()
		ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())

		return identity, false
	}

	restoreWebAuthnRegistrationIdentityFromFlow(ctx, deps, mgr)

	identity.userName = webAuthnRegistrationUserName(mgr)
	if identity.userName == "" {
		ctx.JSON(http.StatusBadRequest, errors.ErrNotLoggedIn.Error())

		return identity, false
	}

	identity.uniqueUserID = mgr.GetString(definitions.SessionKeyUniqueUserID, "")
	if identity.uniqueUserID == "" {
		ctx.JSON(http.StatusInternalServerError, errors.ErrNotLoggedIn.Error())
		SessionCleaner(ctx)

		return identity, false
	}

	var updated bool

	identity.displayName, updated = resolveWebAuthnDisplayName(mgr, identity.userName)
	if identity.displayName == "" {
		ctx.JSON(http.StatusBadRequest, errors.ErrNoDisplayName.Error())
		SessionCleaner(ctx)

		return identity, false
	}

	if updated {
		if err := mgr.Save(ctx); err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			SessionCleaner(ctx)

			return identity, false
		}
	}

	return identity, true
}

// registrationSessionDataFromCookie loads registration session data from the session cookie.
func registrationSessionDataFromCookie(ctx *gin.Context, mgr cookie.Manager) (*webauthn.SessionData, bool) {
	cookieValue := mgr.GetBytes(definitions.SessionKeyRegistration, nil)
	if cookieValue == nil {
		SessionCleaner(ctx)
		ctx.JSON(http.StatusBadRequest, errors.ErrWebAuthnSessionData)

		return nil, false
	}

	sessionData := &webauthn.SessionData{}
	if err := jsonIter.Unmarshal(cookieValue, sessionData); err != nil {
		SessionCleaner(ctx)
		ctx.JSON(http.StatusInternalServerError, err.Error())

		return nil, false
	}

	return sessionData, true
}

// parseRegistrationFinishResponse parses the registration finish payload and optional device name.
func parseRegistrationFinishResponse(ctx *gin.Context) (string, *protocol.ParsedCredentialCreationData, bool) {
	requestBody, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())

		return "", nil, false
	}

	var finishRequest struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}

	var response *protocol.ParsedCredentialCreationData
	if err = jsonIter.Unmarshal(requestBody, &finishRequest); err == nil && len(finishRequest.Credential) > 0 {
		response, err = protocol.ParseCredentialCreationResponseBody(bytes.NewReader(finishRequest.Credential))

		return strings.TrimSpace(finishRequest.Name), response, registrationParseOK(ctx, err)
	}

	response, err = protocol.ParseCredentialCreationResponseBody(bytes.NewReader(requestBody))

	return "", response, registrationParseOK(ctx, err)
}

// registrationParseOK writes the protocol parse error response when parsing failed.
func registrationParseOK(ctx *gin.Context, err error) bool {
	if err == nil {
		return true
	}

	ctx.JSON(http.StatusBadRequest, fmt.Sprintf("%+v", util.ProtoErrToFields(err)))

	return false
}

// persistRegistrationCredential stores the new credential in the configured backend.
func persistRegistrationCredential(ctx *gin.Context, deps AuthDeps, authState *AuthState, credential *webauthn.Credential, deviceName string) bool {
	persistentCredential := &mfa.PersistentCredential{
		Credential: *credential,
		Name:       deviceName,
	}

	if err := authState.SaveWebAuthnCredential(persistentCredential); err != nil {
		level.Error(deps.Logger).Log(
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Failed to persist WebAuthn credential to backend",
			definitions.LogKeyError, err,
		)
		ctx.JSON(http.StatusInternalServerError, err.Error())

		return false
	}

	return true
}

// updateRegistrationUserCache refreshes the Redis WebAuthn user cache when needed.
func updateRegistrationUserCache(ctx *gin.Context, deps AuthDeps, authState *AuthState, user *backend.User) bool {
	if !shouldPersistWebAuthnCache(authState) {
		return true
	}

	if err := authState.updateUser(user); err != nil {
		level.Error(deps.Logger).Log(
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Failed to update WebAuthn user cache",
			definitions.LogKeyError, err,
		)
		ctx.JSON(http.StatusInternalServerError, err.Error())

		return false
	}

	return true
}

// completeRegistrationSession clears registration state and saves the session.
func completeRegistrationSession(ctx *gin.Context, mgr cookie.Manager) bool {
	mgr.Delete(definitions.SessionKeyRegistration)
	mgr.Set(definitions.SessionKeyHaveWebAuthn, true)

	if mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
		flow.RemoveRequireMFAPendingMethod(mgr, definitions.MFAMethodWebAuthn)
	}

	if err := mgr.Save(ctx); err != nil {
		ctx.JSON(http.StatusInternalServerError, err)

		return false
	}

	return true
}

// logRegistrationFinishContext records session and identity details for registration finish.
func logRegistrationFinishContext(ctx *gin.Context, deps AuthDeps, identity webAuthnRegistrationIdentity, sessionData *webauthn.SessionData) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		deps.Cfg,
		deps.Logger,
		definitions.DbgWebAuthn,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "session data finish",
		"content", fmt.Sprintf("%#v", sessionData),
	)

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		deps.Cfg,
		deps.Logger,
		definitions.DbgWebAuthn,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "WebAuthn registration finish",
		"account", identity.userName,
		"unique_user_id", identity.uniqueUserID,
		"display_name", identity.displayName,
	)
}

// BeginRegistration Page: '/mfa/webauthn/register/begin'
func BeginRegistration(deps AuthDeps) gin.HandlerFunc {
	tracer := monittrace.New("nauthilus/core/webauthn")

	return func(ctx *gin.Context) {
		spanCtx, sp := tracer.Start(ctx.Request.Context(), "webauthn.begin_registration")
		requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

		defer requestScope.Restore()
		defer sp.End()

		mgr := cookie.GetManager(ctx)

		identity, ok := registrationIdentityFromSession(ctx, deps, mgr)
		if !ok {
			return
		}

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			deps.Cfg,
			deps.Logger,
			definitions.DbgWebAuthn,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "WebAuthn registration begin",
			"account", identity.userName,
			"unique_user_id", identity.uniqueUserID,
			"display_name", identity.displayName,
		)

		user, ok := registrationUser(ctx, deps, identity)
		if !ok {
			return
		}

		options, sessionData, err := beginRegistrationOptions(deps, user)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err)
			SessionCleaner(ctx)

			return
		}

		if !saveRegistrationSession(ctx, deps, mgr, sessionData) {
			return
		}

		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "success").Inc()
		ctx.JSON(http.StatusOK, options)
	}
}

// FinishRegistration Page: '/mfa/webauthn/register/finish'
func FinishRegistration(deps AuthDeps) gin.HandlerFunc {
	tracer := monittrace.New("nauthilus/core/webauthn")

	return func(ctx *gin.Context) {
		spanCtx, sp := tracer.Start(ctx.Request.Context(), "webauthn.finish_registration")
		requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

		defer requestScope.Restore()
		defer sp.End()

		finishRegistration(ctx, deps)
	}
}

// finishRegistration validates and persists a WebAuthn registration response.
func finishRegistration(ctx *gin.Context, deps AuthDeps) {
	mgr := cookie.GetManager(ctx)

	identity, ok := finishRegistrationIdentityFromSession(ctx, deps, mgr)
	if !ok {
		return
	}

	sessionData, ok := registrationSessionDataFromCookie(ctx, mgr)
	if !ok {
		return
	}

	logRegistrationFinishContext(ctx, deps, identity, sessionData)
	authState := newRegistrationAuthState(ctx, deps)

	user, err := authState.getUser(identity.userName, identity.uniqueUserID, identity.displayName)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())

		return
	}

	deviceName, response, ok := parseRegistrationFinishResponse(ctx)
	if !ok {
		return
	}

	credential, err := webAuthn.CreateCredential(user, *sessionData, response)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, fmt.Sprintf("%+v", util.ProtoErrToFields(err)))

		return
	}

	user.AddCredential(*credential, deviceName)

	if !persistRegistrationCredential(ctx, deps, authState, credential, deviceName) {
		return
	}

	if !updateRegistrationUserCache(ctx, deps, authState, user) {
		return
	}

	authState.PurgeCacheFor(identity.userName)

	if !completeRegistrationSession(ctx, mgr) {
		return
	}

	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "success").Inc()
	ctx.JSON(http.StatusOK, "Registration success")
}

// newRegistrationAuthState builds the AuthState used to persist WebAuthn registration data.
func newRegistrationAuthState(ctx *gin.Context, deps AuthDeps) *AuthState {
	auth := NewAuthStateFromContextWithDeps(ctx, deps)
	auth.WithDefaults(ctx)

	return auth.(*AuthState)
}

// LoginWebAuthnBegin Page: '/login/webauthn/begin'
func LoginWebAuthnBegin(deps AuthDeps) gin.HandlerFunc {
	tracer := monittrace.New("nauthilus/core/webauthn")

	return func(ctx *gin.Context) {
		spanCtx, sp := tracer.Start(ctx.Request.Context(), "webauthn.login_begin")
		requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

		defer requestScope.Restore()
		defer sp.End()

		mgr := cookie.GetManager(ctx)

		user, ok := loginBeginUser(ctx, deps, mgr)
		if !ok {
			return
		}

		options, sessionData, err := beginWebAuthnLoginOptions(user)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())

			return
		}

		if !saveLoginSession(ctx, mgr, sessionData) {
			return
		}

		ctx.JSON(http.StatusOK, options)
	}
}

// CompleteLoginWebAuthn validates a WebAuthn login assertion and stores the
// completed MFA session. The caller is responsible for choosing the transport
// response so browser flows can resume the surrounding IDP flow correctly.
func CompleteLoginWebAuthn(ctx *gin.Context, deps AuthDeps) (*backend.User, bool) {
	tracer := monittrace.New("nauthilus/core/webauthn")

	spanCtx, sp := tracer.Start(ctx.Request.Context(), "webauthn.login_finish")

	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	mgr := cookie.GetManager(ctx)

	loginSession, ok := loadWebAuthnLoginSession(ctx, mgr)
	if !ok {
		return nil, false
	}

	if loginSession.sessionData == nil {
		rejectMissingWebAuthnLoginSession(ctx, deps, loginSession.identity.userName)

		return nil, false
	}

	auth := NewAuthStateFromContextWithDeps(ctx, deps)
	authState := auth.(*AuthState)

	user, ok := resolveWebAuthnLoginUser(ctx, deps, authState, loginSession.identity)
	if !ok {
		return nil, false
	}

	if user == nil {
		LogIDPMFAuthResult(ctx, deps, loginSession.identity.userName, definitions.MFAMethodWebAuthn, "User not found", false)
		ctx.JSON(http.StatusBadRequest, "User not found")

		return nil, false
	}

	assertion, ok := finishWebAuthnLoginAssertion(ctx, deps, authState, user, loginSession.sessionData, sp)
	if !ok {
		return nil, false
	}

	if !persistWebAuthnLoginCredentialUpdate(ctx, deps, authState, user, assertion) {
		return nil, false
	}

	user, ok = completeWebAuthnLogin(ctx, deps, authState, mgr, user)
	if !ok {
		return nil, false
	}

	QueueCompletedIDPMFAPostAction(ctx, authState.deps, user)

	return user, true
}

// LoginWebAuthnFinish Page: '/login/webauthn/finish'
func LoginWebAuthnFinish(deps AuthDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if _, ok := CompleteLoginWebAuthn(ctx, deps); !ok {
			return
		}

		ctx.JSON(http.StatusOK, gin.H{asyncJobFieldStatus: "ok"})
	}
}

// loadWebAuthnLoginSession reads the WebAuthn login identity and ceremony data from the session.
func loadWebAuthnLoginSession(ctx *gin.Context, mgr cookie.Manager) (webAuthnLoginSession, bool) {
	var loginSession webAuthnLoginSession
	if mgr == nil {
		return loginSession, true
	}

	loginSession.identity = sessionWebAuthnLoginIdentity(mgr)

	cookieValue := mgr.GetBytes(definitions.SessionKeyRegistration, nil)
	if cookieValue == nil {
		return loginSession, true
	}

	loginSession.sessionData = &webauthn.SessionData{}
	if err := jsonIter.Unmarshal(cookieValue, loginSession.sessionData); err != nil {
		ctx.JSON(http.StatusInternalServerError, err.Error())

		return loginSession, false
	}

	return loginSession, true
}

// rejectMissingWebAuthnLoginSession reports missing WebAuthn ceremony data as a failed MFA attempt.
func rejectMissingWebAuthnLoginSession(ctx *gin.Context, deps AuthDeps, username string) {
	LogIDPMFAuthResult(ctx, deps, username, definitions.MFAMethodWebAuthn, errors.ErrWebAuthnSessionData.Error(), false)
	ctx.JSON(http.StatusBadRequest, errors.ErrWebAuthnSessionData.Error())
}

// resolveWebAuthnLoginUser resolves the user for session-bound or passwordless WebAuthn login.
func resolveWebAuthnLoginUser(ctx *gin.Context, deps AuthDeps, authState *AuthState, identity webAuthnLoginIdentity) (*backend.User, bool) {
	if identity.userName != "" {
		user, err := authState.getUser(identity.userName, identity.uniqueUserID, identity.displayName)
		if err != nil {
			LogIDPMFAuthResult(ctx, deps, identity.userName, definitions.MFAMethodWebAuthn, err.Error(), false)
			ctx.JSON(http.StatusInternalServerError, err.Error())

			return nil, false
		}

		return user, true
	}

	return resolvePasswordlessWebAuthnLoginUser(ctx, deps, authState)
}

// resolvePasswordlessWebAuthnLoginUser identifies the user by handle from the assertion response.
func resolvePasswordlessWebAuthnLoginUser(ctx *gin.Context, deps AuthDeps, authState *AuthState) (*backend.User, bool) {
	bodyBytes, _ := io.ReadAll(ctx.Request.Body)
	ctx.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(bytes.NewBuffer(bodyBytes))
	if err != nil {
		LogIDPMFAuthResult(ctx, deps, "", definitions.MFAMethodWebAuthn, "Invalid response body", false)
		ctx.JSON(http.StatusBadRequest, "Invalid response body")

		return nil, false
	}

	userHandle := string(parsedResponse.Response.UserHandle)
	if userHandle == "" {
		LogIDPMFAuthResult(ctx, deps, "", definitions.MFAMethodWebAuthn, "No user handle provided", false)
		ctx.JSON(http.StatusBadRequest, "No user handle provided")

		return nil, false
	}

	user, err := backend.GetWebAuthnFromRedis(ctx.Request.Context(), authState.Cfg(), authState.Logger(), authState.Redis(), userHandle)
	if err != nil {
		LogIDPMFAuthResult(ctx, deps, userHandle, definitions.MFAMethodWebAuthn, "User not found", false)
		ctx.JSON(http.StatusBadRequest, "User not found")

		return nil, false
	}

	return user, true
}

// finishWebAuthnLoginAssertion validates the assertion and rejects sign-count rollbacks.
func finishWebAuthnLoginAssertion(
	ctx *gin.Context,
	deps AuthDeps,
	authState *AuthState,
	user *backend.User,
	sessionData *webauthn.SessionData,
	sp webAuthnTraceSpan,
) (webAuthnLoginAssertion, bool) {
	credential, err := webAuthn.FinishLogin(user, *sessionData, ctx.Request)
	if err != nil {
		LogIDPMFAuthResult(ctx, deps, user.Name, definitions.MFAMethodWebAuthn, err.Error(), false)
		ctx.JSON(http.StatusBadRequest, err.Error())

		return webAuthnLoginAssertion{}, false
	}

	assertion := webAuthnLoginAssertion{
		credential:          credential,
		existingCredentials: user.Credentials,
	}
	audit := newWebAuthnSignCountAudit(assertion.existingCredentials, credential, sessionData)
	recordWebAuthnSignCountAudit(sp, authState, credential, audit)

	if audit.oldSignCount != nil && !audit.signCountMonotonic {
		LogIDPMFAuthResult(ctx, deps, user.Name, definitions.MFAMethodWebAuthn, "WebAuthn sign count rollback detected", false)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("login", "webauthn", "fail").Inc()
		ctx.JSON(http.StatusBadRequest, "WebAuthn sign count rollback detected")

		return webAuthnLoginAssertion{}, false
	}

	return assertion, true
}

// newWebAuthnSignCountAudit derives observability fields from a completed assertion.
func newWebAuthnSignCountAudit(
	existingCredentials []mfa.PersistentCredential,
	credential *webauthn.Credential,
	sessionData *webauthn.SessionData,
) webAuthnSignCountAudit {
	newSignCount := credential.Authenticator.SignCount
	oldSignCount := findWebAuthnOldSignCount(existingCredentials, credential.ID)

	signCountMonotonic := true
	if oldSignCount != nil {
		signCountMonotonic = isWebAuthnSignCountMonotonic(*oldSignCount, newSignCount)
	}

	return webAuthnSignCountAudit{
		oldSignCount:       oldSignCount,
		credentialIDHash:   hashCredentialID(credential.ID),
		aaguid:             hex.EncodeToString(credential.Authenticator.AAGUID),
		isResidentKey:      len(sessionData.AllowedCredentialIDs) == 0,
		signCountZero:      newSignCount == 0,
		signCountMonotonic: signCountMonotonic,
		newSignCount:       newSignCount,
	}
}

// findWebAuthnOldSignCount returns the stored counter for the asserted credential.
func findWebAuthnOldSignCount(credentials []mfa.PersistentCredential, credentialID []byte) *uint32 {
	for i := range credentials {
		if bytes.Equal(credentials[i].ID, credentialID) {
			oldValue := credentials[i].Authenticator.SignCount

			return &oldValue
		}
	}

	return nil
}

// recordWebAuthnSignCountAudit emits trace, debug, and anomaly logs for assertion counters.
func recordWebAuthnSignCountAudit(
	sp webAuthnTraceSpan,
	authState *AuthState,
	credential *webauthn.Credential,
	audit webAuthnSignCountAudit,
) {
	setWebAuthnSignCountTrace(sp, credential, audit)
	logWebAuthnSignCountDebug(authState, credential, audit)

	if audit.signCountZero || (audit.oldSignCount != nil && !audit.signCountMonotonic) {
		level.Warn(authState.Logger()).Log(webAuthnSignCountLogFields(authState, credential, audit, "WebAuthn sign count anomaly")...)
	}
}

// setWebAuthnSignCountTrace stores assertion counter details on the active span.
func setWebAuthnSignCountTrace(sp webAuthnTraceSpan, credential *webauthn.Credential, audit webAuthnSignCountAudit) {
	sp.SetAttributes(
		attribute.Int64("webauthn.sign_count", int64(audit.newSignCount)),
		attribute.Bool("webauthn.flags.up", credential.Flags.UserPresent),
		attribute.Bool("webauthn.flags.uv", credential.Flags.UserVerified),
		attribute.Bool("webauthn.is_resident_key", audit.isResidentKey),
		attribute.String("webauthn.credential_id_hash", audit.credentialIDHash),
		attribute.String("webauthn.aaguid", audit.aaguid),
		attribute.Bool("webauthn.sign_count_zero", audit.signCountZero),
	)

	if audit.oldSignCount != nil {
		sp.SetAttributes(
			attribute.Int64("webauthn.sign_count_previous", int64(*audit.oldSignCount)),
			attribute.Bool("webauthn.sign_count_monotonic", audit.signCountMonotonic),
		)
	}
}

// logWebAuthnSignCountDebug writes assertion counter details to the WebAuthn debug module.
func logWebAuthnSignCountDebug(authState *AuthState, credential *webauthn.Credential, audit webAuthnSignCountAudit) {
	util.DebugModuleWithCfg(
		authState.Ctx(),
		authState.Cfg(),
		authState.Logger(),
		definitions.DbgWebAuthn,
		webAuthnSignCountLogFields(authState, credential, audit, "WebAuthn login assertion details")...,
	)
}

// webAuthnSignCountLogFields builds the shared log fields for WebAuthn counter observability.
func webAuthnSignCountLogFields(authState *AuthState, credential *webauthn.Credential, audit webAuthnSignCountAudit, message string) []any {
	keyvals := []any{
		definitions.LogKeyGUID, authState.Runtime.GUID,
		definitions.LogKeyMsg, message,
		webAuthnDebugSignCount, audit.newSignCount,
		webAuthnDebugFlagsUP, credential.Flags.UserPresent,
		webAuthnDebugFlagsUV, credential.Flags.UserVerified,
		webAuthnDebugCredentialIDHash, audit.credentialIDHash,
		webAuthnDebugIsResidentKey, audit.isResidentKey,
		webAuthnDebugAAGUID, audit.aaguid,
		webAuthnDebugSignCountZero, audit.signCountZero,
	}

	if audit.oldSignCount != nil {
		keyvals = append(
			keyvals,
			"sign_count_previous", *audit.oldSignCount,
			"sign_count_monotonic", audit.signCountMonotonic,
		)
	}

	return keyvals
}

// persistWebAuthnLoginCredentialUpdate stores last-used and counter changes after login.
func persistWebAuthnLoginCredentialUpdate(
	ctx *gin.Context,
	deps AuthDeps,
	authState *AuthState,
	user *backend.User,
	assertion webAuthnLoginAssertion,
) bool {
	oldCredential, newPersistentCredential := updateWebAuthnCredentialAfterLogin(
		assertion.existingCredentials,
		assertion.credential,
		time.Now(),
	)
	if oldCredential == nil {
		return true
	}

	if err := persistWebAuthnLoginUpdate(authState, user, oldCredential, newPersistentCredential); err != nil {
		LogIDPMFAuthResult(ctx, deps, user.Name, definitions.MFAMethodWebAuthn, err.Error(), false)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("login", "webauthn", "fail").Inc()

		_ = level.Error(authState.Logger()).Log(
			definitions.LogKeyGUID, authState.Runtime.GUID,
			definitions.LogKeyMsg, "Failed to persist WebAuthn login credential update",
			definitions.LogKeyError, err,
		)
		ctx.JSON(http.StatusInternalServerError, err.Error())

		return false
	}

	return true
}

// completeWebAuthnLogin records success, validates delayed login state, and stores the completed session.
func completeWebAuthnLogin(
	ctx *gin.Context,
	deps AuthDeps,
	authState *AuthState,
	mgr cookie.Manager,
	user *backend.User,
) (*backend.User, bool) {
	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("login", "webauthn", "success").Inc()
	LogIDPMFAuthResult(ctx, deps, user.Name, definitions.MFAMethodWebAuthn, "", true)

	secure := util.ShouldSetSecureCookie()
	ctx.SetCookie("last_mfa_method", "webauthn", 365*24*60*60, "/", "", secure, true)

	if shouldPersistWebAuthnCache(authState) {
		_ = backend.SaveWebAuthnToRedis(ctx.Request.Context(), authState.Logger(), authState.Cfg(), authState.Redis(), user, authState.Cfg().GetServer().GetTimeouts().GetRedisWrite())
	}

	if mgr == nil {
		return user, true
	}

	if !acceptDelayedWebAuthnLogin(ctx, authState, mgr, user) {
		return nil, false
	}

	finalUser := ResolveCompletedIDPMFAUser(mgr, user)
	StoreCompletedIDPMFASession(mgr, user, "webauthn")

	if err := mgr.Save(ctx); err != nil {
		ctx.JSON(http.StatusInternalServerError, err.Error())

		return nil, false
	}

	return finalUser, true
}

// acceptDelayedWebAuthnLogin fails closed when the original password step failed.
func acceptDelayedWebAuthnLogin(ctx *gin.Context, authState *AuthState, mgr cookie.Manager, user *backend.User) bool {
	submittedUsername := mgr.GetString(definitions.SessionKeyUsername, user.Name)
	if isMFAAuthResultValid(mgr, submittedUsername) {
		return true
	}

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "fail").Inc()

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		authState.Cfg(),
		authState.Logger(),
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Delayed-response login rejected after MFA",
		"mfa_method", "webauthn",
		"username", submittedUsername,
	)

	mgr.Delete(definitions.SessionKeyAccount)
	mgr.Delete(definitions.SessionKeyDisplayName)
	mgr.Delete(definitions.SessionKeySubject)
	flow.CleanupMFAState(mgr)
	mgr.Set(definitions.SessionKeyLoginError, "Invalid login or password")

	if saveErr := mgr.Save(ctx); saveErr != nil {
		ctx.JSON(http.StatusInternalServerError, saveErr.Error())

		return false
	}

	ctx.JSON(http.StatusUnauthorized, gin.H{"redirect": webAuthnDelayedFailureRedirect(ctx, mgr)})

	return false
}

// webAuthnDelayedFailureRedirect returns the browser target for delayed-login rejection.
func webAuthnDelayedFailureRedirect(ctx *gin.Context, mgr cookie.Manager) string {
	redirectTarget := "/login"
	if mgr.GetString(definitions.SessionKeyOIDCGrantType, "") != definitions.OIDCFlowDeviceCode {
		return redirectTarget
	}

	redirectTarget = "/oidc/device/verify/failed"
	if languageTag := ctx.Param("languageTag"); languageTag != "" {
		redirectTarget += "/" + languageTag
	}

	return redirectTarget
}

// buildAuthenticatorSelection constructs the protocol.AuthenticatorSelection from the
// WebAuthn configuration. It maps string-based config values to their protocol equivalents.
func buildAuthenticatorSelection(cfg config.File) protocol.AuthenticatorSelection {
	webAuthnCfg := cfg.GetIDP().WebAuthn

	authSelect := protocol.AuthenticatorSelection{
		UserVerification: mapUserVerification(webAuthnCfg.GetUserVerification()),
		ResidentKey:      mapResidentKey(webAuthnCfg.GetResidentKey()),
	}

	switch webAuthnCfg.GetAuthenticatorAttachment() {
	case "":
		// Do not select an authenticator attachment. Let the browser make the decision.
	case "platform":
		authSelect.AuthenticatorAttachment = protocol.Platform
	case "cross-platform":
		authSelect.AuthenticatorAttachment = protocol.CrossPlatform
	}

	if authSelect.ResidentKey == protocol.ResidentKeyRequirementRequired {
		authSelect.RequireResidentKey = protocol.ResidentKeyRequired()
	} else {
		authSelect.RequireResidentKey = protocol.ResidentKeyNotRequired()
	}

	return authSelect
}

// mapResidentKey converts a string resident key requirement to the protocol type.
func mapResidentKey(value string) protocol.ResidentKeyRequirement {
	switch value {
	case "preferred":
		return protocol.ResidentKeyRequirementPreferred
	case authInputReasonRequired:
		return protocol.ResidentKeyRequirementRequired
	default:
		return protocol.ResidentKeyRequirementDiscouraged
	}
}

// mapUserVerification converts a string user verification requirement to the protocol type.
func mapUserVerification(value string) protocol.UserVerificationRequirement {
	switch value {
	case "discouraged":
		return protocol.VerificationDiscouraged
	case authInputReasonRequired:
		return protocol.VerificationRequired
	default:
		return protocol.VerificationPreferred
	}
}

func updateWebAuthnCredentialAfterLogin(credentials []mfa.PersistentCredential, credential *webauthn.Credential, now time.Time) (*mfa.PersistentCredential, *mfa.PersistentCredential) {
	if credential == nil {
		return nil, nil
	}

	var oldCredential *mfa.PersistentCredential

	for i := range credentials {
		if bytes.Equal(credentials[i].ID, credential.ID) {
			oldCredential = &credentials[i]
			break
		}
	}

	if oldCredential == nil {
		return nil, nil
	}

	if !isWebAuthnSignCountMonotonic(oldCredential.Authenticator.SignCount, credential.Authenticator.SignCount) {
		return nil, nil
	}

	newCredential := &mfa.PersistentCredential{
		Credential: *credential,
		Name:       oldCredential.Name,
		LastUsed:   now,
	}

	return oldCredential, newCredential
}

func isWebAuthnSignCountMonotonic(oldSignCount uint32, newSignCount uint32) bool {
	if newSignCount == 0 && oldSignCount == 0 {
		return true
	}

	return newSignCount > oldSignCount
}

type webAuthnCredentialUpdater interface {
	UpdateWebAuthnCredential(oldCredential *mfa.PersistentCredential, newCredential *mfa.PersistentCredential) error
}

func persistWebAuthnLoginUpdate(
	updater webAuthnCredentialUpdater,
	user *backend.User,
	oldCredential *mfa.PersistentCredential,
	newCredential *mfa.PersistentCredential,
) error {
	if updater == nil || user == nil || oldCredential == nil || newCredential == nil {
		return nil
	}

	if err := updater.UpdateWebAuthnCredential(oldCredential, newCredential); err != nil {
		return err
	}

	for index, credential := range user.Credentials {
		if bytes.Equal(credential.ID, newCredential.ID) {
			user.Credentials[index] = *newCredential

			break
		}
	}

	return nil
}

func shouldPersistWebAuthnCache(auth *AuthState) bool {
	if auth == nil {
		return true
	}

	if !auth.Runtime.RemoteBackendRef.IsZero() {
		return false
	}

	mgr := cookie.GetManager(auth.Request.HTTPClientContext)
	if mgr == nil {
		return true
	}

	return definitions.Backend(mgr.GetUint8(definitions.SessionKeyUserBackend, 0)) != definitions.BackendRemote
}

func hashCredentialID(credentialID []byte) string {
	if len(credentialID) == 0 {
		return ""
	}

	sum := sha256.Sum256(credentialID)

	return hex.EncodeToString(sum[:])
}

// isMFAAuthResultValid checks if the authentication result stored in the cookie indicates
// successful first-factor authentication. This is used to implement "Fall B Punkt 1" from
// the IDP login flow specification: if the initial credentials were wrong (delayed response),
// the user must be rejected after successful MFA verification.
//
// Default-deny: returns false if mgr is nil, auth_result is missing/corrupt, HMAC
// verification fails, or auth_result is anything other than AuthResultOK.
func isMFAAuthResultValid(mgr cookie.Manager, username string) bool {
	if mgr != nil {
		switch flow.AuthOutcome(mgr.GetString(definitions.SessionKeyIDPAuthOutcome, "")) {
		case flow.AuthOutcomeFailLatched:
			return false
		case flow.AuthOutcomeOK:
			return true
		}
	}

	result, ok := cookie.VerifyAuthResult(mgr, username)
	if !ok {
		return false
	}

	return result == definitions.AuthResultOK
}

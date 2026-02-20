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

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/model/mfa"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	jsoniter "github.com/json-iterator/go"
	"go.opentelemetry.io/otel/attribute"
)

var webAuthn *webauthn.WebAuthn

// jsonIter is a package-level variable for jsoniter with standard configuration
var jsonIter = jsoniter.ConfigFastest

// getUser retrieves a User object with all their current credentials. This is Database depended. Which backend was used
// can be gotten from the session cookie.
func (a *AuthState) getUser(userName string, uniqueUserID string, displayName string) (*backend.User, error) {
	var (
		passDB      definitions.Backend
		backendName string
		err         error
		user        *backend.User
		credentials []mfa.PersistentCredential
	)

	mgr := cookie.GetManager(a.Request.HTTPClientContext)
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

	if a.Request.Protocol == nil {
		a.Request.Protocol = config.NewProtocol(protocolName)
	} else if a.Request.Protocol.Get() == "" {
		a.Request.Protocol.Set(protocolName)
	}

	if uniqueUserID != "" {
		a.Request.Username = uniqueUserID
	} else if userName != "" {
		a.Request.Username = userName
	}

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

	// We expect the same Database for credentials that was used for authenticating a user!
	if mgr != nil {
		cookieValue := mgr.GetUint8(definitions.SessionKeyUserBackend, 0)

		if cookieValue != 0 {
			passDB = definitions.Backend(cookieValue)
			backendName = mgr.GetString(definitions.SessionKeyUserBackendName, "")

			if backendMgr := a.GetBackendManager(passDB, backendName); backendMgr != nil {
				credentials, err = backendMgr.GetWebAuthnCredentials(a)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	// No cookie (default login page), search all configured databases.
	// Skip backends that do not support this protocol.
	if passDB == definitions.BackendUnknown || len(credentials) == 0 {
		for _, backendType := range a.Cfg().GetServer().GetBackends() {
			if mgr := a.GetBackendManager(backendType.Get(), backendType.GetName()); mgr != nil {
				credentials, err = mgr.GetWebAuthnCredentials(a)
				if err != nil {
					if stderrors.Is(err, errors.ErrLDAPConfig) {
						continue
					}

					return nil, err
				}

				if len(credentials) > 0 {
					break
				}
			}
		}
	}

	if len(credentials) > 0 {
		user = &backend.User{
			Id:          uniqueUserID,
			Name:        userName,
			DisplayName: displayName,
			Credentials: credentials,
		}
	}

	// Registering a device
	if user == nil {
		if user, err = backend.GetWebAuthnFromRedis(a.Ctx(), a.Cfg(), a.Logger(), a.Redis(), uniqueUserID); err != nil {
			return nil, err
		}
	}

	return user, nil
}

func (a *AuthState) putUser(user *backend.User) {
	backend.SaveWebAuthnToRedis(a.Ctx(), a.Logger(), a.Cfg(), a.Redis(), user, a.Cfg().GetServer().Redis.PosCacheTTL)
}

func (a *AuthState) updateUser(user *backend.User) {
	backend.SaveWebAuthnToRedis(a.Ctx(), a.Logger(), a.Cfg(), a.Redis(), user, a.Cfg().GetServer().Redis.PosCacheTTL)
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

// BeginRegistration Page: '/mfa/webauthn/register/begin'
func BeginRegistration(deps AuthDeps) gin.HandlerFunc {
	tracer := monittrace.New("nauthilus/core/webauthn")

	return func(ctx *gin.Context) {
		_, sp := tracer.Start(ctx.Request.Context(), "webauthn.begin_registration")
		defer sp.End()

		var (
			userName     string
			displayName  string
			uniqueUserID string
		)

		mgr := cookie.GetManager(ctx)
		if mgr == nil {
			stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "fail").Inc()
			ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())
			SessionCleaner(ctx)

			return
		}

		if !isWebAuthnRegistrationAuthenticated(mgr) {
			stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "fail").Inc()
			ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())
			SessionCleaner(ctx)

			return
		}

		// We use the account name as username!
		userName = mgr.GetString(definitions.SessionKeyAccount, "")
		if userName == "" {
			ctx.JSON(http.StatusInternalServerError, errors.ErrNotLoggedIn.Error())
			SessionCleaner(ctx)

			return
		}

		uniqueUserID = mgr.GetString(definitions.SessionKeyUniqueUserID, "")
		if uniqueUserID == "" {
			ctx.JSON(http.StatusInternalServerError, errors.ErrNotLoggedIn.Error())
			SessionCleaner(ctx)

			return
		}

		displayName, _ = resolveWebAuthnDisplayName(mgr, userName)
		if displayName == "" {
			ctx.JSON(http.StatusBadRequest, errors.ErrNoDisplayName.Error())
			SessionCleaner(ctx)

			return
		}

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			deps.Cfg,
			deps.Logger,
			definitions.DbgWebAuthn,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "WebAuthn registration begin",
			"account", userName,
			"unique_user_id", uniqueUserID,
			"display_name", displayName,
		)

		auth := NewAuthStateFromContextWithDeps(ctx, deps)
		auth.WithDefaults(ctx)

		user, err := auth.(*AuthState).getUser(userName, uniqueUserID, displayName)
		if err != nil {
			// If it does not exist, create a new one
			user = backend.NewUser(userName, displayName, uniqueUserID)

			auth.(*AuthState).putUser(user)
		}

		authSelect := protocol.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyNotRequired(),
			UserVerification:   protocol.VerificationPreferred,
		}

		conveyancePref := protocol.PreferNoAttestation

		options, sessionData, err := webAuthn.BeginRegistration(
			user,
			webauthn.WithAuthenticatorSelection(authSelect),
			webauthn.WithConveyancePreference(conveyancePref),
		)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err)
			SessionCleaner(ctx)

			return
		}

		// Serialize session data and save it to the encrypted session cookie.
		sessionDataJSON, err := jsonIter.Marshal(*sessionData)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err)
			SessionCleaner(ctx)

			return
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

			return
		}

		// Return the options generated
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "success").Inc()
		ctx.JSON(http.StatusOK, options)
	}
}

// FinishRegistration Page: '/mfa/webauthn/register/finish'
func FinishRegistration(deps AuthDeps) gin.HandlerFunc {
	tracer := monittrace.New("nauthilus/core/webauthn")

	return func(ctx *gin.Context) {
		_, sp := tracer.Start(ctx.Request.Context(), "webauthn.finish_registration")
		defer sp.End()

		var (
			userName     string
			uniqueUserID string
			displayName  string
			deviceName   string
			sessionData  *webauthn.SessionData
		)

		mgr := cookie.GetManager(ctx)
		if mgr == nil {
			stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "fail").Inc()
			ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())

			return
		}

		if !isWebAuthnRegistrationAuthenticated(mgr) {
			stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "fail").Inc()
			ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())

			return
		}

		userName = mgr.GetString(definitions.SessionKeyAccount, "")
		if userName == "" {
			userName = mgr.GetString(definitions.SessionKeyUsername, "")
		}

		if userName == "" {
			ctx.JSON(http.StatusBadRequest, errors.ErrNotLoggedIn.Error())

			return
		}

		uniqueUserID = mgr.GetString(definitions.SessionKeyUniqueUserID, "")
		if uniqueUserID == "" {
			ctx.JSON(http.StatusInternalServerError, errors.ErrNotLoggedIn.Error())
			SessionCleaner(ctx)

			return
		}

		displayName, updated := resolveWebAuthnDisplayName(mgr, userName)
		if displayName == "" {
			ctx.JSON(http.StatusBadRequest, errors.ErrNoDisplayName.Error())
			SessionCleaner(ctx)

			return
		}

		if updated {
			if err := mgr.Save(ctx); err != nil {
				ctx.JSON(http.StatusInternalServerError, err.Error())
				SessionCleaner(ctx)

				return
			}
		}

		cookieValue := mgr.GetBytes(definitions.SessionKeyRegistration, nil)
		if cookieValue != nil {
			sessionData = &webauthn.SessionData{}

			if err := jsonIter.Unmarshal(cookieValue, sessionData); err != nil {
				SessionCleaner(ctx)
				ctx.JSON(http.StatusInternalServerError, err.Error())

				return
			}
		}

		if sessionData == nil {
			SessionCleaner(ctx)
			ctx.JSON(http.StatusBadRequest, errors.ErrWebAuthnSessionData)

			return
		}

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
			"account", userName,
			"unique_user_id", uniqueUserID,
			"display_name", displayName,
		)

		auth := NewAuthStateFromContextWithDeps(ctx, deps)
		auth.WithDefaults(ctx)

		user, err := auth.(*AuthState).getUser(userName, uniqueUserID, displayName)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, err.Error())

			return
		}

		requestBody, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, err.Error())

			return
		}

		var finishRequest struct {
			Name       string          `json:"name"`
			Credential json.RawMessage `json:"credential"`
		}

		var response *protocol.ParsedCredentialCreationData
		if err = jsonIter.Unmarshal(requestBody, &finishRequest); err == nil && len(finishRequest.Credential) > 0 {
			deviceName = strings.TrimSpace(finishRequest.Name)
			response, err = protocol.ParseCredentialCreationResponseBody(bytes.NewReader(finishRequest.Credential))
		} else {
			response, err = protocol.ParseCredentialCreationResponseBody(bytes.NewReader(requestBody))
		}
		if err != nil {
			ctx.JSON(http.StatusBadRequest, fmt.Sprintf("%+v", util.ProtoErrToFields(err)))

			return
		}

		credential, err := webAuthn.CreateCredential(user, *sessionData, response)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, fmt.Sprintf("%+v", util.ProtoErrToFields(err)))

			return
		}

		user.AddCredential(*credential, deviceName)

		persistentCredential := &mfa.PersistentCredential{
			Credential: *credential,
			Name:       deviceName,
		}
		if err = auth.(*AuthState).SaveWebAuthnCredential(persistentCredential); err != nil {
			level.Error(deps.Logger).Log(
				definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
				definitions.LogKeyMsg, "Failed to persist WebAuthn credential to backend",
				definitions.LogKeyError, err,
			)
			ctx.JSON(http.StatusInternalServerError, err.Error())

			return
		}

		auth.(*AuthState).updateUser(user)

		auth.PurgeCacheFor(userName)

		mgr.Delete(definitions.SessionKeyRegistration)

		if err = mgr.Save(ctx); err != nil {
			ctx.JSON(http.StatusInternalServerError, err)

			return
		}

		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "success").Inc()
		ctx.JSON(http.StatusOK, "Registration success")
	}
}

// LoginWebAuthnBegin Page: '/login/webauthn/begin'
func LoginWebAuthnBegin(deps AuthDeps) gin.HandlerFunc {
	tracer := monittrace.New("nauthilus/core/webauthn")

	return func(ctx *gin.Context) {
		_, sp := tracer.Start(ctx.Request.Context(), "webauthn.login_begin")
		defer sp.End()

		var (
			userName     string
			uniqueUserID string
		)

		mgr := cookie.GetManager(ctx)

		if mgr != nil {
			userName = mgr.GetString(definitions.SessionKeyUsername, "")
			uniqueUserID = mgr.GetString(definitions.SessionKeyUniqueUserID, "")
		}

		var user *backend.User

		if userName != "" {
			auth := NewAuthStateFromContextWithDeps(ctx, deps)
			var err error

			user, err = auth.(*AuthState).getUser(userName, uniqueUserID, "")
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, err.Error())

				return
			}

			if user == nil || len(user.Credentials) == 0 {
				ctx.JSON(http.StatusBadRequest, "No WebAuthn credentials found")

				return
			}
		}

		var (
			options     *protocol.CredentialAssertion
			sessionData *webauthn.SessionData
			err         error
		)

		if user == nil {
			options, sessionData, err = webAuthn.BeginDiscoverableLogin()
		} else {
			options, sessionData, err = webAuthn.BeginLogin(user)
		}

		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())

			return
		}

		sessionDataJSON, err := jsonIter.Marshal(*sessionData)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())

			return
		}

		if mgr != nil {
			mgr.Set(definitions.SessionKeyRegistration, sessionDataJSON)

			if err = mgr.Save(ctx); err != nil {
				ctx.JSON(http.StatusInternalServerError, err.Error())

				return
			}
		}

		ctx.JSON(http.StatusOK, options)
	}
}

// LoginWebAuthnFinish Page: '/login/webauthn/finish'
func LoginWebAuthnFinish(deps AuthDeps) gin.HandlerFunc {
	tracer := monittrace.New("nauthilus/core/webauthn")

	return func(ctx *gin.Context) {
		_, sp := tracer.Start(ctx.Request.Context(), "webauthn.login_finish")
		defer sp.End()

		var (
			userName     string
			uniqueUserID string
			sessionData  *webauthn.SessionData
		)

		mgr := cookie.GetManager(ctx)

		if mgr != nil {
			userName = mgr.GetString(definitions.SessionKeyUsername, "")
			uniqueUserID = mgr.GetString(definitions.SessionKeyUniqueUserID, "")

			cookieValue := mgr.GetBytes(definitions.SessionKeyRegistration, nil)
			if cookieValue != nil {
				sessionData = &webauthn.SessionData{}

				if err := jsonIter.Unmarshal(cookieValue, sessionData); err != nil {
					ctx.JSON(http.StatusInternalServerError, err.Error())

					return
				}
			}
		}

		if sessionData == nil {
			ctx.JSON(http.StatusBadRequest, errors.ErrWebAuthnSessionData.Error())

			return
		}

		auth := NewAuthStateFromContextWithDeps(ctx, deps)
		authState := auth.(*AuthState)
		var user *backend.User

		if userName != "" {
			var err error
			user, err = auth.(*AuthState).getUser(userName, uniqueUserID, "")
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, err.Error())

				return
			}
		} else {
			// Passwordless path: Identify user by handle from response
			bodyBytes, _ := io.ReadAll(ctx.Request.Body)
			ctx.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			parsedResponse, err := protocol.ParseCredentialRequestResponseBody(bytes.NewBuffer(bodyBytes))
			if err != nil {
				ctx.JSON(http.StatusBadRequest, "Invalid response body")

				return
			}

			userHandle := string(parsedResponse.Response.UserHandle)
			if userHandle == "" {
				ctx.JSON(http.StatusBadRequest, "No user handle provided")

				return
			}

			user, err = backend.GetWebAuthnFromRedis(ctx.Request.Context(), auth.(*AuthState).Cfg(), auth.(*AuthState).Logger(), auth.(*AuthState).Redis(), userHandle)
			if err != nil {
				ctx.JSON(http.StatusBadRequest, "User not found")

				return
			}
		}

		if user == nil {
			ctx.JSON(http.StatusBadRequest, "User not found")

			return
		}

		credential, err := webAuthn.FinishLogin(user, *sessionData, ctx.Request)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, err.Error())

			return
		}

		credentialIDHash := hashCredentialID(credential.ID)
		aaguid := hex.EncodeToString(credential.Authenticator.AAGUID)
		isResidentKey := len(sessionData.AllowedCredentialIDs) == 0
		newSignCount := credential.Authenticator.SignCount

		// Update sign count and last used if necessary
		existingCredentials := user.Credentials
		var oldSignCount *uint32
		for i := range existingCredentials {
			if bytes.Equal(existingCredentials[i].ID, credential.ID) {
				oldValue := existingCredentials[i].Authenticator.SignCount
				oldSignCount = &oldValue

				break
			}
		}

		signCountZero := newSignCount == 0
		signCountMonotonic := true
		if oldSignCount != nil {
			oldValue := *oldSignCount
			if newSignCount <= oldValue && (newSignCount != 0 || oldValue != 0) {
				signCountMonotonic = false
			}
		}

		sp.SetAttributes(
			attribute.Int64("webauthn.sign_count", int64(newSignCount)),
			attribute.Bool("webauthn.flags.up", credential.Flags.UserPresent),
			attribute.Bool("webauthn.flags.uv", credential.Flags.UserVerified),
			attribute.Bool("webauthn.is_resident_key", isResidentKey),
			attribute.String("webauthn.credential_id_hash", credentialIDHash),
			attribute.String("webauthn.aaguid", aaguid),
			attribute.Bool("webauthn.sign_count_zero", signCountZero),
		)

		if oldSignCount != nil {
			sp.SetAttributes(
				attribute.Int64("webauthn.sign_count_previous", int64(*oldSignCount)),
				attribute.Bool("webauthn.sign_count_monotonic", signCountMonotonic),
			)
		}

		debugKeyvals := []any{
			definitions.LogKeyGUID, authState.Runtime.GUID,
			definitions.LogKeyMsg, "WebAuthn login assertion details",
			"sign_count", newSignCount,
			"flags_up", credential.Flags.UserPresent,
			"flags_uv", credential.Flags.UserVerified,
			"credential_id_hash", credentialIDHash,
			"is_resident_key", isResidentKey,
			"aaguid", aaguid,
			"sign_count_zero", signCountZero,
		}

		if oldSignCount != nil {
			debugKeyvals = append(
				debugKeyvals,
				"sign_count_previous", *oldSignCount,
				"sign_count_monotonic", signCountMonotonic,
			)
		}

		util.DebugModuleWithCfg(
			authState.Ctx(),
			authState.Cfg(),
			authState.Logger(),
			definitions.DbgWebAuthn,
			debugKeyvals...,
		)

		if signCountZero || (oldSignCount != nil && !signCountMonotonic) {
			warnKeyvals := []any{
				definitions.LogKeyGUID, authState.Runtime.GUID,
				definitions.LogKeyMsg, "WebAuthn sign count anomaly",
				"sign_count", newSignCount,
				"flags_up", credential.Flags.UserPresent,
				"flags_uv", credential.Flags.UserVerified,
				"credential_id_hash", credentialIDHash,
				"is_resident_key", isResidentKey,
				"aaguid", aaguid,
				"sign_count_zero", signCountZero,
			}

			if oldSignCount != nil {
				warnKeyvals = append(
					warnKeyvals,
					"sign_count_previous", *oldSignCount,
					"sign_count_monotonic", signCountMonotonic,
				)
			}

			level.Warn(authState.Logger()).Log(warnKeyvals...)
		}

		oldCredential, newPersistentCredential := updateWebAuthnCredentialAfterLogin(
			existingCredentials,
			credential,
			time.Now(),
		)

		if oldCredential != nil {
			// Update the credential in the backend
			_ = auth.UpdateWebAuthnCredential(oldCredential, newPersistentCredential)

			// Also update in user object for cache
			for i, c := range user.Credentials {
				if bytes.Equal(c.ID, credential.ID) {
					user.Credentials[i] = *newPersistentCredential
					break
				}
			}
		}

		// Success!
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("login", "webauthn", "success").Inc()

		// Set last MFA method cookie
		secure := util.ShouldSetSecureCookie()

		ctx.SetCookie("last_mfa_method", "webauthn", 365*24*60*60, "/", "", secure, true)

		// Persist the updated user to Redis (cache)
		_ = backend.SaveWebAuthnToRedis(ctx.Request.Context(), authState.Logger(), authState.Cfg(), authState.Redis(), user, authState.Cfg().GetServer().GetTimeouts().GetRedisWrite())

		if mgr != nil {
			// Check if the original password authentication was successful (delayed response case).
			// If the initial credentials were wrong, we must reject the login even if MFA succeeded.
			// This implements "Fall B Punkt 1" from the IdP login flow specification:
			// User is redirected back to /login/:languageTag with error message, session is reset.
			if !isMFAAuthResultValid(mgr) {
				stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "fail").Inc()

				// Store error message in session for display on login page
				mgr.Set(definitions.SessionKeyLoginError, "Invalid login or password")

				// Clear MFA-related session data but keep flow and error
				mgr.Delete(definitions.SessionKeyRegistration)
				mgr.Delete(definitions.SessionKeyUsername)
				mgr.Delete(definitions.SessionKeyAuthResult)

				if saveErr := mgr.Save(ctx); saveErr != nil {
					ctx.JSON(http.StatusInternalServerError, saveErr.Error())

					return
				}

				// Return JSON with redirect signal - JavaScript will redirect to /login
				ctx.JSON(http.StatusUnauthorized, gin.H{"redirect": "/login"})

				return
			}

			// Important: store user info for next steps
			mgr.Set(definitions.SessionKeyAccount, user.Name)
			mgr.Set(definitions.SessionKeyUniqueUserID, user.Id)
			mgr.Set(definitions.SessionKeyDisplayName, user.DisplayName)
			mgr.Set(definitions.SessionKeySubject, user.Id)
			mgr.Set(definitions.SessionKeyMFACompleted, true)
			mgr.Set(definitions.SessionKeyMFAMethod, "webauthn")

			proto := mgr.GetString(definitions.SessionKeyProtocol, definitions.ProtoIDP)
			mgr.Set(definitions.SessionKeyProtocol, proto)

			ttlVal := mgr.GetInt(definitions.SessionKeyRememberTTL, 0)

			if ttlVal > 0 {
				mgr.SetMaxAge(ttlVal)
				mgr.Delete(definitions.SessionKeyRememberTTL)
			}

			mgr.Delete(definitions.SessionKeyRegistration)
			mgr.Delete(definitions.SessionKeyUsername)
			mgr.Delete(definitions.SessionKeyAuthResult)

			if err = mgr.Save(ctx); err != nil {
				ctx.JSON(http.StatusInternalServerError, err.Error())

				return
			}
		}

		ctx.JSON(http.StatusOK, "Login success")
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

	newCredential := &mfa.PersistentCredential{
		Credential: *credential,
		Name:       oldCredential.Name,
		LastUsed:   now,
	}

	return oldCredential, newCredential
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
// the IdP login flow specification: if the initial credentials were wrong (delayed response),
// the user must be rejected after successful MFA verification.
//
// Returns false if AuthResult is AuthResultFail, true otherwise (including if no AuthResult is set).
func isMFAAuthResultValid(mgr cookie.Manager) bool {
	if mgr == nil {
		return true
	}

	authResult := mgr.GetUint8(definitions.SessionKeyAuthResult, 0)

	return definitions.AuthResult(authResult) != definitions.AuthResultFail
}

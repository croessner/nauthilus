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
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/model/mfa"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	jsoniter "github.com/json-iterator/go"
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

	session := sessions.Default(a.Request.HTTPClientContext)

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
	if cookieValue, err := util.GetSessionValue[uint8](session, definitions.CookieUserBackend); err == nil {
		passDB = definitions.Backend(cookieValue)
		backendName, _ = util.GetSessionValue[string](session, definitions.CookieUserBackendName)

		if mgr := a.GetBackendManager(passDB, backendName); mgr != nil {
			credentials, err = mgr.GetWebAuthnCredentials(a)
			if err != nil {
				return nil, err
			}
		}
	}

	// No cookie (default login page), search all configured databases.
	if passDB == definitions.BackendUnknown || len(credentials) == 0 {
		for _, backendType := range a.Cfg().GetServer().GetBackends() {
			if mgr := a.GetBackendManager(backendType.Get(), backendType.GetName()); mgr != nil {
				credentials, err = mgr.GetWebAuthnCredentials(a)
				if err != nil {
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

		session := sessions.Default(ctx)

		authResult, err := util.GetSessionValue[uint8](session, definitions.CookieAuthResult)
		if err != nil || definitions.AuthResult(authResult) != definitions.AuthResultOK {
			stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "fail").Inc()
			ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())
			SessionCleaner(ctx)

			return
		}

		// We use the account name as username!
		userName, _ = util.GetSessionValue[string](session, definitions.CookieAccount)
		if userName == "" {
			ctx.JSON(http.StatusInternalServerError, errors.ErrNotLoggedIn.Error())
			SessionCleaner(ctx)

			return
		}

		uniqueUserID, _ = util.GetSessionValue[string](session, definitions.CookieUniqueUserID)
		if uniqueUserID == "" {
			ctx.JSON(http.StatusInternalServerError, errors.ErrNotLoggedIn.Error())
			SessionCleaner(ctx)

			return
		}

		displayName, _ = util.GetSessionValue[string](session, definitions.CookieDisplayName)
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

		session.Set(definitions.CookieRegistration, sessionDataJSON)

		if err = session.Save(); err != nil {
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
			sessionData  *webauthn.SessionData
		)

		session := sessions.Default(ctx)

		authResult, err := util.GetSessionValue[uint8](session, definitions.CookieAuthResult)
		if err != nil || definitions.AuthResult(authResult) != definitions.AuthResultOK {
			stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "fail").Inc()
			ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())

			return
		}

		userName, _ = util.GetSessionValue[string](session, definitions.CookieAccount)
		if userName == "" {
			userName, _ = util.GetSessionValue[string](session, definitions.CookieUsername)
		}
		if userName == "" {
			ctx.JSON(http.StatusBadRequest, errors.ErrNotLoggedIn.Error())

			return
		}

		uniqueUserID, _ = util.GetSessionValue[string](session, definitions.CookieUniqueUserID)
		if uniqueUserID == "" {
			ctx.JSON(http.StatusInternalServerError, errors.ErrNotLoggedIn.Error())
			SessionCleaner(ctx)

			return
		}

		displayName, _ = util.GetSessionValue[string](session, definitions.CookieDisplayName)
		if displayName == "" {
			ctx.JSON(http.StatusBadRequest, errors.ErrNoDisplayName.Error())
			SessionCleaner(ctx)

			return
		}

		if cookieValue, err := util.GetSessionValue[[]byte](session, definitions.CookieRegistration); err == nil {
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

		response, err := protocol.ParseCredentialCreationResponseBody(ctx.Request.Body)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, fmt.Sprintf("%+v", util.ProtoErrToFields(err)))

			return
		}

		credential, err := webAuthn.CreateCredential(user, *sessionData, response)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, fmt.Sprintf("%+v", util.ProtoErrToFields(err)))

			return
		}

		user.AddCredential(*credential)

		persistentCredential := &mfa.PersistentCredential{
			Credential: *credential,
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

		session.Delete(definitions.CookieRegistration)
		if err = session.Save(); err != nil {
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
			userName string
		)

		session := sessions.Default(ctx)
		userName, _ = util.GetSessionValue[string](session, definitions.CookieUsername)

		var user *backend.User

		if userName != "" {
			auth := NewAuthStateFromContextWithDeps(ctx, deps)
			// For login, we don't have uniqueUserID yet if we just started the MFA flow.
			// However, getUser tries to find it.
			var err error
			user, err = auth.(*AuthState).getUser(userName, "", "")
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

		session.Set(definitions.CookieRegistration, sessionDataJSON)
		if err = session.Save(); err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())

			return
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
			userName    string
			sessionData *webauthn.SessionData
		)

		session := sessions.Default(ctx)
		userName, _ = util.GetSessionValue[string](session, definitions.CookieUsername)

		if cookieValue, err := util.GetSessionValue[[]byte](session, definitions.CookieRegistration); err == nil {
			sessionData = &webauthn.SessionData{}
			if err := jsonIter.Unmarshal(cookieValue, sessionData); err != nil {
				ctx.JSON(http.StatusInternalServerError, err.Error())

				return
			}
		}

		if sessionData == nil {
			ctx.JSON(http.StatusBadRequest, errors.ErrWebAuthnSessionData.Error())

			return
		}

		auth := NewAuthStateFromContextWithDeps(ctx, deps)
		var user *backend.User

		if userName != "" {
			var err error
			user, err = auth.(*AuthState).getUser(userName, "", "")
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

		// Update sign count and last used if necessary
		existingCredentials, err := auth.GetWebAuthnCredentials()
		if err == nil {
			var oldCredential *mfa.PersistentCredential
			for _, cred := range existingCredentials {
				if bytes.Equal(cred.ID, credential.ID) {
					oldCredential = &cred
					break
				}
			}

			if oldCredential != nil {
				newPersistentCredential := &mfa.PersistentCredential{
					Credential: *credential,
					LastUsed:   time.Now(),
				}
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
		}

		// Success!
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("login", "webauthn", "success").Inc()

		// Set last MFA method cookie
		ctx.SetCookie("last_mfa_method", "webauthn", 365*24*60*60, "/", "", true, true)

		// Persist the updated user to Redis (cache)
		authState := auth.(*AuthState)
		_ = backend.SaveWebAuthnToRedis(ctx.Request.Context(), authState.Logger(), authState.Cfg(), authState.Redis(), user, authState.Cfg().GetServer().GetTimeouts().GetRedisWrite())

		// Set AuthResult to OK if it was Fail (delayed response)
		if authResult, err := util.GetSessionValue[uint8](session, definitions.CookieAuthResult); err == nil {
			if definitions.AuthResult(authResult) == definitions.AuthResultFail {
				session.Set(definitions.CookieAuthResult, uint8(definitions.AuthResultOK))
			}
		}

		// Important: store user info for next steps
		session.Set(definitions.CookieAccount, user.Name)
		session.Set(definitions.CookieUniqueUserID, user.Id)
		session.Set(definitions.CookieDisplayName, user.DisplayName)
		session.Set(definitions.CookieSubject, user.Id)

		proto, err := util.GetSessionValue[string](session, definitions.CookieProtocol)
		if err != nil {
			proto = definitions.ProtoIDP
		}

		session.Set(definitions.CookieProtocol, proto)

		if ttlVal, err := util.GetSessionValue[int](session, definitions.CookieRememberTTL); err == nil {
			session.Options(sessions.Options{
				MaxAge: ttlVal,
				Path:   "/",
			})
			session.Delete(definitions.CookieRememberTTL)
		}

		session.Delete(definitions.CookieRegistration)
		session.Delete(definitions.CookieUsername)
		session.Delete(definitions.CookieAuthResult)

		if err = session.Save(); err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())

			return
		}

		ctx.JSON(http.StatusOK, "Login success")
	}
}

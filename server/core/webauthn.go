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

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
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
		assertOk    bool
		err         error
		user        *backend.User
		credentials []webauthn.Credential
	)

	_ = userName
	_ = displayName

	session := sessions.Default(a.Request.HTTPClientContext)

	// We expect the same Database for credentials that was used for authenticating a user!
	if cookieValue := session.Get(definitions.CookieUserBackend); cookieValue != nil {
		if passDB, assertOk = cookieValue.(definitions.Backend); assertOk {
			if cookieName := session.Get(definitions.CookieUserBackendName); cookieName != nil {
				backendName, _ = cookieName.(string)
			}

			if mgr := a.GetBackendManager(passDB, backendName); mgr != nil {
				credentials, err = mgr.GetWebAuthnCredentials(a)
				if err != nil {
					return nil, err
				}
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

// BeginRegistration Page: '/2fa/v1/webauthn/register/begin'
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

		cookieValue := session.Get(definitions.CookieAuthResult)
		if cookieValue == nil || definitions.AuthResult(cookieValue.(uint8)) != definitions.AuthResultOK {
			stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "fail").Inc()
			ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())
			sessionCleaner(ctx)

			return
		}

		// We use the account name as username!
		cookieValue = session.Get(definitions.CookieAccount)
		if cookieValue != nil {
			if value, assertOkay := cookieValue.(string); assertOkay {
				userName = value
			}
		}

		if userName == "" {
			ctx.JSON(http.StatusInternalServerError, errors.ErrNotLoggedIn.Error())
			sessionCleaner(ctx)

			return
		}

		cookieValue = session.Get(definitions.CookieUniqueUserID)
		if cookieValue != nil {
			if value, assertOkay := cookieValue.(string); assertOkay {
				uniqueUserID = value
			}
		}

		if uniqueUserID == "" {
			ctx.JSON(http.StatusInternalServerError, errors.ErrNotLoggedIn.Error())
			sessionCleaner(ctx)

			return
		}

		cookieValue = session.Get(definitions.CookieDisplayName)
		if cookieValue != nil {
			if value, assertOk := cookieValue.(string); assertOk {
				displayName = value
			}
		}

		if displayName == "" {
			ctx.JSON(http.StatusBadRequest, errors.ErrNoDisplayName.Error())
			sessionCleaner(ctx)

			return
		}

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
			sessionCleaner(ctx)

			return
		}

		// Serialize session data and save it to the encrypted session cookie.
		sessionDataJSON, err := jsonIter.Marshal(*sessionData)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err)
			sessionCleaner(ctx)

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
			sessionCleaner(ctx)

			return
		}

		// Return the options generated
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "success").Inc()
		ctx.JSON(http.StatusOK, options)
	}
}

// FinishRegistration Page: '/2fa/v1/webauthn/register/finish'
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
			passDB       definitions.Backend
			backendName  string
			assertOk     bool
		)

		session := sessions.Default(ctx)

		defer sessionCleaner(ctx)

		cookieValue := session.Get(definitions.CookieAuthResult)
		if cookieValue == nil || definitions.AuthResult(cookieValue.(uint8)) != definitions.AuthResultOK {
			stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "fail").Inc()
			ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())

			return
		}

		cookieValue = session.Get(definitions.CookieUsername)
		if cookieValue != nil {
			if value, assertOkay := cookieValue.(string); assertOkay {
				userName = value
			}
		}

		if userName == "" {
			ctx.JSON(http.StatusBadRequest, errors.ErrNotLoggedIn.Error())

			return
		}

		cookieValue = session.Get(definitions.CookieUniqueUserID)
		if cookieValue != nil {
			if value, assertOkay := cookieValue.(string); assertOkay {
				uniqueUserID = value
			}
		}

		if uniqueUserID == "" {
			ctx.JSON(http.StatusInternalServerError, errors.ErrNotLoggedIn.Error())
			sessionCleaner(ctx)

			return
		}

		cookieValue = session.Get(definitions.CookieDisplayName)
		if cookieValue != nil {
			if value, assertOk := cookieValue.(string); assertOk {
				displayName = value
			}
		}

		if displayName == "" {
			ctx.JSON(http.StatusBadRequest, errors.ErrNoDisplayName.Error())
			sessionCleaner(ctx)

			return
		}

		cookieValue = session.Get(definitions.CookieRegistration)
		if cookieValue != nil {
			if value, assertOkay := cookieValue.([]byte); assertOkay {
				sessionData = &webauthn.SessionData{}

				if err := jsonIter.Unmarshal(value, sessionData); err != nil {
					sessionCleaner(ctx)
					ctx.JSON(http.StatusInternalServerError, err)

					return
				}
			}
		}

		if sessionData == nil {
			sessionCleaner(ctx)
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

		// We expect the same Database for credentials that was used for authenticating a user!
		if cookieValue := session.Get(definitions.CookieUserBackend); cookieValue != nil {
			if passDB, assertOk = cookieValue.(definitions.Backend); assertOk {
				if cookieName := session.Get(definitions.CookieUserBackendName); cookieName != nil {
					backendName, _ = cookieName.(string)
				}
			}
		}

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

		auth.(*AuthState).updateUser(user)

		// Persist to backend if possible
		if passDB != definitions.BackendUnknown {
			if mgr := auth.(*AuthState).GetBackendManager(passDB, backendName); mgr != nil {
				if err = mgr.SaveWebAuthnCredential(auth.(*AuthState), credential); err != nil {
					level.Error(deps.Logger).Log(
						definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
						definitions.LogKeyMsg, "Failed to persist WebAuthn credential to backend",
						definitions.LogKeyError, err,
					)
				}
			}
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
		cookieValue := session.Get(definitions.CookieUsername)
		if cookieValue != nil {
			if value, assertOkay := cookieValue.(string); assertOkay {
				userName = value
			}
		}

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
		cookieValue := session.Get(definitions.CookieUsername)
		if cookieValue != nil {
			if value, assertOkay := cookieValue.(string); assertOkay {
				userName = value
			}
		}

		cookieValue = session.Get(definitions.CookieRegistration)
		if cookieValue != nil {
			if value, assertOkay := cookieValue.([]byte); assertOkay {
				sessionData = &webauthn.SessionData{}
				if err := jsonIter.Unmarshal(value, sessionData); err != nil {
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

		// Update sign count if necessary (the library handles it in the credential object)
		// We should persist the updated sign count to the backend.
		existingCredentials, err := auth.GetWebAuthnCredentials()
		if err == nil {
			var oldCredential *webauthn.Credential
			for _, cred := range existingCredentials {
				if bytes.Equal(cred.ID, credential.ID) {
					oldCredential = &cred
					break
				}
			}

			if oldCredential != nil {
				// Update the credential in the backend
				_ = auth.UpdateWebAuthnCredential(oldCredential, credential)
			}
		}

		// Success!
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("login", "webauthn", "success").Inc()

		// Set AuthResult to OK if it was Fail (delayed response)
		authResult := session.Get(definitions.CookieAuthResult)
		if authResult != nil && definitions.AuthResult(authResult.(uint8)) == definitions.AuthResultFail {
			session.Set(definitions.CookieAuthResult, uint8(definitions.AuthResultOK))
		}

		// Important: store user info for next steps
		session.Set(definitions.CookieAccount, user.Name)
		session.Set(definitions.CookieUniqueUserID, user.Id)
		session.Set(definitions.CookieDisplayName, user.DisplayName)
		session.Set(definitions.CookieSubject, user.Id)

		if ttlVal := session.Get(definitions.CookieRememberTTL); ttlVal != nil {
			session.Options(sessions.Options{
				MaxAge: ttlVal.(int),
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

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
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var webAuthn *webauthn.WebAuthn

// getUser retrieves a User object with all their current credentials. This is Database depended. Which backend was used
// can be gotten from the session cookie.
func getUser(ctx *gin.Context, userName string, uniqueUserID string, displayName string) (*backend.User, error) {
	var (
		passDB        global.Backend
		assertOk      bool
		err           error
		user          *backend.User
		credentialDBs []WebAuthnCredentialDBFunc
		credentials   []webauthn.Credential
	)

	_ = userName
	_ = displayName

	session := sessions.Default(ctx)

	// We expect the same Database for credentials that was used for authenticating a user!
	if cookieValue := session.Get(global.CookieUserBackend); cookieValue != nil {
		if passDB, assertOk = cookieValue.(global.Backend); assertOk {
			switch passDB {
			case global.BackendLDAP:
				credentialDBs = append(credentialDBs, ldapGetWebAuthnCredentials)
			default:
				return nil, errors.ErrUnknownDatabaseBackend
			}
		}
	}

	// No cookie (default login page), search all configured databases.
	if passDB == global.BackendUnknown {
		for _, backendType := range config.LoadableConfig.Server.Backends {
			switch backendType.Get() {
			case global.BackendCache:
				credentialDBs = append(credentialDBs, nil)
			case global.BackendLDAP:
				credentialDBs = append(credentialDBs, ldapGetWebAuthnCredentials)
			// TODO: Add more databases
			default:
				return nil, errors.ErrUnknownDatabaseBackend
			}
		}
	}

	for _, credentialDB := range credentialDBs {
		credentials, err = credentialDB(uniqueUserID)
		if err != nil {
			return nil, err
		}

		if len(credentials) > 0 {
			break
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
		if user, err = backend.GetWebAuthnFromRedis(uniqueUserID); err != nil {
			return nil, err
		} else {
			stats.RedisReadCounter.Inc()
		}
	}

	return user, nil
}

func putUser(ctx *gin.Context, user *backend.User) {
	_ = ctx

	if err := backend.SaveWebAuthnToRedis(user, config.LoadableConfig.Server.Redis.PosCacheTTL); err == nil {
		stats.RedisWriteCounter.Inc()
	}
}

func updateUser(ctx *gin.Context, user *backend.User) {
	_ = ctx

	if err := backend.SaveWebAuthnToRedis(user, config.LoadableConfig.Server.Redis.PosCacheTTL); err == nil {
		stats.RedisWriteCounter.Inc()
	}
}

// Page: '/2fa/v1/webauthn/register/begin'
func beginRegistration(ctx *gin.Context) {
	var (
		userName     string
		displayName  string
		uniqueUserID string
	)

	session := sessions.Default(ctx)

	cookieValue := session.Get(global.CookieAuthResult)
	if cookieValue == nil || global.AuthResult(cookieValue.(uint8)) != global.AuthResultOK {
		ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())
		sessionCleaner(ctx)

		return
	}

	// We use the account name as username!
	cookieValue = session.Get(global.CookieAccount)
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

	cookieValue = session.Get(global.CookieUniqueUserID)
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

	cookieValue = session.Get(global.CookieDisplayName)
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

	// Get user from Database
	user, err := getUser(ctx, userName, uniqueUserID, displayName)
	if err != nil {
		// If it does not exist, create a new one
		user = backend.NewUser(userName, displayName, uniqueUserID)

		putUser(ctx, user)
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
	sessionDataJSON, err := json.Marshal(*sessionData)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, err)
		sessionCleaner(ctx)

		return
	}

	util.DebugModule(
		global.DbgWebAuthn,
		global.LogKeyGUID, ctx.GetString(global.CtxGUIDKey),
		global.LogKeyMsg, "session data begin",
		"content", fmt.Sprintf("%#v", sessionData),
	)

	session.Set(global.CookieRegistration, sessionDataJSON)

	if err = session.Save(); err != nil {
		ctx.JSON(http.StatusInternalServerError, err)
		sessionCleaner(ctx)

		return
	}

	// Return the options generated
	ctx.JSON(http.StatusOK, options)
}

// Page: '/2fa/v1/webauthn/register/finish'
func finishRegistration(ctx *gin.Context) {
	var (
		userName     string
		uniqueUserID string
		displayName  string
		sessionData  *webauthn.SessionData
	)

	session := sessions.Default(ctx)

	defer sessionCleaner(ctx)

	cookieValue := session.Get(global.CookieAuthResult)
	if cookieValue == nil || global.AuthResult(cookieValue.(uint8)) != global.AuthResultOK {
		ctx.JSON(http.StatusUnauthorized, errors.ErrNotLoggedIn.Error())

		return
	}

	cookieValue = session.Get(global.CookieUsername)
	if cookieValue != nil {
		if value, assertOkay := cookieValue.(string); assertOkay {
			userName = value
		}
	}

	if userName == "" {
		ctx.JSON(http.StatusBadRequest, errors.ErrNotLoggedIn.Error())

		return
	}

	cookieValue = session.Get(global.CookieUniqueUserID)
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

	cookieValue = session.Get(global.CookieDisplayName)
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

	cookieValue = session.Get(global.CookieRegistration)
	if cookieValue != nil {
		if value, assertOkay := cookieValue.([]byte); assertOkay {
			sessionData = &webauthn.SessionData{}

			if err := json.Unmarshal(value, sessionData); err != nil {
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

	util.DebugModule(
		global.DbgWebAuthn,
		global.LogKeyGUID, ctx.GetString(global.CtxGUIDKey),
		global.LogKeyMsg, "session data finish",
		"content", fmt.Sprintf("%#v", sessionData),
	)

	user, err := getUser(ctx, userName, uniqueUserID, displayName)
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
	updateUser(ctx, user)

	ctx.JSON(http.StatusOK, "Registration success")
}

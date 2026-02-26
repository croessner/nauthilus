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
	"net/http"

	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
)

// HandleErrWithDeps is a DI-capable variant of HandleErr.
func HandleErrWithDeps(ctx *gin.Context, err error, _ AuthDeps) {
	if err == nil {
		ctx.Status(http.StatusBadRequest)

		return
	}

	ctx.String(http.StatusBadRequest, err.Error())
}

// SessionCleaner removes all user information from the secure cookie.
// After migration to the CookieManager, session data is stored in the encrypted
// nauthilus_secure_data cookie. This function clears all sensitive session keys.
func SessionCleaner(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		return
	}

	// Cleanup all sensitive session keys.
	mgr.Delete(definitions.SessionKeyAuthResult)
	mgr.Delete(definitions.SessionKeyUsername)
	mgr.Delete(definitions.SessionKeyAccount)
	mgr.Delete(definitions.SessionKeyHaveTOTP)
	mgr.Delete(definitions.SessionKeyTOTPURL)
	mgr.Delete(definitions.SessionKeyUserBackend)
	mgr.Delete(definitions.SessionKeyUniqueUserID)
	mgr.Delete(definitions.SessionKeyDisplayName)
	mgr.Delete(definitions.SessionKeyRegistration)
	mgr.Delete(definitions.SessionKeyOIDCClients)
	mgr.Delete(definitions.SessionKeyTOTPSecret)
	mgr.Delete(definitions.SessionKeySubject)
	mgr.Delete(definitions.SessionKeyUserBackendName)
	mgr.Delete(definitions.SessionKeyProtocol)
	mgr.Delete(definitions.SessionKeyRememberTTL)
	mgr.Delete(definitions.SessionKeyLoginError)

	// MFA-related keys
	mgr.Delete(definitions.SessionKeyMFAMulti)
	mgr.Delete(definitions.SessionKeyMFAMethod)
	mgr.Delete(definitions.SessionKeyMFACompleted)

	// Note: SessionKeyLang is intentionally preserved for UX.
	// Cookie is automatically saved by the cookie.Middleware after the handler chain.
}

// ClearBrowserCookies explicitly overwrites security-relevant cookies in the browser with an expired state.
// After the CookieManager migration, only SecureDataCookieName exists as the encrypted secure data cookie.
func ClearBrowserCookies(ctx *gin.Context) {
	secure := util.ShouldSetSecureCookie()

	ctx.SetCookie(definitions.SecureDataCookieName, "", -1, "/", "", secure, true)
}

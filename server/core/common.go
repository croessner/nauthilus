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

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-contrib/sessions"
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

// SessionCleaner removes all user information from the current session.
func SessionCleaner(ctx *gin.Context) {
	session := sessions.Default(ctx)

	// Cleanup
	session.Delete(definitions.CookieAuthResult)
	session.Delete(definitions.CookieUsername)
	session.Delete(definitions.CookieAccount)
	session.Delete(definitions.CookieHaveTOTP)
	session.Delete(definitions.CookieTOTPURL)
	session.Delete(definitions.CookieUserBackend)
	session.Delete(definitions.CookieUniqueUserID)
	session.Delete(definitions.CookieDisplayName)
	session.Delete(definitions.CookieRegistration)
	session.Delete(definitions.CookieOIDCClients)
	session.Delete(definitions.CookieTOTPSecret)
	session.Delete(definitions.CookieSubject)
	session.Delete(definitions.CookieUserBackendName)

	session.Save()
}

// ClearBrowserCookies explicitly overwrites security-relevant cookies in the browser with an expired state.
func ClearBrowserCookies(ctx *gin.Context) {
	ctx.SetCookie(definitions.CookieAccount, "", -1, "/", "", false, true)
	ctx.SetCookie(definitions.CookieAuthResult, "", -1, "/", "", false, true)
	ctx.SetCookie(definitions.CookieUsername, "", -1, "/", "", false, true)
	ctx.SetCookie(definitions.CookieSubject, "", -1, "/", "", false, true)
	ctx.SetCookie(definitions.CookieDisplayName, "", -1, "/", "", false, true)
	ctx.SetCookie(definitions.CookieUniqueUserID, "", -1, "/", "", false, true)
	ctx.SetCookie(definitions.CookieOIDCClients, "", -1, "/", "", false, true)
	ctx.SetCookie(definitions.CookieUserBackend, "", -1, "/", "", false, true)
	ctx.SetCookie(definitions.CookieUserBackendName, "", -1, "/", "", false, true)
	ctx.SetCookie(definitions.CookieTOTPSecret, "", -1, "/", "", false, true)
	ctx.SetCookie(definitions.CookieTOTPURL, "", -1, "/", "", false, true)
	ctx.SetCookie(definitions.CookieRegistration, "", -1, "/", "", false, true)
}

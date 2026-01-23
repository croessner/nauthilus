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

// sessionCleaner removes all user information from the current session.
func sessionCleaner(ctx *gin.Context) {
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

	session.Save()
}

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

	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/util"
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

	for _, key := range sessionCleanerKeys() {
		mgr.Delete(key)
	}

	// Cookie is automatically saved by the cookie.Middleware after the handler chain.
}

// sessionCleanerKeys returns all sensitive browser-session keys.
func sessionCleanerKeys() []string {
	return []string{
		definitions.SessionKeyAuthResult,
		definitions.SessionKeyUsername,
		definitions.SessionKeyAccount,
		definitions.SessionKeyHaveTOTP,
		definitions.SessionKeyHaveWebAuthn,
		definitions.SessionKeyHaveRecoveryCodes,
		definitions.SessionKeyTOTPURL,
		definitions.SessionKeyUserBackend,
		definitions.SessionKeyRemoteBackendRefType,
		definitions.SessionKeyRemoteBackendRefName,
		definitions.SessionKeyRemoteBackendRefProtocol,
		definitions.SessionKeyRemoteBackendRefAuthority,
		definitions.SessionKeyRemoteBackendRefToken,
		definitions.SessionKeyMFAFactorRemoteBackendRefType,
		definitions.SessionKeyMFAFactorRemoteBackendRefName,
		definitions.SessionKeyMFAFactorRemoteBackendRefProtocol,
		definitions.SessionKeyMFAFactorRemoteBackendRefAuthority,
		definitions.SessionKeyMFAFactorRemoteBackendRefToken,
		definitions.SessionKeyUniqueUserID,
		definitions.SessionKeyDisplayName,
		definitions.SessionKeyRegistration,
		definitions.SessionKeyOIDCClients,
		definitions.SessionKeyOIDCConsentExpiries,
		definitions.SessionKeyTOTPSecret,
		definitions.SessionKeyTOTPPendingRegistration,
		definitions.SessionKeyTOTPOperationID,
		definitions.SessionKeyRecoveryCodes,
		definitions.SessionKeyRecoveryCodesRemoteGenerated,
		definitions.SessionKeyRecoveryOperationID,
		definitions.SessionKeySubject,
		definitions.SessionKeyUserBackendName,
		definitions.SessionKeyProtocol,
		definitions.SessionKeyLang,
		definitions.SessionKeyRememberTTL,
		definitions.SessionKeyLoginError,
		definitions.SessionKeyMFAAccount,
		definitions.SessionKeyMFADisplayName,
		definitions.SessionKeyMFAFactorAccount,
		definitions.SessionKeyMFAFactorUniqueUserID,
		definitions.SessionKeyMFAFactorDisplayName,
		definitions.SessionKeyMFAMulti,
		definitions.SessionKeyMFAMethod,
		definitions.SessionKeyMFACompleted,
		definitions.SessionKeyMFAAssuranceAt,
		definitions.SessionKeyMFAAssuranceMethod,
		definitions.SessionKeyMFAAssuranceLevel,
		definitions.SessionKeyMFAAssuranceScope,
	}
}

// ClearBrowserCookies explicitly overwrites security-relevant cookies in the browser with an expired state.
// After the CookieManager migration, only SecureDataCookieName exists as the encrypted secure data cookie.
func ClearBrowserCookies(ctx *gin.Context) {
	secure := util.ShouldSetSecureCookie()

	ctx.SetCookie(definitions.SecureDataCookieName, "", -1, "/", "", secure, true)
}

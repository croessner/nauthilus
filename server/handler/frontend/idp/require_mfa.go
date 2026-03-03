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

package idp

import (
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/gin-gonic/gin"
)

// getRequiredMFAMethods returns the list of MFA methods configured as mandatory
// for the current IdP client or SAML service provider read from the cookie.
// Returns nil when no requirement is configured or the flow type is unknown.
func (h *FrontendHandler) getRequiredMFAMethods(mgr cookie.Manager) []string {
	if mgr == nil || h.deps == nil {
		return nil
	}

	flowType := mgr.GetString(definitions.SessionKeyIdPFlowType, "")
	idpInstance := idp.NewNauthilusIdP(h.deps)

	switch flowType {
	case definitions.ProtoOIDC:
		clientID := mgr.GetString(definitions.SessionKeyIdPClientID, "")
		if clientID == "" {
			return nil
		}

		client, ok := idpInstance.FindClient(clientID)
		if !ok {
			return nil
		}

		return client.GetRequireMFA()

	case definitions.ProtoSAML:
		entityID := mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, "")
		if entityID == "" {
			return nil
		}

		sp, ok := idpInstance.FindSAMLServiceProvider(entityID)
		if !ok {
			return nil
		}

		return sp.GetRequireMFA()
	}

	return nil
}

// getFlowClientIdentifiers resolves flow-specific OIDC/SAML identifiers from the current session.
// Empty strings are returned when no matching flow context is available.
func (h *FrontendHandler) getFlowClientIdentifiers(mgr cookie.Manager) (string, string) {
	if mgr == nil {
		return "", ""
	}

	flowType := mgr.GetString(definitions.SessionKeyIdPFlowType, "")

	switch flowType {
	case definitions.ProtoOIDC:
		return mgr.GetString(definitions.SessionKeyIdPClientID, ""), ""
	case definitions.ProtoSAML:
		return "", mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, "")
	default:
		return "", ""
	}
}

func (h *FrontendHandler) clearRequireMFARegistrationState(mgr cookie.Manager) {
	if mgr == nil {
		return
	}

	mgr.Delete(definitions.SessionKeyRequireMFAFlow)
	mgr.Delete(definitions.SessionKeyRequireMFAPending)
}

// checkRequireMFARegistrationAndRedirect compares the mandatory MFA methods for the
// current IdP flow against the methods already registered by the user.
// If one or more methods are missing the function:
//  1. Writes SessionKeyRequireMFAFlow and SessionKeyRequireMFAPending to the cookie.
//  2. Redirects the browser to the first missing method's registration page.
//  3. Returns true so the caller can stop further processing.
//
// Returns false when no registration is required and the caller may proceed normally.
func (h *FrontendHandler) checkRequireMFARegistrationAndRedirect(ctx *gin.Context, mgr cookie.Manager) bool {
	if mgr == nil {
		return false
	}

	if !mgr.GetBool(definitions.SessionKeyIdPFlowActive, false) {
		return false
	}

	required := h.getRequiredMFAMethods(mgr)
	if len(required) == 0 {
		h.clearRequireMFARegistrationState(mgr)

		return false
	}

	username := mgr.GetString(definitions.SessionKeyAccount, "")
	if username == "" {
		h.clearRequireMFARegistrationState(mgr)

		return false
	}

	protocol := mgr.GetString(definitions.SessionKeyProtocol, "")

	if h.deps == nil {
		return false
	}

	idpInstance := idp.NewNauthilusIdP(h.deps)
	oidcCID, samlEntityID := h.getFlowClientIdentifiers(mgr)

	user, err := idpInstance.GetUserByUsername(ctx, username, oidcCID, samlEntityID)
	if err != nil {
		h.clearRequireMFARegistrationState(mgr)

		return false
	}

	var missing []string

	for _, method := range required {
		switch method {
		case definitions.MFAMethodTOTP:
			if !h.hasTOTP(user) {
				missing = append(missing, definitions.MFAMethodTOTP)
			}

		case definitions.MFAMethodWebAuthn:
			if !h.hasWebAuthn(ctx, user, protocol) {
				missing = append(missing, definitions.MFAMethodWebAuthn)
			}

		case definitions.MFAMethodRecoveryCodes:
			if !h.hasRecoveryCodesForRequireMFA(ctx, mgr, user) {
				missing = append(missing, definitions.MFAMethodRecoveryCodes)
			}
		}
	}

	if len(missing) == 0 {
		h.clearRequireMFARegistrationState(mgr)

		return false
	}

	mgr.Set(definitions.SessionKeyRequireMFAFlow, true)
	mgr.Set(definitions.SessionKeyRequireMFAPending, strings.Join(missing, ","))

	if !h.redirectToNextRequiredMFARegistration(ctx, mgr) {
		h.clearRequireMFARegistrationState(mgr)

		return false
	}

	return true
}

func (h *FrontendHandler) hasRecoveryCodesForRequireMFA(ctx *gin.Context, mgr cookie.Manager, user *backend.User) bool {
	if h.hasRecoveryCodes(user) {
		return true
	}

	if mgr != nil && mgr.GetBool(definitions.SessionKeyRecoveryCodesSaved, false) {
		return true
	}

	username := ""
	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyAccount, "")
	}

	h.purgeCachedAuthenticationForUser(ctx, username)

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		return false
	}

	return userData.NumRecoveryCodes > 0
}

func (h *FrontendHandler) purgeCachedAuthenticationForUser(ctx *gin.Context, username string) {
	if h == nil || h.deps == nil || username == "" {
		return
	}

	state := core.NewAuthStateWithSetupWithDeps(ctx, h.deps.Auth())
	if state == nil {
		return
	}

	authState, ok := state.(*core.AuthState)
	if !ok || authState == nil {
		return
	}

	authState.PurgeCacheFor(username)
}

// redirectToNextRequiredMFARegistration reads the first entry from the
// SessionKeyRequireMFAPending list and issues a 302 redirect to the corresponding
// registration page.  Returns true when a redirect was issued, false otherwise.
func (h *FrontendHandler) redirectToNextRequiredMFARegistration(ctx *gin.Context, mgr cookie.Manager) bool {
	if mgr == nil {
		return false
	}

	pending := mgr.GetString(definitions.SessionKeyRequireMFAPending, "")
	if pending == "" {
		return false
	}

	parts := strings.SplitN(pending, ",", 2)

	switch parts[0] {
	case definitions.MFAMethodTOTP:
		ctx.Redirect(http.StatusFound, definitions.MFARoot+"/totp/register")

		return true

	case definitions.MFAMethodWebAuthn:
		ctx.Redirect(http.StatusFound, definitions.MFARoot+"/webauthn/register")

		return true

	case definitions.MFAMethodRecoveryCodes:
		ctx.Redirect(http.StatusFound, definitions.MFARoot+"/recovery/register")

		return true
	}

	return false
}

// ContinueRequiredMFARegistration is the GET handler for /mfa/register/continue.
// It is called after each individual MFA registration step in a forced-registration
// flow to decide whether another method still needs to be registered or whether the
// original IdP flow can be resumed.
func (h *FrontendHandler) ContinueRequiredMFARegistration(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)

	if mgr == nil {
		ctx.Redirect(http.StatusFound, "/")

		return
	}

	pending := mgr.GetString(definitions.SessionKeyRequireMFAPending, "")

	if pending == "" {
		// All required methods registered — clean up and resume the IdP flow.
		h.clearRequireMFARegistrationState(mgr)
		h.redirectToIdPEndpoint(ctx, mgr)

		return
	}

	// Redirect to the registration page for the next pending method.
	h.redirectToNextRequiredMFARegistration(ctx, mgr)
}

// CancelRequiredMFARegistration is the GET handler for /mfa/register/cancel.
// The user declined to register a required MFA method, so the entire session is
// invalidated:  the forced-registration state is removed, the IdP flow state is
// cleaned up, and the user is logged out before being sent to /logged_out.
func (h *FrontendHandler) CancelRequiredMFARegistration(ctx *gin.Context) {
	core.SessionCleaner(ctx)
	core.ClearBrowserCookies(ctx)

	ctx.Redirect(http.StatusFound, "/logged_out")
}

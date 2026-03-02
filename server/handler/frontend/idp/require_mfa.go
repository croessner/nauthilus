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

	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/gin-gonic/gin"
)

// getRequiredMFAMethods returns the list of MFA methods configured as mandatory
// for the current IdP client or SAML service provider read from the cookie.
// Returns nil when no requirement is configured or the flow type is unknown.
func (h *FrontendHandler) getRequiredMFAMethods(mgr cookie.Manager) []string {
	if mgr == nil {
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
		return false
	}

	username := mgr.GetString(definitions.SessionKeyAccount, "")
	if username == "" {
		return false
	}

	protocol := mgr.GetString(definitions.SessionKeyProtocol, "")

	idpInstance := idp.NewNauthilusIdP(h.deps)

	user, err := idpInstance.GetUserByUsername(ctx, username, "", "")
	if err != nil {
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
		}
	}

	if len(missing) == 0 {
		return false
	}

	mgr.Set(definitions.SessionKeyRequireMFAFlow, true)
	mgr.Set(definitions.SessionKeyRequireMFAPending, strings.Join(missing, ","))

	return h.redirectToNextRequiredMFARegistration(ctx, mgr)
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
	}

	return false
}

// removeFromMFAPendingList removes the first occurrence of method from the
// comma-separated pending list and returns the remainder.
func removeFromMFAPendingList(pending, method string) string {
	if pending == "" {
		return ""
	}

	parts := strings.Split(pending, ",")
	remaining := make([]string, 0, len(parts))

	for _, p := range parts {
		if strings.TrimSpace(p) != method {
			remaining = append(remaining, p)
		}
	}

	return strings.Join(remaining, ",")
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
		mgr.Delete(definitions.SessionKeyRequireMFAFlow)
		mgr.Delete(definitions.SessionKeyRequireMFAPending)
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
	mgr := cookie.GetManager(ctx)

	if mgr != nil {
		mgr.Delete(definitions.SessionKeyRequireMFAFlow)
		mgr.Delete(definitions.SessionKeyRequireMFAPending)

		CleanupIdPFlowState(mgr)

		mgr.Delete(definitions.SessionKeyAccount)
		mgr.Delete(definitions.SessionKeyUniqueUserID)
		mgr.Delete(definitions.SessionKeyDisplayName)
		mgr.Delete(definitions.SessionKeySubject)
		mgr.Delete(definitions.SessionKeyMFACompleted)
	}

	ctx.Redirect(http.StatusFound, "/logged_out")
}

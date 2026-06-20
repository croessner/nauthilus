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
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/idp"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/gin-gonic/gin"
)

const requireMFAFlowID = flowdomain.FlowIDRequireMFA

type oidcMFAMethodSelector func(*config.OIDCClient) []string

type samlMFAMethodSelector func(*config.SAML2ServiceProvider) []string

// getRequiredMFAMethods returns the list of MFA methods configured as mandatory
// for the current IDP client or SAML service provider read from the cookie.
// Returns nil when no requirement is configured or the flow type is unknown.
func (h *FrontendHandler) getRequiredMFAMethods(mgr cookie.Manager) []string {
	return h.getFlowMFAMethods(mgr, (*config.OIDCClient).GetRequireMFA, (*config.SAML2ServiceProvider).GetRequireMFA)
}

// getSupportedMFAMethods returns the list of MFA methods supported for the current
// IDP client or SAML service provider. Empty means all methods are supported.
func (h *FrontendHandler) getSupportedMFAMethods(mgr cookie.Manager) []string {
	return h.getFlowMFAMethods(mgr, (*config.OIDCClient).GetSupportedMFA, (*config.SAML2ServiceProvider).GetSupportedMFA)
}

// getFlowMFAMethods resolves OIDC or SAML MFA method settings from the current flow context.
func (h *FrontendHandler) getFlowMFAMethods(mgr cookie.Manager, oidcSelector oidcMFAMethodSelector, samlSelector samlMFAMethodSelector) []string {
	if mgr == nil || h.deps == nil {
		return nil
	}

	flowType := mgr.GetString(definitions.SessionKeyIDPFlowType, "")
	idpInstance := idp.NewNauthilusIDP(h.deps)

	switch flowType {
	case definitions.ProtoOIDC:
		clientID := mgr.GetString(definitions.SessionKeyIDPClientID, "")
		if clientID == "" {
			return nil
		}

		client, ok := idpInstance.FindClient(clientID)
		if !ok {
			return nil
		}

		return oidcSelector(client)

	case definitions.ProtoSAML:
		entityID := mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, "")
		if entityID == "" {
			return nil
		}

		sp, ok := idpInstance.FindSAMLServiceProvider(entityID)
		if !ok {
			return nil
		}

		return samlSelector(sp)
	}

	return nil
}

func (h *FrontendHandler) isMFAMethodSupported(mgr cookie.Manager, method string) bool {
	supported := h.getSupportedMFAMethods(mgr)
	if len(supported) == 0 {
		return true
	}

	return slices.Contains(supported, method)
}

// getFlowClientIdentifiers resolves flow-specific OIDC/SAML identifiers from the current session.
// Empty strings are returned when no matching flow context is available.
func (h *FrontendHandler) getFlowClientIdentifiers(mgr cookie.Manager) (string, string) {
	if mgr == nil {
		return "", ""
	}

	flowType := mgr.GetString(definitions.SessionKeyIDPFlowType, "")

	switch flowType {
	case definitions.ProtoOIDC:
		return mgr.GetString(definitions.SessionKeyIDPClientID, ""), ""
	case definitions.ProtoSAML:
		return "", mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, "")
	default:
		return "", ""
	}
}

// getRememberMeTTL returns the effective remember-me TTL for the current flow.
// Resolution order:
// 1. Global identity.session.remember_me_ttl
// 2. Deprecated per-client/per-SP remember_me_ttl (legacy fallback)
func (h *FrontendHandler) getRememberMeTTL(oidcCID, samlEntityID string) time.Duration {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return 0
	}

	globalTTL := h.deps.Cfg.GetIDP().GetRememberMeTTL()
	if globalTTL > 0 {
		return globalTTL
	}

	idpInstance := idp.NewNauthilusIDP(h.deps)

	if oidcCID != "" {
		if client, ok := idpInstance.FindClient(oidcCID); ok {
			//nolint:staticcheck // Legacy client fallback is required until deprecated per-client TTL support is removed.
			return client.RememberMeTTL
		}
	}

	if samlEntityID != "" {
		if sp, ok := idpInstance.FindSAMLServiceProvider(samlEntityID); ok {
			//nolint:staticcheck // Legacy service-provider fallback is required until deprecated per-SP TTL support is removed.
			return sp.RememberMeTTL
		}
	}

	return 0
}

func (h *FrontendHandler) shouldShowRememberMe(oidcCID, samlEntityID string) bool {
	return h.getRememberMeTTL(oidcCID, samlEntityID) > 0
}

func (h *FrontendHandler) clearRequireMFARegistrationState(mgr cookie.Manager) {
	if mgr == nil {
		return
	}

	flowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if flowID != requireMFAFlowID {
		flowdomain.ClearRequireMFAContext(mgr)

		return
	}

	// Preserve the original IDP flow type and grant type before aborting the
	// require-mfa sub-flow, because Abort → Delete removes SessionKeyIDPFlowType
	// from the cookie. Without restoring these keys, the resumed parent flow loses
	// protocol context and cannot be continued deterministically.
	savedFlowType := mgr.GetString(definitions.SessionKeyIDPFlowType, "")
	savedGrantType := mgr.GetString(definitions.SessionKeyOIDCGrantType, "")
	savedParentFlowID := mgr.GetString(definitions.SessionKeyRequireMFAParentFlowID, "")

	controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	if _, err := controller.Abort(context.Background(), requireMFAFlowID); err != nil {
		flowdomain.ClearRequireMFAContext(mgr)

		return
	}

	// Restore the original IDP flow context so that the caller can still
	// redirect back to the correct IDP endpoint (OIDC authorize, SAML SSO, etc.).
	flowdomain.RestoreFlowCookieContext(mgr, savedFlowType, savedGrantType)

	if savedParentFlowID != "" {
		mgr.Set(definitions.SessionKeyIDPFlowID, savedParentFlowID)
	}

	flowdomain.SetRequireMFAPending(mgr, "")
}

// checkRequireMFARegistrationAndRedirect compares the mandatory MFA methods for the
// current IDP flow against the methods already registered by the user.
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

	if mgr.GetString(definitions.SessionKeyIDPFlowID, "") == "" {
		return false
	}

	required, user, protocol, ok := h.requireMFARegistrationContext(ctx, mgr)
	if !ok {
		return false
	}

	missing := h.missingRequireMFAMethods(ctx, mgr, user, protocol, required)
	if len(missing) == 0 {
		h.clearRequireMFARegistrationState(mgr)

		return false
	}

	flowdomain.SetRequireMFAPending(mgr, strings.Join(missing, ","))

	return h.startRequireMFARegistrationFlow(ctx, mgr, user, protocol, missing)
}

// requireMFARegistrationContext loads configured requirements and current user.
func (h *FrontendHandler) requireMFARegistrationContext(ctx *gin.Context, mgr cookie.Manager) ([]string, *backend.User, string, bool) {
	required := h.getRequiredMFAMethods(mgr)
	if len(required) == 0 {
		h.clearRequireMFARegistrationState(mgr)

		return nil, nil, "", false
	}

	username := mgr.GetString(definitions.SessionKeyAccount, "")
	if username == "" || h.deps == nil {
		h.clearRequireMFARegistrationState(mgr)

		return nil, nil, "", false
	}

	idpInstance := idp.NewNauthilusIDP(h.deps)
	oidcCID, samlEntityID := h.getFlowClientIdentifiers(mgr)

	user, err := idpInstance.GetUserByUsername(ctx, username, oidcCID, samlEntityID)
	if err != nil {
		h.clearRequireMFARegistrationState(mgr)

		return nil, nil, "", false
	}

	return required, user, mgr.GetString(definitions.SessionKeyProtocol, ""), true
}

// missingRequireMFAMethods returns methods that are still not registered.
func (h *FrontendHandler) missingRequireMFAMethods(
	ctx *gin.Context,
	mgr cookie.Manager,
	user *backend.User,
	protocol string,
	required []string,
) []string {
	missing := make([]string, 0, len(required))

	for _, method := range required {
		if h.requireMFAMethodMissing(ctx, mgr, user, protocol, method) {
			missing = append(missing, method)
		}
	}

	return missing
}

// requireMFAMethodMissing checks one mandatory MFA method.
func (h *FrontendHandler) requireMFAMethodMissing(ctx *gin.Context, mgr cookie.Manager, user *backend.User, protocol string, method string) bool {
	switch method {
	case definitions.MFAMethodTOTP:
		return !h.hasTOTPForRequireMFA(ctx, mgr, user)
	case definitions.MFAMethodWebAuthn:
		return !h.hasWebAuthn(ctx, user, protocol)
	case definitions.MFAMethodRecoveryCodes:
		return !h.hasRecoveryCodesForRequireMFA(ctx, mgr, user)
	default:
		return false
	}
}

// requireMFAFlowProtocol maps the current IDP protocol to flow protocol.
func requireMFAFlowProtocol(protocol string) flowdomain.Protocol {
	switch protocol {
	case definitions.ProtoOIDC:
		return flowdomain.FlowProtocolOIDC
	case definitions.ProtoSAML:
		return flowdomain.FlowProtocolSAML
	default:
		return flowdomain.FlowProtocolUnknown
	}
}

// startRequireMFARegistrationFlow creates and redirects to the require-MFA flow.
func (h *FrontendHandler) startRequireMFARegistrationFlow(
	ctx *gin.Context,
	mgr cookie.Manager,
	user *backend.User,
	protocol string,
	missing []string,
) bool {
	parentFlowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if parentFlowID != "" && parentFlowID != requireMFAFlowID {
		mgr.Set(definitions.SessionKeyRequireMFAParentFlowID, parentFlowID)
	}

	nextTarget := h.nextRequiredMFARegistrationTarget(mgr)
	if nextTarget == "" {
		h.clearRequireMFARegistrationState(mgr)

		return false
	}

	controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	decision, err := controller.Start(ctx.Request.Context(), &flowdomain.State{
		FlowID:       requireMFAFlowID,
		Type:         flowdomain.FlowTypeRequireMFA,
		Protocol:     requireMFAFlowProtocol(protocol),
		CurrentStep:  flowdomain.FlowStepStart,
		ReturnTarget: nextTarget,
		PendingMFA:   true,
		Metadata:     requireMFAFlowMetadata(mgr, user, strings.Join(missing, ",")),
	}, time.Now())
	if err != nil {
		h.clearRequireMFARegistrationState(mgr)

		return false
	}

	if decision.RedirectURI == "" {
		h.clearRequireMFARegistrationState(mgr)

		return false
	}

	advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepRequireMFAChallenge)

	ctx.Redirect(http.StatusFound, decision.RedirectURI)

	return true
}

func requireMFAFlowMetadata(mgr cookie.Manager, user *backend.User, missing string) map[string]string {
	metadata := map[string]string{
		"require_mfa": missing,
	}

	if mgr != nil {
		if account := mgr.GetString(definitions.SessionKeyAccount, ""); account != "" {
			metadata[flowdomain.FlowMetadataAccount] = account
		}

		if uniqueUserID := mgr.GetString(definitions.SessionKeyUniqueUserID, ""); uniqueUserID != "" {
			metadata[flowdomain.FlowMetadataUniqueUserID] = uniqueUserID
		}

		if displayName := mgr.GetString(definitions.SessionKeyDisplayName, ""); displayName != "" {
			metadata[flowdomain.FlowMetadataDisplayName] = displayName
		}
	}

	if user != nil {
		if metadata[flowdomain.FlowMetadataAccount] == "" && user.Name != "" {
			metadata[flowdomain.FlowMetadataAccount] = user.Name
		}

		if metadata[flowdomain.FlowMetadataUniqueUserID] == "" && user.ID != "" {
			metadata[flowdomain.FlowMetadataUniqueUserID] = user.ID
		}

		if metadata[flowdomain.FlowMetadataDisplayName] == "" && user.DisplayName != "" {
			metadata[flowdomain.FlowMetadataDisplayName] = user.DisplayName
		}
	}

	return metadata
}

func (h *FrontendHandler) restoreRequireMFAIdentityContextFromStore(ctx *gin.Context, mgr cookie.Manager) {
	if h == nil || h.deps == nil || h.deps.Cfg == nil || ctx == nil || mgr == nil {
		return
	}

	flowID := requireMFAFlowIDFromSession(mgr)
	if flowID == "" {
		return
	}

	controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	state, err := controller.State(ctx.Request.Context(), flowID)
	if err != nil {
		return
	}

	restoreRequireMFAIdentityContext(mgr, state)
}

func requireMFAFlowIDFromSession(mgr cookie.Manager) string {
	if mgr == nil {
		return ""
	}

	flowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if flowID != "" {
		return flowID
	}

	if mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
		return requireMFAFlowID
	}

	return ""
}

func restoreRequireMFAIdentityContext(mgr cookie.Manager, state *flowdomain.State) {
	if mgr == nil || state == nil || state.Type != flowdomain.FlowTypeRequireMFA || state.Metadata == nil {
		return
	}

	if mgr.GetString(definitions.SessionKeyAccount, "") == "" {
		if account := state.Metadata[flowdomain.FlowMetadataAccount]; account != "" {
			mgr.Set(definitions.SessionKeyAccount, account)
		}
	}

	if mgr.GetString(definitions.SessionKeyUniqueUserID, "") == "" {
		if uniqueUserID := state.Metadata[flowdomain.FlowMetadataUniqueUserID]; uniqueUserID != "" {
			mgr.Set(definitions.SessionKeyUniqueUserID, uniqueUserID)
		}
	}

	if mgr.GetString(definitions.SessionKeyDisplayName, "") == "" {
		if displayName := state.Metadata[flowdomain.FlowMetadataDisplayName]; displayName != "" {
			mgr.Set(definitions.SessionKeyDisplayName, displayName)
		}
	}
}

func (h *FrontendHandler) nextRequiredMFARegistrationTarget(mgr cookie.Manager) string {
	if mgr == nil {
		return ""
	}

	pending := mgr.GetString(definitions.SessionKeyRequireMFAPending, "")
	if pending == "" {
		return ""
	}

	parts := strings.SplitN(pending, ",", 2)

	switch parts[0] {
	case definitions.MFAMethodTOTP:
		return definitions.MFARoot + "/totp/register"
	case definitions.MFAMethodWebAuthn:
		return definitions.MFARoot + "/webauthn/register"
	case definitions.MFAMethodRecoveryCodes:
		return definitions.MFARoot + "/recovery/register"
	}

	return ""
}

func (h *FrontendHandler) hasTOTPForRequireMFA(ctx *gin.Context, mgr cookie.Manager, user *backend.User) bool {
	if h.hasTOTP(user) {
		return true
	}

	if mgr != nil && mgr.GetBool(definitions.SessionKeyHaveTOTP, false) {
		return true
	}

	if h == nil || h.deps == nil || ctx == nil {
		return false
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

	return userData.HaveTOTP
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
	nextTarget := h.nextRequiredMFARegistrationTarget(mgr)
	if nextTarget == "" {
		return false
	}

	ctx.Redirect(http.StatusFound, nextTarget)

	return true
}

// ContinueRequiredMFARegistration is the GET handler for /mfa/register/continue.
// It is called after each individual MFA registration step in a forced-registration
// flow to decide whether another method still needs to be registered or whether the
// original IDP flow can be resumed.
func (h *FrontendHandler) ContinueRequiredMFARegistration(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)

	if mgr == nil {
		ctx.Redirect(http.StatusFound, "/")

		return
	}

	h.restoreRequireMFAIdentityContextFromStore(ctx, mgr)

	pending := mgr.GetString(definitions.SessionKeyRequireMFAPending, "")

	if pending == "" {
		// All required methods registered — clean up and resume the IDP flow.
		h.clearRequireMFARegistrationState(mgr)
		h.resumeIDPFlow(ctx, mgr)

		return
	}

	// Redirect to the registration page for the next pending method.
	h.redirectToNextRequiredMFARegistration(ctx, mgr)
}

// CancelRequiredMFARegistration is the GET handler for /mfa/register/cancel.
// The user declined to register a required MFA method, so the entire session is
// invalidated:  the forced-registration state is removed, the IDP flow state is
// cleaned up, and the user is logged out before being sent to /logged_out.
func (h *FrontendHandler) CancelRequiredMFARegistration(ctx *gin.Context) {
	core.SessionCleaner(ctx)
	core.ClearBrowserCookies(ctx)

	ctx.Redirect(http.StatusFound, "/logged_out")
}

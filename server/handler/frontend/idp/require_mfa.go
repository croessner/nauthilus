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
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/gin-gonic/gin"
)

type oidcMFAMethodSelector func(*config.OIDCClient) []string

type samlMFAMethodSelector func(*config.SAML2ServiceProvider) []string

type oidcRequiredMFALevelProvider interface {
	GetRequiredMFALevel() int
}

type samlRequiredMFALevelProvider interface {
	GetRequiredMFALevel() int
}

const mfaAssuranceFreshness = 10 * time.Minute

const (
	sessionKeyMFASelfServiceStepUpAction = "mfa_self_service_step_up_action"
	sessionKeyMFASelfServiceStepUpReturn = "mfa_self_service_step_up_return"
	sessionKeyMFASelfServiceStepUpAt     = "mfa_self_service_step_up_at"

	mfaSelfServiceActionRecoveryGenerate   = "recovery_generate"
	mfaSelfServiceActionTOTPDelete         = "totp_delete"
	mfaSelfServiceActionWebAuthnDelete     = "webauthn_delete"
	mfaSelfServiceActionWebAuthnDeviceDrop = "webauthn_device_delete"
	mfaSelfServiceActionWebAuthnDeviceName = "webauthn_device_name"
)

type mfaSelfServiceStepUpTarget struct {
	action     string
	returnPath string
}

// getRequiredMFAMethods returns the list of MFA methods configured as mandatory
// for the current IDP client or SAML service provider read from the cookie.
// Returns nil when no requirement is configured or the flow type is unknown.
func (h *FrontendHandler) getRequiredMFAMethods(mgr cookie.Manager) []string {
	return h.getFlowMFAMethods(mgr, (*config.OIDCClient).GetRequireMFA, (*config.SAML2ServiceProvider).GetRequireMFA)
}

// getSupportedMFAMethods returns the explicitly configured MFA methods supported
// for the current IDP client or SAML service provider.
func (h *FrontendHandler) getSupportedMFAMethods(mgr cookie.Manager) []string {
	return h.getFlowMFAMethods(mgr, (*config.OIDCClient).GetSupportedMFA, (*config.SAML2ServiceProvider).GetSupportedMFA)
}

// getEffectiveSupportedMFAMethods resolves the runtime MFA challenge method set.
// Explicit supported_mfa is a client allow-list; when it is unset, all
// registered methods remain eligible. require_mfa is evaluated separately as an
// enrollment/assurance policy and must not silently hide a valid SSO method.
func (h *FrontendHandler) getEffectiveSupportedMFAMethods(mgr cookie.Manager) []string {
	return h.getSupportedMFAMethods(mgr)
}

// getRequiredMFALevel returns the assurance level required by the current flow.
func (h *FrontendHandler) getRequiredMFALevel(mgr cookie.Manager) int {
	if mgr == nil || h.deps == nil {
		return 0
	}

	flowType := mgr.GetString(definitions.SessionKeyIDPFlowType, "")
	idpInstance := idp.NewNauthilusIDP(h.deps)

	switch flowType {
	case definitions.ProtoOIDC:
		clientID := mgr.GetString(definitions.SessionKeyIDPClientID, "")
		if clientID == "" {
			return 0
		}

		client, ok := idpInstance.FindClient(clientID)
		if !ok {
			return 0
		}

		return oidcClientRequiredMFALevel(client)

	case definitions.ProtoSAML:
		entityID := mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, "")
		if entityID == "" {
			return 0
		}

		sp, ok := idpInstance.FindSAMLServiceProvider(entityID)
		if !ok {
			return 0
		}

		return samlServiceProviderRequiredMFALevel(sp)
	}

	return h.getRequiredMFALevelByIdentifier(mgr)
}

// getRequiredMFALevelByIdentifier resolves assurance levels after sub-flow cleanup.
func (h *FrontendHandler) getRequiredMFALevelByIdentifier(mgr cookie.Manager) int {
	idpInstance := idp.NewNauthilusIDP(h.deps)

	if clientID := mgr.GetString(definitions.SessionKeyIDPClientID, ""); clientID != "" {
		if client, ok := idpInstance.FindClient(clientID); ok {
			return oidcClientRequiredMFALevel(client)
		}
	}

	if entityID := mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, ""); entityID != "" {
		if sp, ok := idpInstance.FindSAMLServiceProvider(entityID); ok {
			return samlServiceProviderRequiredMFALevel(sp)
		}
	}

	return 0
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

	return h.getFlowMFAMethodsByIdentifier(mgr, oidcSelector, samlSelector)
}

// getFlowMFAMethodsByIdentifier falls back to explicit client identifiers when
// temporary sub-flow cleanup has removed the protocol marker.
func (h *FrontendHandler) getFlowMFAMethodsByIdentifier(mgr cookie.Manager, oidcSelector oidcMFAMethodSelector, samlSelector samlMFAMethodSelector) []string {
	idpInstance := idp.NewNauthilusIDP(h.deps)

	if clientID := mgr.GetString(definitions.SessionKeyIDPClientID, ""); clientID != "" {
		if client, ok := idpInstance.FindClient(clientID); ok {
			return oidcSelector(client)
		}
	}

	if entityID := mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, ""); entityID != "" {
		if sp, ok := idpInstance.FindSAMLServiceProvider(entityID); ok {
			return samlSelector(sp)
		}
	}

	return nil
}

func (h *FrontendHandler) isMFAMethodSupported(mgr cookie.Manager, method string) bool {
	supported := h.getEffectiveSupportedMFAMethods(mgr)
	if len(supported) == 0 {
		return true
	}

	return slices.Contains(supported, method)
}

// sessionHasFreshMFAAssurance verifies that the session contains recent MFA proof.
func sessionHasFreshMFAAssurance(mgr cookie.Manager, requiredMethods []string, requiredScope string, now time.Time) bool {
	if mgr == nil {
		return false
	}

	method := mfaAssuranceMethodFromSession(mgr)
	if method == "" || !mfaAssuranceMethodAllowed(method, requiredMethods) {
		return false
	}

	assuredAt := time.Unix(mgr.GetInt64(definitions.SessionKeyMFAAssuranceAt, 0), 0)
	if assuredAt.IsZero() || assuredAt.After(now.Add(time.Minute)) {
		return false
	}

	if now.Sub(assuredAt) > mfaAssuranceFreshness {
		return false
	}

	if requiredScope != "" && mgr.GetString(definitions.SessionKeyMFAAssuranceScope, "") != requiredScope {
		return false
	}

	return true
}

// sessionHasFreshMFAAssuranceLevel verifies recent MFA proof at a minimum assurance level.
func sessionHasFreshMFAAssuranceLevel(mgr cookie.Manager, requiredLevel int, requiredScope string, now time.Time) bool {
	if requiredLevel <= 0 {
		return sessionHasFreshMFAAssurance(mgr, nil, requiredScope, now)
	}

	if !sessionHasFreshMFAAssurance(mgr, nil, requiredScope, now) {
		return false
	}

	return mgr.GetInt(definitions.SessionKeyMFAAssuranceLevel, 0) >= requiredLevel
}

// sessionHasFreshScopedMFAAssurance enforces strict method, scope, and level gates.
func sessionHasFreshScopedMFAAssurance(
	mgr cookie.Manager,
	requiredMethods []string,
	requiredScope string,
	requiredLevel int,
	now time.Time,
) bool {
	if len(requiredMethods) == 0 && requiredLevel <= 0 {
		return true
	}

	if len(requiredMethods) > 0 && !sessionHasFreshMFAAssurance(mgr, requiredMethods, requiredScope, now) {
		return false
	}

	if requiredLevel > 0 && !sessionHasFreshMFAAssuranceLevel(mgr, requiredLevel, requiredScope, now) {
		return false
	}

	return true
}

// sessionSatisfiesIDPSSOMFAAssurance accepts either the legacy
// client-scoped/method-scoped proof or a fresh SSO-level MFA proof from the
// current browser session. Normal OIDC/SAML application SSO should not step up
// again immediately after the user already completed MFA for the same session.
func sessionSatisfiesIDPSSOMFAAssurance(mgr cookie.Manager, requiredMethods []string, requiredScope string, now time.Time) bool {
	return sessionSatisfiesIDPSSOMFAAssurancePolicy(mgr, requiredMethods, requiredScope, 0, now)
}

// sessionSatisfiesIDPSSOMFAAssurancePolicy applies browser-SSO assurance semantics.
func sessionSatisfiesIDPSSOMFAAssurancePolicy(
	mgr cookie.Manager,
	requiredMethods []string,
	requiredScope string,
	requiredLevel int,
	now time.Time,
) bool {
	if requiredLevel > 0 {
		return sessionHasFreshMFAAssuranceLevel(mgr, requiredLevel, "", now)
	}

	if sessionHasFreshMFAAssurance(mgr, requiredMethods, requiredScope, now) {
		return true
	}

	return sessionHasFreshMFAAssurance(mgr, nil, "", now)
}

// mfaAssuranceMethodFromSession reads durable assurance method state with a legacy fallback.
func mfaAssuranceMethodFromSession(mgr cookie.Manager) string {
	if mgr == nil {
		return ""
	}

	method := normalizeMFAAssuranceMethod(mgr.GetString(definitions.SessionKeyMFAAssuranceMethod, ""))
	if method != "" {
		return method
	}

	return normalizeMFAAssuranceMethod(mgr.GetString(definitions.SessionKeyMFAMethod, ""))
}

// normalizeMFAAssuranceMethod maps legacy UI method labels to policy constants.
func normalizeMFAAssuranceMethod(method string) string {
	method = strings.TrimSpace(method)

	switch method {
	case "recovery":
		return definitions.MFAMethodRecoveryCodes
	default:
		return method
	}
}

// mfaAssuranceMethodAllowed checks whether a completed MFA method satisfies policy.
func mfaAssuranceMethodAllowed(method string, requiredMethods []string) bool {
	if len(requiredMethods) == 0 {
		return true
	}

	return slices.Contains(requiredMethods, method)
}

// oidcMFAAssuranceScope returns the session assurance scope for an OIDC client.
func oidcMFAAssuranceScope(clientID string) string {
	if clientID == "" {
		return definitions.ProtoOIDC
	}

	return definitions.ProtoOIDC + ":" + clientID
}

// samlMFAAssuranceScope returns the session assurance scope for a SAML service provider.
func samlMFAAssuranceScope(entityID string) string {
	if entityID == "" {
		return definitions.ProtoSAML
	}

	return definitions.ProtoSAML + ":" + entityID
}

// oidcClientRequiredMFAMethods returns the configured MFA policy for a client.
func oidcClientRequiredMFAMethods(client *config.OIDCClient) []string {
	if client == nil {
		return nil
	}

	return client.GetRequireMFA()
}

// samlServiceProviderRequiredMFAMethods returns the configured MFA policy for a service provider.
func samlServiceProviderRequiredMFAMethods(sp *config.SAML2ServiceProvider) []string {
	if sp == nil {
		return nil
	}

	return sp.GetRequireMFA()
}

// oidcClientRequiredMFALevel returns the configured assurance level for a client.
func oidcClientRequiredMFALevel(client *config.OIDCClient) int {
	if client == nil {
		return 0
	}

	provider, ok := any(client).(oidcRequiredMFALevelProvider)
	if !ok {
		return 0
	}

	return provider.GetRequiredMFALevel()
}

// samlServiceProviderRequiredMFALevel returns the configured assurance level for a service provider.
func samlServiceProviderRequiredMFALevel(sp *config.SAML2ServiceProvider) int {
	if sp == nil {
		return 0
	}

	provider, ok := any(sp).(samlRequiredMFALevelProvider)
	if !ok {
		return 0
	}

	return provider.GetRequiredMFALevel()
}

// redirectTargetForMissingMFAAssurance returns the existing MFA challenge page.
func (h *OIDCHandler) redirectTargetForMissingMFAAssurance(ctx *gin.Context) string {
	if h != nil && h.frontend != nil {
		return h.frontend.getMFASelectPath(ctx)
	}

	return frontendMFASelectPath
}

// enforceOIDCClientMFAAssurance blocks final OIDC authorization without fresh MFA.
func (h *OIDCHandler) enforceOIDCClientMFAAssurance(ctx *gin.Context, mgr cookie.Manager, client *config.OIDCClient) bool {
	return h.enforceOIDCClientMFAAssuranceWithChecker(ctx, mgr, client, sessionHasFreshScopedMFAAssurance)
}

type oidcMFAAssuranceChecker func(cookie.Manager, []string, string, int, time.Time) bool

func (h *OIDCHandler) enforceOIDCClientMFAAssuranceWithChecker(
	ctx *gin.Context,
	mgr cookie.Manager,
	client *config.OIDCClient,
	checker oidcMFAAssuranceChecker,
) bool {
	required := oidcClientRequiredMFAMethods(client)
	requiredLevel := oidcClientRequiredMFALevel(client)

	if len(required) == 0 && requiredLevel <= 0 {
		return true
	}

	if checker(mgr, required, oidcMFAAssuranceScope(client.ClientID), requiredLevel, time.Now()) {
		return true
	}

	if !h.prepareOIDCClientMFAAssuranceChallenge(ctx, mgr, client) {
		return false
	}

	ctx.Redirect(http.StatusFound, h.redirectTargetForMissingMFAAssurance(ctx))

	return false
}

// enforceOIDCClientSSOMFAAssurance applies normal browser SSO semantics for
// authorization-code flows. Device-code approval intentionally keeps the
// stricter client-scoped OIDC assurance check.
func (h *OIDCHandler) enforceOIDCClientSSOMFAAssurance(ctx *gin.Context, mgr cookie.Manager, client *config.OIDCClient) bool {
	return h.enforceOIDCClientMFAAssuranceWithChecker(ctx, mgr, client, sessionSatisfiesIDPSSOMFAAssurancePolicy)
}

// enforceSAMLServiceProviderMFAAssurance blocks SAML assertion issuance without fresh MFA.
func (h *SAMLHandler) enforceSAMLServiceProviderMFAAssurance(ctx *gin.Context, mgr cookie.Manager, sp *config.SAML2ServiceProvider) bool {
	required := samlServiceProviderRequiredMFAMethods(sp)
	requiredLevel := samlServiceProviderRequiredMFALevel(sp)

	if len(required) == 0 && requiredLevel <= 0 {
		return true
	}

	if sessionSatisfiesIDPSSOMFAAssurancePolicy(mgr, required, samlMFAAssuranceScope(sp.EntityID), requiredLevel, time.Now()) {
		return true
	}

	if !h.prepareSAMLServiceProviderMFAAssuranceChallenge(ctx, mgr, sp) {
		return false
	}

	ctx.Redirect(http.StatusFound, frontendMFASelectPath)

	return false
}

// prepareOIDCClientMFAAssuranceChallenge seeds the MFA UI for existing sessions.
func (h *OIDCHandler) prepareOIDCClientMFAAssuranceChallenge(ctx *gin.Context, mgr cookie.Manager, client *config.OIDCClient) bool {
	if mgr == nil || client == nil {
		return false
	}

	if !prepareOIDCMFAAssuranceSession(mgr, client.ClientID) {
		return false
	}

	return saveMFAAssuranceChallenge(ctx, mgr, h.deps)
}

// prepareSAMLServiceProviderMFAAssuranceChallenge seeds the MFA UI for SAML step-up.
func (h *SAMLHandler) prepareSAMLServiceProviderMFAAssuranceChallenge(ctx *gin.Context, mgr cookie.Manager, sp *config.SAML2ServiceProvider) bool {
	if mgr == nil || sp == nil {
		return false
	}

	if !prepareSAMLMFAAssuranceSession(mgr, sp.EntityID) {
		return false
	}

	return saveMFAAssuranceChallenge(ctx, mgr, h.deps)
}

// saveMFAAssuranceChallenge persists step-up state before the browser redirect.
func saveMFAAssuranceChallenge(ctx *gin.Context, mgr cookie.Manager, handlerDeps *deps.Deps) bool {
	setMFAAssuranceFlowAuthOutcome(ctx, mgr, handlerDeps)

	now := time.Now()

	storeIDPFlowResumeFallback(mgr, now)
	storeIDPFlowResumeFallbackFromRequest(ctx, mgr, now)

	if err := mgr.Save(ctx); err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to save session")
		return false
	}

	return true
}

// setMFAAssuranceFlowAuthOutcome marks the current flow as authenticated when Redis state is available.
func setMFAAssuranceFlowAuthOutcome(ctx *gin.Context, mgr cookie.Manager, handlerDeps *deps.Deps) {
	if ctx == nil || mgr == nil || handlerDeps == nil || handlerDeps.Redis == nil || handlerDeps.Cfg == nil || handlerDeps.Cfg.GetServer() == nil {
		return
	}

	_ = setFlowAuthOutcome(ctx.Request.Context(), mgr, handlerDeps.Redis, handlerDeps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.AuthOutcomeOK)
}

// prepareOIDCMFAAssuranceSession writes the MFA session state needed by challenge pages.
func prepareOIDCMFAAssuranceSession(mgr cookie.Manager, clientID string) bool {
	return prepareProtocolMFAAssuranceSession(mgr, definitions.ProtoOIDC, clientID, "")
}

// prepareSAMLMFAAssuranceSession writes the MFA session state needed by challenge pages.
func prepareSAMLMFAAssuranceSession(mgr cookie.Manager, entityID string) bool {
	return prepareProtocolMFAAssuranceSession(mgr, definitions.ProtoSAML, "", entityID)
}

// prepareProtocolMFAAssuranceSession writes common MFA state for an IDP protocol.
func prepareProtocolMFAAssuranceSession(mgr cookie.Manager, protocol string, clientID string, samlEntityID string) bool {
	if mgr == nil {
		return false
	}

	account := mgr.GetString(definitions.SessionKeyAccount, "")
	if account == "" {
		return false
	}

	user := &backend.User{
		Name:        account,
		ID:          mgr.GetString(definitions.SessionKeyUniqueUserID, ""),
		DisplayName: mgr.GetString(definitions.SessionKeyDisplayName, ""),
	}
	if user.ID == "" {
		user.ID = mgr.GetString(definitions.SessionKeySubject, "")
	}

	mgr.Set(definitions.SessionKeyUsername, account)
	mgr.Set(definitions.SessionKeyProtocol, protocol)
	mgr.Set(definitions.SessionKeyIDPFlowType, protocol)
	setProtocolMFAAssuranceIdentifier(mgr, clientID, samlEntityID)
	core.StorePendingIDPMFAIdentity(mgr, user)
	core.StorePendingIDPMFAFactor(mgr, user)
	cookie.SetAuthResult(mgr, account, definitions.AuthResultOK)

	return true
}

// setProtocolMFAAssuranceIdentifier records the active OIDC client or SAML SP.
func setProtocolMFAAssuranceIdentifier(mgr cookie.Manager, clientID string, samlEntityID string) {
	if clientID != "" {
		mgr.Set(definitions.SessionKeyIDPClientID, clientID)
	}

	if samlEntityID != "" {
		mgr.Set(definitions.SessionKeyIDPSAMLEntityID, samlEntityID)
	}
}

// redirectExistingSessionMFAAssurance keeps first-factor sessions in the MFA challenge path.
func (h *FrontendHandler) redirectExistingSessionMFAAssurance(ctx *gin.Context, mgr cookie.Manager) bool {
	if !h.prepareExistingSessionMFAAssuranceChallenge(mgr) {
		return false
	}

	ctx.Redirect(http.StatusFound, h.getMFASelectPath(ctx))

	return true
}

// prepareExistingSessionMFAAssuranceChallenge rebuilds MFA state for step-up pages.
func (h *FrontendHandler) prepareExistingSessionMFAAssuranceChallenge(mgr cookie.Manager) bool {
	required := h.getRequiredMFAMethods(mgr)
	requiredLevel := h.getRequiredMFALevel(mgr)

	if len(required) == 0 && requiredLevel <= 0 {
		return false
	}

	oidcClientID, samlEntityID := h.getFlowClientIdentifiers(mgr)

	scope := existingSessionMFAAssuranceScope(oidcClientID, samlEntityID)
	if scope == "" {
		return false
	}

	if sessionSatisfiesIDPSSOMFAAssurancePolicy(mgr, required, scope, requiredLevel, time.Now()) {
		return false
	}

	if oidcClientID != "" {
		return prepareOIDCMFAAssuranceSession(mgr, oidcClientID)
	}

	return prepareSAMLMFAAssuranceSession(mgr, samlEntityID)
}

// existingSessionMFAAssuranceScope resolves the flow-specific assurance scope.
func existingSessionMFAAssuranceScope(oidcClientID string, samlEntityID string) string {
	switch {
	case oidcClientID != "":
		return oidcMFAAssuranceScope(oidcClientID)
	case samlEntityID != "":
		return samlMFAAssuranceScope(samlEntityID)
	default:
		return ""
	}
}

// enforceMFASelfServiceStepUp blocks sensitive MFA mutations without recent MFA.
func (h *FrontendHandler) enforceMFASelfServiceStepUp(ctx *gin.Context) bool {
	if sessionHasFreshMFAAssurance(cookie.GetManager(ctx), nil, definitions.ProtoIDP, time.Now()) {
		return true
	}

	if !h.prepareMFASelfServiceStepUp(ctx) {
		h.renderErrorModal(ctx, "Recent MFA verification required")

		return false
	}

	h.redirectMFASelfServiceStepUp(ctx)

	return false
}

// prepareMFASelfServiceStepUp stores only whitelisted return-and-retry state for
// a sensitive self-service mutation and rebuilds the normal MFA challenge state.
func (h *FrontendHandler) prepareMFASelfServiceStepUp(ctx *gin.Context) bool {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		return false
	}

	target, ok := mfaSelfServiceStepUpTargetForRequest(ctx)
	if !ok {
		return false
	}

	account := mgr.GetString(definitions.SessionKeyAccount, "")
	if account == "" {
		return false
	}

	user := &backend.User{
		Name:        account,
		ID:          mgr.GetString(definitions.SessionKeyUniqueUserID, ""),
		DisplayName: mgr.GetString(definitions.SessionKeyDisplayName, ""),
	}
	if user.ID == "" {
		user.ID = mgr.GetString(definitions.SessionKeySubject, "")
	}

	mgr.Set(sessionKeyMFASelfServiceStepUpAction, target.action)
	mgr.Set(sessionKeyMFASelfServiceStepUpReturn, target.returnPath)
	mgr.Set(sessionKeyMFASelfServiceStepUpAt, time.Now().Unix())
	mgr.Set(definitions.SessionKeyUsername, account)
	mgr.Set(definitions.SessionKeyProtocol, definitions.ProtoIDP)
	mgr.Set(definitions.SessionKeyIDPFlowType, definitions.ProtoIDP)
	mgr.Delete(definitions.SessionKeyIDPClientID)
	mgr.Delete(definitions.SessionKeyIDPSAMLEntityID)
	core.StorePendingIDPMFAIdentity(mgr, user)
	core.StorePendingIDPMFAFactor(mgr, user)
	cookie.SetAuthResult(mgr, account, definitions.AuthResultOK)

	if err := mgr.Save(ctx); err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to save session")

		return false
	}

	return true
}

// mfaSelfServiceStepUpTargetForRequest maps sensitive self-service routes to a
// fixed action label and safe return surface. Request-controlled return URLs are
// deliberately ignored.
func mfaSelfServiceStepUpTargetForRequest(ctx *gin.Context) (mfaSelfServiceStepUpTarget, bool) {
	if ctx == nil || ctx.Request == nil {
		return mfaSelfServiceStepUpTarget{}, false
	}

	method := ctx.Request.Method
	path := unlocalizedMFARootPath(ctx, ctx.Request.URL.Path)

	switch {
	case method == http.MethodPost && isRecoveryGeneratePath(path):
		return mfaSelfServiceStepUpTarget{
			action:     mfaSelfServiceActionRecoveryGenerate,
			returnPath: localizedMFARootPath(ctx, definitions.MFARoot+"/register/home"),
		}, true
	case method == http.MethodDelete && path == definitions.MFARoot+"/totp":
		return mfaSelfServiceStepUpTarget{
			action:     mfaSelfServiceActionTOTPDelete,
			returnPath: localizedMFARootPath(ctx, definitions.MFARoot+"/register/home"),
		}, true
	case method == http.MethodDelete && path == definitions.MFARoot+"/webauthn":
		return mfaSelfServiceStepUpTarget{
			action:     mfaSelfServiceActionWebAuthnDelete,
			returnPath: localizedMFARootPath(ctx, definitions.MFARoot+"/register/home"),
		}, true
	case method == http.MethodDelete && strings.HasPrefix(path, definitions.MFARoot+"/webauthn/device/"):
		return mfaSelfServiceStepUpTarget{
			action:     mfaSelfServiceActionWebAuthnDeviceDrop,
			returnPath: localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/devices"),
		}, true
	case method == http.MethodPost && isWebAuthnDeviceNamePath(path):
		return mfaSelfServiceStepUpTarget{
			action:     mfaSelfServiceActionWebAuthnDeviceName,
			returnPath: localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/devices"),
		}, true
	default:
		return mfaSelfServiceStepUpTarget{}, false
	}
}

// isRecoveryGeneratePath accepts the localized and default recovery generation routes.
func isRecoveryGeneratePath(path string) bool {
	return path == definitions.MFARoot+"/recovery/generate" ||
		strings.HasPrefix(path, definitions.MFARoot+"/recovery/generate/")
}

// isWebAuthnDeviceNamePath accepts WebAuthn credential rename routes.
func isWebAuthnDeviceNamePath(path string) bool {
	return strings.HasPrefix(path, definitions.MFARoot+"/webauthn/device/") &&
		strings.HasSuffix(path, "/name")
}

// redirectMFASelfServiceStepUp sends normal requests and HTMX requests to a
// visible MFA challenge page. HTMX needs HX-Redirect to escape modal targets.
func (h *FrontendHandler) redirectMFASelfServiceStepUp(ctx *gin.Context) {
	target := h.getMFASelectPath(ctx)
	if ctx.GetHeader("HX-Request") != "" {
		ctx.Header("HX-Redirect", target)
		ctx.Status(http.StatusOK)

		return
	}

	ctx.Redirect(http.StatusFound, target)
}

// redirectPendingSelfServiceStepUp returns form-based MFA completions to the
// whitelisted self-service surface where the user can retry the original action.
func (h *FrontendHandler) redirectPendingSelfServiceStepUp(ctx *gin.Context, mgr cookie.Manager) bool {
	target, ok := h.pendingSelfServiceStepUpRedirectURI(ctx, mgr)
	if !ok {
		return false
	}

	ctx.Redirect(http.StatusFound, target)

	return true
}

// pendingSelfServiceStepUpRedirectURI consumes a pending self-service step-up
// return target after verifying that the stored action and return path match the
// server-side whitelist.
func (h *FrontendHandler) pendingSelfServiceStepUpRedirectURI(ctx *gin.Context, mgr cookie.Manager) (string, bool) {
	target := popPendingSelfServiceStepUpReturnTarget(ctx, mgr)
	if target == "" {
		return "", false
	}

	if err := mgr.Save(ctx); err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to save session")

		return "", false
	}

	return target, true
}

// popPendingSelfServiceStepUpReturnTarget clears and validates self-service
// step-up state before returning the safe retry page.
func popPendingSelfServiceStepUpReturnTarget(ctx *gin.Context, mgr cookie.Manager) string {
	if mgr == nil {
		return ""
	}

	action := mgr.GetString(sessionKeyMFASelfServiceStepUpAction, "")
	storedReturn := mgr.GetString(sessionKeyMFASelfServiceStepUpReturn, "")
	clearPendingSelfServiceStepUp(mgr)

	expectedReturn, ok := mfaSelfServiceStepUpReturnForAction(action)
	if !ok || !matchesMFASelfServiceReturn(storedReturn, expectedReturn) {
		return ""
	}

	if ctx != nil && strings.TrimSpace(ctx.Param("languageTag")) != "" {
		return localizedMFARootPath(ctx, expectedReturn)
	}

	return storedReturn
}

// matchesMFASelfServiceReturn accepts the default return surface and its
// localized route variants.
func matchesMFASelfServiceReturn(storedReturn string, expectedReturn string) bool {
	return storedReturn == expectedReturn || strings.HasPrefix(storedReturn, expectedReturn+"/")
}

// mfaSelfServiceStepUpReturnForAction resolves the only valid retry surface for
// each pending self-service action.
func mfaSelfServiceStepUpReturnForAction(action string) (string, bool) {
	switch action {
	case mfaSelfServiceActionRecoveryGenerate, mfaSelfServiceActionTOTPDelete, mfaSelfServiceActionWebAuthnDelete:
		return definitions.MFARoot + "/register/home", true
	case mfaSelfServiceActionWebAuthnDeviceDrop, mfaSelfServiceActionWebAuthnDeviceName:
		return definitions.MFARoot + "/webauthn/devices", true
	default:
		return "", false
	}
}

// clearPendingSelfServiceStepUp removes non-replayable self-service step-up state.
func clearPendingSelfServiceStepUp(mgr cookie.Manager) {
	if mgr == nil {
		return
	}

	mgr.Delete(sessionKeyMFASelfServiceStepUpAction)
	mgr.Delete(sessionKeyMFASelfServiceStepUpReturn)
	mgr.Delete(sessionKeyMFASelfServiceStepUpAt)
}

// recordRequireMFARegistrationAssurance marks a just-satisfied registration flow as fresh MFA proof.
func (h *FrontendHandler) recordRequireMFARegistrationAssurance(mgr cookie.Manager, required []string) {
	if mgr == nil {
		return
	}

	if len(required) == 0 {
		return
	}

	mgr.Set(definitions.SessionKeyMFACompleted, true)

	method := normalizeMFAAssuranceMethod(required[0])

	mgr.Set(definitions.SessionKeyMFAMethod, method)
	mgr.Set(definitions.SessionKeyMFAAssuranceMethod, method)
	mgr.Set(definitions.SessionKeyMFAAssuranceAt, time.Now().Unix())

	oidcClientID, samlEntityID := h.getFlowClientIdentifiers(mgr)
	protocol := definitions.ProtoIDP

	switch {
	case oidcClientID != "":
		protocol = definitions.ProtoOIDC
		mgr.Set(definitions.SessionKeyMFAAssuranceScope, oidcMFAAssuranceScope(oidcClientID))
	case samlEntityID != "":
		protocol = definitions.ProtoSAML
		mgr.Set(definitions.SessionKeyMFAAssuranceScope, definitions.ProtoSAML+":"+samlEntityID)
	default:
		mgr.Delete(definitions.SessionKeyMFAAssuranceScope)
	}

	mgr.Set(definitions.SessionKeyMFAAssuranceLevel, core.IDPMFAAssuranceLevel(mgr, method, protocol))
}

// removeCompletedRequireMFAMethod records assurance when a forced-registration flow is complete.
func (h *FrontendHandler) removeCompletedRequireMFAMethod(ctx *gin.Context, mgr cookie.Manager, method string) string {
	if mgr == nil || !mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
		return ""
	}

	h.getRequireMFAFlowMethodsFromStore(ctx, mgr)

	remaining := flowdomain.RemoveRequireMFAPendingMethod(mgr, method)
	if remaining == "" {
		h.recordRequireMFARegistrationAssurance(mgr, []string{method})
	}

	return remaining
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
		return h.getFlowClientIdentifiersByPresence(mgr)
	}
}

// getFlowClientIdentifiersByPresence recovers identifiers after sub-flow cleanup.
func (h *FrontendHandler) getFlowClientIdentifiersByPresence(mgr cookie.Manager) (string, string) {
	oidcClientID := mgr.GetString(definitions.SessionKeyIDPClientID, "")
	samlEntityID := mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, "")

	switch {
	case oidcClientID != "" && samlEntityID == "":
		return oidcClientID, ""
	case samlEntityID != "" && oidcClientID == "":
		return "", samlEntityID
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
	if !flowdomain.IsRequireMFAFlowID(flowID) {
		flowdomain.ClearRequireMFAContext(mgr)

		return
	}

	if h == nil || h.deps == nil || h.deps.Cfg == nil {
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
	savedOIDCClientID := mgr.GetString(definitions.SessionKeyIDPClientID, "")
	savedSAMLEntityID := mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, "")

	controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	if _, err := controller.Abort(context.Background(), flowID); err != nil {
		flowdomain.ClearRequireMFAContext(mgr)

		return
	}

	// Restore the original IDP flow context so that the caller can still
	// redirect back to the correct IDP endpoint (OIDC authorize, SAML SSO, etc.).
	flowdomain.RestoreFlowCookieContext(mgr, savedFlowType, savedGrantType)
	restoreRequireMFAFlowIdentifiers(mgr, savedOIDCClientID, savedSAMLEntityID)

	if savedParentFlowID != "" {
		mgr.Set(definitions.SessionKeyIDPFlowID, savedParentFlowID)
	}

	flowdomain.SetRequireMFAPending(mgr, "")
}

// restoreRequireMFAFlowIdentifiers restores parent client identifiers after sub-flow cleanup.
func restoreRequireMFAFlowIdentifiers(mgr cookie.Manager, oidcClientID string, samlEntityID string) {
	if mgr == nil {
		return
	}

	if oidcClientID != "" {
		mgr.Set(definitions.SessionKeyIDPClientID, oidcClientID)
	}

	if samlEntityID != "" {
		mgr.Set(definitions.SessionKeyIDPSAMLEntityID, samlEntityID)
	}
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
	redirectURI, ok := h.requireMFARegistrationRedirectURI(ctx, mgr)
	if !ok {
		return false
	}

	ctx.Redirect(http.StatusFound, redirectURI)

	return true
}

// requireMFARegistrationRedirectURI prepares a required-MFA registration flow
// and returns its next target without committing to a concrete HTTP transport.
func (h *FrontendHandler) requireMFARegistrationRedirectURI(ctx *gin.Context, mgr cookie.Manager) (string, bool) {
	if mgr == nil {
		return "", false
	}

	if mgr.GetString(definitions.SessionKeyIDPFlowID, "") == "" {
		return "", false
	}

	lookupCtx := backendDataLookupContext(ctx)
	required, user, protocol, ok := h.requireMFARegistrationContext(lookupCtx, mgr)

	if !ok {
		return "", false
	}

	missing := h.missingRequireMFAMethods(lookupCtx, mgr, user, protocol, required)
	if len(missing) == 0 {
		h.clearRequireMFARegistrationState(mgr)

		return "", false
	}

	flowdomain.SetRequireMFAPending(mgr, strings.Join(missing, ","))

	return h.startRequireMFARegistrationFlow(lookupCtx, mgr, user, protocol, missing)
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

	return required, user, idpProtocolFromSession(mgr), true
}

// idpProtocolFromSession resolves the protocol used to persist internal sub-flows.
func idpProtocolFromSession(mgr cookie.Manager) string {
	if mgr == nil {
		return ""
	}

	protocol := mgr.GetString(definitions.SessionKeyProtocol, "")
	if protocol != "" {
		return protocol
	}

	return mgr.GetString(definitions.SessionKeyIDPFlowType, "")
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
) (string, bool) {
	parentFlowID := requireMFAParentFlowID(mgr)
	if parentFlowID != "" {
		mgr.Set(definitions.SessionKeyRequireMFAParentFlowID, parentFlowID)
	}

	flowID := flowdomain.NewRequireMFAFlowID(parentFlowID)
	if flowID == "" {
		h.clearRequireMFARegistrationState(mgr)

		return "", false
	}

	nextTarget := h.nextRequiredMFARegistrationTarget(mgr)
	if nextTarget == "" {
		h.clearRequireMFARegistrationState(mgr)

		return "", false
	}

	controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	decision, err := controller.Start(ctx.Request.Context(), &flowdomain.State{
		FlowID:       flowID,
		Type:         flowdomain.FlowTypeRequireMFA,
		Protocol:     requireMFAFlowProtocol(protocol),
		CurrentStep:  flowdomain.FlowStepStart,
		ReturnTarget: nextTarget,
		PendingMFA:   true,
		Metadata:     requireMFAFlowMetadata(mgr, user, strings.Join(missing, ",")),
	}, time.Now())
	if err != nil {
		h.clearRequireMFARegistrationState(mgr)

		return "", false
	}

	if decision.RedirectURI == "" {
		h.clearRequireMFARegistrationState(mgr)

		return "", false
	}

	advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepRequireMFAChallenge)

	return decision.RedirectURI, true
}

func requireMFAFlowMetadata(mgr cookie.Manager, user *backend.User, missing string) map[string]string {
	metadata := map[string]string{
		"require_mfa": missing,
	}

	if mgr != nil {
		if clientID := mgr.GetString(definitions.SessionKeyIDPClientID, ""); clientID != "" {
			metadata[flowdomain.FlowMetadataClientID] = clientID
		}

		if entityID := mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, ""); entityID != "" {
			metadata[flowdomain.FlowMetadataSAMLEntityID] = entityID
		}

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

// getRequireMFAFlowMethodsFromStore reads original mandatory methods from flow metadata.
func (h *FrontendHandler) getRequireMFAFlowMethodsFromStore(ctx *gin.Context, mgr cookie.Manager) []string {
	if h == nil || h.deps == nil || h.deps.Cfg == nil || ctx == nil || mgr == nil {
		return nil
	}

	flowID := requireMFAFlowIDFromSession(mgr)
	if flowID == "" {
		return nil
	}

	controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	state, err := controller.State(ctx.Request.Context(), flowID)
	if err != nil || state == nil || state.Type != flowdomain.FlowTypeRequireMFA {
		return nil
	}

	restoreRequireMFAClientContext(mgr, state)

	return requireMFAMethodsFromMetadata(state.Metadata)
}

// requireMFAMethodsFromMetadata parses the required methods stored with a require-MFA flow.
func requireMFAMethodsFromMetadata(metadata map[string]string) []string {
	if metadata == nil {
		return nil
	}

	raw := metadata["require_mfa"]
	if raw == "" {
		return nil
	}

	methods := strings.Split(raw, ",")
	kept := methods[:0]

	for _, method := range methods {
		method = normalizeMFAAssuranceMethod(method)
		if method != "" {
			kept = append(kept, method)
		}
	}

	return kept
}

func (h *FrontendHandler) restoreRequireMFAIdentityContextFromStore(ctx *gin.Context, mgr cookie.Manager) bool {
	if h == nil || h.deps == nil || h.deps.Cfg == nil || ctx == nil || mgr == nil {
		return true
	}

	flowID := requireMFAFlowIDFromSession(mgr)
	if flowID == "" {
		return true
	}

	controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	state, err := controller.State(ctx.Request.Context(), flowID)
	if err != nil {
		return false
	}

	return restoreRequireMFAIdentityContext(mgr, state)
}

func requireMFAFlowIDFromSession(mgr cookie.Manager) string {
	if mgr == nil {
		return ""
	}

	flowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if flowdomain.IsRequireMFAFlowID(flowID) {
		return flowID
	}

	if mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
		return flowdomain.NewRequireMFAFlowID(mgr.GetString(definitions.SessionKeyRequireMFAParentFlowID, ""))
	}

	return ""
}

// restoreRequireMFAIdentityContext restores identity metadata only when it matches the current session.
func restoreRequireMFAIdentityContext(mgr cookie.Manager, state *flowdomain.State) bool {
	if mgr == nil || state == nil || state.Type != flowdomain.FlowTypeRequireMFA || state.Metadata == nil {
		return false
	}

	if !requireMFAIdentityMetadataMatches(mgr, state.Metadata) {
		return false
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

	restoreRequireMFAClientContext(mgr, state)

	return true
}

// restoreRequireMFAClientContext restores the parent client identifier for assurance checks.
func restoreRequireMFAClientContext(mgr cookie.Manager, state *flowdomain.State) {
	if mgr == nil || state == nil || state.Metadata == nil {
		return
	}

	switch state.Protocol {
	case flowdomain.FlowProtocolOIDC:
		if mgr.GetString(definitions.SessionKeyIDPFlowType, "") == "" {
			mgr.Set(definitions.SessionKeyIDPFlowType, definitions.ProtoOIDC)
		}

		if mgr.GetString(definitions.SessionKeyIDPClientID, "") == "" {
			if clientID := state.Metadata[flowdomain.FlowMetadataClientID]; clientID != "" {
				mgr.Set(definitions.SessionKeyIDPClientID, clientID)
			}
		}
	case flowdomain.FlowProtocolSAML:
		if mgr.GetString(definitions.SessionKeyIDPFlowType, "") == "" {
			mgr.Set(definitions.SessionKeyIDPFlowType, definitions.ProtoSAML)
		}

		if mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, "") == "" {
			if entityID := state.Metadata[flowdomain.FlowMetadataSAMLEntityID]; entityID != "" {
				mgr.Set(definitions.SessionKeyIDPSAMLEntityID, entityID)
			}
		}
	}
}

// requireMFAParentFlowID returns the parent flow id used to derive an isolated required-MFA sub-flow.
func requireMFAParentFlowID(mgr cookie.Manager) string {
	if mgr == nil {
		return ""
	}

	parentFlowID := mgr.GetString(definitions.SessionKeyRequireMFAParentFlowID, "")
	if parentFlowID != "" {
		return parentFlowID
	}

	flowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if flowdomain.IsRequireMFAFlowID(flowID) {
		return ""
	}

	return flowID
}

// requireMFAIdentityMetadataMatches rejects stored metadata for a different authenticated identity.
func requireMFAIdentityMetadataMatches(mgr cookie.Manager, metadata map[string]string) bool {
	return requireMFAIdentityFieldMatches(mgr, metadata, definitions.SessionKeyAccount, flowdomain.FlowMetadataAccount) &&
		requireMFAIdentityFieldMatches(mgr, metadata, definitions.SessionKeyUniqueUserID, flowdomain.FlowMetadataUniqueUserID)
}

// requireMFAIdentityFieldMatches compares one current session field with stored flow metadata.
func requireMFAIdentityFieldMatches(mgr cookie.Manager, metadata map[string]string, sessionKey string, metadataKey string) bool {
	current := mgr.GetString(sessionKey, "")
	stored := metadata[metadataKey]

	return current == "" || stored == "" || current == stored
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
	if mgr != nil && mgr.GetBool(definitions.SessionKeyHaveTOTP, false) {
		return true
	}

	if h.hasTOTP(user) {
		return true
	}

	if h == nil || h.deps == nil || ctx == nil {
		return false
	}

	username := ""
	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyAccount, "")
	}

	lookupCtx := backendDataLookupContext(ctx)
	h.purgeCachedAuthenticationForUser(lookupCtx, username)

	userData, err := h.GetUserBackendData(lookupCtx)
	if err != nil || userData == nil {
		return false
	}

	return userData.HaveTOTP
}

func (h *FrontendHandler) hasRecoveryCodesForRequireMFA(ctx *gin.Context, mgr cookie.Manager, user *backend.User) bool {
	if h.hasRecoveryCodes(user) {
		return true
	}

	if mgr != nil && mgr.GetBool(definitions.SessionKeyHaveRecoveryCodes, false) {
		return true
	}

	if mgr != nil && mgr.GetBool(definitions.SessionKeyRecoveryCodesSaved, false) {
		return true
	}

	username := ""
	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyAccount, "")
	}

	lookupCtx := backendDataLookupContext(ctx)
	h.purgeCachedAuthenticationForUser(lookupCtx, username)

	userData, err := h.GetUserBackendData(lookupCtx)
	if err != nil || userData == nil {
		return false
	}

	return userData.NumRecoveryCodes > 0
}

func (h *FrontendHandler) purgeCachedAuthenticationForUser(ctx *gin.Context, username string) {
	if h == nil || h.deps == nil || username == "" {
		return
	}

	lookupCtx := backendDataLookupContext(ctx)
	state := core.NewAuthStateWithSetupWithDeps(lookupCtx, h.deps.Auth())

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

	if !h.restoreRequireMFAIdentityContextFromStore(ctx, mgr) {
		h.clearRequireMFARegistrationState(mgr)
		ctx.Redirect(http.StatusFound, "/")

		return
	}

	pending := mgr.GetString(definitions.SessionKeyRequireMFAPending, "")

	if pending == "" {
		// All required methods registered — clean up and resume the IDP flow.
		required := h.getRequiredMFAMethods(mgr)

		if len(required) == 0 {
			required = h.getRequireMFAFlowMethodsFromStore(ctx, mgr)
		}

		h.clearRequireMFARegistrationState(mgr)

		if len(required) == 0 {
			required = h.getRequiredMFAMethods(mgr)
		}

		h.recordRequireMFARegistrationAssurance(mgr, required)
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

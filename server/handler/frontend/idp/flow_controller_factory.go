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
	"net/url"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/gin-gonic/gin"
)

const (
	frontendDefaultLanguageTag = "en"
	frontendLoginPath          = "/login"
	frontendMFASelectPath      = "/login/mfa"
	frontendDeviceVerifyPath   = "/oidc/device/verify"
	frontendDeviceConsentPath  = "/oidc/device/consent"
	frontendSAMLLogoutPath     = "/saml/slo"

	templateDataCSPNonce            = "CSPNonce"
	templateDataChecked             = "Checked"
	templateDataConfirmNo           = "ConfirmNo"
	templateDataConfirmTitle        = "ConfirmTitle"
	templateDataConfirmYes          = "ConfirmYes"
	templateDataDescription         = "Description"
	templateDataIDPClientName       = "IDPClientName"
	templateDataLanguageCurrentName = "LanguageCurrentName"
	templateDataLanguagePassive     = "LanguagePassive"
	templateDataLanguageTag         = "LanguageTag"
	templateDataName                = "Name"

	mfaMethodRecovery = "recovery"
	mfaMethodTOTP     = "totp"
	mfaMethodWebAuthn = "webauthn"

	oidcClientAuthMethodNone     = "none"
	oidcJSONFieldAccessToken     = "access_token"
	oidcJSONFieldActive          = "active"
	oidcJSONFieldAlgorithm       = "alg"
	oidcJSONFieldExpiresIn       = "expires_in"
	oidcJSONFieldKeyID           = "kid"
	oidcJSONFieldKeyType         = "kty"
	oidcJSONFieldKeyUse          = "use"
	oidcJSONFieldTokenType       = "token_type"
	oidcJSONTokenTypeBearer      = "Bearer"
	oidcJSONWebKeyAlgorithmEdDSA = "EdDSA"
	oidcJSONWebKeyAlgorithmRS256 = "RS256"
	oidcJSONWebKeyTypeOKP        = "OKP"
	oidcJSONWebKeyTypeRSA        = "RSA"
	oidcJSONWebKeyUseSignature   = "sig"
	oidcPKCEChallengeMethodS256  = "S256"
	oidcConsentDecisionAllow     = "allow"

	samlMetricLabelBinding     = "binding"
	samlMetricLabelMessageType = "message_type"
	samlMetricLabelOutcome     = "outcome"
	samlMetricLabelStatus      = "status"
	samlProtocolVersion        = "2.0"
	samlXMLIDAttribute         = "ID"

	idpResumeFallbackTTL = 10 * time.Minute
)

// newFlowController builds an IDP flow controller with Redis-backed state
// when available and cookie-reference fallback when Redis is unavailable.
func newFlowController(mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string) *flowdomain.Controller {
	if redisClient == nil || redisClient.GetWriteHandle() == nil {
		return flowdomain.NewController(flowdomain.NewReferenceAdapter(mgr))
	}

	referenceStore := flowdomain.NewReferenceAdapter(mgr)
	stateStore := flowdomain.NewRedisStore(redisClient.GetWriteHandle(), redisPrefix+"idp:flow", 0)

	return flowdomain.NewController(flowdomain.NewHybridStore(referenceStore, stateStore))
}

// advanceFlow advances the current flow to the given step.
// Errors are intentionally ignored: the flow controller is an enhancement
// and failing to advance must not break the login flow.
func advanceFlow(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string, to flowdomain.Step) {
	if mgr == nil {
		return
	}

	flowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if flowID == "" {
		return
	}

	controller := newFlowController(mgr, redisClient, redisPrefix)

	_, _ = controller.Advance(ctx, flowID, to, time.Now())
}

// completeFlow completes the current flow: deletes the Redis state via
// the controller and then removes all IDP cookie keys.
func completeFlow(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string) {
	if mgr == nil {
		return
	}

	flowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if flowID != "" {
		controller := newFlowController(mgr, redisClient, redisPrefix)

		_, _ = controller.Complete(ctx, flowID)
	}

	flowdomain.CleanupIDPState(mgr)
}

// abortFlow unconditionally deletes the flow state from Redis and cleans
// up all IDP cookie keys.  Use this for denied consent or error paths
// where the policy might not allow a regular Complete.
func abortFlow(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string) {
	if mgr == nil {
		return
	}

	flowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if flowID != "" {
		controller := newFlowController(mgr, redisClient, redisPrefix)

		_, _ = controller.Abort(ctx, flowID)
	}

	flowdomain.CleanupIDPState(mgr)
}

// resumeFlow resolves the persisted flow state and returns the next resume
// decision, including stale-flow recovery where possible.
func resumeFlow(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string) (flowdomain.Decision, error) {
	if mgr == nil {
		return flowdomain.Decision{Type: flowdomain.DecisionTypeRedirect, RedirectURI: "/"}, nil
	}

	flowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if flowID == "" {
		return flowdomain.Decision{Type: flowdomain.DecisionTypeRedirect, RedirectURI: "/"}, nil
	}

	controller := newFlowController(mgr, redisClient, redisPrefix)

	decision, err := controller.Resume(ctx, flowID)
	if err == nil {
		return decision, nil
	}

	recoveryDecision, recoverErr := controller.Recover(ctx, flowID, err)
	if recoverErr != nil {
		return flowdomain.Decision{}, err
	}

	return recoveryDecision, nil
}

func getFlowAuthOutcome(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string) (flowdomain.AuthOutcome, bool) {
	if mgr == nil {
		return flowdomain.AuthOutcomeUnknown, false
	}

	flowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if flowID == "" {
		return flowdomain.AuthOutcomeUnknown, false
	}

	controller := newFlowController(mgr, redisClient, redisPrefix)

	state, err := controller.State(ctx, flowID)
	if err != nil || state == nil {
		return flowdomain.AuthOutcomeUnknown, false
	}

	return state.AuthOutcome, true
}

func flowAuthFailureLatched(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string) bool {
	outcome, ok := getFlowAuthOutcome(ctx, mgr, redisClient, redisPrefix)

	return ok && outcome == flowdomain.AuthOutcomeFailLatched
}

func resetFlowAuthOutcomeForRetry(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string) bool {
	if mgr == nil {
		return false
	}

	flowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if flowID == "" {
		return false
	}

	controller := newFlowController(mgr, redisClient, redisPrefix)

	return controller.ResetAuthOutcomeForRetry(ctx, flowID, time.Now()) == nil
}

func resetFlowAuthOutcomeForLoginAttempt(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string) bool {
	if resetFlowAuthOutcomeForRetry(ctx, mgr, redisClient, redisPrefix) {
		return true
	}

	return setFlowAuthOutcome(ctx, mgr, redisClient, redisPrefix, flowdomain.AuthOutcomeUnknown)
}

func setFlowAuthOutcome(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string, outcome flowdomain.AuthOutcome) bool {
	if mgr == nil {
		return false
	}

	flowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if flowID == "" {
		return false
	}

	controller := newFlowController(mgr, redisClient, redisPrefix)

	return controller.SetAuthOutcome(ctx, flowID, outcome, time.Now()) == nil
}

// resumeIDPFlow resumes an interrupted IDP flow and performs the redirect
// implied by the flow decision.
func (h *FrontendHandler) resumeIDPFlow(ctx *gin.Context, mgr cookie.Manager) {
	redirectURI, ok := h.resumeIDPFlowRedirectURI(ctx, mgr)
	if !ok {
		return
	}

	if redirectURI == flowdomain.FlowMetadataResumeTargetDeviceCodeComplete {
		if h == nil || h.deps == nil {
			ctx.Redirect(http.StatusFound, "/")

			return
		}

		h.completeDeviceCodeFlow(ctx, mgr)

		return
	}

	ctx.Redirect(http.StatusFound, redirectURI)
}

// resumeIDPFlowRedirectURI resolves the next flow target without writing a
// redirect response. Fetch-based frontends use this to resume the same flow as
// form-based MFA completions.
func (h *FrontendHandler) resumeIDPFlowRedirectURI(ctx *gin.Context, mgr cookie.Manager) (string, bool) {
	redisClient, redisPrefix := h.flowStore()
	fallbackRedirectURI := fallbackIDPFlowRedirectURI(mgr)

	decision, err := resumeFlow(ctx.Request.Context(), mgr, redisClient, redisPrefix)
	if err != nil {
		ctx.Redirect(http.StatusFound, "/")

		return "", false
	}

	redirectURI := decision.RedirectURI
	if shouldUseFallbackIDPFlowRedirectURI(redirectURI) && fallbackRedirectURI != "" {
		redirectURI = fallbackRedirectURI
	}

	if redirectURI == "" {
		redirectURI = "/"
	}

	if isLoginSelfResume(ctx.Request.URL.Path, redirectURI) {
		abortFlow(ctx.Request.Context(), mgr, redisClient, redisPrefix)
		h.renderNoFlowError(ctx)

		return "", false
	}

	return redirectURI, true
}

func shouldUseFallbackIDPFlowRedirectURI(redirectURI string) bool {
	if redirectURI == "" {
		return true
	}

	return redirectURI == "/"
}

func fallbackIDPFlowRedirectURI(mgr cookie.Manager) string {
	if mgr == nil {
		return ""
	}

	if !idpResumeFallbackFresh(mgr, time.Now()) {
		return ""
	}

	target := mgr.GetString(definitions.SessionKeyIDPResumeFallbackURL, "")
	if target == flowdomain.FlowMetadataResumeTargetDeviceCodeComplete {
		return target
	}

	return safeLocalIDPResumeTarget(target)
}

func storeIDPFlowResumeFallback(mgr cookie.Manager, now time.Time) {
	if mgr == nil || mgr.GetString(definitions.SessionKeyIDPFlowID, "") == "" {
		return
	}

	var fallbackURL string

	switch mgr.GetString(definitions.SessionKeyIDPFlowType, "") {
	case definitions.ProtoOIDC:
		fallbackURL = oidcFlowResumeFallbackURL(mgr)
	case definitions.ProtoSAML:
		fallbackURL = safeLocalIDPResumeTarget(mgr.GetString(definitions.SessionKeyIDPOriginalURL, ""))
	}

	if fallbackURL == "" {
		mgr.Delete(definitions.SessionKeyIDPResumeFallbackURL)
		mgr.Delete(definitions.SessionKeyIDPResumeFallbackAt)

		return
	}

	mgr.Set(definitions.SessionKeyIDPResumeFallbackURL, fallbackURL)
	mgr.Set(definitions.SessionKeyIDPResumeFallbackAt, now.Unix())
}

// storeIDPFlowResumeFallbackFromRequest preserves the active local IdP request
// when Redis-backed flow state cannot be reconstructed from cookie metadata.
func storeIDPFlowResumeFallbackFromRequest(ctx *gin.Context, mgr cookie.Manager, now time.Time) {
	if ctx == nil || ctx.Request == nil || mgr == nil {
		return
	}

	if fallbackIDPFlowRedirectURI(mgr) != "" {
		return
	}

	fallbackURL := safeLocalIDPResumeTarget(ctx.Request.URL.RequestURI())
	if fallbackURL == "" || isLoginPath(redirectPath(fallbackURL)) {
		return
	}

	mgr.Set(definitions.SessionKeyIDPResumeFallbackURL, fallbackURL)
	mgr.Set(definitions.SessionKeyIDPResumeFallbackAt, now.Unix())
}

func oidcFlowResumeFallbackURL(mgr cookie.Manager) string {
	if mgr.GetString(definitions.SessionKeyOIDCGrantType, "") == definitions.OIDCFlowDeviceCode {
		if mgr.GetString(definitions.SessionKeyDeviceCode, "") != "" {
			return flowdomain.FlowMetadataResumeTargetDeviceCodeComplete
		}

		return ""
	}

	return safeLocalIDPResumeTarget(newOIDCAuthorizeFlowContext(mgr).ResumeAuthorizeURL())
}

func idpResumeFallbackFresh(mgr cookie.Manager, now time.Time) bool {
	createdAt := mgr.GetInt64(definitions.SessionKeyIDPResumeFallbackAt, 0)
	if createdAt <= 0 {
		return false
	}

	created := time.Unix(createdAt, 0)

	return !now.Before(created) && now.Sub(created) <= idpResumeFallbackTTL
}

func safeLocalIDPResumeTarget(rawTarget string) string {
	if rawTarget == "" {
		return ""
	}

	parsed, err := url.Parse(rawTarget)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") {
		return ""
	}

	return rawTarget
}

func (h *FrontendHandler) flowStore() (rediscli.Client, string) {
	if h == nil || h.deps == nil {
		return nil, ""
	}

	redisClient := h.deps.Redis
	redisPrefix := ""

	if h.deps.Cfg != nil && h.deps.Cfg.GetServer() != nil {
		redisPrefix = h.deps.Cfg.GetServer().GetRedis().GetPrefix()
	}

	return redisClient, redisPrefix
}

func isLoginSelfResume(requestPath string, redirectURI string) bool {
	return isLoginPath(requestPath) && isLoginPath(redirectPath(redirectURI))
}

func redirectPath(rawURI string) string {
	parsed, err := url.Parse(rawURI)
	if err != nil || parsed.Path == "" {
		return rawURI
	}

	return parsed.Path
}

func isLoginPath(path string) bool {
	return path == frontendLoginPath || strings.HasPrefix(path, frontendLoginPath+"/")
}

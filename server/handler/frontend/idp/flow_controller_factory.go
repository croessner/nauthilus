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
	"net/url"
	"strings"

	"github.com/croessner/nauthilus/v4/server/core/cookie"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/gin-gonic/gin"
)

const (
	frontendDefaultLanguageTag = "en"
	frontendLoginPath          = "/login"
	frontendMFASelectPath      = "/login/mfa"
	frontendDeviceVerifyPath   = "/oidc/device/verify"
	frontendDeviceConsentPath  = "/oidc/device/consent"
	frontendSAMLSSOPath        = "/saml/sso"
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
)

// resumeCanonicalIDPFlow redirects from one unambiguous typed protocol record without legacy fallback state.
func (h *FrontendHandler) resumeCanonicalIDPFlow(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	state *flowdomain.State,
) bool {
	if ctx == nil || session == nil || state == nil || state.FlowID == "" {
		return false
	}

	decision, err := flowdomain.NewProtocolAggregate(session.Stores, session.Handle, 0).
		Resume(ctx.Request.Context(), state.FlowID)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return false
	}

	if decision.RedirectURI == flowdomain.FlowMetadataResumeTargetDeviceCodeComplete {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return false
	}

	redirectURI := safeLocalIDPResumeTarget(decision.RedirectURI)
	if redirectURI == "" || isLoginSelfResume(ctx.Request.URL.Path, redirectURI) {
		ctx.AbortWithStatus(http.StatusConflict)

		return false
	}

	ctx.Redirect(http.StatusFound, redirectURI)

	return true
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

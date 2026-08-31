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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/idp"
	"github.com/croessner/nauthilus/v4/server/idp/dcr"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/gin-gonic/gin"
)

// oidcAuthorizeRequest carries validated authorization request parameters.
type oidcAuthorizeRequest struct {
	clientID            string
	redirectURI         string
	scope               string
	state               string
	nonce               string
	responseType        string
	prompt              string
	codeChallenge       string
	codeChallengeMethod string
}

// readOIDCAuthorizeRequest reads and normalizes authorization request parameters.
func readOIDCAuthorizeRequest(ctx *gin.Context) (oidcAuthorizeRequest, bool) {
	request := oidcAuthorizeRequest{
		clientID:      ctx.Query(oidcParamClientID),
		redirectURI:   ctx.Query(oidcParamRedirectURI),
		scope:         ctx.Query(oidcParamScope),
		state:         ctx.Query(oidcParamState),
		nonce:         ctx.Query(oidcParamNonce),
		responseType:  ctx.Query(oidcParamResponseType),
		prompt:        ctx.Query(oidcParamPrompt),
		codeChallenge: ctx.Query(oidcParamCodeChallenge),
	}

	request.codeChallengeMethod = ctx.Query(oidcParamCodeChallengeMethod)

	return request, true
}

// validateOIDCAuthorizeRequest verifies client, redirect, response type, and PKCE.
func (h *OIDCHandler) validateOIDCAuthorizeRequest(ctx *gin.Context, request *oidcAuthorizeRequest) (*config.OIDCClient, bool) {
	client, err := h.idp.ResolveClient(ctx.Request.Context(), request.clientID)
	if err != nil {
		if strings.HasPrefix(request.clientID, dcr.ClientIDPrefix) && !errors.Is(err, dcr.ErrNotFound) {
			ctx.JSON(http.StatusServiceUnavailable, gin.H{definitions.LogKeyError: oidcErrorServerError})

			return nil, false
		}

		ctx.String(http.StatusBadRequest, "Invalid client_id")

		return nil, false
	}

	if !h.idp.ValidateRedirectURI(client, request.redirectURI) {
		ctx.String(http.StatusBadRequest, "Invalid redirect_uri")

		return nil, false
	}

	if request.responseType != oidcResponseTypeCode {
		return rejectOIDCAuthorizeMetadata(ctx, client, *request, oidcErrorUnsupportedResponseType, "Only response_type=code is supported")
	}

	codeChallengeMethod, methodErr := normalizeCodeChallengeMethod(request.codeChallenge, request.codeChallengeMethod)
	if methodErr != nil {
		return rejectOIDCAuthorizeMetadata(ctx, client, *request, oidcErrorInvalidRequest, methodErr.Error())
	}

	request.codeChallengeMethod = codeChallengeMethod

	if client.RequiresPKCE() && request.codeChallenge == "" {
		return rejectOIDCAuthorizeMetadata(ctx, client, *request, oidcErrorInvalidRequest, "PKCE is required for this client")
	}

	return client, true
}

// rejectOIDCAuthorizeMetadata redirects dynamic-client errors only after validating the redirect URI.
func rejectOIDCAuthorizeMetadata(ctx *gin.Context, client *config.OIDCClient, request oidcAuthorizeRequest, errorCode string, message string) (*config.OIDCClient, bool) {
	if client.Dynamic {
		redirectOIDCAuthorizeError(ctx, request.redirectURI, request.state, errorCode)

		return nil, false
	}

	ctx.String(http.StatusBadRequest, message)

	return nil, false
}

// redirectOIDCAuthorizeError redirects an authorization error to the client.
func redirectOIDCAuthorizeError(ctx *gin.Context, redirectURI string, state string, errorCode string) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Invalid redirect_uri")

		return
	}

	query := target.Query()
	query.Set(definitions.LogKeyError, errorCode)
	if state != "" {
		query.Set(oidcParamState, state)
	}

	target.RawQuery = query.Encode()

	ctx.Redirect(http.StatusFound, target.String())
}

// buildOIDCCallbackRedirectURL appends authorization response parameters safely.
func buildOIDCCallbackRedirectURL(redirectURI string, code string, state string) (string, error) {
	callbackURL, err := url.Parse(strings.TrimSpace(redirectURI))
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(callbackURL.String()) == "" {
		return "", fmt.Errorf("redirect_uri is missing")
	}

	query := callbackURL.Query()
	query.Set(oidcParamCode, code)

	if state != "" {
		query.Set(oidcParamState, state)
	}

	callbackURL.RawQuery = query.Encode()
	callbackURL.Fragment = ""

	return callbackURL.String(), nil
}

// oidcAuthorizeRequestMatchesMetadata binds a request to persisted typed flow metadata.
func oidcAuthorizeRequestMatchesMetadata(metadata map[string]string, request oidcAuthorizeRequest) bool {
	return metadata[flowdomain.FlowMetadataClientID] == request.clientID &&
		metadata[flowdomain.FlowMetadataRedirectURI] == request.redirectURI &&
		metadata[flowdomain.FlowMetadataScope] == request.scope &&
		metadata[flowdomain.FlowMetadataState] == request.state &&
		metadata[flowdomain.FlowMetadataNonce] == request.nonce &&
		metadata[flowdomain.FlowMetadataResponseType] == request.responseType &&
		metadata[flowdomain.FlowMetadataPrompt] == request.prompt &&
		metadata[flowdomain.FlowMetadataCodeChallenge] == request.codeChallenge &&
		metadata[flowdomain.FlowMetadataCodeChallengeMethod] == request.codeChallengeMethod
}

var oidcAuthorizeSingleValueParameters = []string{
	oidcParamResponseType,
	oidcParamClientID,
	oidcParamRedirectURI,
	oidcParamScope,
	oidcParamState,
	oidcParamNonce,
	oidcParamPrompt,
	oidcParamCodeChallenge,
	oidcParamCodeChallengeMethod,
}

func rejectDuplicateOIDCAuthorizeParameters(ctx *gin.Context) bool {
	if ctx == nil || ctx.Request == nil || ctx.Request.URL == nil {
		return false
	}

	values := ctx.Request.URL.Query()
	for _, key := range oidcAuthorizeSingleValueParameters {
		if len(values[key]) <= 1 {
			continue
		}

		ctx.String(http.StatusBadRequest, "duplicate parameter: "+key)

		return true
	}

	return false
}

// handleAuthorizationCodeTokenExchange processes the authorization_code grant type
// within the token endpoint.
func (h *OIDCHandler) handleAuthorizationCodeTokenExchange(ctx *gin.Context, client *config.OIDCClient, grantType string) {
	clientID := client.ClientID
	code := formValue(ctx, oidcParamCode)

	session, getErr := h.storage.ConsumeSession(ctx.Request.Context(), code)
	if getErr != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: oidcErrorInvalidGrant})

		return
	}

	if session.ClientID != clientID {
		ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: oidcErrorInvalidGrant})

		return
	}

	if formValue(ctx, oidcParamRedirectURI) != session.RedirectURI {
		ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: oidcErrorInvalidGrant})

		return
	}

	if pkceErr := validatePKCEVerifier(session.CodeChallenge, session.CodeChallengeMethod, formValue(ctx, oidcParamCodeVerifier)); pkceErr != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: oidcErrorInvalidGrant})

		return
	}

	idToken, accessToken, refreshToken, expiresIn, err := h.idp.IssueTokens(ctx.Request.Context(), session)
	if err != nil {
		h.logTokenError(ctx, grantType, clientID, err)

		return
	}

	if err := h.idp.TouchDynamicClient(ctx.Request.Context(), client, "authorization_code_exchange"); err != nil {
		_ = h.storage.DeleteAccessToken(ctx.Request.Context(), accessToken)
		if refreshToken != "" && client.Dynamic {
			_ = h.storage.DeleteDynamicRefreshToken(ctx.Request.Context(), refreshToken)
		}

		h.logTokenError(ctx, grantType, clientID, err)

		return
	}

	h.sendTokenResponse(ctx, clientID, grantType, &tokenResponse{
		idToken:      idToken,
		accessToken:  accessToken,
		refreshToken: refreshToken,
		expiresIn:    expiresIn,
	})
}

// handleRefreshTokenExchange processes the refresh_token grant type
// within the token endpoint.
func (h *OIDCHandler) handleRefreshTokenExchange(ctx *gin.Context, client *config.OIDCClient, grantType string) {
	clientID := client.ClientID
	rt := formValue(ctx, oidcParamRefreshToken)

	_, idToken, accessToken, refreshToken, expiresIn, err := h.idp.ExchangeRefreshToken(ctx.Request.Context(), rt, clientID)
	if err != nil {
		if errors.Is(err, idp.ErrInvalidRefreshToken) || errors.Is(err, idp.ErrRefreshTokenClientMismatch) {
			setOIDCTokenFailureReason(ctx, oidcRefreshTokenFailureReason(err))
			ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: oidcErrorInvalidGrant})

			return
		}

		h.logTokenError(ctx, grantType, clientID, err)

		return
	}

	h.sendTokenResponse(ctx, clientID, grantType, &tokenResponse{
		idToken:      idToken,
		accessToken:  accessToken,
		refreshToken: refreshToken,
		expiresIn:    expiresIn,
	})
}

// loadOIDCConsentSession loads a consent session by challenge.
func (h *OIDCHandler) oidcConsentOptionalScopeChoices(ctx *gin.Context, client *config.OIDCClient, plan consentScopePlan) []gin.H {
	customScopes := h.deps.Cfg.GetIDP().OIDC.GetEffectiveCustomScopes(client)
	lang := consentLanguage(ctx)
	choices := make([]gin.H, 0, len(plan.Optional))

	for _, scope := range plan.Optional {
		description, ok := consentScopeDescription(ctx, h.deps.Cfg, h.deps.Logger, customScopes, lang, scope)
		if !ok {
			continue
		}

		choices = append(choices, gin.H{
			templateDataName:        scope,
			templateDataDescription: description,
			templateDataChecked:     true,
		})
	}

	return choices
}

// oidcConsentPageData builds template data for the consent prompt.
func normalizeCodeChallengeMethod(codeChallenge, codeChallengeMethod string) (string, error) {
	if codeChallenge == "" {
		if codeChallengeMethod != "" {
			return "", fmt.Errorf("code_challenge_method requires code_challenge")
		}

		return "", nil
	}

	if codeChallengeMethod != oidcPKCEChallengeMethodS256 {
		return "", fmt.Errorf("unsupported code_challenge_method: only S256 is allowed")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(codeChallenge)
	if err != nil || len(codeChallenge) != 43 || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != codeChallenge {
		return "", fmt.Errorf("invalid S256 code_challenge")
	}

	return oidcPKCEChallengeMethodS256, nil
}

func validatePKCEVerifier(codeChallenge, codeChallengeMethod, codeVerifier string) error {
	challenge := strings.TrimSpace(codeChallenge)
	if challenge == "" {
		return nil
	}

	if !isValidCodeVerifier(codeVerifier) {
		return fmt.Errorf("invalid code_verifier")
	}

	if codeChallengeMethod != oidcPKCEChallengeMethodS256 {
		return fmt.Errorf("unsupported code_challenge_method: only S256 is allowed")
	}

	sum := sha256.Sum256([]byte(codeVerifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])

	if subtle.ConstantTimeCompare([]byte(challenge), []byte(expected)) != 1 {
		return fmt.Errorf("code_verifier mismatch")
	}

	return nil
}

func isValidCodeVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}

	for _, char := range verifier {
		if char >= 'A' && char <= 'Z' {
			continue
		}

		if char >= 'a' && char <= 'z' {
			continue
		}

		if char >= '0' && char <= '9' {
			continue
		}

		switch char {
		case '-', '.', '_', '~':
			continue
		default:
			return false
		}
	}

	return true
}

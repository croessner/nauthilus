// Copyright (C) 2026 Christian Rößner
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
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/gin-gonic/gin"
)

// oidcParamIssuer is the RFC 9207 authorization response issuer parameter.
const oidcParamIssuer = "iss"

// oidcAuthorizationResponse builds authorization responses (RFC 6749 section 4.1.2) for an already validated
// redirect URI. Success and error responses both carry the RFC 9207 issuer identifier, so a client talking to
// several authorization servers can detect a mix-up before it redeems a code.
type oidcAuthorizationResponse struct {
	issuer string
}

// newOIDCAuthorizationResponse binds the response builder to the currently configured issuer.
func newOIDCAuthorizationResponse(cfg config.File) oidcAuthorizationResponse {
	if cfg == nil || cfg.GetIDP() == nil {
		return oidcAuthorizationResponse{}
	}

	return oidcAuthorizationResponse{issuer: cfg.GetIDP().OIDC.Issuer}
}

// successURL returns the redirect target that delivers an authorization code.
func (r oidcAuthorizationResponse) successURL(redirectURI string, code string, state string) (string, error) {
	return r.build(redirectURI, state, oidcParamCode, code)
}

// redirectError redirects an authorization error to the client, or answers 500 when the redirect URI is unusable.
func (r oidcAuthorizationResponse) redirectError(ctx *gin.Context, redirectURI string, state string, errorCode string) {
	target, err := r.build(redirectURI, state, definitions.LogKeyError, errorCode)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Invalid redirect_uri")

		return
	}

	ctx.Redirect(http.StatusFound, target)
}

// build appends one response parameter, state, and iss to the redirect URI and drops any fragment. Existing query
// parameters of a registered redirect URI are preserved.
func (r oidcAuthorizationResponse) build(redirectURI string, state string, name string, value string) (string, error) {
	callbackURL, err := url.Parse(strings.TrimSpace(redirectURI))
	if err != nil {
		return "", err
	}

	if callbackURL.String() == "" {
		return "", fmt.Errorf("redirect_uri is missing")
	}

	query := callbackURL.Query()
	query.Set(name, value)

	if state != "" {
		query.Set(oidcParamState, state)
	}

	if r.issuer != "" {
		query.Set(oidcParamIssuer, r.issuer)
	}

	callbackURL.RawQuery = query.Encode()
	callbackURL.Fragment = ""

	return callbackURL.String(), nil
}

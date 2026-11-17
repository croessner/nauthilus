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
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	domainidp "github.com/croessner/nauthilus/v4/server/idp"
	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
)

// newConsentRequiredHandler builds a miniredis-backed OIDC handler whose browser client must ask for consent.
func newConsentRequiredHandler(t *testing.T) *OIDCHandler {
	t.Helper()

	clients := resourceIndicatorClients()
	clients[0].SkipConsent = false

	return newMiniredisOIDCHandler(t, clients)
}

// authorizeUntilConsent sends an authorization request for an authenticated session and returns the consent
// challenge of the consent page the browser is redirected to; the challenge is visible to the user agent.
func authorizeUntilConsent(t *testing.T, handler *OIDCHandler) string {
	t.Helper()

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	router := gin.New()
	router.GET("/oidc/authorize", cookie.CanonicalMiddleware(runtime, cookie.CanonicalProtocolEntry), handler.AuthorizeCanonical)

	request := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+completionAuthorizeQuery().Encode(), nil)
	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusFound || location.Path != "/oidc/consent" ||
		location.Query().Get("consent_challenge") == "" {
		t.Fatalf("authorize = %d %q, err = %v, want the consent page", response.Code, response.Header().Get("Location"), err)
	}

	return location.Query().Get("consent_challenge")
}

// TestConsentChallengeIsNeverRedeemableAsAuthorizationCode pins that the browser-visible consent challenge never
// works as an authorization code: the token endpoint must not issue tokens before the user decided on consent.
func TestConsentChallengeIsNeverRedeemableAsAuthorizationCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := newConsentRequiredHandler(t)
	challenge := authorizeUntilConsent(t, handler)

	for _, code := range []string{"consent:" + challenge, challenge} {
		answer := postResourceTokenRequest(t, handler, url.Values{
			oidcParamGrantType: {definitions.OIDCFlowAuthorizationCode}, oidcParamCode: {code},
			oidcParamRedirectURI: {resourceTestRedirectURI},
		})

		if answer[definitions.LogKeyError] != oidcErrorInvalidGrant || answer[oidcJSONFieldAccessToken] != nil {
			t.Fatalf("token request with code %q = %v, want invalid_grant before any consent decision", code, answer)
		}
	}
}

// TestLegacyConsentLayoutIsNeverRedeemable pins the rolling-update case: an older instance still stores a pending
// consent under the authorization-code key "consent:<challenge>". The token endpoint must reject that value without
// touching storage, so the pending consent stays available to the consent page of the older instance.
func TestLegacyConsentLayoutIsNeverRedeemable(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := newConsentRequiredHandler(t)
	legacyCode := "consent:3MFYvlVNNQuLdCCecbulBwzrWrM"
	pending := &domainidp.OIDCSession{ClientID: resourceTestClientID, UserID: "identity-42", Username: "alice",
		RedirectURI: resourceTestRedirectURI, Scopes: []string{definitions.ScopeOpenID}}

	if err := handler.storage.StoreSession(context.Background(), legacyCode, pending, canonicalOIDCAuthorizationTTL); err != nil {
		t.Fatalf("StoreSession() error = %v", err)
	}

	answer := postResourceTokenRequest(t, handler, url.Values{
		oidcParamGrantType: {definitions.OIDCFlowAuthorizationCode}, oidcParamCode: {legacyCode},
		oidcParamRedirectURI: {resourceTestRedirectURI},
	})
	if answer[definitions.LogKeyError] != oidcErrorInvalidGrant || answer[oidcJSONFieldAccessToken] != nil {
		t.Fatalf("legacy consent value as code = %v, want invalid_grant", answer)
	}

	if _, err := handler.storage.GetSession(context.Background(), legacyCode); err != nil {
		t.Fatalf("legacy pending consent was consumed by the token request: %v", err)
	}
}

// TestAuthorizationCodeShapeAcceptsOnlyIssuedCodeCharacters pins the token-endpoint code shape: unreserved URI
// characters within a bounded length, which every issued code (a KSUID) satisfies.
func TestAuthorizationCodeShapeAcceptsOnlyIssuedCodeCharacters(t *testing.T) {
	cases := map[string]bool{
		ksuid.New().String(): true, "token-code_1.~": true, "": false, "consent:abc": false, "a b": false,
		strings.Repeat("a", 257): false, "%3A": false, "ä": false,
	}

	for code, want := range cases {
		if got := validAuthorizationCodeShape(code); got != want {
			t.Fatalf("validAuthorizationCodeShape(%q) = %v, want %v", code, got, want)
		}
	}
}

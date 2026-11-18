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
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	domainidp "github.com/croessner/nauthilus/v4/server/idp"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

const hostedAuthorizeResource = "https://auth.example.com/mcp"

// steppingClock is a test clock that can be moved forward between requests.
type steppingClock struct {
	now *time.Time
}

// Now returns the current test time.
func (c steppingClock) Now() time.Time { return *c.now }

// hostedAuthorizeFixture holds a handler whose client is admitted to one hosted resource.
type hostedAuthorizeFixture struct {
	handler *OIDCHandler
	mock    redismock.ClientMock
	runtime *cookie.CanonicalRuntime
	cookie  *http.Cookie
	client  config.OIDCClient
	now     *time.Time
}

// newHostedAuthorizeFixture builds an authenticated browser session and a handler whose user loader returns groups.
func newHostedAuthorizeFixture(t *testing.T, groups []string) hostedAuthorizeFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)

	now := time.Date(2026, time.November, 18, 8, 0, 0, 0, time.UTC)
	runtime, browserCookie, _ := seedCanonicalIDPFlowWithClock(t, nil, steppingClock{now: &now})
	authenticateCanonicalFixture(t, runtime, browserCookie)

	client := latchedConsentOIDCClient()
	client.SkipConsent = true
	client.Scopes = append(client.Scopes, definitions.ScopeHistoryRead)

	handler, mock := newOIDCCallbackRedirectTestHandlerWithClient(t, client)
	handler.deps.Cfg.(*mockOIDCCfg).hostedResources = []config.OIDCHostedResource{{
		Name: "support-mcp", Resource: hostedAuthorizeResource, Scopes: []string{definitions.ScopeHistoryRead},
		StaticClients: []string{client.ClientID}, MaxAuthenticationAge: 5 * time.Minute,
		UserRight: config.OIDCHostedResourceUserRight{From: config.HostedResourceUserRightFromGroups, AnyOf: []string{"support"}},
	}}
	handler.canonicalAuthorizeUserLoader = func(
		_ *gin.Context,
		_ *cookie.CanonicalSession,
		identity cookie.SessionIdentity,
		_ *config.OIDCClient,
		_ []string,
	) (*backend.User, error) {
		return &backend.User{ID: identity.Reference, Name: identity.Account, DisplayName: identity.DisplayName, Groups: groups}, nil
	}

	return hostedAuthorizeFixture{handler: handler, mock: mock, runtime: runtime, cookie: browserCookie, client: client, now: &now}
}

// authorize sends one authorization request for the hosted resource.
func (f hostedAuthorizeFixture) authorize(t *testing.T, prompt string) (*httptest.ResponseRecorder, *url.URL) {
	t.Helper()

	router := gin.New()
	router.GET("/oidc/authorize", cookie.CanonicalMiddleware(f.runtime, cookie.CanonicalProtocolEntry), f.handler.AuthorizeCanonical)

	query := url.Values{
		oidcParamClientID: {f.client.ClientID}, oidcParamRedirectURI: {f.client.RedirectURIs[0]},
		oidcParamScope: {definitions.ScopeHistoryRead}, oidcParamState: {"hosted-state"},
		oidcParamResponseType: {oidcResponseTypeCode}, oidcParamResource: {hostedAuthorizeResource},
	}

	if prompt != "" {
		query.Set(oidcParamPrompt, prompt)
	}

	request := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+query.Encode(), nil)
	request.AddCookie(f.cookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location %q: %v", response.Header().Get("Location"), err)
	}

	return response, location
}

// assertClientError checks an error redirect to the client that carries state and the RFC 9207 issuer.
func assertClientError(t *testing.T, response *httptest.ResponseRecorder, location *url.URL, errorCode string) {
	t.Helper()

	query := location.Query()
	if response.Code != http.StatusFound || !strings.HasPrefix(location.String(), "https://app.example.com/callback?") ||
		query.Get(definitions.LogKeyError) != errorCode || query.Get(oidcParamState) != "hosted-state" ||
		query.Get(oidcParamIssuer) != "https://auth.example.com" || query.Has(oidcParamCode) {
		t.Fatalf("authorize = %d %q, want %s error redirect", response.Code, location, errorCode)
	}
}

// TestHostedResourceAuthorizeIssuesCodeForEntitledUser pins the success path: an entitled user with a young login
// receives a code, and the response carries iss.
func TestHostedResourceAuthorizeIssuesCodeForEntitledUser(t *testing.T) {
	fixture := newHostedAuthorizeFixture(t, []string{"support"})
	expectOIDCAuthorizationCodeStorage(fixture.mock)

	response, location := fixture.authorize(t, "")
	if response.Code != http.StatusFound || location.Query().Get(oidcParamCode) == "" ||
		location.Query().Get(oidcParamIssuer) != "https://auth.example.com" {
		t.Fatalf("authorize = %d %q, want code redirect with iss", response.Code, location)
	}

	if err := fixture.mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("code storage expectations: %v", err)
	}
}

// TestHostedResourceAuthorizeDeniesUserWithoutRight pins access_denied for a user outside the entitling groups,
// with no code stored and the flow consumed.
func TestHostedResourceAuthorizeDeniesUserWithoutRight(t *testing.T) {
	fixture := newHostedAuthorizeFixture(t, []string{"staff"})

	response, location := fixture.authorize(t, "")
	assertClientError(t, response, location, oidcErrorAccessDenied)

	if flows := openCanonicalFixture(t, fixture.runtime, fixture.cookie).Anchor.Value.OIDCFlows; len(flows) != 0 {
		t.Fatalf("refused authorization left flow state: %v", flows)
	}

	if err := fixture.mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("a refused authorization wrote state: %v", err)
	}
}

// TestHostedResourceAuthorizeRequiresYoungLogin pins max_authentication_age at authorization: prompt=none answers
// login_required without ending the session, and an interactive request restarts the login.
func TestHostedResourceAuthorizeRequiresYoungLogin(t *testing.T) {
	fixture := newHostedAuthorizeFixture(t, []string{"support"})
	*fixture.now = fixture.now.Add(10 * time.Minute)

	response, location := fixture.authorize(t, oidcClientAuthMethodNone)
	assertClientError(t, response, location, oidcErrorLoginRequired)

	if _, authenticated := openCanonicalFixture(t, fixture.runtime, fixture.cookie).Identity(); !authenticated {
		t.Fatal("prompt=none must not end the browser session")
	}

	response, location = fixture.authorize(t, "")
	if response.Code != http.StatusFound || strings.HasPrefix(location.String(), "https://app.example.com/") {
		t.Fatalf("authorize with an old login = %d %q, want a new login", response.Code, location)
	}

	if err := fixture.mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("an old login wrote a code: %v", err)
	}
}

// TestTokenErrorMapsHostedLoginAgeToInvalidGrant pins that a code exchange or refresh refused for an old login
// answers invalid_grant, so clients start a new authorization instead of retrying.
func TestTokenErrorMapsHostedLoginAgeToInvalidGrant(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, _ := newOIDCCallbackRedirectTestHandler(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, oidcEndpointPathToken, nil)

	handler.logTokenError(ctx, oidcGrantTypeRefreshToken, "client", fmt.Errorf("refresh: %w", domainidp.ErrHostedAuthenticationExpired))

	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), oidcErrorInvalidGrant) {
		t.Fatalf("token error = %d %s, want invalid_grant", recorder.Code, recorder.Body.String())
	}
}

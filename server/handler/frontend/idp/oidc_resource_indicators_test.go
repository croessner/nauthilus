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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	domainidp "github.com/croessner/nauthilus/v4/server/idp"
	"github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

const (
	resourceTestClientID    = "test-client"
	resourceTestRedirectURI = "https://app.example.com/callback"
	resourceTestMail        = "https://mail.example.org/jmap"
	resourceTestDAV         = "https://dav.example.org"
	resourceTestForeign     = "https://foreign.example.org"
)

// resourceIndicatorClients returns the issuing client, the resource server that allowlists it, and a
// resource server that does not.
func resourceIndicatorClients() []config.OIDCClient {
	return []config.OIDCClient{
		{
			ClientID: resourceTestClientID, ClientSecret: secret.New("test-secret"),
			RedirectURIs: []string{resourceTestRedirectURI}, SkipConsent: true,
			Scopes:     []string{definitions.ScopeOpenID, definitions.ScopeOfflineAccess},
			GrantTypes: []string{definitions.OIDCFlowAuthorizationCode, oidcGrantTypeRefreshToken, oidcGrantTypeClientCredentials, definitions.OIDCGrantTypeDeviceCode},
		},
		{
			ClientID: "mail-rs", ClientSecret: secret.New("test-secret"),
			TokenIntrospection: config.OIDCTokenIntrospection{Resources: []string{resourceTestMail, resourceTestDAV}, Clients: []string{resourceTestClientID}},
		},
		{
			ClientID: "foreign-rs", ClientSecret: secret.New("test-secret"),
			TokenIntrospection: config.OIDCTokenIntrospection{Resources: []string{resourceTestForeign}, Clients: []string{"mail-rs"}},
		},
	}
}

// newResourceIndicatorHandler builds an OIDC handler whose token state lives in miniredis.
func newResourceIndicatorHandler(t *testing.T) *OIDCHandler {
	t.Helper()

	tokenRedis := miniredis.RunT(t)
	cfg := &mockOIDCCfg{issuer: "https://auth.example.com", signingKey: secret.New(generateTestKey()), clients: resourceIndicatorClients()}
	handlerDeps := &deps.Deps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Redis:       rediscli.NewTestClient(redis.NewClient(&redis.Options{Addr: tokenRedis.Addr()})),
		LangManager: &mockLangManager{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler := NewOIDCHandler(handlerDeps, domainidp.NewNauthilusIDP(handlerDeps), nil)
	handler.canonicalAuthorizeUserLoader = func(
		_ *gin.Context, _ *cookie.CanonicalSession, identity cookie.SessionIdentity, _ *config.OIDCClient, _ []string,
	) (*backend.User, error) {
		return &backend.User{ID: identity.Reference, Name: identity.Account, DisplayName: identity.DisplayName}, nil
	}

	return handler
}

// resourceAuthorizeQuery builds an authorization request with the given resource parameters.
func resourceAuthorizeQuery(resources ...string) url.Values {
	return url.Values{
		oidcParamClientID: {resourceTestClientID}, oidcParamRedirectURI: {resourceTestRedirectURI},
		oidcParamScope: {"openid offline_access"}, oidcParamState: {"state-r"},
		oidcParamResponseType: {oidcResponseTypeCode}, oidcParamResource: resources,
	}
}

// postResourceTokenRequest sends one token request authenticated as the issuing client.
func postResourceTokenRequest(t *testing.T, handler *OIDCHandler, form url.Values) map[string]any {
	t.Helper()

	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequest(http.MethodPost, oidcEndpointPathToken, strings.NewReader(form.Encode()))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request.SetBasicAuth(resourceTestClientID, "test-secret")

	handler.Token(ctx)

	return mustDecodeOIDCTestJSON(t, response)
}

// accessTokenAudienceClaim decodes the audience of an issued JWT access token.
func accessTokenAudienceClaim(t *testing.T, token any) any {
	t.Helper()

	tokenString, ok := token.(string)
	if !assert.True(t, ok, "access_token missing") {
		return nil
	}

	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
	assert.NoError(t, err)
	assert.Equal(t, resourceTestClientID, claims[definitions.ClaimAuthorizedParty])

	return claims["aud"]
}

func TestOIDCAuthorizeRejectsInvalidResources(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := newResourceIndicatorHandler(t)

	cases := []struct {
		name      string
		resources []string
	}{
		{name: "unregistered", resources: []string{"https://unknown.example.org"}},
		{name: "not allowlisted for the client", resources: []string{resourceTestForeign}},
		{name: "relative", resources: []string{"/jmap"}},
		{name: "fragment", resources: []string{resourceTestMail + "#part"}},
		{name: "empty", resources: []string{""}},
		{name: "one bad value spoils the request", resources: []string{resourceTestMail, "https://unknown.example.org"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(response)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+resourceAuthorizeQuery(tc.resources...).Encode(), nil)

			handler.AuthorizeCanonical(ctx)

			assert.Equal(t, http.StatusBadRequest, response.Code)
			assert.Equal(t, "Invalid resource", response.Body.String())
		})
	}
}

// authorizeResourceCode runs an authorization request with resources through the login resume and
// returns the issued authorization code.
func authorizeResourceCode(t *testing.T, handler *OIDCHandler, resources ...string) string {
	t.Helper()

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	router := gin.New()
	router.GET("/oidc/authorize", cookie.CanonicalMiddleware(runtime, cookie.CanonicalProtocolEntry), handler.AuthorizeCanonical)

	entry := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+resourceAuthorizeQuery(resources...).Encode(), nil)
	entry.AddCookie(browserCookie)

	entryResponse := httptest.NewRecorder()
	router.ServeHTTP(entryResponse, entry)

	login, err := url.Parse(entryResponse.Header().Get("Location"))
	if !assert.NoError(t, err) || !assert.Equal(t, http.StatusFound, entryResponse.Code) {
		return ""
	}

	flowID := login.Query().Get(flow.FlowTicketParameter)
	session := openCanonicalFixture(t, runtime, browserCookie)
	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, canonicalOIDCAuthorizationTTL)

	state, err := store.Load(context.Background(), flowID)
	if !assert.NoError(t, err) {
		return ""
	}

	assert.Equal(t, resourceTestMail+" "+resourceTestDAV, state.Metadata[flow.FlowMetadataResource], "resources are deduplicated in request order")

	// Simulate the completed login and resume the stored authorization request.
	authenticateCanonicalFixture(t, runtime, browserCookie)

	state.AuthOutcome = flow.AuthOutcomeOK
	assert.NoError(t, store.Save(context.Background(), state))

	resume := httptest.NewRequest(http.MethodGet, flow.AppendTicket(state.Metadata[flow.FlowMetadataResumeTarget], flowID), nil)
	resume.AddCookie(browserCookie)

	resumeResponse := httptest.NewRecorder()
	router.ServeHTTP(resumeResponse, resume)

	callback, err := url.Parse(resumeResponse.Header().Get("Location"))
	if !assert.NoError(t, err) || !assert.Equal(t, http.StatusFound, resumeResponse.Code) {
		return ""
	}

	code := callback.Query().Get(oidcParamCode)
	assert.NotEmpty(t, code)

	return code
}

func TestOIDCResourceIndicatorsFlowFromAuthorizeThroughRefresh(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := newResourceIndicatorHandler(t)
	code := authorizeResourceCode(t, handler, resourceTestMail, resourceTestDAV, resourceTestMail)

	// The code exchange narrows the access token; the refresh token keeps the full grant.
	exchanged := postResourceTokenRequest(t, handler, url.Values{
		oidcParamGrantType: {definitions.OIDCFlowAuthorizationCode}, oidcParamCode: {code},
		oidcParamRedirectURI: {resourceTestRedirectURI}, oidcParamResource: {resourceTestDAV},
	})
	assert.Equal(t, []any{resourceTestClientID, resourceTestDAV}, accessTokenAudienceClaim(t, exchanged[oidcJSONFieldAccessToken]))

	refreshToken, _ := exchanged[oidcParamRefreshToken].(string)
	assert.NotEmpty(t, refreshToken)

	outside := postResourceTokenRequest(t, handler, url.Values{
		oidcParamGrantType: {oidcGrantTypeRefreshToken}, oidcParamRefreshToken: {refreshToken},
		oidcParamResource: {resourceTestForeign},
	})
	assert.Equal(t, map[string]any{definitions.LogKeyError: oidcErrorInvalidTarget}, outside)

	narrowed := postResourceTokenRequest(t, handler, url.Values{
		oidcParamGrantType: {oidcGrantTypeRefreshToken}, oidcParamRefreshToken: {refreshToken},
		oidcParamResource: {resourceTestMail},
	})
	assert.Equal(t, []any{resourceTestClientID, resourceTestMail}, accessTokenAudienceClaim(t, narrowed[oidcJSONFieldAccessToken]))

	if rotated, ok := narrowed[oidcParamRefreshToken].(string); ok && rotated != "" {
		refreshToken = rotated
	}

	full := postResourceTokenRequest(t, handler, url.Values{
		oidcParamGrantType: {oidcGrantTypeRefreshToken}, oidcParamRefreshToken: {refreshToken},
	})
	assert.Equal(t, []any{resourceTestClientID, resourceTestMail, resourceTestDAV}, accessTokenAudienceClaim(t, full[oidcJSONFieldAccessToken]),
		"narrowing one access token never shrinks or widens the stored grant")
}

func TestOIDCAuthorizationCodeExchangeRejectsResourceOutsideGrant(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := newResourceIndicatorHandler(t)
	code := "resource-code"
	err := handler.storage.StoreSession(context.Background(), code, &domainidp.OIDCSession{
		ClientID: resourceTestClientID, UserID: "identity-42", RedirectURI: resourceTestRedirectURI,
		Scopes: []string{definitions.ScopeOpenID}, AccessTokenResources: []string{resourceTestMail},
	}, canonicalOIDCAuthorizationTTL)
	assert.NoError(t, err)

	response := postResourceTokenRequest(t, handler, url.Values{
		oidcParamGrantType: {definitions.OIDCFlowAuthorizationCode}, oidcParamCode: {code},
		oidcParamRedirectURI: {resourceTestRedirectURI}, oidcParamResource: {resourceTestDAV},
	})
	assert.Equal(t, map[string]any{definitions.LogKeyError: oidcErrorInvalidTarget}, response)

	// The rejected narrowing is detected before the code is consumed, so the code stays redeemable once.
	redeemed := postResourceTokenRequest(t, handler, url.Values{
		oidcParamGrantType: {definitions.OIDCFlowAuthorizationCode}, oidcParamCode: {code},
		oidcParamRedirectURI: {resourceTestRedirectURI}, oidcParamResource: {resourceTestMail},
	})
	assert.Equal(t, []any{resourceTestClientID, resourceTestMail}, accessTokenAudienceClaim(t, redeemed[oidcJSONFieldAccessToken]))

	replayed := postResourceTokenRequest(t, handler, url.Values{
		oidcParamGrantType: {definitions.OIDCFlowAuthorizationCode}, oidcParamCode: {code},
		oidcParamRedirectURI: {resourceTestRedirectURI},
	})
	assert.Equal(t, map[string]any{definitions.LogKeyError: oidcErrorInvalidGrant}, replayed)
}

func TestOIDCClientCredentialsRejectsResource(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := newResourceIndicatorHandler(t)
	response := postResourceTokenRequest(t, handler, url.Values{
		oidcParamGrantType: {oidcGrantTypeClientCredentials}, oidcParamScope: {definitions.ScopeAuthenticate},
		oidcParamResource: {resourceTestMail},
	})
	assert.Equal(t, map[string]any{definitions.LogKeyError: oidcErrorInvalidTarget}, response)
}

func TestValidateCanonicalOIDCConsentSelectionBindsResources(t *testing.T) {
	handler := newResourceIndicatorHandler(t)
	clients := handler.deps.Cfg.GetIDP().OIDC.Clients
	state := &flow.State{Metadata: map[string]string{
		flow.FlowMetadataClientID: resourceTestClientID, flow.FlowMetadataRedirectURI: resourceTestRedirectURI,
		flow.FlowMetadataScope: definitions.ScopeOpenID, flow.FlowMetadataResource: resourceTestMail,
	}}
	identity := cookie.SessionIdentity{Reference: "identity-42", Account: "alice"}

	cases := []struct {
		name      string
		resources []string
		wantErr   bool
	}{
		{name: "matching resources", resources: []string{resourceTestMail}},
		{name: "dropped resources", wantErr: true},
		{name: "widened resources", resources: []string{resourceTestMail, resourceTestDAV}, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := handler.validateCanonicalOIDCConsentSelection(canonicalOIDCConsentSelection{
				identity: identity, state: state, client: &clients[0],
				pending: &domainidp.OIDCSession{
					ClientID: resourceTestClientID, RedirectURI: resourceTestRedirectURI, UserID: "identity-42", Username: "alice",
					Scopes: []string{definitions.ScopeOpenID}, AccessTokenResources: tc.resources,
				},
			})
			assert.Equal(t, tc.wantErr, err != nil)
		})
	}
}

func TestDeviceAuthorizationValidatesAndStoresResources(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := newResourceIndicatorHandler(t)
	store := &countingDeviceCodeStore{}
	handler.deviceStore = store

	form := url.Values{oidcParamClientID: {resourceTestClientID}, oidcParamScope: {definitions.ScopeOpenID}, oidcParamResource: {resourceTestForeign}}
	rejected := postDeviceAuthorization(handler, form, resourceTestClientID, "test-secret")
	assert.Equal(t, http.StatusBadRequest, rejected.Code)
	assert.Equal(t, map[string]any{definitions.LogKeyError: oidcErrorInvalidTarget}, mustDecodeOIDCTestJSON(t, rejected))
	assert.Empty(t, store.requests, "a rejected resource must not allocate device state")

	form[oidcParamResource] = []string{resourceTestMail, resourceTestDAV, resourceTestMail}
	accepted := postDeviceAuthorization(handler, form, resourceTestClientID, "test-secret")
	assert.Equal(t, http.StatusOK, accepted.Code)

	if assert.Len(t, store.requests, 1) {
		assert.Equal(t, []string{resourceTestMail, resourceTestDAV}, store.requests[0].Resources)
	}
}

// pollAuthorizedDeviceCode performs one device-code token poll with optional resource parameters.
func pollAuthorizedDeviceCode(t *testing.T, handler *OIDCHandler, deviceCode string, resources ...string) map[string]any {
	t.Helper()

	request, err := handler.deviceStore.GetDeviceCode(context.Background(), deviceCode)
	if !assert.NoError(t, err) {
		return nil
	}

	form := url.Values{oidcParamDeviceCode: {deviceCode}, oidcParamResource: resources}
	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequest(http.MethodPost, oidcEndpointPathToken, strings.NewReader(form.Encode()))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	clients := handler.deps.Cfg.GetIDP().OIDC.Clients
	handler.handleDeviceCodePollStatus(ctx, deviceCode, request, &clients[0])

	return mustDecodeOIDCTestJSON(t, response)
}

func TestDeviceCodeTokenCarriesAndNarrowsResources(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := newResourceIndicatorHandler(t)
	request := &domainidp.DeviceCodeRequest{
		ClientID: resourceTestClientID, Scopes: []string{definitions.ScopeOpenID},
		Resources: []string{resourceTestMail, resourceTestDAV}, Status: domainidp.DeviceCodeStatusAuthorized,
		IDTokenClaims: map[string]any{}, AccessTokenClaims: map[string]any{},
		ExpiresAt: time.Now().Add(10 * time.Minute), VerificationLocked: true,
	}
	request.StoreUserSnapshot(backend.NewUser("alice", "Alice Example", "identity-42"))
	assert.NoError(t, handler.deviceStore.StoreDeviceCode(context.Background(), "resource-device-code", request, 10*time.Minute))

	rejected := pollAuthorizedDeviceCode(t, handler, "resource-device-code", resourceTestForeign)
	assert.Equal(t, map[string]any{definitions.LogKeyError: oidcErrorInvalidTarget}, rejected, "the device code stays claimable")

	issued := pollAuthorizedDeviceCode(t, handler, "resource-device-code", resourceTestDAV)
	assert.Equal(t, []any{resourceTestClientID, resourceTestDAV}, accessTokenAudienceClaim(t, issued[oidcJSONFieldAccessToken]))
}

func TestOIDCLogoutClientFromClaimsHandlesResourceAudiences(t *testing.T) {
	handler := newResourceIndicatorHandler(t)

	cases := []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{name: "id token with string audience", claims: map[string]any{"aud": resourceTestClientID}, want: resourceTestClientID},
		{name: "resource access token names its client in azp", claims: map[string]any{
			"aud": []any{resourceTestClientID, resourceTestMail}, definitions.ClaimAuthorizedParty: resourceTestClientID,
		}, want: resourceTestClientID},
		{name: "array audience without azp fails closed", claims: map[string]any{"aud": []any{resourceTestClientID, resourceTestMail}}},
		{name: "malformed azp fails closed", claims: map[string]any{"aud": resourceTestClientID, definitions.ClaimAuthorizedParty: 42}},
		{name: "unknown client", claims: map[string]any{"aud": "unknown-client"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := handler.oidcLogoutClientFromClaims(tc.claims)
			if tc.want == "" {
				assert.Nil(t, client)

				return
			}

			if assert.NotNil(t, client) {
				assert.Equal(t, tc.want, client.ClientID)
			}
		})
	}
}

// introspectAsResourceServer introspects a token authenticated as the mail resource server.
func introspectAsResourceServer(t *testing.T, handler *OIDCHandler, token any) map[string]any {
	t.Helper()

	tokenString, _ := token.(string)
	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequest(http.MethodPost, oidcEndpointPathIntrospect, strings.NewReader(url.Values{"token": {tokenString}}.Encode()))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request.SetBasicAuth("mail-rs", "test-secret")

	handler.Introspect(ctx)

	return mustDecodeOIDCTestJSON(t, response)
}

func TestOIDCOpaqueResourceTokensNarrowOnlyTheAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := newResourceIndicatorHandler(t)
	handler.deps.Cfg.(*mockOIDCCfg).clients[0].AccessTokenType = "opaque"
	code := authorizeResourceCode(t, handler, resourceTestMail, resourceTestDAV)

	exchanged := postResourceTokenRequest(t, handler, url.Values{
		oidcParamGrantType: {definitions.OIDCFlowAuthorizationCode}, oidcParamCode: {code},
		oidcParamRedirectURI: {resourceTestRedirectURI}, oidcParamResource: {resourceTestDAV},
	})
	accessToken, _ := exchanged[oidcJSONFieldAccessToken].(string)
	refreshToken, _ := exchanged[oidcParamRefreshToken].(string)

	if !assert.NotEmpty(t, accessToken) || !assert.NotContains(t, accessToken, ".", "opaque token expected") || !assert.NotEmpty(t, refreshToken) {
		return
	}

	ctx := context.Background()

	stored, err := handler.storage.GetAccessToken(ctx, accessToken)
	if assert.NoError(t, err) {
		assert.Equal(t, []string{resourceTestDAV}, stored.AccessTokenResources, "the opaque session carries only the narrowed resources")
	}

	grant, err := handler.storage.GetRefreshToken(ctx, refreshToken)
	if assert.NoError(t, err) {
		assert.Equal(t, []string{resourceTestMail, resourceTestDAV}, grant.AccessTokenResources, "the refresh grant keeps every resource")
	}

	introspected := introspectAsResourceServer(t, handler, accessToken)
	assert.Equal(t, true, introspected["active"])
	assert.Equal(t, []any{resourceTestClientID, resourceTestDAV}, introspected["aud"])
	assert.Equal(t, resourceTestClientID, introspected[definitions.ClaimAuthorizedParty])

	refreshed := postResourceTokenRequest(t, handler, url.Values{
		oidcParamGrantType: {oidcGrantTypeRefreshToken}, oidcParamRefreshToken: {refreshToken},
	})
	full := introspectAsResourceServer(t, handler, refreshed[oidcJSONFieldAccessToken])
	assert.Equal(t, true, full["active"])
	assert.Equal(t, []any{resourceTestClientID, resourceTestMail, resourceTestDAV}, full["aud"], "a request without resource yields the full grant")
}

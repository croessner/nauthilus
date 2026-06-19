// Copyright (C) 2026 Christian Roessner
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
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/openapi/requesttest"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/gin-gonic/gin"
)

const (
	oidcContractClientSecret    = "synthetic-client-secret"
	oidcContractClientAssertion = "synthetic-client-assertion"
	oidcContractIssuer          = "https://auth.example.com"
	oidcContractRedirectURI     = "https://client.example/callback"
	oidcContractScope           = "openid profile"
	oidcContractState           = "state-1"
	oidcDiscoveryAuthEndpoint   = "authorization_endpoint"
	oidcDiscoveryIssuerField    = "issuer"
	oidcDiscoveryJWKSURIField   = "jwks_uri"
	oidcDiscoveryTokenEndpoint  = "token_endpoint"
	oidcJWKSAlgorithmField      = "alg"
	oidcJWKSKIDField            = "kid"
	oidcJWKSTypeField           = "kty"
	oidcJWKSUseField            = "use"
)

func TestOIDCTokenRequestsMatchOpenAPIContract(t *testing.T) {
	validator := requesttest.NewIDPValidator(t)

	requesttest.AssertCases(t, validator, []requesttest.Case{
		{
			Name:      "client credentials token request accepts form body",
			Request:   requesttest.NewFormRequest(http.MethodPost, "/oidc/token", oidcTokenContractForm(oidcParamGrantType, oidcGrantTypeClientCredentials, oidcParamClientID, "synthetic-client", oidcParamClientSecret, oidcContractClientSecret, oidcParamScope, oidcContractScope)),
			WantValid: true,
		},
		{
			Name: "token request rejects missing grant type",
			Request: requesttest.NewFormRequest(
				http.MethodPost,
				"/oidc/token",
				oidcTokenContractForm(oidcParamClientID, "synthetic-client", oidcParamClientSecret, oidcContractClientSecret),
			),
			WantErrorContains:        oidcParamGrantType,
			ForbiddenErrorSubstrings: []string{oidcContractClientSecret},
		},
		{
			Name: "token request rejects unsupported grant type",
			Request: requesttest.NewFormRequest(
				http.MethodPost,
				"/oidc/token",
				oidcTokenContractForm(oidcParamGrantType, "password", oidcParamClientID, "synthetic-client", oidcParamClientAssertion, oidcContractClientAssertion),
			),
			WantErrorContains:        oidcParamGrantType,
			ForbiddenErrorSubstrings: []string{oidcContractClientAssertion},
		},
		{
			Name: "token request rejects wrong content type",
			Request: requesttest.NewRequest(
				http.MethodPost,
				"/oidc/token",
				"application/json",
				`{"grant_type":"client_credentials","client_secret":"`+oidcContractClientSecret+`"}`,
			),
			WantErrorContains:        "unexpected value",
			ForbiddenErrorSubstrings: []string{oidcContractClientSecret},
		},
	})
}

func TestOIDCDiscoveryAndJWKSResponsesMatchOpenAPIContract(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := requesttest.NewIDPValidator(t)
	cfg := &mockOIDCCfg{
		issuer:       oidcContractIssuer,
		signingKey:   secret.New(generateTestKey()),
		signingKeyID: "contract-kid",
	}
	router := newOIDCTestRouter(t, cfg, false)

	tests := []struct {
		assertBody func(t *testing.T, body []byte)
		name       string
		path       string
	}{
		{
			name:       "discovery",
			path:       "/.well-known/openid-configuration",
			assertBody: assertOIDCDiscoveryContractBody,
		},
		{
			name:       "jwks",
			path:       "/oidc/jwks",
			assertBody: assertJWKSContractBody,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, tt.path, nil)
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, request)

			requesttest.AssertRecorderResponse(t, validator, request, recorder, requesttest.ResponseValidation{
				ExpectedMediaType: "application/json",
			})
			tt.assertBody(t, recorder.Body.Bytes())
		})
	}
}

func TestBrowserLoginResponsesUseBrowserContractSemantics(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := requesttest.NewIDPValidator(t)

	t.Run("login form is html form response", func(t *testing.T) {
		runLoginFormResponseContract(t, validator)
	})

	t.Run("logged-in login request redirects to oidc flow", func(t *testing.T) {
		runLoggedInLoginRedirectContract(t, validator)
	})
}

func assertOIDCDiscoveryContractBody(t *testing.T, body []byte) {
	t.Helper()

	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("discovery body is not JSON: %v", err)
	}

	for _, key := range []string{oidcDiscoveryIssuerField, oidcDiscoveryAuthEndpoint, oidcDiscoveryTokenEndpoint, oidcDiscoveryJWKSURIField} {
		if strings.TrimSpace(document[key].(string)) == "" {
			t.Fatalf("discovery field %q missing or empty", key)
		}
	}
}

func assertJWKSContractBody(t *testing.T, body []byte) {
	t.Helper()

	var document map[string][]map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("jwks body is not JSON: %v", err)
	}

	keys := document["keys"]
	if len(keys) != 1 {
		t.Fatalf("jwks keys length = %d, want 1", len(keys))
	}

	for _, field := range []string{oidcJWKSTypeField, oidcJWKSAlgorithmField, oidcJWKSUseField, oidcJWKSKIDField} {
		if strings.TrimSpace(keys[0][field].(string)) == "" {
			t.Fatalf("jwks key field %q missing or empty", field)
		}
	}
}

func runLoginFormResponseContract(t *testing.T, validator *requesttest.Validator) {
	t.Helper()

	router := newLoginResponseContractRouter(t, map[string]any{
		definitions.SessionKeyIdPFlowID:      "flow-form",
		definitions.SessionKeyIdPFlowType:    definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType:  definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIdPClientID:    latchedConsentClientID,
		definitions.SessionKeyIdPRedirectURI: oidcContractRedirectURI,
	})

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	requesttest.AssertRecorderResponse(t, validator, request, recorder, requesttest.ResponseValidation{
		ExpectedMediaType: "text/html",
		ExcludeBody:       true,
	})

	body := recorder.Body.String()
	for _, snippet := range []string{`<form`, `method="post"`, `action="/login"`, `name="username"`, `name="password"`} {
		if !strings.Contains(body, snippet) {
			t.Fatalf("login form body missing %q: %s", snippet, body)
		}
	}
}

func runLoggedInLoginRedirectContract(t *testing.T, validator *requesttest.Validator) {
	t.Helper()

	router := newLoginResponseContractRouter(t, map[string]any{
		definitions.SessionKeyAccount:         frontendTestAccount,
		definitions.SessionKeyIdPFlowID:       "flow-redirect",
		definitions.SessionKeyIdPFlowType:     definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType:   definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIdPClientID:     latchedConsentClientID,
		definitions.SessionKeyIdPRedirectURI:  oidcContractRedirectURI,
		definitions.SessionKeyIdPScope:        oidcContractScope,
		definitions.SessionKeyIdPState:        oidcContractState,
		definitions.SessionKeyIdPResponseType: oidcParamCode,
	})

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	requesttest.AssertRecorderResponse(t, validator, request, recorder, requesttest.ResponseValidation{
		RequiredHeaders: []string{"Location"},
		ExcludeBody:     true,
	})

	location := recorder.Header().Get("Location")
	if !strings.Contains(location, "/oidc/authorize") || !strings.Contains(location, "client_id="+latchedConsentClientID) {
		t.Fatalf("redirect Location = %q, want OIDC authorize target", location)
	}

	if strings.Contains(recorder.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("redirect Content-Type = %q, want browser redirect semantics", recorder.Header().Get("Content-Type"))
	}
}

func oidcTokenContractForm(pairs ...string) string {
	values := make(url.Values)

	for index := 0; index+1 < len(pairs); index += 2 {
		values.Set(pairs[index], pairs[index+1])
	}

	return values.Encode()
}

func newLoginResponseContractRouter(t *testing.T, sessionData map[string]any) *gin.Engine {
	t.Helper()

	d := &deps.Deps{
		Cfg:         &mockFrontendCfg{},
		Env:         config.NewTestEnvironmentConfig(),
		LangManager: &mockLangManager{},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	handler := NewFrontendHandler(d)
	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("idp_login.html").Parse(
		`<html><body><form method="post" action="{{ .PostLoginEndpoint }}"><input name="username"><input name="password" type="password"></form></body></html>`,
	)))
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: sessionData})
		ctx.Next()
	})
	router.GET("/login", handler.Login)

	return router
}

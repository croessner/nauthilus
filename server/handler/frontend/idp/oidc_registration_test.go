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
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp/dcr"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

type registrationServiceStub struct {
	response   dcr.RegistrationResponse
	reserveErr error
	err        error
}

// ReserveAttempt returns the fixture-owned attempt result.
func (s registrationServiceStub) ReserveAttempt(_ context.Context, _ string) error {
	return s.reserveErr
}

// Register returns the fixture-owned result.
func (s registrationServiceStub) Register(_ context.Context, _ dcr.EffectiveMetadata, _ string) (dcr.RegistrationResponse, error) {
	return s.response, s.err
}

func TestOIDCRegistrationHTTPMatrix(t *testing.T) {
	tests := []struct {
		service     dynamicRegistrationService
		name        string
		contentType string
		body        string
		wantError   string
		wantStatus  int
	}{
		{name: "missing media type", body: `{}`, wantStatus: http.StatusUnsupportedMediaType, wantError: "Unsupported Media Type"},
		{name: "wrong media type", contentType: "text/plain", body: `{}`, wantStatus: http.StatusUnsupportedMediaType, wantError: "Unsupported Media Type"},
		{name: "invalid JSON", contentType: "application/json", body: `{`, wantStatus: http.StatusBadRequest, wantError: "invalid_client_metadata"},
		{name: "invalid redirect", contentType: "application/json", body: `{"redirect_uris":["https://client.example/cb"]}`, wantStatus: http.StatusBadRequest, wantError: "invalid_redirect_uri"},
		{name: "software statement", contentType: "application/json", body: `{"software_statement":"signed"}`, wantStatus: http.StatusBadRequest, wantError: "unapproved_software_statement"},
		{name: "attempt rate limited", contentType: "application/json", body: `{`, service: registrationServiceStub{reserveErr: dcr.ErrRateLimited}, wantStatus: http.StatusTooManyRequests, wantError: "Too Many Requests"},
		{name: "rate limited", contentType: "application/json", body: validRegistrationBody(), service: registrationServiceStub{err: dcr.ErrRateLimited}, wantStatus: http.StatusTooManyRequests, wantError: "Too Many Requests"},
		{name: "repository unavailable", contentType: "application/json", body: validRegistrationBody(), service: registrationServiceStub{err: dcr.ErrUnavailable}, wantStatus: http.StatusServiceUnavailable, wantError: "Service Unavailable"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := newRegistrationTestRouter(t, test.service)

			request := httptest.NewRequest(http.MethodPost, oidcRegistrationEndpointPath, strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}

			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != test.wantStatus || !strings.Contains(response.Body.String(), test.wantError) {
				t.Fatalf("response = %d %s, want %d containing %q", response.Code, response.Body.String(), test.wantStatus, test.wantError)
			}

			assertRegistrationNoStoreHeaders(t, response)
		})
	}
}

func TestOIDCRegistrationRejectsOversizedBody(t *testing.T) {
	router := newRegistrationTestRouter(t, registrationServiceStub{})
	request := httptest.NewRequest(http.MethodPost, oidcRegistrationEndpointPath, strings.NewReader(strings.Repeat("x", 16_385)))
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", response.Code)
	}

	assertRegistrationNoStoreHeaders(t, response)
}

func TestOIDCRegistrationReturnsOnlyEffectivePublicMetadata(t *testing.T) {
	stub := registrationServiceStub{response: dcr.RegistrationResponse{
		EffectiveMetadata: dcr.EffectiveMetadata{
			RedirectURIs:             []string{"http://127.0.0.1/callback"},
			GrantTypes:               []string{dcr.GrantAuthorizationCode},
			ResponseTypes:            []string{dcr.ResponseTypeCode},
			Scope:                    "openid",
			TokenEndpointAuthMethod:  dcr.TokenEndpointAuthMethodNone,
			ApplicationType:          dcr.ApplicationTypeNative,
			SubjectType:              dcr.SubjectTypePublic,
			IDTokenSignedResponseAlg: dcr.IDTokenSigningAlgorithm,
		},
		ClientID:         "dcr_generated",
		ClientIDIssuedAt: 1_700_000_000,
	}}
	router := newRegistrationTestRouter(t, stub)
	request := httptest.NewRequest(http.MethodPost, oidcRegistrationEndpointPath, strings.NewReader(validRegistrationBody()))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")

	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s, want 201", response.Code, response.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	for _, forbidden := range []string{"client_secret", "registration_access_token", "registration_client_uri"} {
		if _, present := payload[forbidden]; present {
			t.Fatalf("response exposed %s", forbidden)
		}
	}

	assertRegistrationNoStoreHeaders(t, response)
}

func TestOIDCRegistrationWrongMethodReturns405(t *testing.T) {
	router := newRegistrationTestRouter(t, registrationServiceStub{})
	request := httptest.NewRequest(http.MethodGet, oidcRegistrationEndpointPath, nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", response.Code)
	}

	if !strings.Contains(response.Header().Get("Allow"), http.MethodPost) {
		t.Fatalf("Allow = %q, want POST", response.Header().Get("Allow"))
	}

	assertRegistrationNoStoreHeaders(t, response)
}

// newRegistrationTestRouter creates an enabled handler with an isolated service boundary.
func newRegistrationTestRouter(t *testing.T, service dynamicRegistrationService) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &mockOIDCCfg{
		issuer:              "https://auth.example.com",
		signingKey:          secret.New(generateTestKey()),
		dynamicRegistration: true,
		dynamicPolicy: config.OIDCDynamicClientRegistrationConfig{
			RequiredScopes: []string{"openid"},
		},
	}
	db, _ := redismock.NewClientMock()
	dependencies := &deps.Deps{
		Cfg:         cfg,
		Env:         config.NewTestEnvironmentConfig(),
		LangManager: &mockLangManager{},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:       rediscli.NewTestClient(db),
	}
	util.SetDefaultEnvironment(dependencies.Env)
	handler := NewOIDCHandler(dependencies, nil, nil)

	if service == nil {
		service = registrationServiceStub{err: errors.New("unexpected registration service call")}
	}

	handler.registrationService = service
	router := gin.New()
	handler.Register(router)

	return router
}

// validRegistrationBody returns the minimal profile request used by HTTP tests.
func validRegistrationBody() string {
	return `{"redirect_uris":["http://127.0.0.1/callback"]}`
}

// assertRegistrationNoStoreHeaders verifies the registration cache prohibition.
func assertRegistrationNoStoreHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()

	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers = %q / %q", response.Header().Get("Cache-Control"), response.Header().Get("Pragma"))
	}
}

// Copyright (C) 2024 Christian Roessner
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

package mfa_backchannel

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
)

type recordingMFABackchannelApplication struct {
	lookupInputs []core.AuthInput
	outcome      *core.AuthOutcome
}

// Authenticate rejects password evaluation from the MFA mutation adapter.
func (a *recordingMFABackchannelApplication) Authenticate(context.Context, core.AuthInput) (*core.AuthOutcome, error) {
	return nil, errors.New("unexpected MFA backchannel authentication")
}

// LookupIdentity records the admitted mutation target.
func (a *recordingMFABackchannelApplication) LookupIdentity(
	_ context.Context,
	input core.AuthInput,
) (*core.AuthOutcome, error) {
	a.lookupInputs = append(a.lookupInputs, input)

	return a.outcome, nil
}

// ListAccounts rejects enumeration from the MFA mutation adapter.
func (a *recordingMFABackchannelApplication) ListAccounts(context.Context, core.AuthInput) (*core.ListAccountsOutcome, error) {
	return nil, errors.New("unexpected MFA backchannel account listing")
}

func performRequest(t *testing.T, handler gin.HandlerFunc, method string, url string, body string) *httptest.ResponseRecorder {
	t.Helper()

	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, url, strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler(ctx)

	return recorder
}

func TestValidationErrors(t *testing.T) {
	handler := New(&handlerdeps.Deps{})

	t.Run("AddTOTP_MissingUsername", func(t *testing.T) {
		recorder := performRequest(t, handler.AddTOTP, http.MethodPost, "/totp", `{"totp_secret":"abc"}`)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", recorder.Code)
		}
	})

	t.Run("DeleteTOTP_MissingUsername", func(t *testing.T) {
		recorder := performRequest(t, handler.DeleteTOTP, http.MethodDelete, "/totp", `{}`)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", recorder.Code)
		}
	})

	t.Run("AddRecoveryCodes_MissingCodes", func(t *testing.T) {
		recorder := performRequest(t, handler.AddRecoveryCodes, http.MethodPost, "/totp/recovery-codes", `{"username":"user"}`)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", recorder.Code)
		}
	})

	t.Run("GetWebAuthnCredential_MissingUsername", func(t *testing.T) {
		recorder := performRequest(t, handler.GetWebAuthnCredential, http.MethodGet, "/webauthn/credential", "")
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", recorder.Code)
		}
	})

	t.Run("SaveWebAuthnCredential_MissingCredential", func(t *testing.T) {
		recorder := performRequest(t, handler.SaveWebAuthnCredential, http.MethodPost, "/webauthn/credential", `{"username":"user"}`)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", recorder.Code)
		}
	})

	t.Run("UpdateWebAuthnCredential_MissingOldCredential", func(t *testing.T) {
		recorder := performRequest(t, handler.UpdateWebAuthnCredential, http.MethodPut, "/webauthn/credential", `{"username":"user","credential":"{}"}`)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", recorder.Code)
		}
	})

	t.Run("DeleteWebAuthnCredential_MissingCredential", func(t *testing.T) {
		recorder := performRequest(t, handler.DeleteWebAuthnCredential, http.MethodDelete, "/webauthn/credential", `{"username":"user"}`)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", recorder.Code)
		}
	})
}

func TestMFABackchannelMutationRejectsBaseScopeBearer(t *testing.T) {
	router := newMFABackchannelScopeRouter(definitions.ScopeAuthenticate)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mfa-backchannel/totp", strings.NewReader(`{"username":"alice","totp_secret":"secret"}`))
	request.Header.Set("Authorization", "Bearer base-scope-token")
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", response.Code)
	}
}

func TestBuildAuthStateUsesApplicationAdmissionAndExactBackendBinding(t *testing.T) {
	application := &recordingMFABackchannelApplication{outcome: &core.AuthOutcome{
		Decision: core.AuthDecisionOK, Account: "alice", Protocol: definitions.ProtoIDP,
		Backend: definitions.BackendLua, BackendName: definitions.DefaultBackendName,
	}}
	handler := newRecordingMFABackchannelHandler(application)
	ctx := newMFABackchannelApplicationContext(t)

	selection, err := newMFABackendSelection(definitions.BackendLuaName, definitions.DefaultBackendName)
	if err != nil {
		t.Fatalf("newMFABackendSelection() error = %v", err)
	}

	authState, err := handler.buildAuthState(ctx, selection, "alice", "external-session-42")
	if err != nil {
		t.Fatalf("buildAuthState() error = %v", err)
	}

	assertMFABackchannelApplicationInput(t, application, selection, authState)
}

func TestBuildAuthStateRejectsBackendMismatchBeforeMutation(t *testing.T) {
	application := &recordingMFABackchannelApplication{outcome: &core.AuthOutcome{
		Decision: core.AuthDecisionOK, Account: "alice", Protocol: definitions.ProtoIDP,
		Backend: definitions.BackendLDAP, BackendName: definitions.DefaultBackendName,
	}}
	handler := newRecordingMFABackchannelHandler(application)
	ctx := newMFABackchannelApplicationContext(t)

	selection, err := newMFABackendSelection(definitions.BackendLuaName, definitions.DefaultBackendName)
	if err != nil {
		t.Fatalf("newMFABackendSelection() error = %v", err)
	}

	if _, err = handler.buildAuthState(ctx, selection, "alice", "external-session-42"); err == nil {
		t.Fatal("buildAuthState() accepted a mismatched application backend")
	}

	if len(application.lookupInputs) != 1 {
		t.Fatalf("application lookup calls = %d, want 1", len(application.lookupInputs))
	}
}

// assertMFABackchannelApplicationInput verifies detached admission and specialized state mapping.
func assertMFABackchannelApplicationInput(
	t *testing.T,
	application *recordingMFABackchannelApplication,
	selection mfaBackendSelection,
	authState *core.AuthState,
) {
	t.Helper()

	if len(application.lookupInputs) != 1 {
		t.Fatalf("application lookup calls = %d, want 1", len(application.lookupInputs))
	}

	input := application.lookupInputs[0]
	if input.Mode != core.AuthModeLookupIdentity || input.EntryPoint != core.AuthnEntryIDPMFABackend {
		t.Fatalf("application operation = %q/%d, want lookup/MFA backend", input.Mode, input.EntryPoint)
	}

	if input.Credentials.Username != "alice" || input.Context.Protocol != definitions.ProtoIDP {
		t.Fatalf("application identity/protocol = %q/%q, want alice/idp", input.Credentials.Username, input.Context.Protocol)
	}

	if input.IDP.ExistingBackendRef != selection.backendRef {
		t.Fatalf("application backend ref = %#v, want %#v", input.IDP.ExistingBackendRef, selection.backendRef)
	}

	if _, ok := input.Context.RequestMetadata["authorization"]; ok {
		t.Fatal("authorization header crossed the application boundary")
	}

	if _, ok := input.Context.RequestMetadata["cookie"]; ok {
		t.Fatal("cookie header crossed the application boundary")
	}

	if authState.Request.ExternalSessionID != "external-session-42" {
		t.Fatalf("specialized external session = %q, want external-session-42", authState.Request.ExternalSessionID)
	}

	if !selection.matches(authState) {
		t.Fatal("specialized state lost the admitted backend binding")
	}
}

// newRecordingMFABackchannelHandler builds the smallest application-backed handler fixture.
func newRecordingMFABackchannelHandler(application core.AuthApplicationService) *Handler {
	db, _ := redismock.NewClientMock()
	cfg := &config.FileSettings{
		Server: &config.ServerSection{Redis: config.Redis{Prefix: "mfa-backchannel-application:"}},
		IDP:    &config.IDPSection{},
	}

	return New(&handlerdeps.Deps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(), Logger: slog.Default(),
		Redis: rediscli.NewTestClient(db), AuthApplication: application,
	})
}

// newMFABackchannelApplicationContext returns protected transport evidence without browser-state ownership.
func newMFABackchannelApplicationContext(t *testing.T) *gin.Context {
	t.Helper()

	gin.SetMode(gin.TestMode)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "https://idp.example.test/api/v1/mfa-backchannel/totp", nil)
	ctx.Request.RemoteAddr = "192.0.2.60:4242"
	ctx.Request.Header.Set("Authorization", "Bearer service-token")
	ctx.Request.Header.Set("Cookie", "must-not-cross=browser-state")
	ctx.Set(definitions.CtxGUIDKey, "mfa-backchannel-application-request")
	ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	return ctx
}

// newMFABackchannelScopeRouter builds MFA backchannel routes behind bearer base auth.
func newMFABackchannelScopeRouter(scope string) *gin.Engine {
	gin.SetMode(gin.TestMode)

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			OIDCAuth: config.OIDCAuth{Enabled: true},
		},
	}
	validator := &mfaBackchannelTokenValidator{
		claims: jwt.MapClaims{
			"aud":                      definitions.AudienceBackchannelAPI,
			definitions.ClaimClientID:  "mfa-client",
			"scope":                    scope,
			"sub":                      "mfa-client",
			definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
		},
	}

	router := gin.New()
	router.Use(gin.Recovery())

	group := router.Group("/api/v1")
	group.Use(func(ctx *gin.Context) {
		if !oidcbearer.AuthorizeAuthenticateScope(ctx, validator, cfg, slog.Default()) {
			return
		}

		ctx.Next()
	})

	New(&handlerdeps.Deps{}).Register(group)

	return router
}

type mfaBackchannelTokenValidator struct {
	claims jwt.MapClaims
}

// ValidateToken returns static claims for MFA backchannel route tests.
func (v *mfaBackchannelTokenValidator) ValidateToken(context.Context, string) (jwt.MapClaims, error) {
	return v.claims, nil
}

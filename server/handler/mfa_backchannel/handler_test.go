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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/middleware/oidcbearer"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

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

// newMFABackchannelScopeRouter builds MFA backchannel routes behind bearer base auth.
func newMFABackchannelScopeRouter(scope string) *gin.Engine {
	gin.SetMode(gin.TestMode)

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			OIDCAuth: config.OIDCAuth{Enabled: true},
		},
	}
	validator := &mfaBackchannelTokenValidator{
		claims: jwt.MapClaims{"scope": scope},
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

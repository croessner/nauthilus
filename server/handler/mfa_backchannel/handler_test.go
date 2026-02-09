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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	"github.com/gin-gonic/gin"
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
	handler := NewWithDeps(&handlerdeps.Deps{})

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

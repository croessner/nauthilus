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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const authorizationResponseIssuer = "https://login.example.test"

// TestOIDCAuthorizationResponseCarriesIssuer pins RFC 9207: code and error responses carry iss, registered query
// parameters survive, fragments are dropped, and an unset issuer adds no empty parameter.
func TestOIDCAuthorizationResponseCarriesIssuer(t *testing.T) {
	response := oidcAuthorizationResponse{issuer: authorizationResponseIssuer}

	for name, tc := range map[string]struct {
		response    oidcAuthorizationResponse
		redirectURI string
		state       string
		want        string
	}{
		"code with state": {
			response, "http://127.0.0.1/callback", "s 1",
			"http://127.0.0.1/callback?code=c&iss=https%3A%2F%2Flogin.example.test&state=s+1",
		},
		"code without state, registered query and fragment": {
			response, " http://localhost/callback?keep=1#frag ", "",
			"http://localhost/callback?code=c&iss=https%3A%2F%2Flogin.example.test&keep=1",
		},
		"no issuer configured": {
			oidcAuthorizationResponse{}, "http://127.0.0.1/callback", "",
			"http://127.0.0.1/callback?code=c",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := tc.response.successURL(tc.redirectURI, "c", tc.state)
			if !assert.NoError(t, err) {
				return
			}

			assert.Equal(t, tc.want, got)
		})
	}

	if _, err := response.successURL("  ", "c", ""); err == nil {
		t.Fatal("an empty redirect URI must be refused")
	}

	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)

	response.redirectError(ctx, "http://127.0.0.1/callback", "s", "login_required")
	assert.Equal(t, http.StatusFound, recorder.Code)
	assert.Equal(t, "http://127.0.0.1/callback?error=login_required&iss=https%3A%2F%2Flogin.example.test&state=s",
		recorder.Header().Get("Location"))

	recorder = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)

	response.redirectError(ctx, "http://[::1", "s", "login_required")
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Empty(t, recorder.Header().Get("Location"))
}

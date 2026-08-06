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
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	nauthilusidp "github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestValidateOIDCAuthorizeRequest_ConfidentialClientRequiresConfiguredPKCE(t *testing.T) {
	gin.SetMode(gin.TestMode)

	client := config.OIDCClient{
		ClientID:                "matrix-client",
		ClientSecret:            secret.New("matrix-secret"),
		RedirectURIs:            []string{"https://matrix.example.test/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		RequirePKCE:             true,
	}
	cfg := &mockOIDCCfg{
		issuer:     "https://auth.example.test",
		signingKey: secret.New(generateTestKey()),
		clients:    []config.OIDCClient{client},
	}
	handlerDeps := &deps.Deps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler := NewOIDCHandler(handlerDeps, nauthilusidp.NewNauthilusIDP(handlerDeps), nil)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)

	request := oidcAuthorizeRequest{
		clientID:     client.ClientID,
		redirectURI:  client.RedirectURIs[0],
		responseType: oidcResponseTypeCode,
	}
	_, accepted := handler.validateOIDCAuthorizeRequest(ctx, &request)

	assert.False(t, accepted)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "PKCE is required for this client")
}

func TestNormalizeCodeChallengeMethodRequiresExactS256AndValidChallenge(t *testing.T) {
	digest := sha256.Sum256([]byte("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"))
	validChallenge := base64.RawURLEncoding.EncodeToString(digest[:])
	tests := []struct {
		challenge string
		method    string
		name      string
		wantError bool
	}{
		{name: "valid", challenge: validChallenge, method: oidcPKCEChallengeMethodS256},
		{name: "lowercase method", challenge: validChallenge, method: "s256", wantError: true},
		{name: "padded method", challenge: validChallenge, method: " S256 ", wantError: true},
		{name: "short challenge", challenge: "short", method: oidcPKCEChallengeMethodS256, wantError: true},
		{name: "padded challenge", challenge: validChallenge + "=", method: oidcPKCEChallengeMethodS256, wantError: true},
		{name: "whitespace challenge", challenge: " " + validChallenge, method: oidcPKCEChallengeMethodS256, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := normalizeCodeChallengeMethod(test.challenge, test.method)
			assert.Equal(t, test.wantError, err != nil)
		})
	}
}

func TestValidatePKCEVerifierDoesNotNormalizeWhitespace(t *testing.T) {
	verifier := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])

	assert.NoError(t, validatePKCEVerifier(challenge, oidcPKCEChallengeMethodS256, verifier))
	assert.Error(t, validatePKCEVerifier(challenge, oidcPKCEChallengeMethodS256, " "+verifier))
	assert.Error(t, validatePKCEVerifier(challenge, oidcPKCEChallengeMethodS256, verifier+" "))
}

func TestRejectOIDCAuthorizeMetadataUsesExplicitErrorAndPreservesQuery(t *testing.T) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)
	request := oidcAuthorizeRequest{
		redirectURI: "http://127.0.0.1/callback?existing=value",
		state:       "state value",
	}

	_, accepted := rejectOIDCAuthorizeMetadata(ctx, &config.OIDCClient{Dynamic: true}, request, oidcErrorUnsupportedResponseType, "unsupported")

	assert.False(t, accepted)
	assert.Equal(t, "http://127.0.0.1/callback?error=unsupported_response_type&existing=value&state=state+value", recorder.Header().Get("Location"))
}

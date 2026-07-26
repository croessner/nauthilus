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

	_, accepted := handler.validateOIDCAuthorizeRequest(ctx, oidcAuthorizeRequest{
		clientID:     client.ClientID,
		redirectURI:  client.RedirectURIs[0],
		responseType: oidcResponseTypeCode,
	})

	assert.False(t, accepted)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "PKCE is required for this client")
}

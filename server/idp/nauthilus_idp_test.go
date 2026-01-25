// Copyright (C) 2025 Christian Rößner
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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/stretchr/testify/assert"
)

func generateTestKey() string {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return string(pemData)
}

type mockIdpConfig struct {
	config.File
	oidc config.OIDCConfig
}

func (m *mockIdpConfig) GetIdP() *config.IdPSection {
	return &config.IdPSection{
		OIDC: m.oidc,
	}
}

func TestNauthilusIdP_Tokens(t *testing.T) {
	signingKey := generateTestKey()
	oidcCfg := config.OIDCConfig{
		Issuer:     "https://issuer.example.com",
		SigningKey: signingKey,
		Clients: []config.OIDCClient{
			{ClientID: "client1", RedirectURIs: []string{"http://localhost/cb"}, DelayedResponse: true},
		},
	}
	cfg := &mockIdpConfig{oidc: oidcCfg}
	d := &deps.Deps{Cfg: cfg}
	idp := NewNauthilusIdP(d)
	ctx := context.Background()

	t.Run("FindClient", func(t *testing.T) {
		client, found := idp.FindClient("client1")
		assert.True(t, found)
		assert.Equal(t, "client1", client.ClientID)

		_, found = idp.FindClient("nonexistent")
		assert.False(t, found)
	})

	t.Run("IsDelayedResponse", func(t *testing.T) {
		assert.True(t, idp.IsDelayedResponse("client1", ""))
		assert.False(t, idp.IsDelayedResponse("nonexistent", ""))
	})

	t.Run("ValidateRedirectURI", func(t *testing.T) {
		client := &oidcCfg.Clients[0]
		assert.True(t, idp.ValidateRedirectURI(client, "http://localhost/cb"))
		assert.False(t, idp.ValidateRedirectURI(client, "http://malicious.com"))
	})

	t.Run("ValidatePostLogoutRedirectURI", func(t *testing.T) {
		client := &config.OIDCClient{
			PostLogoutRedirectURIs: []string{"https://app.com/logout-cb"},
		}
		assert.True(t, idp.ValidatePostLogoutRedirectURI(client, "https://app.com/logout-cb"))
		assert.True(t, idp.ValidatePostLogoutRedirectURI(client, ""))
		assert.False(t, idp.ValidatePostLogoutRedirectURI(client, "https://evil.com"))
	})

	t.Run("IssueLogoutToken", func(t *testing.T) {
		token, err := idp.IssueLogoutToken(ctx, "client1", "user123")
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		claims, err := idp.ValidateToken(ctx, token)
		assert.NoError(t, err)
		assert.Equal(t, "user123", claims["sub"])
		assert.Equal(t, "client1", claims["aud"])
		events, ok := claims["events"].(map[string]any)
		assert.True(t, ok)
		assert.Contains(t, events, "http://schemas.openid.net/event/backchannel-logout")
	})

	t.Run("IssueAndValidateToken", func(t *testing.T) {
		session := &OIDCSession{
			ClientID: "client1",
			UserID:   "user123",
			Scopes:   []string{"openid", "profile"},
			AuthTime: time.Now(),
		}

		idToken, accessToken, err := idp.IssueTokens(ctx, session)
		assert.NoError(t, err)
		assert.NotEmpty(t, idToken)
		assert.NotEmpty(t, accessToken)

		claims, err := idp.ValidateToken(ctx, idToken)
		assert.NoError(t, err)
		assert.Equal(t, "user123", claims["sub"])
		assert.Equal(t, "https://issuer.example.com", claims["iss"])
	})
}

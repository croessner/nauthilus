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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

type mockOIDCCfg struct {
	config.File
	issuer string
}

func (m *mockOIDCCfg) GetIdP() *config.IdPSection {
	return &config.IdPSection{
		OIDC: config.OIDCConfig{
			Issuer:     m.issuer,
			SigningKey: generateTestKey(),
		},
	}
}

func generateTestKey() string {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return string(pemData)
}

func (m *mockOIDCCfg) GetServer() *config.ServerSection {
	return &config.ServerSection{
		Redis: config.Redis{
			Prefix: "test:",
		},
	}
}

func TestOIDCHandler_Discovery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	issuer := "https://auth.example.com"
	cfg := &mockOIDCCfg{issuer: issuer}

	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:   cfg,
		Redis: rClient,
	}

	// idpInstance can be nil for Discovery
	h := NewOIDCHandler(d, nil)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	h.Discovery(ctx)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, issuer, resp["issuer"])
	assert.Equal(t, issuer+"/oidc/authorize", resp["authorization_endpoint"])
}

func TestOIDCHandler_JWKS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &mockOIDCCfg{issuer: "https://auth.example.com"}
	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)
	d := &deps.Deps{Cfg: cfg, Redis: rClient}
	h := NewOIDCHandler(d, nil)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	h.JWKS(ctx)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.NotNil(t, resp["keys"])
}

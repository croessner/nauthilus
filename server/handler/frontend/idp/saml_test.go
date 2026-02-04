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
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

type mockSAMLCfg struct {
	config.File
	entityID    string
	certificate string
	key         string
}

func (m *mockSAMLCfg) GetIdP() *config.IdPSection {
	return &config.IdPSection{
		OIDC: config.OIDCConfig{
			Issuer: "https://auth.example.com",
		},
		SAML2: config.SAML2Config{
			EntityID: m.entityID,
			Cert:     m.certificate,
			Key:      m.key,
		},
	}
}

func (m *mockSAMLCfg) GetServer() *config.ServerSection {
	return &config.ServerSection{}
}

func TestSAMLHandler_Metadata(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Generate a self-signed certificate for the test
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test IdP"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	assert.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	entityID := "https://auth.example.com/saml"
	cfg := &mockSAMLCfg{
		entityID:    entityID,
		certificate: string(certPEM),
		key:         string(keyPEM),
	}

	d := &deps.Deps{
		Cfg:    cfg,
		Logger: slog.Default(),
	}
	store := cookie.NewStore([]byte("secret"))
	h := NewSAMLHandler(store, d, nil)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/saml/metadata", nil)

	h.Metadata(ctx)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), entityID)
}

func TestSAML_Routes_HaveLuaContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &mockSAMLCfg{entityID: "test", certificate: "test"}
	d := &deps.Deps{Cfg: cfg}
	store := cookie.NewStore([]byte("secret"))
	h := NewSAMLHandler(store, d, nil)

	r := gin.New()
	h.Register(r)

	routes := []string{"/saml/metadata", "/saml/sso"}
	for _, path := range routes {
		t.Run(path, func(t *testing.T) {
			// Let's define r and the test to be more precise
			r := gin.New()
			var capturedCtx *gin.Context
			r.Use(func(c *gin.Context) {
				c.Next()
				capturedCtx = c
			})
			h.Register(r)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", path, nil)
			r.ServeHTTP(w, req)

			_, exists := capturedCtx.Get(definitions.CtxDataExchangeKey)
			assert.True(t, exists, "Lua context should be set for path: %s", path)

			svc, _ := capturedCtx.Get(definitions.CtxServiceKey)
			assert.Equal(t, definitions.ServIdP, svc)
		})
	}
}

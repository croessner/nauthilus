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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

type mockSAMLCfg struct {
	config.File
	entityID    string
	certificate string
}

func (m *mockSAMLCfg) GetIdP() *config.IdPSection {
	return &config.IdPSection{
		OIDC: config.OIDCConfig{
			Issuer: "https://auth.example.com",
		},
		SAML2: config.SAML2Config{
			EntityID:    m.entityID,
			Certificate: m.certificate,
		},
	}
}

func TestSAMLHandler_Metadata(t *testing.T) {
	gin.SetMode(gin.TestMode)
	entityID := "https://auth.example.com/saml"
	cert := "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----"
	cfg := &mockSAMLCfg{entityID: entityID, certificate: cert}

	d := &deps.Deps{Cfg: cfg}
	h := NewSAMLHandler(d, nil)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/saml/metadata", nil)

	h.Metadata(ctx)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), entityID)
	assert.Contains(t, w.Body.String(), "ABC")
	assert.NotContains(t, w.Body.String(), "-----BEGIN CERTIFICATE-----")
}

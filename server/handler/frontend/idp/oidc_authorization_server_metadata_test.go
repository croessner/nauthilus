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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestAuthorizationServerMetadataLocations pins the RFC 8414 root and path-insertion forms: the inserted path must
// equal the current issuer path, and the served document is the OIDC discovery document including the RFC 9207 flag.
func TestAuthorizationServerMetadataLocations(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	for name, tc := range map[string]struct {
		issuer string
		path   string
		status int
	}{
		"root issuer, root form":             {"https://auth.example.com", authorizationServerMetadataPath, http.StatusOK},
		"root issuer, inserted path":         {"https://auth.example.com", authorizationServerMetadataPath + "/idp", http.StatusNotFound},
		"root issuer, trailing slash":        {"https://auth.example.com", authorizationServerMetadataPath + "/", http.StatusNotFound},
		"path issuer, inserted path":         {"https://auth.example.com/idp", authorizationServerMetadataPath + "/idp", http.StatusOK},
		"path issuer, nested inserted path":  {"https://auth.example.com/a/b/", authorizationServerMetadataPath + "/a/b", http.StatusOK},
		"path issuer, foreign inserted path": {"https://auth.example.com/idp", authorizationServerMetadataPath + "/other", http.StatusNotFound},
		"path issuer, prefix of the path":    {"https://auth.example.com/idp", authorizationServerMetadataPath + "/id", http.StatusNotFound},
		"path issuer, appended root form":    {"https://auth.example.com/idp", authorizationServerMetadataPath, http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			router := newOIDCTestRouter(t, &mockOIDCCfg{issuer: tc.issuer, signingKey: secret.New(generateTestKey())}, false)
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tc.path, nil))

			if !assert.Equal(t, tc.status, recorder.Code) {
				return
			}

			if tc.status != http.StatusOK {
				return
			}

			var metadata map[string]any

			if !assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &metadata)) {
				return
			}

			assert.Equal(t, tc.issuer, metadata["issuer"])
			assert.Equal(t, true, metadata["authorization_response_iss_parameter_supported"])
			assert.Equal(t, mustGetOIDCDiscoveryResponse(t, tc.issuer), metadata)
		})
	}
}

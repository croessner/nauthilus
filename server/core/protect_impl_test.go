// Copyright (C) 2026 Christian Roessner
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

package core

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestProtectedEndpointClientIgnoresClientIPFromUntrustedPeer(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := newProtectedEndpointClientTestConfig("198.51.100.10")
	ctx := newProtectedEndpointClientTestContext("198.51.100.20:54321", map[string]string{
		"Client-IP":     "203.0.113.77",
		"X-Client-Port": "2525",
	})

	auth := &AuthState{}
	clientIP, clientPort := protectedEndpointClient(ctx, cfg, nil, auth)

	assert.Equal(t, "198.51.100.20", clientIP)
	assert.Equal(t, "54321", clientPort)
}

func TestProtectedEndpointClientUsesForwardedIPFromTrustedProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := newProtectedEndpointClientTestConfig("198.51.100.10")
	ctx := newProtectedEndpointClientTestContext("198.51.100.10:54321", map[string]string{
		"X-Forwarded-For": "203.0.113.88",
	})

	auth := &AuthState{}
	clientIP, _ := protectedEndpointClient(ctx, cfg, nil, auth)

	assert.Equal(t, "203.0.113.88", clientIP)
}

// newProtectedEndpointClientTestContext builds a request context for protected endpoint IP tests.
func newProtectedEndpointClientTestContext(remoteAddr string, headers map[string]string) *gin.Context {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.RemoteAddr = remoteAddr

	for key, value := range headers {
		ctx.Request.Header.Set(key, value)
	}

	return ctx
}

// newProtectedEndpointClientTestConfig returns proxy trust settings for protected endpoint tests.
func newProtectedEndpointClientTestConfig(trustedProxies ...string) config.File {
	return &config.FileSettings{
		Server: &config.ServerSection{
			TrustedProxies: trustedProxies,
		},
	}
}

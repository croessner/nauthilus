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

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/gin-gonic/gin"
)

const (
	registrationTestProxy    = "10.0.0.1"
	registrationTestClient   = "198.51.100.7"
	registrationTestRealIP   = "203.0.113.9"
	registrationTestProxyNet = "10.0.0.0/8"
)

// newRegistrationSourceContext builds a request from a trusted proxy whose engine trusts the proxy the same
// way the production router does, so Gin's own ClientIP would honor X-Real-IP.
func newRegistrationSourceContext(t *testing.T, headers map[string]string) (*gin.Context, config.File) {
	t.Helper()

	ctx, engine := gin.CreateTestContext(httptest.NewRecorder())
	if err := engine.SetTrustedProxies([]string{registrationTestProxyNet}); err != nil {
		t.Fatalf("SetTrustedProxies() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, oidcRegistrationEndpointPath, nil)
	request.RemoteAddr = registrationTestProxy + ":40000"

	for key, value := range headers {
		request.Header.Set(key, value)
	}

	ctx.Request = request

	cfg := &config.FileSettings{Server: &config.ServerSection{TrustedProxies: []string{registrationTestProxyNet}}}

	return ctx, cfg
}

func TestRegistrationSourceIgnoresXRealIPForInvalidForwardedChain(t *testing.T) {
	ctx, cfg := newRegistrationSourceContext(t, map[string]string{
		"X-Forwarded-For": "unknown",
		"X-Real-IP":       registrationTestRealIP,
	})

	if gin := ctx.ClientIP(); gin != registrationTestRealIP {
		t.Fatalf("fixture precondition: Gin ClientIP() = %q, want the X-Real-IP fallback %q", gin, registrationTestRealIP)
	}

	if got := registrationSource(ctx, cfg, log.GetLogger()); got != registrationTestProxy {
		t.Fatalf("registrationSource() = %q, want the direct peer %q", got, registrationTestProxy)
	}
}

func TestRegistrationSourceUsesTrustedForwardedClient(t *testing.T) {
	ctx, cfg := newRegistrationSourceContext(t, map[string]string{
		"X-Forwarded-For": registrationTestClient,
		"X-Real-IP":       registrationTestRealIP,
	})

	if got := registrationSource(ctx, cfg, log.GetLogger()); got != registrationTestClient {
		t.Fatalf("registrationSource() = %q, want the forwarded client %q", got, registrationTestClient)
	}
}

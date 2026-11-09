package core

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const headerDecodeLoopbackIP = "127.0.0.1"

func newHeaderDecodeTestConfig() *config.FileSettings {
	return &config.FileSettings{
		Server: &config.ServerSection{
			DefaultHTTPRequestHeader: config.DefaultHTTPRequestHeader{
				Username:     "Auth-User",
				Password:     "Auth-Pass",
				Protocol:     "Auth-Protocol",
				AuthMethod:   "Auth-Method",
				LoginAttempt: "Auth-Login-Attempt",
				LocalIP:      "X-Local-IP",
				LocalPort:    "X-Auth-Port",
				ClientIP:     "Client-IP",
				ClientPort:   "X-Client-Port",
				ClientID:     "X-Client-ID",
				ClientHost:   "Client-Host",
				SSLSubject:   "X-SSL-Client-DN",
			},
		},
	}
}

func TestHeaderBasedAuth_IgnoresConfiguredClientIPFromUntrustedPeer(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := newHeaderDecodeTestConfig()
	cfg.Server.TrustedProxies = []string{"198.51.100.10"}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.RemoteAddr = "198.51.100.20:54321"
	ctx.Request.Header.Set("Client-IP", "203.0.113.77")
	ctx.Request.Header.Set("X-Client-Port", "2525")

	auth := NewAuthStateFromContextWithDeps(ctx, AuthDeps{Cfg: cfg})
	state := auth.(*AuthState)

	state.WithClientInfo(ctx)

	assert.Equal(t, "198.51.100.20", state.Request.ClientIP)
	assert.Equal(t, "", state.Request.XClientPort)
}

func TestHeaderBasedAuth_UsesTrustedForwardedClientIPWhenConfiguredHeaderIsMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := newHeaderDecodeTestConfig()
	cfg.Server.TrustedProxies = []string{headerDecodeLoopbackIP}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.RemoteAddr = headerDecodeLoopbackIP + ":54321"
	ctx.Request.Header.Set("X-Forwarded-For", "203.0.113.10")

	auth := NewAuthStateFromContextWithDeps(ctx, AuthDeps{Cfg: cfg})
	state := auth.(*AuthState)

	state.WithClientInfo(ctx)

	assert.Equal(t, "203.0.113.10", state.Request.ClientIP)
}

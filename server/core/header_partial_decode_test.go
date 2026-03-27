package core

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

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

func setEncodedHeaders(r *http.Request) {
	r.Header.Set("Auth-User", "alice%40example.com")
	r.Header.Set("Auth-Pass", "my%20password")
	r.Header.Set("Auth-Protocol", "smtp%2Btls")
	r.Header.Set("Auth-Method", "plain%20login")
	r.Header.Set("Auth-Login-Attempt", "%32")
	r.Header.Set("X-Local-IP", "10.0.0.%31")
	r.Header.Set("X-Auth-Port", "%39%39%33")
	r.Header.Set("Client-IP", "203.0.113.%31")
	r.Header.Set("X-Client-Port", "%31%32%33%34")
	r.Header.Set("X-Client-ID", "cid%2Babc+def")
	r.Header.Set("Client-Host", "mail%2Eexample%2Etest")
	r.Header.Set("X-SSL-Client-DN", "CN%3Dalice%2CO%3DExample")
}

func TestHeaderBasedAuth_DecodesConfiguredRequestHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := newHeaderDecodeTestConfig()
	SetDefaultConfigFile(cfg)
	t.Cleanup(func() {
		SetDefaultConfigFile(nil)
	})

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	setEncodedHeaders(ctx.Request)

	auth := NewAuthStateFromContextWithDeps(ctx, AuthDeps{Cfg: cfg})
	state := auth.(*AuthState)

	state.WithClientInfo(ctx)
	state.WithLocalInfo(ctx)
	state.WithXSSL(ctx)
	setupHeaderBasedAuth(ctx, state)

	assert.Equal(t, "alice@example.com", state.GetUsername())
	assert.Equal(t, "my password", state.PasswordString())
	assert.Equal(t, "smtp+tls", state.GetProtocol().Get())
	assert.Equal(t, "plain login", state.Request.Method)
	assert.Equal(t, uint(1), state.Security.LoginAttempts)
	assert.Equal(t, "10.0.0.1", state.Request.XLocalIP)
	assert.Equal(t, "993", state.Request.XPort)
	assert.Equal(t, "203.0.113.1", state.Request.ClientIP)
	assert.Equal(t, "1234", state.Request.XClientPort)
	assert.Equal(t, "cid+abc+def", state.Request.XClientID)
	assert.Equal(t, "mail.example.test", state.Request.ClientHost)
	assert.Equal(t, "CN=alice,O=Example", state.Request.XSSLClientDN)
}

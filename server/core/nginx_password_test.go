package core

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSetupHeaderBasedAuth_NginxPasswordDecoding(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tt := range nginxPasswordDecodingCases() {
		t.Run(tt.name, func(t *testing.T) {
			auth := newNginxPasswordAuthState(t, tt.passwordHeader)

			assert.Equal(t, tt.expectedPassword, auth.PasswordString())
		})
	}
}

type nginxPasswordDecodingCase struct {
	name             string
	passwordHeader   string
	expectedPassword string
}

// nginxPasswordDecodingCases returns URL-encoded password header cases.
func nginxPasswordDecodingCases() []nginxPasswordDecodingCase {
	return []nginxPasswordDecodingCase{
		{
			name:             "Plain password",
			passwordHeader:   "password123",
			expectedPassword: "password123",
		},
		{
			name:             "URL encoded password with ampersand",
			passwordHeader:   "pass%26word",
			expectedPassword: "pass&word",
		},
		{
			name:             "URL encoded password with percent",
			passwordHeader:   "100%25percent",
			expectedPassword: "100%percent",
		},
		{
			name:             "URL encoded password with space",
			passwordHeader:   "my%20password",
			expectedPassword: "my password",
		},
		{
			name:             "Mixed encoding",
			passwordHeader:   "pass%20word%26100%25",
			expectedPassword: "pass word&100%",
		},
		{
			name:             "Password with plus sign (should remain plus)",
			passwordHeader:   "pass+word%26",
			expectedPassword: "pass+word&",
		},
	}
}

// newNginxPasswordAuthState builds an AuthState with the supplied password header.
func newNginxPasswordAuthState(t *testing.T, passwordHeader string) *AuthState {
	t.Helper()

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			DefaultHTTPRequestHeader: config.DefaultHTTPRequestHeader{
				Password: "Auth-Pass",
			},
		},
	}
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request, _ = http.NewRequest("GET", "/", nil)
	ctx.Request.Header.Set("Auth-Pass", passwordHeader)
	ctx.Set(definitions.CtxServiceKey, definitions.ServNginx)
	ctx.Set(definitions.CtxGUIDKey, "test-guid")
	ctx.Set(definitions.CtxDataExchangeKey, &lualib.Context{})

	SetDefaultConfigFile(cfg)
	auth := NewAuthStateFromContextWithDeps(ctx, AuthDeps{Cfg: cfg})
	setupHeaderBasedAuth(ctx, auth)

	return auth.(*AuthState)
}

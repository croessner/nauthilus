package core

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSetupHeaderBasedAuth_NginxPasswordDecoding(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name             string
		passwordHeader   string
		expectedPassword string
	}{
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.FileSettings{
				Server: &config.ServerSection{
					DefaultHTTPRequestHeader: config.DefaultHTTPRequestHeader{
						Password: "Auth-Pass",
					},
				},
			}

			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request, _ = http.NewRequest("GET", "/", nil)
			ctx.Request.Header.Set("Auth-Pass", tt.passwordHeader)
			ctx.Set(definitions.CtxServiceKey, definitions.ServNginx)
			ctx.Set(definitions.CtxGUIDKey, "test-guid")
			ctx.Set(definitions.CtxDataExchangeKey, &lualib.Context{})

			deps := AuthDeps{
				Cfg: cfg,
			}
			SetDefaultConfigFile(cfg)

			auth := NewAuthStateFromContextWithDeps(ctx, deps)
			setupHeaderBasedAuth(ctx, auth)

			assert.Equal(t, tt.expectedPassword, auth.(*AuthState).Request.Password)
		})
	}
}

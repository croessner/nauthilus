package idp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestLoginRedirects(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Error if direct access without IDP flow in cookie", func(t *testing.T) {
		r := gin.New()
		r.Use(func(ctx *gin.Context) {
			// No IDP flow active in cookie
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyAccount: "testuser",
			}}
			ctx.Set(definitions.CtxSecureDataKey, mgr)
			ctx.Next()
		})

		h := &FrontendHandler{}

		r.GET(frontendLoginPath, h.Login)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, frontendLoginPath, nil)

		r.ServeHTTP(w, req)

		// Without a valid IDP flow in cookie, we expect an error
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Redirect to OIDC authorize if already logged in with valid OIDC flow in cookie", func(t *testing.T) {
		r := gin.New()
		r.Use(func(ctx *gin.Context) {
			// Valid OIDC flow in cookie
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyAccount:        "testuser",
				definitions.SessionKeyIDPFlowID:      "flow-oidc",
				definitions.SessionKeyIDPFlowType:    definitions.ProtoOIDC,
				definitions.SessionKeyOIDCGrantType:  definitions.OIDCFlowAuthorizationCode,
				definitions.SessionKeyIDPClientID:    "test-client",
				definitions.SessionKeyIDPRedirectURI: "https://example.com/callback",
				definitions.SessionKeyIDPScope:       "openid profile",
				definitions.SessionKeyIDPState:       "state123",
			}}
			ctx.Set(definitions.CtxSecureDataKey, mgr)
			ctx.Next()
		})

		h := &FrontendHandler{}

		r.GET(frontendLoginPath, h.Login)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, frontendLoginPath, nil)

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		// Should redirect to OIDC authorize endpoint with parameters from cookie
		location := w.Header().Get("Location")
		assert.Contains(t, location, "/oidc/authorize")
		assert.Contains(t, location, "client_id=test-client")
	})

	t.Run("Redirect to SAML SSO if already logged in with valid SAML2 flow in cookie", func(t *testing.T) {
		r := gin.New()
		r.Use(func(ctx *gin.Context) {
			// Valid SAML2 flow in cookie
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyAccount:         "testuser",
				definitions.SessionKeyIDPFlowID:       "flow-saml",
				definitions.SessionKeyIDPFlowType:     definitions.ProtoSAML,
				definitions.SessionKeyIDPSAMLEntityID: "sp-1",
				definitions.SessionKeyIDPOriginalURL:  "/saml/sso?SAMLRequest=abc123",
			}}
			ctx.Set(definitions.CtxSecureDataKey, mgr)
			ctx.Next()
		})

		h := &FrontendHandler{}

		r.GET(frontendLoginPath, h.Login)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, frontendLoginPath, nil)

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		// Should redirect to original SAML SSO URL from cookie
		assert.Equal(t, "/saml/sso?SAMLRequest=abc123", w.Header().Get("Location"))
	})

	t.Run("Error if IDP flow type is invalid", func(t *testing.T) {
		r := gin.New()
		r.Use(func(ctx *gin.Context) {
			// Invalid flow type in cookie
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyAccount:     "testuser",
				definitions.SessionKeyIDPFlowID:   "flow-invalid",
				definitions.SessionKeyIDPFlowType: "invalid",
			}}
			ctx.Set(definitions.CtxSecureDataKey, mgr)
			ctx.Next()
		})

		h := &FrontendHandler{}

		r.GET(frontendLoginPath, h.Login)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, frontendLoginPath, nil)

		r.ServeHTTP(w, req)

		// Invalid flow type should result in error
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestIsValidIDPFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		cookieData map[string]any
		expected   bool
	}{
		{
			name:       "No cookie data",
			cookieData: map[string]any{},
			expected:   false,
		},
		{
			name: "Flow not active",
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID: "",
			},
			expected: false,
		},
		{
			name: "Valid OIDC authorization code flow",
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:      "flow-oidc",
				definitions.SessionKeyIDPFlowType:    definitions.ProtoOIDC,
				definitions.SessionKeyOIDCGrantType:  definitions.OIDCFlowAuthorizationCode,
				definitions.SessionKeyIDPClientID:    "test-client",
				definitions.SessionKeyIDPRedirectURI: "https://example.com/callback",
			},
			expected: true,
		},
		{
			name: "OIDC flow without grant type is invalid",
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:   "flow-oidc-no-grant",
				definitions.SessionKeyIDPFlowType: definitions.ProtoOIDC,
			},
			expected: false,
		},
		{
			name: "Valid OIDC device code flow",
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:     "flow-device",
				definitions.SessionKeyIDPFlowType:   definitions.ProtoOIDC,
				definitions.SessionKeyOIDCGrantType: definitions.OIDCFlowDeviceCode,
				definitions.SessionKeyIDPClientID:   "device-client",
				definitions.SessionKeyDeviceCode:    "ABCD-1234",
			},
			expected: true,
		},
		{
			name: "OIDC flow without client_id",
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:      "flow-oidc",
				definitions.SessionKeyIDPFlowType:    definitions.ProtoOIDC,
				definitions.SessionKeyIDPRedirectURI: "https://example.com/callback",
				definitions.SessionKeyOIDCGrantType:  definitions.OIDCFlowAuthorizationCode,
			},
			expected: false,
		},
		{
			name: "OIDC flow without redirect_uri",
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:     "flow-oidc",
				definitions.SessionKeyIDPFlowType:   definitions.ProtoOIDC,
				definitions.SessionKeyIDPClientID:   "test-client",
				definitions.SessionKeyOIDCGrantType: definitions.OIDCFlowAuthorizationCode,
			},
			expected: false,
		},
		{
			name: "Valid SAML2 flow",
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:      "flow-saml",
				definitions.SessionKeyIDPFlowType:    definitions.ProtoSAML,
				definitions.SessionKeyIDPOriginalURL: "/saml/sso?SAMLRequest=abc",
			},
			expected: true,
		},
		{
			name: "SAML2 flow without original URL",
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:   "flow-saml",
				definitions.SessionKeyIDPFlowType: definitions.ProtoSAML,
			},
			expected: false,
		},
		{
			name: "Invalid flow type",
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:   "flow-invalid",
				definitions.SessionKeyIDPFlowType: "invalid",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()

			var result bool

			r.Use(func(ctx *gin.Context) {
				mgr := &mockCookieManager{data: tt.cookieData}
				ctx.Set(definitions.CtxSecureDataKey, mgr)
				ctx.Next()
			})

			h := &FrontendHandler{}

			r.GET("/test", func(ctx *gin.Context) {
				result = h.isValidIDPFlow(ctx)
				ctx.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)

			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsLoginSelfResume(t *testing.T) {
	tests := []struct {
		name        string
		requestPath string
		redirectURI string
		want        bool
	}{
		{
			name:        "login to login",
			requestPath: frontendLoginPath,
			redirectURI: frontendLoginPath,
			want:        true,
		},
		{
			name:        "localized login loop",
			requestPath: "/login/en",
			redirectURI: frontendLoginPath,
			want:        true,
		},
		{
			name:        "absolute login loop",
			requestPath: frontendLoginPath,
			redirectURI: "https://split.example.test:18080/login/en",
			want:        true,
		},
		{
			name:        "login to authorize",
			requestPath: frontendLoginPath,
			redirectURI: "/oidc/authorize?client_id=test-client",
			want:        false,
		},
		{
			name:        "non-login request",
			requestPath: "/oidc/consent",
			redirectURI: frontendLoginPath,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isLoginSelfResume(tt.requestPath, tt.redirectURI))
		})
	}
}

func TestShouldDenyDeviceCodeAfterMFA(t *testing.T) {
	handler := &FrontendHandler{}

	t.Run("nil manager does not deny", func(t *testing.T) {
		assert.False(t, handler.shouldDenyDeviceCodeAfterMFA(nil, nil))
	})

	t.Run("missing auth result does not deny", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{}}
		assert.False(t, handler.shouldDenyDeviceCodeAfterMFA(nil, mgr))
	})

	t.Run("explicit auth fail with valid HMAC denies", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{}}
		mgr.Set(definitions.SessionKeyUsername, "testuser")
		cookie.SetAuthResult(mgr, "testuser", definitions.AuthResultFail)
		assert.True(t, handler.shouldDenyDeviceCodeAfterMFA(nil, mgr))
	})

	t.Run("auth ok with valid HMAC does not deny", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{}}
		mgr.Set(definitions.SessionKeyUsername, "testuser")
		cookie.SetAuthResult(mgr, "testuser", definitions.AuthResultOK)
		assert.False(t, handler.shouldDenyDeviceCodeAfterMFA(nil, mgr))
	})

	t.Run("tampered auth result (raw set without HMAC) denies", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyUsername:   "testuser",
			definitions.SessionKeyAuthResult: uint8(definitions.AuthResultOK),
		}}
		// No HMAC set — should be treated as tampered and denied
		assert.True(t, handler.shouldDenyDeviceCodeAfterMFA(nil, mgr))
	})
}

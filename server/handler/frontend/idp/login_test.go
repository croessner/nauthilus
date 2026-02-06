package idp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestLoginRedirects(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Error if direct access without IdP flow in cookie", func(t *testing.T) {
		r := gin.New()
		r.Use(func(ctx *gin.Context) {
			// No IdP flow active in cookie
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyAccount: "testuser",
			}}
			ctx.Set(definitions.CtxSecureDataKey, mgr)
			ctx.Next()
		})

		h := &FrontendHandler{}

		r.GET("/login", h.Login)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/login", nil)

		r.ServeHTTP(w, req)

		// Without a valid IdP flow in cookie, we expect an error
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Redirect to OIDC authorize if already logged in with valid OIDC flow in cookie", func(t *testing.T) {
		r := gin.New()
		r.Use(func(ctx *gin.Context) {
			// Valid OIDC flow in cookie
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyAccount:        "testuser",
				definitions.SessionKeyIdPFlowActive:  true,
				definitions.SessionKeyIdPFlowType:    definitions.ProtoOIDC,
				definitions.SessionKeyIdPClientID:    "test-client",
				definitions.SessionKeyIdPRedirectURI: "https://example.com/callback",
				definitions.SessionKeyIdPScope:       "openid profile",
				definitions.SessionKeyIdPState:       "state123",
			}}
			ctx.Set(definitions.CtxSecureDataKey, mgr)
			ctx.Next()
		})

		h := &FrontendHandler{}

		r.GET("/login", h.Login)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/login", nil)

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
				definitions.SessionKeyAccount:        "testuser",
				definitions.SessionKeyIdPFlowActive:  true,
				definitions.SessionKeyIdPFlowType:    definitions.ProtoSAML,
				definitions.SessionKeyIdPOriginalURL: "/saml/sso?SAMLRequest=abc123",
			}}
			ctx.Set(definitions.CtxSecureDataKey, mgr)
			ctx.Next()
		})

		h := &FrontendHandler{}

		r.GET("/login", h.Login)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/login", nil)

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		// Should redirect to original SAML SSO URL from cookie
		assert.Equal(t, "/saml/sso?SAMLRequest=abc123", w.Header().Get("Location"))
	})

	t.Run("Error if IdP flow type is invalid", func(t *testing.T) {
		r := gin.New()
		r.Use(func(ctx *gin.Context) {
			// Invalid flow type in cookie
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyAccount:       "testuser",
				definitions.SessionKeyIdPFlowActive: true,
				definitions.SessionKeyIdPFlowType:   "invalid",
			}}
			ctx.Set(definitions.CtxSecureDataKey, mgr)
			ctx.Next()
		})

		h := &FrontendHandler{}

		r.GET("/login", h.Login)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/login", nil)

		r.ServeHTTP(w, req)

		// Invalid flow type should result in error
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestIsValidIdPFlow(t *testing.T) {
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
				definitions.SessionKeyIdPFlowActive: false,
			},
			expected: false,
		},
		{
			name: "Valid OIDC flow",
			cookieData: map[string]any{
				definitions.SessionKeyIdPFlowActive:  true,
				definitions.SessionKeyIdPFlowType:    definitions.ProtoOIDC,
				definitions.SessionKeyIdPClientID:    "test-client",
				definitions.SessionKeyIdPRedirectURI: "https://example.com/callback",
			},
			expected: true,
		},
		{
			name: "OIDC flow without client_id",
			cookieData: map[string]any{
				definitions.SessionKeyIdPFlowActive:  true,
				definitions.SessionKeyIdPFlowType:    definitions.ProtoOIDC,
				definitions.SessionKeyIdPRedirectURI: "https://example.com/callback",
			},
			expected: false,
		},
		{
			name: "OIDC flow without redirect_uri",
			cookieData: map[string]any{
				definitions.SessionKeyIdPFlowActive: true,
				definitions.SessionKeyIdPFlowType:   definitions.ProtoOIDC,
				definitions.SessionKeyIdPClientID:   "test-client",
			},
			expected: false,
		},
		{
			name: "Valid SAML2 flow",
			cookieData: map[string]any{
				definitions.SessionKeyIdPFlowActive:  true,
				definitions.SessionKeyIdPFlowType:    definitions.ProtoSAML,
				definitions.SessionKeyIdPOriginalURL: "/saml/sso?SAMLRequest=abc",
			},
			expected: true,
		},
		{
			name: "SAML2 flow without original URL",
			cookieData: map[string]any{
				definitions.SessionKeyIdPFlowActive: true,
				definitions.SessionKeyIdPFlowType:   definitions.ProtoSAML,
			},
			expected: false,
		},
		{
			name: "Invalid flow type",
			cookieData: map[string]any{
				definitions.SessionKeyIdPFlowActive: true,
				definitions.SessionKeyIdPFlowType:   "invalid",
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
				result = h.isValidIdPFlow(ctx)
				ctx.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)

			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expected, result)
		})
	}
}

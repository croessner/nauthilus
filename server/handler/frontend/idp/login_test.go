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

	for _, tt := range loginRedirectCases() {
		t.Run(tt.name, func(t *testing.T) {
			recorder := runLoginRedirect(tt.cookieData)

			assertLoginRedirectResponse(t, recorder, tt)
		})
	}
}

type loginRedirectCase struct {
	name             string
	location         string
	cookieData       map[string]any
	locationContains []string
	status           int
}

// loginRedirectCases returns login redirect and rejection scenarios.
func loginRedirectCases() []loginRedirectCase {
	return []loginRedirectCase{
		{
			name: "Error if direct access without IDP flow in cookie",
			cookieData: map[string]any{
				definitions.SessionKeyAccount: "testuser",
			},
			status: http.StatusBadRequest,
		},
		{
			name: "Redirect to OIDC authorize if already logged in with valid OIDC flow in cookie",
			cookieData: map[string]any{
				definitions.SessionKeyAccount:        "testuser",
				definitions.SessionKeyIDPFlowID:      "flow-oidc",
				definitions.SessionKeyIDPFlowType:    definitions.ProtoOIDC,
				definitions.SessionKeyOIDCGrantType:  definitions.OIDCFlowAuthorizationCode,
				definitions.SessionKeyIDPClientID:    "test-client",
				definitions.SessionKeyIDPRedirectURI: "https://example.com/callback",
				definitions.SessionKeyIDPScope:       "openid profile",
				definitions.SessionKeyIDPState:       "state123",
			},
			locationContains: []string{"/oidc/authorize", "client_id=test-client"},
			status:           http.StatusFound,
		},
		{
			name: "Redirect to SAML SSO if already logged in with valid SAML2 flow in cookie",
			cookieData: map[string]any{
				definitions.SessionKeyAccount:         "testuser",
				definitions.SessionKeyIDPFlowID:       "flow-saml",
				definitions.SessionKeyIDPFlowType:     definitions.ProtoSAML,
				definitions.SessionKeyIDPSAMLEntityID: "sp-1",
				definitions.SessionKeyIDPOriginalURL:  "/saml/sso?SAMLRequest=abc123",
			},
			location: "/saml/sso?SAMLRequest=abc123",
			status:   http.StatusFound,
		},
		{
			name: "Error if IDP flow type is invalid",
			cookieData: map[string]any{
				definitions.SessionKeyAccount:     "testuser",
				definitions.SessionKeyIDPFlowID:   "flow-invalid",
				definitions.SessionKeyIDPFlowType: "invalid",
			},
			status: http.StatusBadRequest,
		},
	}
}

// runLoginRedirect executes the login endpoint with one cookie state.
func runLoginRedirect(cookieData map[string]any) *httptest.ResponseRecorder {
	r := gin.New()
	r.Use(secureDataTestMiddleware(cookieData))
	r.GET(frontendLoginPath, (&FrontendHandler{}).Login)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, frontendLoginPath, nil)
	r.ServeHTTP(w, req)

	return w
}

// secureDataTestMiddleware installs a mock secure-data cookie manager.
func secureDataTestMiddleware(cookieData map[string]any) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: cookieData})
		ctx.Next()
	}
}

// assertLoginRedirectResponse verifies status and optional Location expectations.
func assertLoginRedirectResponse(t *testing.T, recorder *httptest.ResponseRecorder, tc loginRedirectCase) {
	t.Helper()

	assert.Equal(t, tc.status, recorder.Code)

	location := recorder.Header().Get("Location")
	if tc.location != "" {
		assert.Equal(t, tc.location, location)
	}

	for _, fragment := range tc.locationContains {
		assert.Contains(t, location, fragment)
	}
}

func TestIsValidIDPFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tt := range validIDPFlowCases() {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, runIsValidIDPFlow(tt.cookieData))
		})
	}
}

type validIDPFlowCase struct {
	name       string
	cookieData map[string]any
	expected   bool
}

// validIDPFlowCases returns valid and invalid IDP flow cookie states.
func validIDPFlowCases() []validIDPFlowCase {
	cases := make([]validIDPFlowCase, 0, 10)
	cases = append(cases, baselineIDPFlowCases()...)
	cases = append(cases, oidcIDPFlowCases()...)
	cases = append(cases, samlIDPFlowCases()...)

	return cases
}

// baselineIDPFlowCases returns generic missing and invalid flow states.
func baselineIDPFlowCases() []validIDPFlowCase {
	return []validIDPFlowCase{
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
			name: "Invalid flow type",
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:   "flow-invalid",
				definitions.SessionKeyIDPFlowType: "invalid",
			},
			expected: false,
		},
	}
}

// oidcIDPFlowCases returns valid and invalid OIDC flow states.
func oidcIDPFlowCases() []validIDPFlowCase {
	return []validIDPFlowCase{
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
	}
}

// samlIDPFlowCases returns valid and invalid SAML flow states.
func samlIDPFlowCases() []validIDPFlowCase {
	return []validIDPFlowCase{
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
	}
}

// runIsValidIDPFlow executes flow validation inside a Gin request.
func runIsValidIDPFlow(cookieData map[string]any) bool {
	r := gin.New()
	r.Use(secureDataTestMiddleware(cookieData))

	var result bool

	r.GET("/test", func(ctx *gin.Context) {
		result = (&FrontendHandler{}).isValidIDPFlow(ctx)
		ctx.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	return result
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

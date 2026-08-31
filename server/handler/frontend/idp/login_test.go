package idp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestLoginRedirects(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tt := range loginRedirectCases() {
		t.Run(tt.name, func(t *testing.T) {
			recorder := runLoginRedirect(t, tt)

			assertLoginRedirectResponse(t, recorder, tt)
		})
	}
}

type loginRedirectCase struct {
	name             string
	location         string
	state            *flowdomain.State
	locationContains []string
	status           int
	authenticated    bool
}

// loginRedirectCases returns login redirect and rejection scenarios.
func loginRedirectCases() []loginRedirectCase {
	return []loginRedirectCase{
		{
			name:   "Error if direct access has no canonical typed IDP flow",
			status: http.StatusBadRequest,
		},
		{
			name: "Redirect to OIDC authorize if canonical session is authenticated",
			state: &flowdomain.State{
				FlowID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Type: flowdomain.FlowTypeOIDCAuthorization,
				Protocol: flowdomain.FlowProtocolOIDC, CurrentStep: flowdomain.FlowStepLogin,
				AuthOutcome: flowdomain.AuthOutcomeOK, ReturnTarget: "/oidc/authorize?client_id=test-client",
				Metadata: map[string]string{
					flowdomain.FlowMetadataClientID: "test-client", flowdomain.FlowMetadataRedirectURI: "https://example.com/callback",
					flowdomain.FlowMetadataResponseType: oidcParamCode,
				},
			},
			locationContains: []string{"/oidc/authorize", "client_id=test-client"},
			status:           http.StatusFound,
			authenticated:    true,
		},
		{
			name: "Redirect to SAML SSO if canonical session is authenticated",
			state: &flowdomain.State{
				FlowID: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", Type: flowdomain.FlowTypeSAML,
				Protocol: flowdomain.FlowProtocolSAML, CurrentStep: flowdomain.FlowStepLogin,
				AuthOutcome: flowdomain.AuthOutcomeOK, ReturnTarget: "/saml/sso?SAMLRequest=abc123",
				Metadata: map[string]string{
					flowdomain.FlowMetadataSAMLEntityID: "sp-1", flowdomain.FlowMetadataOriginalURL: "/saml/sso?SAMLRequest=abc123",
				},
			},
			locationContains: []string{"/saml/sso", "SAMLRequest=abc123"},
			status:           http.StatusFound,
			authenticated:    true,
		},
		{
			name: "Error if canonical typed flow metadata is incomplete",
			state: &flowdomain.State{
				FlowID: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", Type: flowdomain.FlowTypeOIDCAuthorization,
				Protocol: flowdomain.FlowProtocolOIDC, CurrentStep: flowdomain.FlowStepLogin,
				AuthOutcome: flowdomain.AuthOutcomeUnknown,
			},
			status: http.StatusBadRequest,
		},
	}
}

// runLoginRedirect executes the login endpoint with one canonical envelope and optional typed flow.
func runLoginRedirect(t *testing.T, test loginRedirectCase) *httptest.ResponseRecorder {
	t.Helper()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, test.state)
	if test.authenticated {
		authenticateCanonicalFixture(t, runtime, browserCookie)
	}

	handler := &FrontendHandler{}
	if test.authenticated {
		handler = canonicalLoginRedirectHandler()
	}

	r := gin.New()
	r.Use(cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation))
	r.GET(frontendLoginPath, handler.Login)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, flowdomain.AppendTicket(frontendLoginPath, flowID), nil)
	req.AddCookie(browserCookie)
	r.ServeHTTP(w, req)

	return w
}

// canonicalLoginRedirectHandler resolves zero-policy OIDC and SAML clients from authoritative configuration.
func canonicalLoginRedirectHandler() *FrontendHandler {
	return &FrontendHandler{deps: &deps.Deps{Cfg: &mockFrontendCfg{FileSettings: config.FileSettings{
		IDP: &config.IDPSection{
			OIDC:  config.OIDCConfig{Clients: []config.OIDCClient{{ClientID: "test-client"}}},
			SAML2: config.SAML2Config{ServiceProviders: []config.SAML2ServiceProvider{{EntityID: "sp-1"}}},
		},
	}}}}
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
			assert.Equal(t, tt.expected, runIsValidIDPFlow(t, tt.state, tt.ticket))
		})
	}
}

type validIDPFlowCase struct {
	state    *flowdomain.State
	name     string
	ticket   string
	expected bool
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
			name: "No canonical flow ticket", expected: false,
		},
		{
			name: "Flow not active", ticket: "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM", expected: false,
		},
		{
			name: "Invalid flow type",
			state: &flowdomain.State{
				FlowID: "IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII", Type: flowdomain.FlowTypeUnknown,
				Protocol: flowdomain.FlowProtocolOIDC, CurrentStep: flowdomain.FlowStepLogin,
				AuthOutcome: flowdomain.AuthOutcomeUnknown,
			},
			ticket:   "IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII",
			expected: false,
		},
	}
}

// oidcIDPFlowCases returns valid and invalid OIDC flow states.
func oidcIDPFlowCases() []validIDPFlowCase {
	return []validIDPFlowCase{
		{
			name: "Valid OIDC authorization code flow",
			state: &flowdomain.State{
				FlowID: "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO", Type: flowdomain.FlowTypeOIDCAuthorization,
				Protocol: flowdomain.FlowProtocolOIDC, CurrentStep: flowdomain.FlowStepLogin,
				AuthOutcome: flowdomain.AuthOutcomeUnknown,
				Metadata: map[string]string{
					flowdomain.FlowMetadataClientID: "test-client", flowdomain.FlowMetadataRedirectURI: "https://example.com/callback",
					flowdomain.FlowMetadataResponseType: "code",
				},
			},
			ticket:   "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO",
			expected: true,
		},
		{
			name: "OIDC flow without response type is invalid",
			state: &flowdomain.State{
				FlowID: "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN", Type: flowdomain.FlowTypeOIDCAuthorization,
				Protocol: flowdomain.FlowProtocolOIDC, CurrentStep: flowdomain.FlowStepLogin,
				AuthOutcome: flowdomain.AuthOutcomeUnknown,
				Metadata: map[string]string{
					flowdomain.FlowMetadataClientID: "test-client", flowdomain.FlowMetadataRedirectURI: "https://example.com/callback",
				},
			},
			ticket:   "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN",
			expected: false,
		},
		{
			name: "Valid OIDC device code flow",
			state: &flowdomain.State{
				FlowID: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", Type: flowdomain.FlowTypeOIDCDeviceCode,
				Protocol: flowdomain.FlowProtocolOIDC, CurrentStep: flowdomain.FlowStepLogin,
				AuthOutcome: flowdomain.AuthOutcomeUnknown, GrantType: definitions.OIDCFlowDeviceCode,
				Metadata: map[string]string{
					flowdomain.FlowMetadataClientID: "device-client", flowdomain.FlowMetadataDeviceCode: "ABCD-1234",
				},
			},
			ticket:   "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
			expected: true,
		},
		{
			name: "OIDC flow without client_id",
			state: &flowdomain.State{
				FlowID: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", Type: flowdomain.FlowTypeOIDCAuthorization,
				Protocol: flowdomain.FlowProtocolOIDC, CurrentStep: flowdomain.FlowStepLogin,
				AuthOutcome: flowdomain.AuthOutcomeUnknown,
				Metadata: map[string]string{
					flowdomain.FlowMetadataRedirectURI: "https://example.com/callback", flowdomain.FlowMetadataResponseType: "code",
				},
			},
			ticket:   "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
			expected: false,
		},
		{
			name: "OIDC flow without redirect_uri",
			state: &flowdomain.State{
				FlowID: "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU", Type: flowdomain.FlowTypeOIDCAuthorization,
				Protocol: flowdomain.FlowProtocolOIDC, CurrentStep: flowdomain.FlowStepLogin,
				AuthOutcome: flowdomain.AuthOutcomeUnknown,
				Metadata: map[string]string{
					flowdomain.FlowMetadataClientID: "test-client", flowdomain.FlowMetadataResponseType: "code",
				},
			},
			ticket:   "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU",
			expected: false,
		},
	}
}

// samlIDPFlowCases returns valid and invalid SAML flow states.
func samlIDPFlowCases() []validIDPFlowCase {
	return []validIDPFlowCase{
		{
			name: "Valid SAML2 flow",
			state: &flowdomain.State{
				FlowID: "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS", Type: flowdomain.FlowTypeSAML,
				Protocol: flowdomain.FlowProtocolSAML, CurrentStep: flowdomain.FlowStepLogin,
				AuthOutcome: flowdomain.AuthOutcomeUnknown,
				Metadata: map[string]string{
					flowdomain.FlowMetadataSAMLEntityID: "sp-1", flowdomain.FlowMetadataOriginalURL: "/saml/sso?SAMLRequest=abc",
				},
			},
			ticket:   "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
			expected: true,
		},
		{
			name: "SAML2 flow without original URL",
			state: &flowdomain.State{
				FlowID: "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL", Type: flowdomain.FlowTypeSAML,
				Protocol: flowdomain.FlowProtocolSAML, CurrentStep: flowdomain.FlowStepLogin,
				AuthOutcome: flowdomain.AuthOutcomeUnknown,
				Metadata:    map[string]string{flowdomain.FlowMetadataSAMLEntityID: "sp-1"},
			},
			ticket:   "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL",
			expected: false,
		},
	}
}

// runIsValidIDPFlow executes flow validation inside a Gin request.
func runIsValidIDPFlow(t *testing.T, state *flowdomain.State, ticket string) bool {
	t.Helper()

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, state)
	r := gin.New()
	r.Use(cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation))

	var result bool

	r.GET("/test", func(ctx *gin.Context) {
		result = (&FrontendHandler{}).isValidIDPFlow(ctx)
		ctx.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test?flow="+ticket, nil)
	req.AddCookie(browserCookie)
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

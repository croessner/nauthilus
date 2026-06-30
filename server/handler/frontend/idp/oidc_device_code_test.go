package idp

import (
	"context"
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	devicecode "github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/idp/clientauth"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestApplyDeviceCodeMFASessionStateCopiesCompletedMethod(t *testing.T) {
	request := &devicecode.DeviceCodeRequest{}
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyMFACompleted: true,
		definitions.SessionKeyMFAMethod:    "webauthn",
	}}

	applyDeviceCodeMFASessionState(mgr, request)

	assert.True(t, request.MFACompleted)
	assert.Equal(t, "webauthn", request.MFAMethod)
}

type noopDeviceCodeStore struct{}

func (n *noopDeviceCodeStore) StoreDeviceCode(_ context.Context, _ string, _ *devicecode.DeviceCodeRequest, _ time.Duration) error {
	return nil
}

func (n *noopDeviceCodeStore) GetDeviceCode(_ context.Context, _ string) (*devicecode.DeviceCodeRequest, error) {
	return nil, nil
}

func (n *noopDeviceCodeStore) GetDeviceCodeByUserCode(_ context.Context, _ string) (string, *devicecode.DeviceCodeRequest, error) {
	return "", nil, nil
}

func (n *noopDeviceCodeStore) UpdateDeviceCode(_ context.Context, _ string, _ *devicecode.DeviceCodeRequest) error {
	return nil
}

func (n *noopDeviceCodeStore) DeleteDeviceCode(_ context.Context, _ string) error {
	return nil
}

type countingDeviceCodeStore struct {
	requests        []*devicecode.DeviceCodeRequest
	updatedRequests []*devicecode.DeviceCodeRequest
}

// StoreDeviceCode records stored requests without touching Redis.
func (s *countingDeviceCodeStore) StoreDeviceCode(_ context.Context, _ string, request *devicecode.DeviceCodeRequest, _ time.Duration) error {
	s.requests = append(s.requests, request)

	return nil
}

// GetDeviceCode is unused by allocation tests and returns no request.
func (s *countingDeviceCodeStore) GetDeviceCode(_ context.Context, _ string) (*devicecode.DeviceCodeRequest, error) {
	return nil, nil
}

// GetDeviceCodeByUserCode is unused by allocation tests and returns no request.
func (s *countingDeviceCodeStore) GetDeviceCodeByUserCode(_ context.Context, _ string) (string, *devicecode.DeviceCodeRequest, error) {
	return "", nil, nil
}

// UpdateDeviceCode records updated requests without touching Redis.
func (s *countingDeviceCodeStore) UpdateDeviceCode(_ context.Context, _ string, request *devicecode.DeviceCodeRequest) error {
	s.updatedRequests = append(s.updatedRequests, request)

	return nil
}

// DeleteDeviceCode is unused by allocation tests and is a no-op.
func (s *countingDeviceCodeStore) DeleteDeviceCode(_ context.Context, _ string) error {
	return nil
}

func newTestDeviceCodeOIDCHandler(t *testing.T) (*OIDCHandler, config.OIDCClient) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	client := config.OIDCClient{
		ClientID:     "test-client",
		ClientSecret: secret.New("test-secret"),
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{definitions.ScopeOpenID, "profile", "email"},
		GrantTypes:   []string{definitions.OIDCGrantTypeDeviceCode},
	}

	cfg := &mockOIDCCfg{
		issuer:     "https://auth.example.com",
		signingKey: secret.New(generateTestKey()),
		clients:    []config.OIDCClient{client},
	}

	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	core.SetDefaultLogger(d.Logger)

	idpInstance := devicecode.NewNauthilusIDP(d)
	handler := NewOIDCHandler(d, idpInstance, nil)
	handler.deviceStore = &noopDeviceCodeStore{}

	return handler, client
}

// newDeviceAuthorizationHandler builds a handler with a counting device store.
func newDeviceAuthorizationHandler(t *testing.T, client config.OIDCClient) (*OIDCHandler, *countingDeviceCodeStore) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	cfg := &mockOIDCCfg{
		issuer:     "https://auth.example.com",
		signingKey: secret.New(generateTestKey()),
		clients:    []config.OIDCClient{client},
	}

	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)
	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	store := &countingDeviceCodeStore{}
	handler := NewOIDCHandler(d, devicecode.NewNauthilusIDP(d), nil)
	handler.deviceStore = store

	return handler, store
}

// postDeviceAuthorization submits a form-encoded device authorization request.
func postDeviceAuthorization(handler *OIDCHandler, form url.Values, basicID string, basicSecret string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/oidc/device", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if basicID != "" || basicSecret != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}

	ctx.Request = req
	handler.DeviceAuthorization(ctx)

	return recorder
}

func TestDeviceAuthorizationRequiresClientAuthBeforeStateAllocation(t *testing.T) {
	client := config.OIDCClient{
		ClientID:     "device-confidential",
		ClientSecret: secret.New("device-secret"),
		GrantTypes:   []string{definitions.OIDCGrantTypeDeviceCode},
		Scopes:       []string{definitions.ScopeOpenID},
	}
	handler, store := newDeviceAuthorizationHandler(t, client)

	form := url.Values{}
	form.Add(oidcParamClientID, client.ClientID)
	form.Add(oidcParamScope, definitions.ScopeOpenID)

	recorder := postDeviceAuthorization(handler, form, "", "")

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Empty(t, store.requests)
}

func TestDeviceAuthorizationRequiresConfiguredClientAuthBeforeStateAllocation(t *testing.T) {
	tests := []struct {
		name       string
		authMethod string
	}{
		{
			name:       "private_key_jwt",
			authMethod: clientauth.MethodPrivateKeyJWT,
		},
		{
			name:       "client_secret_basic",
			authMethod: clientauth.MethodClientSecretBasic,
		},
		{
			name:       "client_secret_post",
			authMethod: clientauth.MethodClientSecretPost,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			client := config.OIDCClient{
				ClientID:                "device-" + testCase.name,
				TokenEndpointAuthMethod: testCase.authMethod,
				GrantTypes:              []string{definitions.OIDCGrantTypeDeviceCode},
				Scopes:                  []string{definitions.ScopeOpenID},
			}
			handler, store := newDeviceAuthorizationHandler(t, client)

			form := url.Values{}
			form.Add(oidcParamClientID, client.ClientID)
			form.Add(oidcParamScope, definitions.ScopeOpenID)

			recorder := postDeviceAuthorization(handler, form, "", "")

			assert.Equal(t, http.StatusUnauthorized, recorder.Code)
			assert.Empty(t, store.requests)
		})
	}
}

func TestDeviceAuthorizationStoresStateForAuthenticatedConfidentialClient(t *testing.T) {
	client := config.OIDCClient{
		ClientID:     "device-confidential-valid",
		ClientSecret: secret.New("device-secret"),
		GrantTypes:   []string{definitions.OIDCGrantTypeDeviceCode},
		Scopes:       []string{definitions.ScopeOpenID},
	}
	handler, store := newDeviceAuthorizationHandler(t, client)

	form := url.Values{}
	form.Add(oidcParamClientID, client.ClientID)
	form.Add(oidcParamScope, definitions.ScopeOpenID)

	recorder := postDeviceAuthorization(handler, form, client.ClientID, "device-secret")

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Len(t, store.requests, 1)
	assert.Equal(t, client.ClientID, store.requests[0].ClientID)
}

func TestDeviceAuthorizationStoresStateForPublicClient(t *testing.T) {
	client := config.OIDCClient{
		ClientID:                "device-public",
		TokenEndpointAuthMethod: oidcClientAuthMethodNone,
		GrantTypes:              []string{definitions.OIDCGrantTypeDeviceCode},
		Scopes:                  []string{definitions.ScopeOpenID},
	}
	handler, store := newDeviceAuthorizationHandler(t, client)

	form := url.Values{}
	form.Add(oidcParamClientID, client.ClientID)
	form.Add(oidcParamScope, definitions.ScopeOpenID)

	recorder := postDeviceAuthorization(handler, form, "", "")

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Len(t, store.requests, 1)
	assert.Equal(t, client.ClientID, store.requests[0].ClientID)
}

func TestAuthorizeDeviceCodeDirectlyRequireMFABlocksMissingAssurance(t *testing.T) {
	client := config.OIDCClient{
		ClientID:   "device-client-require-mfa",
		RequireMFA: []string{definitions.MFAMethodTOTP},
	}
	handler, store := newDeviceAuthorizationHandler(t, client)
	ctx, _ := newDeviceAuthorizeDirectContext(nil)
	request := newDeviceAuthorizeDirectRequest(client.ClientID)

	handler.authorizeDeviceCodeDirectly(ctx, "device-code-missing-mfa", request, &client, newDeviceAuthorizeDirectUser())

	assert.Empty(t, store.updatedRequests)
}

func TestAuthorizeDeviceCodeDirectlyRequireMFAPermitsFreshAssurance(t *testing.T) {
	client := config.OIDCClient{
		ClientID:   "device-client-fresh-mfa",
		RequireMFA: []string{definitions.MFAMethodTOTP},
	}
	handler, store := newDeviceAuthorizationHandler(t, client)
	ctx, recorder := newDeviceAuthorizeDirectContext(map[string]any{
		definitions.SessionKeyMFACompleted:      true,
		definitions.SessionKeyMFAMethod:         definitions.MFAMethodTOTP,
		definitions.SessionKeyMFAAssuranceAt:    time.Now().Unix(),
		definitions.SessionKeyMFAAssuranceScope: oidcMFAAssuranceScope(client.ClientID),
	})
	request := newDeviceAuthorizeDirectRequest(client.ClientID)

	handler.authorizeDeviceCodeDirectly(ctx, "device-code-fresh-mfa", request, &client, newDeviceAuthorizeDirectUser())

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Len(t, store.updatedRequests, 1)
	assert.Equal(t, devicecode.DeviceCodeStatusAuthorized, store.updatedRequests[0].Status)
}

func TestAuthorizeDeviceCodeDirectlyNoRequireMFAPreservesAuthorization(t *testing.T) {
	client := config.OIDCClient{ClientID: "device-client-no-mfa"}
	handler, store := newDeviceAuthorizationHandler(t, client)
	ctx, recorder := newDeviceAuthorizeDirectContext(nil)
	request := newDeviceAuthorizeDirectRequest(client.ClientID)

	handler.authorizeDeviceCodeDirectly(ctx, "device-code-no-mfa", request, &client, newDeviceAuthorizeDirectUser())

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Len(t, store.updatedRequests, 1)
	assert.Equal(t, devicecode.DeviceCodeStatusAuthorized, store.updatedRequests[0].Status)
}

func newDeviceAuthorizeDirectContext(data map[string]any) (*gin.Context, *httptest.ResponseRecorder) {
	if data == nil {
		data = make(map[string]any)
	}

	recorder := httptest.NewRecorder()
	ctx, engine := gin.CreateTestContext(recorder)
	engine.SetHTMLTemplate(template.Must(template.New("device-direct").Parse(`
{{ define "idp_device_code_success.html" }}authorized{{ end }}
{{ define "idp_device_code_error.html" }}{{ .Error }}{{ end }}
`)))

	ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/device/verify", nil)
	ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: data})

	return ctx, recorder
}

func newDeviceAuthorizeDirectRequest(clientID string) *devicecode.DeviceCodeRequest {
	return &devicecode.DeviceCodeRequest{
		ClientID: clientID,
		Scopes:   []string{definitions.ScopeOpenID},
		UserCode: "USER-CODE",
	}
}

func newDeviceAuthorizeDirectUser() *backend.User {
	return &backend.User{ID: "user-123", Name: "alice"}
}

func TestIssueDeviceCodeTokens_RejectsMissingPersistedClaims(t *testing.T) {
	handler, client := newTestDeviceCodeOIDCHandler(t)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/token", nil)
	ctx.Set(definitions.CtxServiceKey, "test")

	request := &devicecode.DeviceCodeRequest{
		ClientID: client.ClientID,
		Scopes:   []string{definitions.ScopeOpenID, "profile", "email"},
		Status:   devicecode.DeviceCodeStatusAuthorized,
	}

	handler.issueDeviceCodeTokens(ctx, "device-code-1", request, &client)

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "server_error")
}

func TestIssueDeviceCodeTokens_UsesPersistedClaimsFromDeviceRequest(t *testing.T) {
	handler, client := newTestDeviceCodeOIDCHandler(t)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/token", nil)
	ctx.Set(definitions.CtxServiceKey, "test")

	request := &devicecode.DeviceCodeRequest{
		ClientID: client.ClientID,
		Scopes:   []string{definitions.ScopeOpenID, "profile", "email"},
		Status:   devicecode.DeviceCodeStatusAuthorized,
		IDTokenClaims: map[string]any{
			"sub":                "user-123",
			"preferred_username": "alice",
			"email":              "alice@example.com",
		},
		AccessTokenClaims: map[string]any{
			"email": "alice@example.com",
		},
	}
	request.StoreUserSnapshot(&backend.User{
		ID:          "user-123",
		Name:        "alice",
		DisplayName: "Alice Example",
		Attributes: bktype.AttributeMapping{
			"uid": {"alice"},
		},
	})

	handler.issueDeviceCodeTokens(ctx, "device-code-2", request, &client)
	assert.Equal(t, http.StatusOK, recorder.Code)

	var tokenResp map[string]any

	err := json.Unmarshal(recorder.Body.Bytes(), &tokenResp)
	assert.NoError(t, err)

	idToken, ok := tokenResp["id_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, idToken)

	claims, err := handler.idp.ValidateToken(context.Background(), idToken)
	assert.NoError(t, err)
	assert.Equal(t, "alice", claims["preferred_username"])
	assert.Equal(t, "alice@example.com", claims["email"])
}

func TestIssueDeviceCodeTokens_RehydratesMissingClaimsFromSnapshot(t *testing.T) {
	handler, client := newTestDeviceCodeOIDCHandler(t)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/token", nil)
	ctx.Set(definitions.CtxServiceKey, "test")

	request := &devicecode.DeviceCodeRequest{
		ClientID: client.ClientID,
		Scopes:   []string{definitions.ScopeOpenID, "profile", "email"},
		Status:   devicecode.DeviceCodeStatusAuthorized,
	}
	request.StoreUserSnapshot(&backend.User{
		ID:          "user-123",
		Name:        "alice",
		DisplayName: "Alice Example",
		Attributes: bktype.AttributeMapping{
			"mail": {"alice@example.com"},
		},
	})

	handler.issueDeviceCodeTokens(ctx, "device-code-3", request, &client)
	assert.Equal(t, http.StatusOK, recorder.Code)

	var tokenResp map[string]any

	err := json.Unmarshal(recorder.Body.Bytes(), &tokenResp)
	assert.NoError(t, err)

	idToken, ok := tokenResp["id_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, idToken)

	claims, err := handler.idp.ValidateToken(context.Background(), idToken)
	assert.NoError(t, err)
	assert.Equal(t, "alice", claims["preferred_username"])
}

package idp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	devicecode "github.com/croessner/nauthilus/v4/server/idp"
	"github.com/croessner/nauthilus/v4/server/idp/clientauth"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

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

func (n *noopDeviceCodeStore) ClaimAuthorizedDeviceCode(_ context.Context, _ string, _ string) (*devicecode.DeviceCodeRequest, error) {
	return nil, nil
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

func (s *countingDeviceCodeStore) ClaimAuthorizedDeviceCode(_ context.Context, _ string, _ string) (*devicecode.DeviceCodeRequest, error) {
	return nil, nil
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

	server := miniredis.RunT(t)
	db := redis.NewClient(&redis.Options{Addr: server.Addr()})
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

func TestAuthorizedDeviceCodeConcurrentPollsIssueOneTokenResponse(t *testing.T) {
	handler, client := newTestDeviceCodeOIDCHandler(t)
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})

	t.Cleanup(func() { _ = handle.Close() })

	const deviceCodeValue = "concurrent-authorized-device-code"

	store := devicecode.NewRedisDeviceCodeStore(rediscli.NewTestClient(handle), "test:")
	request := &devicecode.DeviceCodeRequest{
		ClientID:           client.ClientID,
		Scopes:             []string{definitions.ScopeOpenID},
		Status:             devicecode.DeviceCodeStatusAuthorized,
		IDTokenClaims:      map[string]any{"sub": "user-123"},
		AccessTokenClaims:  map[string]any{"sub": "user-123"},
		ExpiresAt:          time.Now().Add(10 * time.Minute),
		VerificationLocked: true,
	}
	request.StoreUserSnapshot(backend.NewUser("alice", "Alice Example", "user-123"))

	if err := store.StoreDeviceCode(t.Context(), deviceCodeValue, request, 10*time.Minute); err != nil {
		t.Fatalf("store authorized device code: %v", err)
	}

	handler.deviceStore = store
	statuses := concurrentAuthorizedDevicePollStatuses(handler, &client, request, deviceCodeValue)
	successes := 0

	for status := range statuses {
		if status == http.StatusOK {
			successes++
		}
	}

	if successes != 1 {
		t.Fatalf("successful token responses = %d, want 1", successes)
	}
}

// concurrentAuthorizedDevicePollStatuses releases two token polls from one barrier.
func concurrentAuthorizedDevicePollStatuses(
	handler *OIDCHandler,
	client *config.OIDCClient,
	request *devicecode.DeviceCodeRequest,
	deviceCodeValue string,
) <-chan int {
	var waitGroup sync.WaitGroup

	start := make(chan struct{})
	statuses := make(chan int, 2)

	for range 2 {
		waitGroup.Add(1)

		go func() {
			defer waitGroup.Done()

			<-start

			response := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(response)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/token", nil)
			handler.handleDeviceCodePollStatus(ctx, deviceCodeValue, request, client)

			statuses <- response.Code
		}()
	}

	close(start)
	waitGroup.Wait()
	close(statuses)

	return statuses
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

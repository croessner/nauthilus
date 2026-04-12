package idp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	devicecode "github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/secret"
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

func newTestDeviceCodeOIDCHandler(t *testing.T) (*OIDCHandler, config.OIDCClient) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	client := config.OIDCClient{
		ClientID:     "test-client",
		ClientSecret: secret.New("test-secret"),
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{definitions.ScopeOpenId, "profile", "email"},
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

	idpInstance := devicecode.NewNauthilusIdP(d)
	handler := NewOIDCHandler(d, idpInstance, nil)
	handler.deviceStore = &noopDeviceCodeStore{}

	return handler, client
}

func TestIssueDeviceCodeTokens_RejectsMissingPersistedClaims(t *testing.T) {
	handler, client := newTestDeviceCodeOIDCHandler(t)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/token", nil)
	ctx.Set(definitions.CtxServiceKey, "test")

	request := &devicecode.DeviceCodeRequest{
		ClientID: client.ClientID,
		Scopes:   []string{definitions.ScopeOpenId, "profile", "email"},
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
		Scopes:   []string{definitions.ScopeOpenId, "profile", "email"},
		Status:   devicecode.DeviceCodeStatusAuthorized,
		IdTokenClaims: map[string]any{
			"sub":                "user-123",
			"preferred_username": "alice",
			"email":              "alice@example.com",
		},
		AccessTokenClaims: map[string]any{
			"email": "alice@example.com",
		},
	}
	request.StoreUserSnapshot(&backend.User{
		Id:          "user-123",
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

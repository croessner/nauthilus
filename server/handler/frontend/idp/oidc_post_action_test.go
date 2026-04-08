package idp

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	domainidp "github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

type mockOIDCPostActionCfg struct {
	*mockOIDCCfg
}

func (m *mockOIDCPostActionCfg) HaveLuaActions() bool {
	return true
}

func (m *mockOIDCPostActionCfg) HasFeature(feature string) bool {
	return feature == definitions.FeatureBruteForce
}

func newOIDCTokenPostActionHandler() *OIDCHandler {
	cfg := &mockOIDCPostActionCfg{
		mockOIDCCfg: &mockOIDCCfg{
			issuer:     "https://auth.example.com",
			signingKey: secret.New(generateTestKey()),
			clients: []config.OIDCClient{
				{
					ClientID:     "test-client",
					ClientSecret: secret.New("test-secret"),
				},
			},
		},
	}

	d := &deps.Deps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	return &OIDCHandler{deps: d}
}

func newCanceledTokenContext(t *testing.T) *gin.Context {
	t.Helper()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	requestCtx, cancel := context.WithCancel(context.Background())
	cancel()

	req := httptest.NewRequest(http.MethodPost, "/oidc/token", nil).WithContext(requestCtx)
	req.RemoteAddr = "192.0.2.10:12345"
	ctx.Request = req
	ctx.Set(definitions.CtxGUIDKey, "token-post-action-test")
	ctx.Set(definitions.CtxServiceKey, definitions.ServIdP)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	return ctx
}

func waitForQueuedAction(t *testing.T, requestChan <-chan *action.Action) {
	t.Helper()

	select {
	case act := <-requestChan:
		if act == nil {
			t.Fatal("expected queued action, got nil")
		}

		if act.HTTPRequest == nil {
			t.Fatal("expected HTTP request on queued action")
		}

		if err := act.HTTPRequest.Context().Err(); err != nil {
			t.Fatalf("expected detached post-action request context, got err=%v", err)
		}

		act.FinishedChan <- action.Done{}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected post action to be queued")
	}
}

func TestRunOIDCTokenPostActionQueuesActionWhenRequestContextCanceled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	requestChan := make(chan *action.Action, 1)
	originalRequestChan := action.RequestChan
	action.RequestChan = requestChan
	t.Cleanup(func() {
		action.RequestChan = originalRequestChan
	})

	handler := newOIDCTokenPostActionHandler()
	ctx := newCanceledTokenContext(t)

	handler.runOIDCTokenPostAction(
		ctx,
		"client_credentials",
		"test-client",
		"client_secret_post",
		http.StatusOK,
		"success",
		5*time.Millisecond,
	)

	waitForQueuedAction(t, requestChan)
}

func TestRunOIDCTokenPostActionCopiesMFASessionState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	requestChan := make(chan *action.Action, 1)
	originalRequestChan := action.RequestChan
	action.RequestChan = requestChan
	t.Cleanup(func() {
		action.RequestChan = originalRequestChan
	})

	handler := newOIDCTokenPostActionHandler()
	ctx := newCanceledTokenContext(t)
	ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
		definitions.SessionKeyMFAMethod:    "webauthn",
		definitions.SessionKeyMFACompleted: true,
	}})

	handler.runOIDCTokenPostAction(
		ctx,
		"authorization_code",
		"test-client",
		"client_secret_post",
		http.StatusOK,
		"success",
		5*time.Millisecond,
	)

	select {
	case act := <-requestChan:
		if act == nil || act.CommonRequest == nil {
			t.Fatal("expected queued action with CommonRequest")
		}

		assert.Equal(t, "webauthn", act.MFAMethod)
		assert.True(t, act.MFACompleted)
		assert.False(t, act.FeatureStageExpected)
		assert.False(t, act.FilterStageExpected)
		act.FinishedChan <- action.Done{}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected post action to be queued")
	}
}

func TestRunOIDCTokenPostActionUsesRequestScopedMFAOverrides(t *testing.T) {
	gin.SetMode(gin.TestMode)

	requestChan := make(chan *action.Action, 1)
	originalRequestChan := action.RequestChan
	action.RequestChan = requestChan
	t.Cleanup(func() {
		action.RequestChan = originalRequestChan
	})

	handler := newOIDCTokenPostActionHandler()
	ctx := newCanceledTokenContext(t)
	ctx.Set(definitions.CtxMFACompletedKey, true)
	ctx.Set(definitions.CtxMFAMethodKey, "totp")

	handler.runOIDCTokenPostAction(
		ctx,
		"device_code",
		"test-client",
		"client_secret_post",
		http.StatusOK,
		"success",
		5*time.Millisecond,
	)

	select {
	case act := <-requestChan:
		if act == nil || act.CommonRequest == nil {
			t.Fatal("expected queued action with CommonRequest")
		}

		assert.Equal(t, "totp", act.MFAMethod)
		assert.True(t, act.MFACompleted)
		assert.False(t, act.FeatureStageExpected)
		assert.False(t, act.FilterStageExpected)
		act.FinishedChan <- action.Done{}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected post action to be queued")
	}
}

func TestRunOIDCTokenPostActionCopiesOIDCSessionSubject(t *testing.T) {
	gin.SetMode(gin.TestMode)

	requestChan := make(chan *action.Action, 1)
	originalRequestChan := action.RequestChan
	action.RequestChan = requestChan
	t.Cleanup(func() {
		action.RequestChan = originalRequestChan
	})

	handler := newOIDCTokenPostActionHandler()
	ctx := newCanceledTokenContext(t)

	setOIDCTokenPostActionSubject(ctx, &domainidp.OIDCSession{
		UserID:       "user-123",
		Username:     "alice",
		DisplayName:  "Alice Example",
		MFACompleted: true,
		MFAMethod:    "webauthn",
	})

	handler.runOIDCTokenPostAction(
		ctx,
		"refresh_token",
		"test-client",
		"client_secret_post",
		http.StatusOK,
		"success",
		5*time.Millisecond,
	)

	select {
	case act := <-requestChan:
		if act == nil || act.CommonRequest == nil {
			t.Fatal("expected queued action with CommonRequest")
		}

		assert.Equal(t, "alice", act.Username)
		assert.Equal(t, "user-123", act.UniqueUserID)
		assert.Equal(t, "Alice Example", act.DisplayName)
		assert.Equal(t, "webauthn", act.MFAMethod)
		assert.True(t, act.MFACompleted)
		assert.True(t, act.UserFound)
		act.FinishedChan <- action.Done{}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected post action to be queued")
	}
}

package idp

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	domainidp "github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/action"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

type mockOIDCPostActionCfg struct {
	*mockOIDCCfg
}

func (m *mockOIDCPostActionCfg) HaveLuaActions() bool {
	return true
}

func (m *mockOIDCPostActionCfg) HasRuntimeModule(environmentName string) bool {
	return environmentName == definitions.ControlBruteForce
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

func newTokenPostActionContext(t *testing.T) (*gin.Context, context.CancelFunc, *core.PostActionExecutionGate) {
	t.Helper()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	requestCtx, cancel := context.WithCancel(context.Background())

	req := httptest.NewRequest(http.MethodPost, "/oidc/token", nil).WithContext(requestCtx)
	req.RemoteAddr = "192.0.2.10:12345"
	ctx.Request = req
	ctx.Set(definitions.CtxGUIDKey, "token-post-action-test")
	ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())
	gate := core.InstallPostActionExecutionGate(ctx)

	return ctx, cancel, gate
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

// assertQueuedMFAPostAction verifies MFA metadata on a queued token post-action.
func assertQueuedMFAPostAction(t *testing.T, requestChan <-chan *action.Action, expectedMethod string) {
	t.Helper()

	select {
	case act := <-requestChan:
		if act == nil || act.CommonRequest == nil {
			t.Fatal("expected queued action with CommonRequest")
		}

		assert.Equal(t, expectedMethod, act.MFAMethod)
		assert.True(t, act.MFACompleted)
		assert.False(t, act.EnvironmentStageExpected)
		assert.False(t, act.SubjectStageExpected)

		act.FinishedChan <- action.Done{}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected post action to be queued")
	}
}

func TestRunOIDCTokenPostActionContinuesAfterAcceptedRequestCancellation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	requestChan := make(chan *action.Action, 1)
	originalRequestChan := action.PostActionRequestChan
	action.PostActionRequestChan = requestChan

	t.Cleanup(func() {
		action.PostActionRequestChan = originalRequestChan
	})

	handler := newOIDCTokenPostActionHandler()
	ctx, cancel, gate := newTokenPostActionContext(t)

	handler.runOIDCTokenPostAction(
		ctx,
		"client_credentials",
		"test-client",
		"client_secret_post",
		http.StatusOK,
		"success",
		5*time.Millisecond,
	)

	cancel()
	gate.Complete()
	waitForQueuedAction(t, requestChan)
}

func TestRunOIDCTokenPostActionCopiesMFASessionState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	requestChan := make(chan *action.Action, 1)
	originalRequestChan := action.PostActionRequestChan
	action.PostActionRequestChan = requestChan

	t.Cleanup(func() {
		action.PostActionRequestChan = originalRequestChan
	})

	handler := newOIDCTokenPostActionHandler()
	ctx, cancel, gate := newTokenPostActionContext(t)
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

	cancel()
	gate.Complete()
	assertQueuedMFAPostAction(t, requestChan, "webauthn")
}

func TestRunOIDCTokenPostActionUsesRequestScopedMFAOverrides(t *testing.T) {
	gin.SetMode(gin.TestMode)

	requestChan := make(chan *action.Action, 1)
	originalRequestChan := action.PostActionRequestChan
	action.PostActionRequestChan = requestChan

	t.Cleanup(func() {
		action.PostActionRequestChan = originalRequestChan
	})

	handler := newOIDCTokenPostActionHandler()
	ctx, cancel, gate := newTokenPostActionContext(t)
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

	cancel()
	gate.Complete()
	assertQueuedMFAPostAction(t, requestChan, "totp")
}

func TestRunOIDCTokenPostActionCopiesOIDCSessionSubject(t *testing.T) {
	gin.SetMode(gin.TestMode)

	requestChan := make(chan *action.Action, 1)
	originalRequestChan := action.PostActionRequestChan
	action.PostActionRequestChan = requestChan

	t.Cleanup(func() {
		action.PostActionRequestChan = originalRequestChan
	})

	handler := newOIDCTokenPostActionHandler()
	ctx, cancel, gate := newTokenPostActionContext(t)

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

	cancel()
	gate.Complete()

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

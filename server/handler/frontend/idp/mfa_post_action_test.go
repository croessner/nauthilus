// Copyright (C) 2025 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package idp

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	corepkg "github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/action"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func newMFACompletionDeps() *deps.Deps {
	return &deps.Deps{
		Cfg: &mockOIDCPostActionCfg{
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
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// newMFAPostActionTestContext builds an MFA request context without Gin-level proxy trust.
func newMFAPostActionTestContext(t *testing.T, mgr *mockCookieManager) *gin.Context {
	t.Helper()

	w := httptest.NewRecorder()
	ctx, engine := gin.CreateTestContext(w)

	if err := engine.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/login/mfa", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("User-Agent", "mfa-post-action-test")
	ctx.Request = req
	ctx.Set(definitions.CtxGUIDKey, "mfa-post-action-guid")
	ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())
	ctx.Set(definitions.CtxSecureDataKey, mgr)

	return ctx
}

func waitForQueuedPostAction(t *testing.T, requestChan <-chan *action.Action) *action.Action {
	t.Helper()

	select {
	case act := <-requestChan:
		if act == nil {
			t.Fatal("expected queued action, got nil")
		}

		if act.CommonRequest == nil {
			t.Fatal("expected CommonRequest on queued action")
		}

		if act.HTTPRequest == nil {
			t.Fatal("expected HTTP request on queued action")
		}

		if err := act.HTTPRequest.Context().Err(); err != nil {
			t.Fatalf("expected detached post-action request context, got err=%v", err)
		}

		return act
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected post action to be queued")
	}

	return nil
}

func TestFinalizeMFALoginPreservesMFAMethodAndQueuesPostAction(t *testing.T) {
	gin.SetMode(gin.TestMode)

	requestChan := make(chan *action.Action, 1)
	originalRequestChan := action.RequestChan
	action.RequestChan = requestChan

	t.Cleanup(func() {
		action.RequestChan = originalRequestChan
	})

	d := newMFACompletionDeps()
	handler := &FrontendHandler{deps: d}
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyMFAMethod:   "totp",
		definitions.SessionKeyProtocol:    definitions.ProtoOIDC,
		definitions.SessionKeyIDPFlowType: definitions.ProtoOIDC,
		definitions.SessionKeyIDPClientID: "test-client",
	}}
	ctx := newMFAPostActionTestContext(t, mgr)
	user := backend.NewUser("alice", "Alice Example", "uid-1")

	handler.finalizeMFALogin(ctx, user)

	assert.Equal(t, "totp", mgr.GetString(definitions.SessionKeyMFAMethod, ""))
	assert.True(t, mgr.GetBool(definitions.SessionKeyMFACompleted, false))

	act := waitForQueuedPostAction(t, requestChan)
	assert.Equal(t, "totp", act.MFAMethod)
	assert.True(t, act.MFACompleted)
	assert.Equal(t, definitions.ProtoOIDC, act.Protocol)
	assert.Equal(t, "test-client", act.OIDCCID)
	assert.False(t, act.EnvironmentStageExpected)
	assert.False(t, act.SubjectStageExpected)
	assert.Equal(t, "alice", act.Account)
	assert.Equal(t, "uid-1", act.UniqueUserID)

	act.FinishedChan <- action.Done{}
}

func TestQueueCompletedIDPMFAPostActionUsesCurrentProtocolState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []completedMFAPostActionProtocolCase{
		{
			name:         "oidc totp",
			flowType:     definitions.ProtoOIDC,
			method:       "totp",
			oidcClientID: "test-client",
		},
		{
			name:         "saml webauthn",
			flowType:     definitions.ProtoSAML,
			method:       "webauthn",
			samlEntityID: "https://sp.example.com/metadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			act := runCompletedMFAPostActionProtocolCase(t, tt)

			assertCompletedMFAPostActionProtocol(t, act, tt)

			act.FinishedChan <- action.Done{}
		})
	}
}

type completedMFAPostActionProtocolCase struct {
	name         string
	flowType     string
	method       string
	oidcClientID string
	samlEntityID string
}

// runCompletedMFAPostActionProtocolCase queues one completed MFA post-action case.
func runCompletedMFAPostActionProtocolCase(
	t *testing.T,
	tc completedMFAPostActionProtocolCase,
) *action.Action {
	t.Helper()

	requestChan := make(chan *action.Action, 1)
	originalRequestChan := action.RequestChan
	action.RequestChan = requestChan

	t.Cleanup(func() {
		action.RequestChan = originalRequestChan
	})

	mgr := &mockCookieManager{data: completedMFAPostActionCookieData(tc)}
	ctx := newMFAPostActionTestContext(t, mgr)
	user := backend.NewUser("alice", "Alice Example", "uid-1")

	if !corepkg.QueueCompletedIDPMFAPostAction(ctx, newMFACompletionDeps().Auth(), user) {
		t.Fatal("expected MFA post action to be queued")
	}

	return waitForQueuedPostAction(t, requestChan)
}

// completedMFAPostActionCookieData returns session state for one completed MFA case.
func completedMFAPostActionCookieData(tc completedMFAPostActionProtocolCase) map[string]any {
	return map[string]any{
		definitions.SessionKeyProtocol:        tc.flowType,
		definitions.SessionKeyIDPFlowType:     tc.flowType,
		definitions.SessionKeyMFAMethod:       tc.method,
		definitions.SessionKeyMFACompleted:    true,
		definitions.SessionKeyIDPClientID:     tc.oidcClientID,
		definitions.SessionKeyIDPSAMLEntityID: tc.samlEntityID,
	}
}

// assertCompletedMFAPostActionProtocol verifies protocol-specific queued action fields.
func assertCompletedMFAPostActionProtocol(
	t *testing.T,
	act *action.Action,
	tc completedMFAPostActionProtocolCase,
) {
	t.Helper()

	assert.Equal(t, tc.method, act.MFAMethod)
	assert.True(t, act.MFACompleted)
	assert.Equal(t, tc.flowType, act.Protocol)
	assert.Equal(t, tc.oidcClientID, act.OIDCCID)
	assert.Equal(t, tc.samlEntityID, act.SAMLEntityID)
	assert.False(t, act.EnvironmentStageExpected)
	assert.False(t, act.SubjectStageExpected)
}

func TestQueueCompletedIDPMFAPostActionUsesTrustedForwardedClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	requestChan := make(chan *action.Action, 1)
	originalRequestChan := action.RequestChan
	action.RequestChan = requestChan

	t.Cleanup(func() {
		action.RequestChan = originalRequestChan
	})

	d := newMFACompletionDeps()
	cfg := d.Cfg.(*mockOIDCPostActionCfg)
	cfg.trustedProxies = []string{"192.168.0.5"}

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyProtocol:     definitions.ProtoOIDC,
		definitions.SessionKeyIDPFlowType:  definitions.ProtoOIDC,
		definitions.SessionKeyMFAMethod:    definitions.MFAMethodTOTP,
		definitions.SessionKeyMFACompleted: true,
		definitions.SessionKeyIDPClientID:  "test-client",
	}}
	ctx := newMFAPostActionTestContext(t, mgr)
	ctx.Request.RemoteAddr = "192.168.0.5:44321"
	ctx.Request.Header.Set("X-Forwarded-For", "203.0.113.10")

	user := backend.NewUser("alice", "Alice Example", "uid-1")

	if !corepkg.QueueCompletedIDPMFAPostAction(ctx, d.Auth(), user) {
		t.Fatal("expected MFA post action to be queued")
	}

	act := waitForQueuedPostAction(t, requestChan)
	assert.Equal(t, "203.0.113.10", act.ClientIP)

	act.FinishedChan <- action.Done{}
}

package core

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestLogIDPMFAuthResult_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx, logBuf := newIDPMFALogContext(t)

	LogIDPMFAuthResult(ctx, AuthDeps{Cfg: newIDPMFALogConfig(), Logger: newIDPMFALogger(logBuf)}, "alice", definitions.MFAMethodTOTP, "", true)

	output := logBuf.String()

	assert.Contains(t, output, "Second-factor authentication was successful")
	assert.Contains(t, output, "mfa_method=totp")
	assert.Contains(t, output, "auth_method=totp")
	assert.Contains(t, output, "authenticated=ok")
	assert.Contains(t, output, "authn=true")
	assert.Contains(t, output, "username=alice")
	assert.Contains(t, output, "oidc_cid=test-client")
	assert.Contains(t, output, "client_ip=203.0.113.10")
}

func TestLogIDPMFAuthResult_FailureNormalizesRecoveryMethod(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx, logBuf := newIDPMFALogContext(t)

	LogIDPMFAuthResult(ctx, AuthDeps{Cfg: newIDPMFALogConfig(), Logger: newIDPMFALogger(logBuf)}, "alice", "recovery", "Invalid recovery code", false)

	output := logBuf.String()

	assert.Contains(t, output, "Second-factor authentication has failed")
	assert.Contains(t, output, "mfa_method=recovery_codes")
	assert.Contains(t, output, "auth_method=recovery_codes")
	assert.Contains(t, output, "authenticated=fail")
	assert.Contains(t, output, "authn=false")
	assert.Contains(t, output, "status_message=\"Invalid recovery code\"")
	assert.Contains(t, output, "username=alice")
	assert.Contains(t, output, "client_ip=203.0.113.10")
}

func newIDPMFALogContext(t *testing.T) (*gin.Context, *bytes.Buffer) {
	t.Helper()

	logBuf := &bytes.Buffer{}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/login/totp", bytes.NewBufferString(`{"credential":"ok"}`))
	req.RemoteAddr = "198.51.100.10:54321"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mfa-log-test")
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	ctx.Request = req
	ctx.Set(definitions.CtxGUIDKey, "mfa-guid")
	ctx.Set(definitions.CtxServiceKey, definitions.ServIdP)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())
	ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
		definitions.SessionKeyProtocol:    definitions.ProtoOIDC,
		definitions.SessionKeyIdPFlowType: definitions.ProtoOIDC,
		definitions.SessionKeyIdPClientID: "test-client",
	}})

	return ctx, logBuf
}

func newIDPMFALogConfig() config.File {
	return &config.FileSettings{
		Server: &config.ServerSection{
			Log: config.Log{},
		},
	}
}

func newIDPMFALogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

package logging

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

func TestLoggerMiddlewareIncludesExternalSessionWhenSet(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const externalSessionID = "external-session-1"

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	router := gin.New()
	router.Use(LoggerMiddleware(logger))
	router.GET("/test", func(ctx *gin.Context) {
		ctx.Set(definitions.CtxExternalSessionKey, externalSessionID)
		ctx.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}

	logLine := buf.String()
	if !strings.Contains(logLine, `external_session=external-session-1`) {
		t.Fatalf("expected external session in log line, got %q", logLine)
	}
}

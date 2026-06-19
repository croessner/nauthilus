package logging

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
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

func TestLoggerMiddlewareUsesTrustedForwardedClientIPFromConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var buf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			TrustedProxies: []string{"192.168.0.5"},
		},
	}

	router := gin.New()
	if err := router.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies() failed: %v", err)
	}

	router.Use(LoggerMiddlewareWithConfig(logger, cfg))
	router.POST("/login/totp/:languageTag", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/login/totp/de", nil)
	req.RemoteAddr = "192.168.0.5:44321"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")

	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	logLine := buf.String()
	if !strings.Contains(logLine, `client_ip=203.0.113.10`) {
		t.Fatalf("expected forwarded client IP in log line, got %q", logLine)
	}
}

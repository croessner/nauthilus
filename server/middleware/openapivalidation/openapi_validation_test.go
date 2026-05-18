// Copyright (C) 2026 Christian Roessner
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

package openapivalidation

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
)

const runtimeValidationSecret = "synthetic-runtime-secret"

func TestNewManagementMiddleware_DefaultDisabledReturnsNil(t *testing.T) {
	handler, err := NewManagementMiddleware(&config.OpenAPIValidation{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewManagementMiddleware() error = %v, want nil", err)
	}

	if handler != nil {
		t.Fatal("NewManagementMiddleware() handler != nil, want nil when disabled")
	}
}

func TestMiddlewareAllowsSelectedValidRequestAndRestoresBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(newTestMiddleware(t, config.OpenAPIValidationOperationFlushUserCache, nil))
	router.DELETE("/api/v1/cache/flush", func(ctx *gin.Context) {
		body, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}

		if string(body) != `{"user":"alice@example.test"}` {
			t.Fatalf("body = %q, want preserved JSON body", string(body))
		}

		ctx.Status(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/cache/flush", strings.NewReader(`{"user":"alice@example.test"}`))
	request.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
}

func TestMiddlewareRejectsSelectedInvalidRequestWithSanitizedLog(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var logs bytes.Buffer

	router := gin.New()
	router.Use(newTestMiddleware(t, config.OpenAPIValidationOperationFlushUserCache, &logs))
	router.DELETE("/api/v1/cache/flush", func(_ *gin.Context) {
		t.Fatal("handler should not run after OpenAPI runtime validation failure")
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodDelete,
		"/api/v1/cache/flush",
		strings.NewReader(`{"password":"`+runtimeValidationSecret+`"}`),
	)
	request.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}

	if strings.Contains(recorder.Body.String(), runtimeValidationSecret) {
		t.Fatalf("response body leaked sensitive value: %q", recorder.Body.String())
	}

	if strings.Contains(logs.String(), runtimeValidationSecret) {
		t.Fatalf("log output leaked sensitive value: %q", logs.String())
	}

	if !strings.Contains(logs.String(), "OpenAPI runtime request validation failed") {
		t.Fatalf("log output = %q, want validation failure message", logs.String())
	}
}

func TestMiddlewareSkipsUnselectedOperations(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(newTestMiddleware(t, config.OpenAPIValidationOperationFlushUserCache, nil))
	router.POST("/api/v1/auth/json", func(ctx *gin.Context) {
		ctx.Status(http.StatusAccepted)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/json",
		strings.NewReader(`{"username":"alice@example.test","password":"`+runtimeValidationSecret+`","service":"imap"}`),
	)
	request.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d for unselected operation", recorder.Code, http.StatusAccepted)
	}
}

func newTestMiddleware(t *testing.T, operation string, logs *bytes.Buffer) gin.HandlerFunc {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if logs != nil {
		logger = slog.New(slog.NewTextHandler(logs, nil))
	}

	handler, err := NewManagementMiddleware(&config.OpenAPIValidation{
		Operations: []string{operation},
		Enabled:    true,
		Enforce:    true,
	}, logger)
	if err != nil {
		t.Fatalf("NewManagementMiddleware() error = %v", err)
	}

	if handler == nil {
		t.Fatal("NewManagementMiddleware() handler = nil, want active middleware")
	}

	return handler
}

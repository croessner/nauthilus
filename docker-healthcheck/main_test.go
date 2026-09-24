// Copyright (C) 2026 Christian Rößner
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

package main

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/handler/health"
	"github.com/gin-gonic/gin"
)

// newHealthServer serves the real health routes of the server without configuration or Redis.
func newHealthServer(t *testing.T) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	health.New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), nil).Register(engine)

	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)

	return server
}

// runHealthcheck runs the healthcheck client against one path of the test server.
func runHealthcheck(t *testing.T, server *httptest.Server, path string) error {
	t.Helper()

	cfg := Config{URL: server.URL + path, Timeout: 5 * time.Second}
	client := NewClient(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(t.Context(), cfg.Timeout)
	defer cancel()

	return client.Run(ctx)
}

// TestHealthcheckAcceptsLivenessEndpoint pins that the image's healthcheck binary accepts the liveness
// document of /livez, so Kubernetes can use it as the liveness probe.
func TestHealthcheckAcceptsLivenessEndpoint(t *testing.T) {
	if err := runHealthcheck(t, newHealthServer(t), health.LivenessPath); err != nil {
		t.Fatalf("healthcheck rejected %s: %v", health.LivenessPath, err)
	}
}

// TestHealthcheckRejectsPlainPing pins why /ping is no probe target for the healthcheck binary: it
// answers plain text, which the binary cannot decode.
func TestHealthcheckRejectsPlainPing(t *testing.T) {
	err := runHealthcheck(t, newHealthServer(t), "/ping")
	if err == nil || !strings.Contains(err.Error(), "decode healthz response") {
		t.Fatalf("expected a decode error for /ping, got %v", err)
	}
}

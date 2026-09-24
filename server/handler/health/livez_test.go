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

package health

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// redisCallCounter is a go-redis hook that counts every dial, command and pipeline.
type redisCallCounter struct {
	calls atomic.Int64
}

// DialHook counts dial attempts.
func (c *redisCallCounter) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c.calls.Add(1)

		return next(ctx, network, addr)
	}
}

// ProcessHook counts single commands.
func (c *redisCallCounter) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		c.calls.Add(1)

		return next(ctx, cmd)
	}
}

// ProcessPipelineHook counts pipelines.
func (c *redisCallCounter) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		c.calls.Add(1)

		return next(ctx, cmds)
	}
}

// serveLiveness registers the health routes with a counting Redis client and no configuration and
// serves one GET /livez.
func serveLiveness(t *testing.T) (*httptest.ResponseRecorder, *redisCallCounter) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	counter := &redisCallCounter{}
	db := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	db.AddHook(counter)

	t.Cleanup(func() { _ = db.Close() })

	engine := gin.New()
	New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), rediscli.NewTestClient(db)).Register(engine)

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, LivenessPath, nil))

	return recorder, counter
}

// TestLivenessCheckAnswersUpWithoutDependencies pins the fixed liveness document and that the probe
// touches neither the configuration nor Redis.
func TestLivenessCheckAnswersUpWithoutDependencies(t *testing.T) {
	recorder, counter := serveLiveness(t)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	if got := recorder.Header().Get("Content-Type"); got != livenessContentType {
		t.Fatalf("expected content type %q, got %q", livenessContentType, got)
	}

	if got := recorder.Body.String(); got != `{"status":"up"}` {
		t.Fatalf("unexpected liveness document %q", got)
	}

	var result HealthzResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("liveness document is not a readiness-compatible document: %v", err)
	}

	if result.Status != healthzStatusUp {
		t.Fatalf("expected status %q, got %q", healthzStatusUp, result.Status)
	}

	if calls := counter.calls.Load(); calls != 0 {
		t.Fatalf("expected no Redis calls, got %d", calls)
	}
}

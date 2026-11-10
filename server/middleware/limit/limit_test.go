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

package limit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/conncause"
	"github.com/croessner/nauthilus/v4/server/definitions"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// probeBypassPaths lists the routes that must pass a saturated limiter.
var probeBypassPaths = []string{"/ping", "/livez", "/healthz", "/metrics"}

// serveLimitedRoutes serves one GET per path through the given middleware and returns the status codes.
func serveLimitedRoutes(middleware gin.HandlerFunc, paths ...string) map[string]int {
	engine := gin.New()
	engine.Use(middleware)

	for _, path := range paths {
		engine.GET(path, func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
	}

	codes := make(map[string]int, len(paths))

	for _, path := range paths {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.RemoteAddr = "192.0.2.10:1234"

		engine.ServeHTTP(recorder, request)

		codes[path] = recorder.Code
	}

	return codes
}

// TestLimitCounterBypassesProbeRoutes pins that probes and metrics scrapes pass a full concurrency limiter
// while ordinary routes are rejected.
func TestLimitCounterBypassesProbeRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	codes := serveLimitedRoutes(NewLimitCounter(0).Middleware(), append([]string{"/other"}, probeBypassPaths...)...)

	for _, path := range probeBypassPaths {
		assert.Equal(t, http.StatusOK, codes[path], path)
	}

	assert.Equal(t, http.StatusTooManyRequests, codes["/other"])
}

// TestIPRateLimiterBypassesProbeRoutes pins that probes and metrics scrapes pass an exhausted rate limiter
// while ordinary routes are rejected.
func TestIPRateLimiterBypassesProbeRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	codes := serveLimitedRoutes(NewIPRateLimiter(0, 0).Middleware(), append([]string{"/other"}, probeBypassPaths...)...)

	for _, path := range probeBypassPaths {
		assert.Equal(t, http.StatusOK, codes[path], path)
	}

	assert.Equal(t, http.StatusTooManyRequests, codes["/other"])
}

func TestLimitCounterNeverAdmitsMoreThanTheMaximum(t *testing.T) {
	const (
		maximum = 8
		callers = 64
	)

	counter := NewLimitCounter(maximum)

	var (
		wait     sync.WaitGroup
		peak     atomic.Int32
		admitted atomic.Int32
	)

	for range callers {
		wait.Go(func() {
			for range 200 {
				current, ok := counter.TryAcquire()
				if !ok {
					continue
				}

				admitted.Add(1)

				for {
					seen := peak.Load()
					if current <= seen || peak.CompareAndSwap(seen, current) {
						break
					}
				}

				counter.Release()
			}
		})
	}

	wait.Wait()

	if peak.Load() > maximum || admitted.Load() == 0 || counter.CurrentConnections != 0 {
		t.Fatalf("peak = %d, admitted = %d, left = %d; want peak <= %d and a drained counter",
			peak.Load(), admitted.Load(), counter.CurrentConnections, maximum)
	}
}

// noticeLevel is the JSON level label of the custom NOTICE level.
var noticeLevel = (slog.LevelInfo + definitions.SlogNoticeLevelOffset).String()

// TestLimitCounterLogsTerminatedRequestsByCause pins that client disconnects are logged at NOTICE with
// status 499, while server-side connection terminations are logged at WARN; both carry their cause and duration.
func TestLimitCounterLogsTerminatedRequestsByCause(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		cause      error
		name       string
		wantLevel  string
		wantMsg    string
		wantError  string
		wantStatus int
	}{
		{name: "client disconnected", cause: conncause.ErrClientDisconnected, wantLevel: noticeLevel, wantMsg: definitions.MsgClientClosedRequest, wantError: conncause.ErrClientDisconnected.Error(), wantStatus: definitions.StatusClientClosedRequest},
		{name: "stream reset without cause", cause: context.Canceled, wantLevel: noticeLevel, wantMsg: definitions.MsgClientClosedRequest, wantError: context.Canceled.Error(), wantStatus: definitions.StatusClientClosedRequest},
		{name: "server timeout", cause: conncause.ErrConnectionTimeout, wantLevel: slog.LevelWarn.String(), wantMsg: msgRequestConnectionTerminated, wantError: conncause.ErrConnectionTimeout.Error(), wantStatus: http.StatusOK},
		{name: "closed locally", cause: conncause.ErrConnectionClosedLocally, wantLevel: slog.LevelWarn.String(), wantMsg: msgRequestConnectionTerminated, wantError: conncause.ErrConnectionClosedLocally.Error(), wantStatus: http.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer

			logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
			engine := gin.New()
			engine.Use(NewLimitCounter(4).MiddlewareWithLogger(logger))
			engine.GET("/other", func(*gin.Context) {})

			ctx, cancel := context.WithCancelCause(context.Background())
			cancel(test.cause)

			recorder := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/other", nil)

			engine.ServeHTTP(recorder, request)

			record := findLogRecord(t, output.String(), test.wantMsg)
			assert.Equal(t, test.wantLevel, record["level"])
			assert.Equal(t, test.wantError, record[definitions.LogKeyError])
			assert.Contains(t, record, logKeyDurationMS)
			assert.NotContains(t, record, definitions.LogKeyClientIP, "client_ip is logged only when the handler resolved it")
			assert.Equal(t, test.wantStatus, recorder.Code)
		})
	}
}

// TestTerminatedRequestLogOmitsUnknownDuration pins that a request without a recorded start time logs no
// duration_ms instead of a misleading zero.
func TestTerminatedRequestLogOmitsUnknownDuration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/other", nil)

	keyvals := terminatedRequestLogValues(ctx, conncause.Termination{Cause: conncause.ErrClientDisconnected}, requestDuration{})

	assert.NotContains(t, keyvals, logKeyDurationMS)
}

// TestLimitCounterLogsClientCloseAfterTCPDisconnect reproduces a client-side request timeout: the client closes the
// TCP connection while the handler still runs. The middleware must log NOTICE "Client Closed Request" with the
// transport cause, a plausible duration, and the client IP and protocol the handler resolved.
func TestLimitCounterLogsClientCloseAfterTCPDisconnect(t *testing.T) {
	const clientTimeout = 150 * time.Millisecond

	output := &lockedBuffer{}
	server, finished := newBlockingCauseServer(t, output)

	closeClientAfter(t, server.Listener.Addr().String(), clientTimeout)

	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not finish after the client closed the connection")
	}

	record := findLogRecord(t, output.String(), definitions.MsgClientClosedRequest)
	assert.Equal(t, noticeLevel, record["level"])
	assert.Contains(t, record[definitions.LogKeyError], conncause.ErrClientDisconnected.Error())
	assert.Equal(t, "192.0.2.10", record[definitions.LogKeyClientIP])
	assert.Equal(t, "imap", record[definitions.LogKeyProtocol])
	assert.EqualValues(t, definitions.StatusClientClosedRequest, record["status"])

	duration, ok := record[logKeyDurationMS].(float64)
	if !ok {
		t.Fatalf("duration_ms = %#v, want a number", record[logKeyDurationMS])
	}

	assert.GreaterOrEqual(t, duration, float64(clientTimeout.Milliseconds()/2))
	assert.Less(t, duration, float64((5 * time.Second).Milliseconds()))
}

// newBlockingCauseServer serves /auth through the limit middleware behind the cause listener. The handler resolves
// client IP and protocol like the auth handler and blocks until the request context ends; finished closes once the
// middleware has logged.
func newBlockingCauseServer(t *testing.T, output io.Writer) (*httptest.Server, <-chan struct{}) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	finished := make(chan struct{})
	logger := slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: slog.LevelDebug}))

	engine := gin.New()
	engine.Use(func(ctx *gin.Context) {
		defer close(finished)

		ctx.Next()
	})
	engine.Use(NewLimitCounter(4).MiddlewareWithLogger(logger))
	engine.GET("/auth", func(ctx *gin.Context) {
		ctx.Set(definitions.CtxClientIPKey, "192.0.2.10")
		ctx.Set(definitions.CtxAuthProtocolKey, "imap")

		select {
		case <-ctx.Request.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})

	server := httptest.NewUnstartedServer(engine)
	server.Listener = conncause.NewListener(server.Listener)
	server.Config.ConnContext = conncause.ConnContext
	server.Start()
	t.Cleanup(server.Close)

	return server, finished
}

// closeClientAfter sends one request over a raw TCP connection and closes it after timeout, like a client whose
// request deadline expired.
func closeClientAfter(t *testing.T, address string, timeout time.Duration) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = io.WriteString(conn, "GET /auth HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	time.Sleep(timeout)

	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
}

// lockedBuffer is a log sink that the server goroutine writes while the test reads it.
type lockedBuffer struct {
	buffer bytes.Buffer
	mu     sync.Mutex
}

// Write appends one log record under the lock.
func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.Write(p)
}

// String returns the collected log output under the lock.
func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.String()
}

// findLogRecord returns the first JSON log record with the given message or fails the test.
func findLogRecord(t *testing.T, output string, msg string) map[string]any {
	t.Helper()

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		record := map[string]any{}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("invalid JSON log line %q: %v", scanner.Text(), err)
		}

		if record[slog.MessageKey] == msg {
			return record
		}
	}

	t.Fatalf("no log record with msg %q in %s", msg, output)

	return nil
}

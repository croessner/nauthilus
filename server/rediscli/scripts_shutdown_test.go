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

package rediscli

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/redis/go-redis/v9"
)

// newScriptUploadTestClient returns a miniredis server and a client facade over it with an empty script cache.
func newScriptUploadTestClient(t *testing.T) (*miniredis.Miniredis, *redis.Client, Client) {
	t.Helper()

	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	server := miniredis.RunT(t)
	db := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1})

	t.Cleanup(func() { _ = db.Close() })

	ClearScriptCache()
	t.Cleanup(ClearScriptCache)

	return server, db, NewTestClient(db)
}

// captureScriptLogs routes the package logger and a caller logger into one JSON buffer.
func captureScriptLogs(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()

	buffer := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	previous := log.Logger
	log.Logger = logger

	t.Cleanup(func() { log.Logger = previous })

	return logger, buffer
}

// requireNoOperatorAlarm fails when a shutdown-only outcome produced WARN or ERROR records.
func requireNoOperatorAlarm(t *testing.T, buffer *bytes.Buffer) {
	t.Helper()

	output := buffer.String()
	if strings.Contains(output, `"level":"ERROR"`) || strings.Contains(output, `"level":"WARN"`) {
		t.Fatalf("shutdown outcome logged an operator alarm:\n%s", output)
	}
}

func TestUploadAllScriptsThroughClosedClientReportsShutdownWithoutAlarm(t *testing.T) {
	_, db, client := newScriptUploadTestClient(t)
	logger, buffer := captureScriptLogs(t)

	if err := db.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}

	err := UploadAllScripts(t.Context(), logger, client)
	if !errors.Is(err, redis.ErrClosed) {
		t.Fatalf("UploadAllScripts error = %v, want redis.ErrClosed", err)
	}

	if !IsClientShutdownError(err) {
		t.Fatalf("IsClientShutdownError(%v) = false, want true", err)
	}

	requireNoOperatorAlarm(t, buffer)
}

func TestUploadAllScriptsStopsBeforeRedisWhenContextIsCanceled(t *testing.T) {
	server, _, client := newScriptUploadTestClient(t)
	logger, buffer := captureScriptLogs(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	before := server.CommandCount()

	err := UploadAllScripts(ctx, logger, client)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("UploadAllScripts error = %v, want context.Canceled", err)
	}

	if after := server.CommandCount(); after != before {
		t.Fatalf("Redis commands after cancellation = %d, want %d", after, before)
	}

	requireNoOperatorAlarm(t, buffer)
}

func TestUploadAllScriptsStillAlarmsOnRedisOutage(t *testing.T) {
	server, _, client := newScriptUploadTestClient(t)
	logger, buffer := captureScriptLogs(t)

	server.Close()

	err := UploadAllScripts(t.Context(), logger, client)
	if err == nil {
		t.Fatal("UploadAllScripts error = nil, want outage error")
	}

	if IsClientShutdownError(err) {
		t.Fatalf("IsClientShutdownError(%v) = true, want false for an outage", err)
	}

	if !strings.Contains(buffer.String(), `"level":"ERROR"`) {
		t.Fatalf("outage did not log an ERROR record:\n%s", buffer.String())
	}
}

func TestUploadAllScriptsUploadsEveryScript(t *testing.T) {
	_, _, client := newScriptUploadTestClient(t)
	logger, _ := captureScriptLogs(t)

	if err := UploadAllScripts(t.Context(), logger, client); err != nil {
		t.Fatalf("UploadAllScripts: %v", err)
	}

	scriptsMutex.RLock()
	defer scriptsMutex.RUnlock()

	if len(scripts) != len(LuaScripts) {
		t.Fatalf("cached scripts = %d, want %d", len(scripts), len(LuaScripts))
	}
}

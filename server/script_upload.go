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
	"log/slog"
	"sync/atomic"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/rediscli"
)

// scriptUploader uploads the host Lua scripts through one Redis client.
type scriptUploader func(ctx context.Context, logger *slog.Logger, client rediscli.Client) error

// scriptUploadTask owns one background upload of the host Lua scripts.
//
// The owner of the Redis client cancels the task and waits for it before it closes
// or replaces that client, so the upload never runs through a closed client.
type scriptUploadTask struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// startScriptUpload runs upload in the background with a context derived from parent.
//
// Scripts are also uploaded lazily on first use, so a failed upload is logged and
// never stops the process. A stop through cancellation or a closed client is not logged
// as a warning because it belongs to shutdown or client replacement.
func startScriptUpload(parent context.Context, logger *slog.Logger, client rediscli.Client, upload scriptUploader) *scriptUploadTask {
	ctx, cancel := context.WithCancel(parent)
	task := &scriptUploadTask{cancel: cancel, done: make(chan struct{})}

	go func() {
		defer close(task.done)
		defer cancel()

		err := upload(ctx, logger, client)
		if err == nil {
			return
		}

		if rediscli.IsClientShutdownError(err) {
			level.Info(logger).Log(
				definitions.LogKeyMsg, "Stopped the startup upload of Redis Lua scripts; they are uploaded on first use",
				definitions.LogKeyError, err,
			)

			return
		}

		level.Warn(logger).Log(
			definitions.LogKeyMsg, "Failed to upload all Redis Lua scripts at startup; they are uploaded on first use",
			definitions.LogKeyError, err,
		)
	}()

	return task
}

// stop cancels the upload and waits until it returned or waitCtx ended.
// It reports whether the upload goroutine has returned.
func (t *scriptUploadTask) stop(waitCtx context.Context) bool {
	if t == nil {
		return true
	}

	t.cancel()

	select {
	case <-t.done:
		return true
	case <-waitCtx.Done():
		return false
	}
}

// scriptUploadSlot holds the current background script upload of one context store.
type scriptUploadSlot struct {
	current atomic.Pointer[scriptUploadTask]
}

// replace installs task and stops the previous upload, bounded by waitCtx.
func (s *scriptUploadSlot) replace(waitCtx context.Context, logger *slog.Logger, task *scriptUploadTask) {
	stopScriptUploadTask(waitCtx, logger, s.current.Swap(task))
}

// stop removes and stops the current upload, bounded by waitCtx.
func (s *scriptUploadSlot) stop(waitCtx context.Context, logger *slog.Logger) {
	stopScriptUploadTask(waitCtx, logger, s.current.Swap(nil))
}

// stopScriptUploadTask stops one upload and warns when it outlives the wait budget.
func stopScriptUploadTask(waitCtx context.Context, logger *slog.Logger, task *scriptUploadTask) {
	if task == nil || task.stop(waitCtx) {
		return
	}

	level.Warn(logger).Log(
		definitions.LogKeyMsg, "Startup upload of Redis Lua scripts did not stop in time; the Redis client may be closed underneath it",
		definitions.LogKeyError, waitCtx.Err(),
	)
}

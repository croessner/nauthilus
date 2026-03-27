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

package util

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
)

// HTTPRequestContextError returns the current error state of the HTTP request context.
func HTTPRequestContextError(req *http.Request) error {
	if req == nil {
		return nil
	}

	if reqCtx := req.Context(); reqCtx != nil {
		return reqCtx.Err()
	}

	return nil
}

// HTTPRequestDone returns the request cancellation channel if available.
func HTTPRequestDone(req *http.Request) <-chan struct{} {
	if req == nil {
		return nil
	}

	if reqCtx := req.Context(); reqCtx != nil {
		return reqCtx.Done()
	}

	return nil
}

// ContextWithHTTPRequestCancellation derives a context from parent and forwards HTTP request cancellation into it.
func ContextWithHTTPRequestCancellation(parent context.Context, req *http.Request) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	if req == nil {
		return ctx, cancel
	}

	reqCtx := req.Context()
	if reqCtx == nil {
		return ctx, cancel
	}

	if err := reqCtx.Err(); err != nil {
		cancel()

		return ctx, cancel
	}

	stop := context.AfterFunc(reqCtx, cancel)

	return ctx, func() {
		stop()
		cancel()
	}
}

// IsHTTPRequestCanceled reports whether the HTTP request context is canceled and emits an info log when it is.
func IsHTTPRequestCanceled(logger *slog.Logger, req *http.Request, session, phase string) bool {
	err := HTTPRequestContextError(req)
	if err == nil {
		return false
	}

	parts := []any{
		definitions.LogKeyMsg, "HTTP request context canceled; client probably disconnected",
		"phase", phase,
		definitions.LogKeyError, err,
	}

	if session != "" {
		parts = append(parts, definitions.LogKeyGUID, session)
	}

	if req != nil {
		parts = append(parts, "method", req.Method)

		if req.URL != nil {
			parts = append(parts, "path", req.URL.Path)
		}
	}

	_ = level.Info(logger).Log(parts...)

	return true
}

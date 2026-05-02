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

package lualib

import (
	"context"
	"errors"
)

const (
	// RuntimeCancellationSourceNone means no inspected context has been canceled.
	RuntimeCancellationSourceNone = "none"

	// RuntimeCancellationSourceRequest means the parent request context was canceled.
	RuntimeCancellationSourceRequest = "request_context"

	// RuntimeCancellationSourceParallelGroup means a parallel Lua execution group canceled sibling work.
	RuntimeCancellationSourceParallelGroup = "parallel_group"

	// RuntimeCancellationSourceLuaTimeout means the per-script Lua runtime deadline expired.
	RuntimeCancellationSourceLuaTimeout = "lua_timeout"

	// RuntimeCancellationSourceLuaContext means the Lua runtime context was canceled without a deadline expiry.
	RuntimeCancellationSourceLuaContext = "lua_context"
)

// RuntimeCancellationDiagnostics describes the cancellation state around one Lua script failure.
type RuntimeCancellationDiagnostics struct {
	Source     string
	RuntimeErr string
	GroupErr   string
	RequestErr string
}

// NewRuntimeCancellationDiagnostics inspects related contexts and returns a stable cancellation source.
func NewRuntimeCancellationDiagnostics(runtimeCtx context.Context, groupCtx context.Context, requestCtx context.Context) RuntimeCancellationDiagnostics {
	diagnostics := RuntimeCancellationDiagnostics{
		Source:     RuntimeCancellationSourceNone,
		RuntimeErr: contextErrorName(runtimeCtx),
		GroupErr:   contextErrorName(groupCtx),
		RequestErr: contextErrorName(requestCtx),
	}

	switch {
	case diagnostics.RequestErr != "":
		diagnostics.Source = RuntimeCancellationSourceRequest
	case diagnostics.GroupErr != "":
		diagnostics.Source = RuntimeCancellationSourceParallelGroup
	case errors.Is(contextError(runtimeCtx), context.DeadlineExceeded):
		diagnostics.Source = RuntimeCancellationSourceLuaTimeout
	case diagnostics.RuntimeErr != "":
		diagnostics.Source = RuntimeCancellationSourceLuaContext
	}

	return diagnostics
}

// LogValues returns structured slog key-value pairs for cancellation diagnostics.
func (d RuntimeCancellationDiagnostics) LogValues() []any {
	return []any{
		"cancel_source", d.Source,
		"lua_context_error", d.RuntimeErr,
		"parallel_group_error", d.GroupErr,
		"request_context_error", d.RequestErr,
	}
}

func contextErrorName(ctx context.Context) string {
	err := contextError(ctx)
	if err == nil {
		return ""
	}

	if errors.Is(err, context.Canceled) {
		return context.Canceled.Error()
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded.Error()
	}

	return err.Error()
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}

	return ctx.Err()
}

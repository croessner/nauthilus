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

	"github.com/croessner/nauthilus/v4/server/conncause"
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
		RuntimeErr: conncause.ContextErrorName(runtimeCtx),
		GroupErr:   conncause.ContextErrorName(groupCtx),
		RequestErr: conncause.ContextErrorName(requestCtx),
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
		conncause.LogKeyCancelSource, d.Source,
		"lua_context_error", d.RuntimeErr,
		"parallel_group_error", d.GroupErr,
		conncause.LogKeyRequestContextError, d.RequestErr,
	}
}

// contextError returns ctx.Err() and tolerates a nil context.
func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}

	return ctx.Err()
}

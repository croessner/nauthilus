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

package conncause

import (
	"context"
	"errors"
	"net/http"
)

const (
	// CancelSourceRequest means the own request context of the failing request has ended.
	CancelSourceRequest = "request"

	// CancelSourceForeign means the error carries a cancellation or deadline although the own request context is
	// still active: the cancellation came from work shared with another request or from an internal deadline.
	CancelSourceForeign = "foreign"

	// LogKeyCancelSource is the log field for the derived cancellation source.
	LogKeyCancelSource = "cancel_source"

	// LogKeyRequestContextError is the log field for the error of the own request context.
	LogKeyRequestContextError = "request_context_error"

	// LogKeyRequestContextCause is the log field for the cause of the own request context.
	LogKeyRequestContextCause = "request_context_cause"
)

// requestContextKey anchors the transport request context inside every context derived from it.
type requestContextKey struct{}

// CancelDiagnostics describes the state of the own request context around one failure.
type CancelDiagnostics struct {
	// RequestErr is the normalized ctx.Err() of the own request context, or empty while it is active.
	RequestErr string

	// RequestCause is the context.Cause of the own request context, or empty while it is active.
	RequestCause string

	// Source is CancelSourceRequest, CancelSourceForeign, or empty when no cancellation is involved.
	Source string
}

// DiagnoseCancel classifies err against the own request context. Pass the request context itself, not a context
// derived for internal work, because derived contexts may be canceled by internal code. A nil request context
// yields empty diagnostics.
func DiagnoseCancel(requestCtx context.Context, err error) CancelDiagnostics {
	if requestCtx == nil {
		return CancelDiagnostics{}
	}

	diagnostics := CancelDiagnostics{
		RequestErr:   ContextErrorName(requestCtx),
		RequestCause: contextCauseText(requestCtx),
	}

	switch {
	case diagnostics.RequestErr != "":
		diagnostics.Source = CancelSourceRequest
	case isCancellation(err):
		diagnostics.Source = CancelSourceForeign
	}

	return diagnostics
}

// DiagnoseCallCancel classifies err for work that runs under callCtx against the request context anchored by
// WithRequestContext. It reports false when callCtx has no anchor or when callCtx is detached from the anchored
// request: an ended request with a still active callCtx means the work outlives the request, so attributing its
// failure to the request would mislead.
func DiagnoseCallCancel(callCtx context.Context, err error) (CancelDiagnostics, bool) {
	requestCtx, ok := RequestContext(callCtx)
	if !ok {
		return CancelDiagnostics{}, false
	}

	if requestCtx.Err() != nil && callCtx.Err() == nil {
		return CancelDiagnostics{}, false
	}

	return DiagnoseCancel(requestCtx, err), true
}

// LogValues returns the structured log fields for the diagnostics. The field names match the Lua cancel
// diagnostics so operators can correlate both.
func (d CancelDiagnostics) LogValues() []any {
	return []any{
		LogKeyCancelSource, d.Source,
		LogKeyRequestContextError, d.RequestErr,
		LogKeyRequestContextCause, d.RequestCause,
	}
}

// WithRequestContext anchors ctx as the request context of one transport request, so code that only receives a
// derived context can still inspect the request. An existing anchor is kept, because the outermost transport
// context is the request context.
func WithRequestContext(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}

	if _, ok := RequestContext(ctx); ok {
		return ctx
	}

	return context.WithValue(ctx, requestContextKey{}, ctx)
}

// DetachRequestContext returns a context that keeps the values of ctx but neither its cancellation nor its request
// anchor. Work that outlives the request must use it, so its failures are not attributed to the ended request.
func DetachRequestContext(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}

	return context.WithValue(context.WithoutCancel(ctx), requestContextKey{}, nil)
}

// RequestContext returns the request context anchored by WithRequestContext.
func RequestContext(ctx context.Context) (context.Context, bool) {
	if ctx == nil {
		return nil, false
	}

	requestCtx, ok := ctx.Value(requestContextKey{}).(context.Context)

	return requestCtx, ok && requestCtx != nil
}

// OwnRequestContext returns the request context anchored in ctx, or ctx itself when no anchor exists. Use it where
// only a context derived from the request is at hand.
func OwnRequestContext(ctx context.Context) context.Context {
	if requestCtx, ok := RequestContext(ctx); ok {
		return requestCtx
	}

	return ctx
}

// RequestHandler anchors the context of every HTTP request served by next.
func RequestHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		next.ServeHTTP(writer, request.WithContext(WithRequestContext(request.Context())))
	})
}

// ContextErrorName returns a stable name for ctx.Err(), or an empty string while ctx is active or nil.
func ContextErrorName(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	err := ctx.Err()

	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return context.Canceled.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded.Error()
	default:
		return err.Error()
	}
}

// contextCauseText returns the text of context.Cause for an ended ctx, or an empty string while it is active.
func contextCauseText(ctx context.Context) string {
	if ctx.Err() == nil {
		return ""
	}

	cause := context.Cause(ctx)
	if cause == nil {
		return ""
	}

	return cause.Error()
}

// isCancellation reports whether err carries a context cancellation or an expired deadline.
func isCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

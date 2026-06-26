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

package pluginapi

import (
	"context"
	"time"
)

// HookScope describes the host authorization surface for a hook.
type HookScope string

const (
	// HookScopePublic marks a hook as public.
	HookScopePublic HookScope = "public"

	// HookScopeInternal marks a hook as internal.
	HookScopeInternal HookScope = "internal"

	// HookScopeAdmin marks a hook as administrative.
	HookScopeAdmin HookScope = "admin"
)

// HookAuth describes authentication required before a hook is called.
type HookAuth string

const (
	// HookAuthNone requires no hook-specific authentication.
	HookAuthNone HookAuth = "none"

	// HookAuthToken requires a configured token.
	HookAuthToken HookAuth = "token"

	// HookAuthSession requires an authenticated session.
	HookAuthSession HookAuth = "session"

	// HookAuthAdmin requires administrative authorization regardless of the declared hook scope.
	HookAuthAdmin HookAuth = "admin"
)

// HookDescriptor describes an HTTP-facing plugin hook.
type HookDescriptor struct {
	Timeout      time.Duration
	Name         string
	Method       string
	Path         string
	Alias        string
	Scope        HookScope
	Auth         HookAuth
	MaxBodyBytes int64
}

// HookRequest is the API-level request value passed to hook plugins.
// Headers and query values are host-built copies; secret-bearing headers are redacted before invocation.
type HookRequest struct {
	Snapshot RequestSnapshot
	Headers  map[string][]string
	Query    map[string][]string
	Body     []byte
	Path     string
	Method   string
}

// HookResponse is the API-level response value returned by hook plugins.
// Use standard net/http status constants for StatusCode; the host filters unsafe headers and keeps HEAD bodies empty.
type HookResponse struct {
	Headers    map[string][]string
	Body       []byte
	StatusCode int
}

// Hook handles one HTTP-facing plugin endpoint.
type Hook interface {
	Descriptor() HookDescriptor
	Serve(context.Context, HookRequest) (HookResponse, error)
}

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
	"net/http"
)

// HTTPRequestContextScope owns one temporary context replacement on an HTTP request pointer.
type HTTPRequestContextScope struct {
	target   **http.Request
	previous *http.Request
	active   bool
}

// NewHTTPRequestContextScope installs requestContext on target until Restore is called.
func NewHTTPRequestContextScope(requestContext context.Context, target **http.Request) *HTTPRequestContextScope {
	scope := &HTTPRequestContextScope{target: target}
	if target == nil || *target == nil || requestContext == nil {
		return scope
	}

	scope.previous = *target
	scope.active = true
	*target = (*target).WithContext(requestContext)

	return scope
}

// Restore reinstates the request pointer that was active before the scope began.
func (s *HTTPRequestContextScope) Restore() {
	if s == nil || !s.active || s.target == nil {
		return
	}

	*s.target = s.previous
	s.active = false
	s.target = nil
	s.previous = nil
}

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

package core

import (
	"context"

	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
)

// requestContextScope owns temporary request-context replacements for one child operation.
type requestContextScope struct {
	authRequest *util.HTTPRequestContextScope
	ginRequest  *util.HTTPRequestContextScope
}

// scopeRequestContext installs requestContext for child work on both request holders.
func (a *AuthState) scopeRequestContext(requestContext context.Context, ctx *gin.Context) *requestContextScope {
	scope := &requestContextScope{}

	if ctx != nil {
		scope.ginRequest = util.NewHTTPRequestContextScope(requestContext, &ctx.Request)
	}

	if a != nil {
		scope.authRequest = util.NewHTTPRequestContextScope(requestContext, &a.Request.HTTPClientRequest)
	}

	return scope
}

// Restore reinstates the request objects that were active before the scope began.
func (s *requestContextScope) Restore() {
	if s == nil {
		return
	}

	if s.ginRequest != nil {
		s.ginRequest.Restore()
	}

	if s.authRequest != nil {
		s.authRequest.Restore()
	}
}

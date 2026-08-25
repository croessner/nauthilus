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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequestResourcePrefersRegisteredGinFullPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	resource := ""

	router.GET("/auth/:account", func(ctx *gin.Context) {
		resource = RequestResource(ctx, ctx.Request, "fallback")
		ctx.Status(http.StatusNoContent)
	})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/alice", nil)
	router.ServeHTTP(response, request)

	if resource != "/auth/:account" {
		t.Fatalf("expected registered route, got %q", resource)
	}
}

func TestRequestResourceFallsBackWhenGinFullPathIsEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)

	response := httptest.NewRecorder()
	ctx := gin.CreateTestContextOnly(response, gin.New())
	request := httptest.NewRequest(http.MethodPost, "/grpc/auth/v1/Authenticate?cache=0", nil)
	ctx.Request = request

	if resource := RequestResource(ctx, request, "fallback"); resource != "/grpc/auth/v1/Authenticate" {
		t.Fatalf("expected request URL path, got %q", resource)
	}
}

func TestRequestResourceUsesStableFallbackWithoutRequestPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	response := httptest.NewRecorder()
	ctx := gin.CreateTestContextOnly(response, gin.New())

	tests := []struct {
		name     string
		ctx      *gin.Context
		request  *http.Request
		fallback string
		want     string
	}{
		{
			name:     "context request",
			ctx:      contextWithRequest("/from/context"),
			fallback: "fallback",
			want:     "/from/context",
		},
		{
			name:     "explicit fallback",
			ctx:      ctx,
			fallback: "fallback",
			want:     "fallback",
		},
		{
			name: "default fallback",
			want: "unknown_resource",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if resource := RequestResource(test.ctx, test.request, test.fallback); resource != test.want {
				t.Fatalf("expected %q, got %q", test.want, resource)
			}
		})
	}
}

// contextWithRequest constructs an isolated Gin context carrying the requested URL.
func contextWithRequest(path string) *gin.Context {
	ctx := gin.CreateTestContextOnly(httptest.NewRecorder(), gin.New())
	ctx.Request = httptest.NewRequest(http.MethodGet, path, nil)

	return ctx
}

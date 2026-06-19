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

package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRegisterManagementOpenAPI_ServesSpecDocuments(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	group := router.Group("/api/v1")
	RegisterManagementOpenAPI(group)

	assertOpenAPIDocument(t, router, "/api/v1/openapi.yaml", "application/yaml; charset=utf-8", "openapi: 3.1.0")
	assertOpenAPIDocument(t, router, "/api/v1/openapi.json", "application/json; charset=utf-8", `"openapi": "3.1.0"`)
}

func TestWithIDPOpenAPI_ServesPublicSpecDocuments(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := NewRouter(nil).WithIDPOpenAPI().Build()

	assertOpenAPIDocument(t, router, "/.well-known/openapi.yaml", "application/yaml; charset=utf-8", "Nauthilus IDP API")
	assertOpenAPIDocument(t, router, "/.well-known/openapi.json", "application/json; charset=utf-8", `"title": "Nauthilus IDP API"`)
}

func assertOpenAPIDocument(t *testing.T, router http.Handler, path string, contentType string, bodySubstring string) {
	t.Helper()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want %d", path, recorder.Code, http.StatusOK)
	}

	if got := recorder.Header().Get("Content-Type"); got != contentType {
		t.Fatalf("GET %s Content-Type = %q, want %q", path, got, contentType)
	}

	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("GET %s X-Content-Type-Options = %q, want nosniff", path, got)
	}

	if !strings.Contains(recorder.Body.String(), bodySubstring) {
		t.Fatalf("GET %s body = %q, want substring %q", path, recorder.Body.String(), bodySubstring)
	}
}

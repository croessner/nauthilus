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

package auth

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHandlerRegistersCBORAuthEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	api := router.Group("/api/v1")

	New(nil).Register(api)

	routes := registeredRoutes(router)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		key := method + " /api/v1/auth/cbor"
		if !routes[key] {
			t.Fatalf("expected %s route to be registered", key)
		}
	}
}

func registeredRoutes(router *gin.Engine) map[string]bool {
	routes := make(map[string]bool)

	for _, route := range router.Routes() {
		routes[route.Method+" "+route.Path] = true
	}

	return routes
}

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

	"github.com/croessner/nauthilus/server/openapi"
	"github.com/gin-gonic/gin"
)

const (
	idPOpenAPIYAMLPath        = "/.well-known/openapi.yaml"
	idPOpenAPIJSONPath        = "/.well-known/openapi.json"
	managementOpenAPIYAMLPath = "/openapi.yaml"
	managementOpenAPIJSONPath = "/openapi.json"
)

// RegisterManagementOpenAPI registers the protected management API contract on
// the caller-provided group. The caller owns authentication middleware.
func RegisterManagementOpenAPI(router gin.IRouter) {
	router.GET(managementOpenAPIYAMLPath, serveOpenAPI("application/yaml; charset=utf-8", openapi.ManagementYAML))
	router.GET(managementOpenAPIJSONPath, serveOpenAPI("application/json; charset=utf-8", openapi.ManagementJSON))
}

// WithIDPOpenAPI registers the public IdP API contract.
func (r *Router) WithIDPOpenAPI() *Router {
	r.Engine.GET(idPOpenAPIYAMLPath, serveOpenAPI("application/yaml; charset=utf-8", openapi.IDPYAML))
	r.Engine.GET(idPOpenAPIJSONPath, serveOpenAPI("application/json; charset=utf-8", openapi.IDPJSON))

	return r
}

func serveOpenAPI(contentType string, body func() []byte) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Header("X-Content-Type-Options", "nosniff")
		ctx.Data(http.StatusOK, contentType, body())
	}
}

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

package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/openapi/requesttest"
	"github.com/gin-gonic/gin"
)

const (
	openAPIContractJSONMedia = "application/json"
	openAPIContractYAMLMedia = "application/yaml"
	openAPIContractNoSniff   = "nosniff"
)

type openAPIResponseContractCase struct {
	validator     *requesttest.Validator
	router        http.Handler
	name          string
	path          string
	expectedMedia string
	excludeBody   bool
}

func TestOpenAPIDocumentResponsesMatchOpenAPIContract(t *testing.T) {
	gin.SetMode(gin.TestMode)

	managementRouter := gin.New()
	RegisterManagementOpenAPI(managementRouter.Group("/api/v1"))

	idpRouter := NewRouter(nil).WithIDPOpenAPI().Build()

	for _, tt := range openAPIResponseContractCases(t, managementRouter, idpRouter) {
		t.Run(tt.name, func(t *testing.T) {
			runOpenAPIResponseContractCase(t, tt)
		})
	}
}

func openAPIResponseContractCases(t *testing.T, managementRouter http.Handler, idpRouter http.Handler) []openAPIResponseContractCase {
	t.Helper()

	return []openAPIResponseContractCase{
		{
			name:          "management yaml",
			router:        managementRouter,
			validator:     requesttest.NewManagementValidator(t),
			path:          "/api/v1/openapi.yaml",
			expectedMedia: openAPIContractYAMLMedia,
			excludeBody:   true,
		},
		{
			name:          "management json",
			router:        managementRouter,
			validator:     requesttest.NewManagementValidator(t),
			path:          "/api/v1/openapi.json",
			expectedMedia: openAPIContractJSONMedia,
		},
		{
			name:          "idp yaml",
			router:        idpRouter,
			validator:     requesttest.NewIDPValidator(t),
			path:          "/.well-known/openapi.yaml",
			expectedMedia: openAPIContractYAMLMedia,
			excludeBody:   true,
		},
		{
			name:          "idp json",
			router:        idpRouter,
			validator:     requesttest.NewIDPValidator(t),
			path:          "/.well-known/openapi.json",
			expectedMedia: openAPIContractJSONMedia,
		},
	}
}

func runOpenAPIResponseContractCase(t *testing.T, tt openAPIResponseContractCase) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, tt.path, nil)
	recorder := httptest.NewRecorder()

	tt.router.ServeHTTP(recorder, request)

	requesttest.AssertRecorderResponse(t, tt.validator, request, recorder, requesttest.ResponseValidation{
		ExpectedMediaType: tt.expectedMedia,
		RequiredHeaderValues: map[string]string{
			"X-Content-Type-Options": openAPIContractNoSniff,
		},
		ExcludeBody: tt.excludeBody,
	})
}

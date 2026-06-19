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

package cache

import (
	"net/http"
	"testing"

	"github.com/croessner/nauthilus/v3/server/openapi/requesttest"
)

const cacheContractSecret = "synthetic-cache-secret"

func TestCacheRequestsMatchOpenAPIContract(t *testing.T) {
	validator := requesttest.NewManagementValidator(t)

	requesttest.AssertCases(t, validator, []requesttest.Case{
		{
			Name:      "sync cache flush accepts user body",
			Request:   requesttest.NewJSONRequest(http.MethodDelete, "/api/v1/cache/flush", `{"user":"alice@example.test"}`),
			WantValid: true,
		},
		{
			Name:      "async cache flush accepts user body",
			Request:   requesttest.NewJSONRequest(http.MethodDelete, "/api/v1/cache/flush/async", `{"user":"alice@example.test"}`),
			WantValid: true,
		},
		{
			Name: "cache flush rejects missing user",
			Request: requesttest.NewJSONRequest(
				http.MethodDelete,
				"/api/v1/cache/flush",
				`{"password":"`+cacheContractSecret+`"}`,
			),
			WantErrorContains:        "user",
			ForbiddenErrorSubstrings: []string{cacheContractSecret},
		},
		{
			Name: "cache flush rejects unknown fields",
			Request: requesttest.NewJSONRequest(
				http.MethodDelete,
				"/api/v1/cache/flush/async",
				`{"user":"alice@example.test","client_secret":"`+cacheContractSecret+`"}`,
			),
			WantErrorContains:        "client_secret",
			ForbiddenErrorSubstrings: []string{cacheContractSecret},
		},
	})
}

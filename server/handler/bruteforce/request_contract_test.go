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

package bruteforce

import (
	"net/http"
	"testing"

	"github.com/croessner/nauthilus/server/openapi/requesttest"
)

const bruteForceContractToken = "synthetic-bruteforce-token"

func TestBruteForceRequestsMatchOpenAPIContract(t *testing.T) {
	validator := requesttest.NewManagementValidator(t)

	requesttest.AssertCases(t, validator, []requesttest.Case{
		{
			Name:      "list accepts query-free get request",
			Request:   requesttest.NewRequest(http.MethodGet, "/api/v1/bruteforce/list", "", ""),
			WantValid: true,
		},
		{
			Name:      "filtered list accepts account and IP arrays",
			Request:   requesttest.NewJSONRequest(http.MethodPost, "/api/v1/bruteforce/list", `{"accounts":["alice@example.test"],"ip_addresses":["203.0.113.10"]}`),
			WantValid: true,
		},
		{
			Name:      "sync flush accepts rule body",
			Request:   requesttest.NewJSONRequest(http.MethodDelete, "/api/v1/bruteforce/flush", validBruteForceFlushContractBody()),
			WantValid: true,
		},
		{
			Name:      "async flush accepts rule body",
			Request:   requesttest.NewJSONRequest(http.MethodDelete, "/api/v1/bruteforce/flush/async", validBruteForceFlushContractBody()),
			WantValid: true,
		},
		{
			Name: "filtered list rejects unknown fields",
			Request: requesttest.NewJSONRequest(
				http.MethodPost,
				"/api/v1/bruteforce/list",
				`{"accounts":["alice@example.test"],"access_token":"`+bruteForceContractToken+`"}`,
			),
			WantErrorContains:        "access_token",
			ForbiddenErrorSubstrings: []string{bruteForceContractToken},
		},
		{
			Name: "flush rejects missing rule name",
			Request: requesttest.NewJSONRequest(
				http.MethodDelete,
				"/api/v1/bruteforce/flush",
				`{"ip_address":"203.0.113.10","refresh_token":"`+bruteForceContractToken+`"}`,
			),
			WantErrorContains:        "rule_name",
			ForbiddenErrorSubstrings: []string{bruteForceContractToken},
		},
	})
}

func validBruteForceFlushContractBody() string {
	return `{"ip_address":"203.0.113.10","rule_name":"rule-a","protocol":"imap","oidc_cid":"synthetic-client"}`
}

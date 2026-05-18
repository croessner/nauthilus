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

package auth

import (
	"net/http"
	"testing"

	"github.com/croessner/nauthilus/server/openapi/requesttest"
)

const (
	authContractClientIP           = "203.0.113.10"
	authContractHeaderClientIP     = "Client-IP"
	authContractHeaderLoginAttempt = "Auth-Login-Attempt"
	authContractHeaderMethod       = "Auth-Method"
	authContractHeaderPassword     = "Auth-Pass"
	authContractHeaderProtocol     = "Auth-Protocol"
	authContractHeaderUsername     = "Auth-User"
	authContractHeaderSecret       = "synthetic-header-password"
	authContractJSONSecret         = "synthetic-json-password"
	authContractUsername           = "alice@example.test"
)

func TestJSONAuthRequestsMatchOpenAPIContract(t *testing.T) {
	validator := requesttest.NewManagementValidator(t)

	requesttest.AssertCases(t, validator, []requesttest.Case{
		{
			Name:      "json auth accepts strict body",
			Request:   requesttest.NewJSONRequest(http.MethodPost, "/api/v1/auth/json?cache=0&in-memory=0", validJSONAuthContractBody()),
			WantValid: true,
		},
		{
			Name: "json auth rejects unknown field",
			Request: requesttest.NewJSONRequest(
				http.MethodPost,
				"/api/v1/auth/json",
				`{"username":"alice@example.test","password":"`+authContractJSONSecret+`","service":"imap"}`,
			),
			WantErrorContains:        "service",
			ForbiddenErrorSubstrings: []string{authContractJSONSecret},
		},
		{
			Name: "json auth rejects unsupported query enum",
			Request: requesttest.NewJSONRequest(
				http.MethodPost,
				"/api/v1/auth/json?cache=1",
				validJSONAuthContractBody(),
			),
			WantErrorContains:        "cache",
			ForbiddenErrorSubstrings: []string{authContractJSONSecret},
		},
	})
}

func TestHeaderAuthRequestsMatchOpenAPIContract(t *testing.T) {
	validator := requesttest.NewManagementValidator(t)

	requesttest.AssertCases(t, validator, []requesttest.Case{
		{
			Name:      "header auth accepts header-heavy request",
			Request:   requesttest.WithHeaders(requesttest.NewRequest(http.MethodGet, "/api/v1/auth/header?cache=0", "", ""), validHeaderAuthContractHeaders()),
			WantValid: true,
		},
		{
			Name: "header auth rejects invalid protocol header",
			Request: requesttest.WithHeaders(
				requesttest.NewRequest(http.MethodGet, "/api/v1/auth/header", "", ""),
				headerAuthContractHeadersWith(authContractHeaderProtocol, "nntp"),
			),
			WantErrorContains:        authContractHeaderProtocol,
			ForbiddenErrorSubstrings: []string{authContractHeaderSecret},
		},
		{
			Name: "header auth rejects unexpected body",
			Request: requesttest.WithHeaders(
				requesttest.NewJSONRequest(http.MethodPost, "/api/v1/auth/header", `{"username":"alice@example.test"}`),
				validHeaderAuthContractHeaders(),
			),
			WantErrorContains:        "request body not allowed",
			ForbiddenErrorSubstrings: []string{authContractHeaderSecret},
		},
	})
}

func TestNginxAuthRequestsMatchOpenAPIContract(t *testing.T) {
	validator := requesttest.NewManagementValidator(t)

	requesttest.AssertCases(t, validator, []requesttest.Case{
		{
			Name:      "nginx auth accepts header-heavy request",
			Request:   requesttest.WithHeaders(requesttest.NewRequest(http.MethodPost, "/api/v1/auth/nginx?in-memory=0", "", ""), validHeaderAuthContractHeaders()),
			WantValid: true,
		},
		{
			Name: "nginx auth rejects negative login attempt",
			Request: requesttest.WithHeaders(
				requesttest.NewRequest(http.MethodGet, "/api/v1/auth/nginx", "", ""),
				headerAuthContractHeadersWith(authContractHeaderLoginAttempt, "-1"),
			),
			WantErrorContains:        authContractHeaderLoginAttempt,
			ForbiddenErrorSubstrings: []string{authContractHeaderSecret},
		},
	})
}

func validJSONAuthContractBody() string {
	return `{"username":"` + authContractUsername + `","password":"` + authContractJSONSecret + `","client_ip":"` + authContractClientIP + `","client_port":"12345","protocol":"imap","method":"plain","auth_login_attempt":1}`
}

func validHeaderAuthContractHeaders() map[string]string {
	return map[string]string{
		authContractHeaderUsername:     authContractUsername,
		authContractHeaderPassword:     authContractHeaderSecret,
		authContractHeaderProtocol:     "imap",
		authContractHeaderMethod:       "PLAIN",
		authContractHeaderLoginAttempt: "1",
		authContractHeaderClientIP:     authContractClientIP,
		"X-Client-Port":                "12345",
	}
}

func headerAuthContractHeadersWith(name string, value string) map[string]string {
	headers := validHeaderAuthContractHeaders()
	headers[name] = value

	return headers
}

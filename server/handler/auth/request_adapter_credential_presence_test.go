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
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/encoding/cborcodec"

	"github.com/gin-gonic/gin"
)

const (
	credentialPresenceSecret   = "synthetic-presence-password"
	credentialPresenceUsername = "alice@example.test"
	credentialPresenceJSON     = "application/json"
	credentialPresenceForm     = "application/x-www-form-urlencoded"
	credentialPresenceCBOR     = "application/cbor"
)

// credentialPresenceCase describes one HTTP auth request and the expected adapter verdict.
type credentialPresenceCase struct {
	headers      map[string]string
	name         string
	service      string
	method       string
	body         string
	contentType  string
	wantField    string
	wantUsername string
	wantOK       bool
	wantPassword bool
}

// TestHTTPAuthInputBuilderTreatsEmptyCredentialValuesAsAuthInput pins that empty username or password values reach
// the auth pipeline as an ordinary failed login, while missing credential keys stay a 400 Bad Request.
func TestHTTPAuthInputBuilderTreatsEmptyCredentialValuesAsAuthInput(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := append(structuredCredentialPresenceCases(t), formAndHeaderCredentialPresenceCases()...)
	cases = append(cases, basicCredentialPresenceCases()...)

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			assertCredentialPresenceCase(t, test)
		})
	}
}

// assertCredentialPresenceCase runs one case through the production HTTP auth input builder.
func assertCredentialPresenceCase(t *testing.T, test credentialPresenceCase) {
	t.Helper()

	method := test.method
	if method == "" {
		method = http.MethodPost
	}

	builder := newHTTPAuthInputBuilder(applicationBoundaryDeps())
	ctx, recorder := newHTTPAuthAdapterTestContext(method, "/api/v1/auth/"+test.service, test.body, test.contentType, test.service)

	for name, value := range test.headers {
		ctx.Request.Header[name] = []string{value}
	}

	input, ok := builder.Build(ctx)
	if ok != test.wantOK {
		t.Fatalf("Build() ok = %v, want %v (status %d, body %q)", ok, test.wantOK, recorder.Code, recorder.Body.String())
	}

	if !test.wantOK {
		assertCredentialPresenceRejection(t, test, ctx.Writer.Status(), recorder.Body.String())

		return
	}

	if input.Credentials.Username != test.wantUsername {
		t.Fatalf("username = %q, want %q", input.Credentials.Username, test.wantUsername)
	}

	if input.Credentials.Password.IsZero() == test.wantPassword {
		t.Fatalf("password present = %v, want %v", !input.Credentials.Password.IsZero(), test.wantPassword)
	}
}

// assertCredentialPresenceRejection checks the 400 status and, for structured bodies, the named missing field.
func assertCredentialPresenceRejection(t *testing.T, test credentialPresenceCase, status int, body string) {
	t.Helper()

	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", status, http.StatusBadRequest)
	}

	if strings.Contains(body, credentialPresenceSecret) {
		t.Fatalf("rejection body leaked the password: %q", body)
	}

	if test.wantField != "" && !strings.Contains(body, `"field":"`+test.wantField+`"`) {
		t.Fatalf("rejection body = %q, want field %q", body, test.wantField)
	}
}

// structuredCredentialPresenceCases covers JSON and CBOR bodies.
func structuredCredentialPresenceCases(t *testing.T) []credentialPresenceCase {
	t.Helper()

	return []credentialPresenceCase{
		{name: "json empty username", service: definitions.ServJSON, contentType: credentialPresenceJSON,
			body: `{"username":"","password":"` + credentialPresenceSecret + `"}`, wantOK: true, wantPassword: true},
		{name: "json empty password", service: definitions.ServJSON, contentType: credentialPresenceJSON,
			body: `{"username":"` + credentialPresenceUsername + `","password":""}`, wantOK: true,
			wantUsername: credentialPresenceUsername},
		{name: "json empty username and password", service: definitions.ServJSON, contentType: credentialPresenceJSON,
			body: `{"username":"","password":""}`, wantOK: true},
		{name: "json missing username", service: definitions.ServJSON, contentType: credentialPresenceJSON,
			body: `{"password":"` + credentialPresenceSecret + `"}`, wantField: "Username"},
		{name: "json null username", service: definitions.ServJSON, contentType: credentialPresenceJSON,
			body: `{"username":null,"password":"` + credentialPresenceSecret + `"}`, wantField: "Username"},
		{name: "json missing password", service: definitions.ServJSON, contentType: credentialPresenceJSON,
			body: `{"username":"` + credentialPresenceUsername + `"}`, wantField: "Password"},
		{name: "json null password", service: definitions.ServJSON, contentType: credentialPresenceJSON,
			body: `{"username":"` + credentialPresenceUsername + `","password":null}`, wantField: "Password"},
		{name: "json unknown field stays rejected", service: definitions.ServJSON, contentType: credentialPresenceJSON,
			body: `{"username":"","password":"","unexpected":"value"}`},
		{name: "json invalid non-empty username stays rejected", service: definitions.ServJSON,
			contentType: credentialPresenceJSON, body: `{"username":"bad user","password":"` + credentialPresenceSecret + `"}`},
		{name: "cbor empty username", service: definitions.ServCBOR, contentType: credentialPresenceCBOR,
			body:   credentialPresenceCBORBody(t, map[string]string{"username": "", "password": credentialPresenceSecret}),
			wantOK: true, wantPassword: true},
		{name: "cbor empty password", service: definitions.ServCBOR, contentType: credentialPresenceCBOR,
			body:   credentialPresenceCBORBody(t, map[string]string{"username": credentialPresenceUsername, "password": ""}),
			wantOK: true, wantUsername: credentialPresenceUsername},
		{name: "cbor missing username", service: definitions.ServCBOR, contentType: credentialPresenceCBOR,
			body: credentialPresenceCBORBody(t, map[string]string{"password": credentialPresenceSecret}), wantField: "Username"},
		{name: "cbor missing password", service: definitions.ServCBOR, contentType: credentialPresenceCBOR,
			body: credentialPresenceCBORBody(t, map[string]string{"username": credentialPresenceUsername}), wantField: "Password"},
		{name: "json GET without body has no credential keys", service: definitions.ServJSON, method: http.MethodGet},
	}
}

// formAndHeaderCredentialPresenceCases covers urlencoded bodies and the configured header transports.
func formAndHeaderCredentialPresenceCases() []credentialPresenceCase {
	return []credentialPresenceCase{
		{name: "form empty username", service: definitions.ServJSON, contentType: credentialPresenceForm,
			body: "username=&password=" + credentialPresenceSecret, wantOK: true, wantPassword: true},
		{name: "form empty username with realm stays empty", service: definitions.ServJSON,
			contentType: credentialPresenceForm, body: "username=&realm=example.test&password=" + credentialPresenceSecret,
			wantOK: true, wantPassword: true},
		{name: "form empty password", service: definitions.ServJSON, contentType: credentialPresenceForm,
			body: "username=" + credentialPresenceUsername + "&password=", wantOK: true, wantUsername: credentialPresenceUsername},
		{name: "form missing username", service: definitions.ServJSON, contentType: credentialPresenceForm,
			body: "password=" + credentialPresenceSecret},
		{name: "form missing password", service: definitions.ServJSON, contentType: credentialPresenceForm,
			body: "username=" + credentialPresenceUsername},
		{name: "header empty username", service: definitions.ServHeader, method: http.MethodGet,
			headers: map[string]string{"Auth-User": "", "Auth-Pass": credentialPresenceSecret}, wantOK: true, wantPassword: true},
		{name: "header empty password", service: definitions.ServHeader, method: http.MethodGet,
			headers: map[string]string{"Auth-User": credentialPresenceUsername, "Auth-Pass": ""}, wantOK: true,
			wantUsername: credentialPresenceUsername},
		{name: "nginx empty username and password", service: definitions.ServNginx, method: http.MethodGet,
			headers: map[string]string{"Auth-User": "", "Auth-Pass": ""}, wantOK: true},
		{name: "header missing username", service: definitions.ServHeader, method: http.MethodGet,
			headers: map[string]string{"Auth-Pass": credentialPresenceSecret}},
		{name: "nginx missing password", service: definitions.ServNginx, method: http.MethodGet,
			headers: map[string]string{"Auth-User": credentialPresenceUsername}},
	}
}

// basicCredentialPresenceCases covers HTTP Basic, whose separator carries both credential keys.
func basicCredentialPresenceCases() []credentialPresenceCase {
	return []credentialPresenceCase{
		{name: "basic empty username", service: definitions.ServBasic, method: http.MethodGet,
			headers: credentialPresenceBasicHeader(":" + credentialPresenceSecret), wantOK: true, wantPassword: true},
		{name: "basic empty password", service: definitions.ServBasic, method: http.MethodGet,
			headers: credentialPresenceBasicHeader(credentialPresenceUsername + ":"), wantOK: true,
			wantUsername: credentialPresenceUsername},
	}
}

// credentialPresenceBasicHeader encodes one Basic authorization header.
func credentialPresenceBasicHeader(presentation string) map[string]string {
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(presentation))}
}

// credentialPresenceCBORBody encodes one CBOR map so tests can omit individual keys.
func credentialPresenceCBORBody(t *testing.T, fields map[string]string) string {
	t.Helper()

	payload, err := cborcodec.Marshal(fields)
	if err != nil {
		t.Fatalf("cborcodec.Marshal() error = %v", err)
	}

	return string(payload)
}

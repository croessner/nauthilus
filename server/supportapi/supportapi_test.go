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

package supportapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

// TestDecodeStrict pins the shared argument rules of every transport.
func TestDecodeStrict(t *testing.T) {
	type request struct {
		Name string `json:"name"`
	}

	for name, tc := range map[string]struct {
		raw  string
		want bool
	}{
		"object":          {`{"name":"a"}`, true},
		"padded object":   {" \n{\"name\":\"a\"}\n", true},
		"unknown field":   {`{"name":"a","role":"admin"}`, false},
		"duplicate name":  {`{"name":"a","name":"b"}`, false},
		"trailing value":  {`{"name":"a"}{}`, false},
		"array":           {`[{"name":"a"}]`, false},
		"empty":           {``, false},
		"malformed":       {`{"name":`, false},
		"case variant ok": {`{"Name":"a"}`, true},
	} {
		t.Run(name, func(t *testing.T) {
			var target request
			if got := DecodeStrict([]byte(tc.raw), &target); got != tc.want {
				t.Fatalf("DecodeStrict(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestOperationTableAndSchemas pins the five operations, their self-contained object input schemas, and the
// untrusted-data notice of their model descriptions.
func TestOperationTableAndSchemas(t *testing.T) {
	names := []string{OperationAttemptSearch, OperationAttemptDetail, OperationBanHistory, OperationDiagnostics,
		OperationLogOverview}

	if len(Operations()) != len(names) {
		t.Fatalf("operations = %d", len(Operations()))
	}

	for _, name := range names {
		operation, ok := Lookup(name)
		if !ok || len(operation.Scopes) == 0 || !strings.HasPrefix(operation.HTTPPath, "/support/") ||
			!strings.Contains(operation.ModelDescription(), "untrusted data") {
			t.Fatalf("operation %s = %+v", name, operation)
		}

		assertSelfContainedObjectSchema(t, operation)
	}

	if _, ok := Lookup("shell"); ok {
		t.Fatal("unknown operations must not resolve")
	}
}

// TestAttemptSearchSchemaOffersTheOutputChoice pins that the MCP tool schema, derived from OpenAPI, offers the same
// response_mode and include_ban_context arguments as HTTP and refuses unknown modes.
func TestAttemptSearchSchemaOffersTheOutputChoice(t *testing.T) {
	operation, _ := Lookup(OperationAttemptSearch)

	schema, err := operation.InputSchema()
	if err != nil {
		t.Fatal(err)
	}

	var document struct {
		Properties map[string]struct {
			Type string   `json:"type"`
			Enum []string `json:"enum"`
		} `json:"properties"`
	}

	if err = json.Unmarshal(schema, &document); err != nil {
		t.Fatal(err)
	}

	mode, ban := document.Properties["response_mode"], document.Properties["include_ban_context"]
	if mode.Type != "string" || strings.Join(mode.Enum, ",") != "detailed,compact" || ban.Type != "boolean" {
		t.Fatalf("schema properties = %+v / %+v, want response_mode {detailed, compact} and boolean include_ban_context", mode, ban)
	}
}

// assertSelfContainedObjectSchema checks that an operation's input schema is a closed object without references.
func assertSelfContainedObjectSchema(t *testing.T, operation Operation) {
	t.Helper()

	schema, err := operation.InputSchema()
	if err != nil {
		t.Fatalf("InputSchema(%s) = %v", operation.Name, err)
	}

	var document map[string]any
	if json.Unmarshal(schema, &document) != nil || document["type"] != "object" ||
		document["additionalProperties"] != false || strings.Contains(string(schema), "$ref") {
		t.Fatalf("schema of %s = %s", operation.Name, schema)
	}
}

// TestExecuteRendersSharedEnvelopes pins not-configured, invalid, forbidden, and too-large envelopes.
func TestExecuteRendersSharedEnvelopes(t *testing.T) {
	services := Services{}
	diagnostics, _ := Lookup(OperationDiagnostics)
	history, _ := Lookup(OperationAttemptSearch)
	operator := supportaccess.VerifiedCredential{Method: supportaccess.CredentialOAuthUser, ClientID: "cli", Subject: "a",
		Scopes: []string{"nauthilus:operations_read"}}

	for name, tc := range map[string]struct {
		response Response
		status   int
		code     string
	}{
		"not configured": {services.Execute(context.Background(), diagnostics, operator, []byte(`{"schema_version":"1"}`)), http.StatusServiceUnavailable, "OPERATIONS_NOT_CONFIGURED"},
		"forbidden":      {services.Execute(context.Background(), diagnostics, supportaccess.VerifiedCredential{}, []byte(`{}`)), http.StatusForbidden, "FORBIDDEN"},
		"invalid":        {services.Execute(context.Background(), history, operator, []byte(`{"x":1}`)), http.StatusBadRequest, "INVALID_REQUEST"},
		"transport":      {InvalidRequest(diagnostics), http.StatusBadRequest, "INVALID_REQUEST"},
		"too large":      {ResponseTooLarge(history), http.StatusUnprocessableEntity, "RESPONSE_TOO_LARGE"},
	} {
		t.Run(name, func(t *testing.T) {
			var body struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
				SchemaVersion string `json:"schema_version"`
			}

			if json.Unmarshal(tc.response.Body, &body) != nil || tc.response.Status != tc.status || body.Error.Code != tc.code ||
				body.Error.Message == "" || body.SchemaVersion != "1" || !tc.response.IsError() {
				t.Fatalf("response = %d %s", tc.response.Status, tc.response.Body)
			}
		})
	}
}

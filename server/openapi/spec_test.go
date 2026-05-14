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

package openapi

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type operationExpectation struct {
	method string
	path   string
}

const (
	methodDelete = "delete"
	methodGet    = "get"
	methodPost   = "post"

	openAPIVersion = "3.1.0"

	pathBrowserLogin     = "/login"
	pathAuthCBOR         = "/api/v1/auth/cbor"
	pathAuthJSON         = "/api/v1/auth/json"
	pathBruteForceList   = "/api/v1/bruteforce/list"
	pathOIDCUserSessions = "/api/v1/oidc/sessions/{user_id}"
	pathSAMLSLO          = "/saml/slo"
)

var stableMachineOperations = []operationExpectation{
	{method: methodGet, path: "/api/v1/openapi.yaml"},
	{method: methodGet, path: "/api/v1/openapi.json"},
	{method: methodGet, path: pathAuthJSON},
	{method: methodPost, path: pathAuthJSON},
	{method: methodGet, path: pathAuthCBOR},
	{method: methodPost, path: pathAuthCBOR},
	{method: methodGet, path: pathBruteForceList},
	{method: methodPost, path: pathBruteForceList},
	{method: methodDelete, path: "/api/v1/bruteforce/flush"},
	{method: methodDelete, path: "/api/v1/bruteforce/flush/async"},
	{method: methodDelete, path: "/api/v1/cache/flush"},
	{method: methodDelete, path: "/api/v1/cache/flush/async"},
	{method: methodGet, path: "/api/v1/config/load"},
	{method: methodGet, path: "/api/v1/async/jobs/{jobId}"},
	{method: methodGet, path: "/api/v1/mfa/totp/setup"},
	{method: methodPost, path: "/api/v1/mfa/totp/register"},
	{method: methodDelete, path: "/api/v1/mfa/totp"},
	{method: methodPost, path: "/api/v1/mfa/recovery-codes/generate"},
	{method: methodGet, path: "/api/v1/mfa/webauthn/register/begin"},
	{method: methodPost, path: "/api/v1/mfa/webauthn/register/finish"},
	{method: methodDelete, path: "/api/v1/mfa/webauthn/{credentialID}"},
	{method: methodGet, path: pathOIDCUserSessions},
	{method: methodDelete, path: pathOIDCUserSessions},
	{method: methodDelete, path: "/api/v1/oidc/sessions/{user_id}/{token}"},
}

var stableIDPOperations = []operationExpectation{
	{method: methodGet, path: "/.well-known/openapi.yaml"},
	{method: methodGet, path: "/.well-known/openapi.json"},
	{method: methodGet, path: "/.well-known/openid-configuration"},
	{method: methodGet, path: "/oidc/authorize"},
	{method: methodPost, path: "/oidc/token"},
	{method: methodGet, path: "/oidc/userinfo"},
	{method: methodPost, path: "/oidc/introspect"},
	{method: methodGet, path: "/oidc/jwks"},
	{method: methodPost, path: "/oidc/device"},
	{method: methodGet, path: "/oidc/logout"},
	{method: methodGet, path: "/saml/metadata"},
	{method: methodGet, path: "/saml/sso"},
	{method: methodGet, path: pathSAMLSLO},
	{method: methodPost, path: pathSAMLSLO},
	{method: methodGet, path: pathBrowserLogin},
	{method: methodPost, path: pathBrowserLogin},
}

func TestManagementSpecYAMLDocumentsStableMachineAPIs(t *testing.T) {
	doc := parseYAMLSpec(t, ManagementYAML())

	assertSpecDocumentsOperations(t, doc, "Nauthilus", stableMachineOperations)
}

func TestIDPSpecYAMLDocumentsStableIDPEndpoints(t *testing.T) {
	doc := parseYAMLSpec(t, IDPYAML())

	assertSpecDocumentsOperations(t, doc, "IdP", stableIDPOperations)
}

func TestSpecJSONRendersFromEmbeddedYAML(t *testing.T) {
	var doc openAPISpec
	if err := json.Unmarshal(ManagementJSON(), &doc); err != nil {
		t.Fatalf("ManagementJSON() returned invalid JSON: %v", err)
	}

	if doc.OpenAPI != openAPIVersion {
		t.Fatalf("openapi = %q, want %s", doc.OpenAPI, openAPIVersion)
	}

	if len(doc.Paths) == 0 {
		t.Fatal("paths is empty")
	}

	var idpDoc openAPISpec
	if err := json.Unmarshal(IDPJSON(), &idpDoc); err != nil {
		t.Fatalf("IDPJSON() returned invalid JSON: %v", err)
	}

	if len(idpDoc.Paths) == 0 {
		t.Fatal("idp paths is empty")
	}
}

func TestSpecAccessorsReturnDefensiveCopies(t *testing.T) {
	yamlBytes := ManagementYAML()
	jsonBytes := ManagementJSON()
	idpYAMLBytes := IDPYAML()
	idpJSONBytes := IDPJSON()

	yamlBytes[0] = 'x'
	jsonBytes[0] = 'x'
	idpYAMLBytes[0] = 'x'
	idpJSONBytes[0] = 'x'

	if ManagementYAML()[0] == 'x' {
		t.Fatal("ManagementYAML() returned a mutable package-level slice")
	}

	if ManagementJSON()[0] == 'x' {
		t.Fatal("ManagementJSON() returned a mutable package-level slice")
	}

	if IDPYAML()[0] == 'x' {
		t.Fatal("IDPYAML() returned a mutable package-level slice")
	}

	if IDPJSON()[0] == 'x' {
		t.Fatal("IDPJSON() returned a mutable package-level slice")
	}
}

type openAPISpec struct {
	OpenAPI string `json:"openapi" yaml:"openapi"`
	Info    struct {
		Title string `json:"title" yaml:"title"`
	} `json:"info" yaml:"info"`
	Paths map[string]map[string]any `json:"paths" yaml:"paths"`
}

func parseYAMLSpec(t *testing.T, content []byte) openAPISpec {
	t.Helper()

	var doc openAPISpec
	if err := yaml.Unmarshal(content, &doc); err != nil {
		t.Fatalf("YAML() returned invalid YAML: %v", err)
	}

	return doc
}

func assertSpecDocumentsOperations(t *testing.T, doc openAPISpec, titleSubstring string, expectedOperations []operationExpectation) {
	t.Helper()

	if doc.OpenAPI != openAPIVersion {
		t.Fatalf("openapi = %q, want %s", doc.OpenAPI, openAPIVersion)
	}

	if !strings.Contains(doc.Info.Title, titleSubstring) {
		t.Fatalf("info.title = %q, want title containing %q", doc.Info.Title, titleSubstring)
	}

	for _, expected := range expectedOperations {
		operations, ok := doc.Paths[expected.path]
		if !ok {
			t.Fatalf("paths[%q] missing", expected.path)
		}

		if _, ok := operations[expected.method]; !ok {
			t.Fatalf("paths[%q][%q] missing", expected.path, expected.method)
		}
	}
}

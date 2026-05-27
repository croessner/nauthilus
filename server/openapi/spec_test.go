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
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type operationExpectation struct {
	method string
	path   string
}

const (
	methodDelete           = "delete"
	methodGet              = "get"
	methodPost             = "post"
	openAPIBaseURLDefault  = "https://nauthilus.example.com"
	openAPIBaseURLName     = "baseUrl"
	openAPIBaseURLTemplate = "{baseUrl}"

	openAPIVersion = "3.1.0"

	specIDPName        = "idp"
	specManagementName = "management"

	pathBrowserLogin                 = "/login"
	pathAuthCBOR                     = "/api/v1/auth/cbor"
	pathAuthHeader                   = "/api/v1/auth/header"
	pathAuthJSON                     = "/api/v1/auth/json"
	pathAuthNginx                    = "/api/v1/auth/nginx"
	pathBruteForceList               = "/api/v1/bruteforce/list"
	pathOIDCAuthorize                = "/oidc/authorize"
	pathOIDCDeviceVerify             = "/oidc/device/verify"
	pathOIDCJWKS                     = "/oidc/jwks"
	pathOIDCUserSessions             = "/api/v1/oidc/sessions/{user_id}"
	pathSAMLSLO                      = "/saml/slo"
	pathSAMLMetadata                 = "/saml/metadata"
	pathSAMLSSO                      = "/saml/sso"
	pathWellKnownOpenAPIJSON         = "/.well-known/openapi.json"
	pathWellKnownOpenAPIYAML         = "/.well-known/openapi.yaml"
	pathWellKnownOpenIDConfiguration = "/.well-known/openid-configuration"

	managementAsyncJobStatusDone       = "DONE"
	managementAsyncJobStatusError      = "ERROR"
	managementAsyncJobStatusInProgress = "INPROGRESS"
	managementAsyncJobStatusQueued     = "QUEUED"
)

var stableMachineOperations = []operationExpectation{
	{method: methodGet, path: "/api/v1/openapi.yaml"},
	{method: methodGet, path: "/api/v1/openapi.json"},
	{method: methodGet, path: pathAuthJSON},
	{method: methodPost, path: pathAuthJSON},
	{method: methodGet, path: pathAuthCBOR},
	{method: methodPost, path: pathAuthCBOR},
	{method: methodGet, path: pathAuthHeader},
	{method: methodPost, path: pathAuthHeader},
	{method: methodGet, path: pathAuthNginx},
	{method: methodPost, path: pathAuthNginx},
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
	{method: methodGet, path: pathWellKnownOpenAPIYAML},
	{method: methodGet, path: pathWellKnownOpenAPIJSON},
	{method: methodGet, path: pathWellKnownOpenIDConfiguration},
	{method: methodGet, path: pathOIDCAuthorize},
	{method: methodPost, path: "/oidc/token"},
	{method: methodGet, path: "/oidc/userinfo"},
	{method: methodPost, path: "/oidc/introspect"},
	{method: methodGet, path: pathOIDCJWKS},
	{method: methodPost, path: "/oidc/device"},
	{method: methodGet, path: "/oidc/logout"},
	{method: methodGet, path: pathSAMLMetadata},
	{method: methodGet, path: pathSAMLSSO},
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

func TestIDPSpecDocumentsClientCredentialsGrant(t *testing.T) {
	doc := parseYAMLSpec(t, IDPYAML())

	tokenRequest, ok := doc.Components.Schemas["TokenRequest"]
	if !ok {
		t.Fatal("components.schemas.TokenRequest missing")
	}

	grantType, ok := tokenRequest.Properties["grant_type"]
	if !ok {
		t.Fatal("TokenRequest.properties.grant_type missing")
	}

	if !stringSliceContains(grantType.Enum, "client_credentials") {
		t.Fatalf("TokenRequest.properties.grant_type.enum = %v, want client_credentials", grantType.Enum)
	}

	if _, ok := tokenRequest.Properties["scope"]; !ok {
		t.Fatal("TokenRequest.properties.scope missing for client_credentials requests")
	}

	if _, ok := tokenRequest.Properties["client_assertion"]; !ok {
		t.Fatal("TokenRequest.properties.client_assertion missing for private_key_jwt client authentication")
	}
}

func TestManagementSpecDocumentsAsyncJobStatusLifecycle(t *testing.T) {
	doc := parseYAMLSpec(t, ManagementYAML())

	acceptedStatus := requireSchemaProperty(t, doc, "AsyncAcceptedPayload", "status")
	expectedAcceptedStatuses := []string{managementAsyncJobStatusQueued}

	if !stringSlicesEqual(acceptedStatus.Enum, expectedAcceptedStatuses) {
		t.Fatalf("AsyncAcceptedPayload.properties.status.enum = %v, want %v", acceptedStatus.Enum, expectedAcceptedStatuses)
	}

	status := requireSchemaProperty(t, doc, "AsyncJobStatusPayload", "status")
	expectedStatuses := []string{
		managementAsyncJobStatusQueued,
		managementAsyncJobStatusInProgress,
		managementAsyncJobStatusDone,
		managementAsyncJobStatusError,
	}

	if !stringSlicesEqual(status.Enum, expectedStatuses) {
		t.Fatalf("AsyncJobStatusPayload.properties.status.enum = %v, want %v", status.Enum, expectedStatuses)
	}
}

func TestSpecsExposeConfigurableBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
	}{
		{name: specManagementName, content: ManagementYAML()},
		{name: specIDPName, content: IDPYAML()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := parseYAMLSpec(t, tt.content)
			if len(doc.Servers) != 1 {
				t.Fatalf("servers has %d entries, want 1", len(doc.Servers))
			}

			server := doc.Servers[0]
			if server.URL != openAPIBaseURLTemplate {
				t.Fatalf("servers[0].url = %q, want %q", server.URL, openAPIBaseURLTemplate)
			}

			variable, ok := server.Variables[openAPIBaseURLName]
			if !ok {
				t.Fatalf("servers[0].variables[%q] missing", openAPIBaseURLName)
			}

			if variable.Default != openAPIBaseURLDefault {
				t.Fatalf("servers[0].variables[%q].default = %q, want %q", openAPIBaseURLName, variable.Default, openAPIBaseURLDefault)
			}

			if !strings.Contains(variable.Description, "base URL") {
				t.Fatalf("servers[0].variables[%q].description = %q, want base URL guidance", openAPIBaseURLName, variable.Description)
			}
		})
	}
}

func requireSchemaProperty(t *testing.T, doc openAPISpec, schemaName string, propertyName string) openAPIProperty {
	t.Helper()

	schema, ok := doc.Components.Schemas[schemaName]
	if !ok {
		t.Fatalf("components.schemas.%s missing", schemaName)
	}

	property, ok := schema.Properties[propertyName]
	if !ok {
		t.Fatalf("%s.properties.%s missing", schemaName, propertyName)
	}

	return property
}

func stringSlicesEqual(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}

	return true
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
	Components openAPIComponents         `json:"components" yaml:"components"`
	Paths      map[string]map[string]any `json:"paths" yaml:"paths"`
	Servers    []openAPIServer           `json:"servers" yaml:"servers"`
}

type openAPIComponents struct {
	Schemas map[string]openAPISchema `json:"schemas" yaml:"schemas"`
}

type openAPISchema struct {
	Properties map[string]openAPIProperty `json:"properties" yaml:"properties"`
}

type openAPIProperty struct {
	Enum []string `json:"enum" yaml:"enum"`
}

type openAPIServer struct {
	URL         string                           `json:"url" yaml:"url"`
	Description string                           `json:"description" yaml:"description"`
	Variables   map[string]openAPIServerVariable `json:"variables" yaml:"variables"`
}

type openAPIServerVariable struct {
	Default     string `json:"default" yaml:"default"`
	Description string `json:"description" yaml:"description"`
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

func stringSliceContains(values []string, expected string) bool {
	return slices.Contains(values, expected)
}

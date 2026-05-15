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
	"strings"
	"testing"
)

func TestEmbeddedSpecsPassParserBackedContractGate(t *testing.T) {
	for _, document := range parserBackedContractDocuments() {
		t.Run(document.name, func(t *testing.T) {
			if err := document.validate(); err != nil {
				t.Fatalf("parser-backed OpenAPI contract gate failed: %v", err)
			}
		})
	}
}

func TestParserBackedContractGateRejectsBrokenContracts(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		want    string
	}{
		{
			name: "broken reference",
			content: replaceOpenAPISnippet(t, ManagementYAML(),
				`$ref: "#/components/responses/AuthJSONSuccess"`,
				`$ref: "#/components/responses/MissingAuthJSONSuccess"`),
			want: "MissingAuthJSONSuccess",
		},
		{
			name: "missing operation metadata",
			content: replaceOpenAPISnippet(t, ManagementYAML(),
				"operationId: getOpenAPIYAML",
				"x-operationId: getOpenAPIYAML"),
			want: "operationId missing",
		},
		{
			name: "missing protected security",
			content: replaceOpenAPISnippet(t, ManagementYAML(),
				"security:\n        - backchannelBasic: []\n        - backchannelBearer: []",
				"security: []"),
			want: "protected operation missing security requirements",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			document := openAPIContractDocument{
				name:               tt.name,
				content:            tt.content,
				expectedOperations: stableMachineOperations,
			}

			err := document.validate()
			if err == nil {
				t.Fatal("parser-backed OpenAPI contract gate accepted a broken contract")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want substring %q", err, tt.want)
			}
		})
	}
}

func parserBackedContractDocuments() []openAPIContractDocument {
	return []openAPIContractDocument{
		{
			name:               specManagementName,
			content:            ManagementYAML(),
			expectedOperations: stableMachineOperations,
		},
		{
			name:               specIDPName,
			content:            IDPYAML(),
			expectedOperations: stableIDPOperations,
			publicOperations: openAPIOperationSet(
				operationExpectation{method: methodGet, path: pathWellKnownOpenAPIYAML},
				operationExpectation{method: methodGet, path: pathWellKnownOpenAPIJSON},
				operationExpectation{method: methodGet, path: pathWellKnownOpenIDConfiguration},
				operationExpectation{method: methodGet, path: pathOIDCAuthorize},
				operationExpectation{method: methodGet, path: pathOIDCJWKS},
				operationExpectation{method: methodGet, path: pathOIDCDeviceVerify},
				operationExpectation{method: methodPost, path: pathOIDCDeviceVerify},
				operationExpectation{method: methodGet, path: pathSAMLMetadata},
				operationExpectation{method: methodGet, path: pathSAMLSSO},
				operationExpectation{method: methodGet, path: pathSAMLSLO},
				operationExpectation{method: methodPost, path: pathSAMLSLO},
				operationExpectation{method: methodGet, path: pathBrowserLogin},
				operationExpectation{method: methodPost, path: pathBrowserLogin},
				operationExpectation{method: methodGet, path: "/logged_out"},
			),
		},
	}
}

func replaceOpenAPISnippet(t *testing.T, content []byte, oldValue string, newValue string) []byte {
	t.Helper()

	original := string(content)
	if !strings.Contains(original, oldValue) {
		t.Fatalf("OpenAPI test fixture does not contain %q", oldValue)
	}

	return []byte(strings.Replace(original, oldValue, newValue, 1))
}

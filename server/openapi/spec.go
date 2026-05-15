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

// Package openapi exposes embedded OpenAPI contracts for stable HTTP APIs.
//
// YAML documents are the canonical sources. JSON is rendered from the same
// embedded bytes so served formats stay in sync.
package openapi

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed openapi.yaml
var baseManagementSpecYAML []byte

//go:embed idp.yaml
var idpSpecYAML []byte

var managementSpecYAML = mustManagementSpecYAML()
var managementSpecJSON = mustRenderJSON(managementSpecYAML)
var idpSpecJSON = mustRenderJSON(idpSpecYAML)

// ManagementYAML returns the embedded management OpenAPI document in YAML format.
func ManagementYAML() []byte {
	return cloneSpecBytes(managementSpecYAML)
}

// ManagementJSON returns the embedded management OpenAPI document rendered as JSON.
func ManagementJSON() []byte {
	return cloneSpecBytes(managementSpecJSON)
}

// IDPYAML returns the embedded public IdP OpenAPI document in YAML format.
func IDPYAML() []byte {
	return cloneSpecBytes(idpSpecYAML)
}

// IDPJSON returns the embedded public IdP OpenAPI document rendered as JSON.
func IDPJSON() []byte {
	return cloneSpecBytes(idpSpecJSON)
}

func cloneSpecBytes(content []byte) []byte {
	return append([]byte(nil), content...)
}

func mustRenderJSON(content []byte) []byte {
	var document map[string]any
	if err := yaml.Unmarshal(content, &document); err != nil {
		panic(fmt.Sprintf("invalid embedded OpenAPI YAML: %v", err))
	}

	rendered, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("failed to render embedded OpenAPI JSON: %v", err))
	}

	return append(rendered, '\n')
}

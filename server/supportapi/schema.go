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
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/croessner/nauthilus/v4/server/openapi"
)

const (
	componentSchemaPrefix = "#/components/schemas/"

	// maxSchemaDepth bounds $ref inlining.
	maxSchemaDepth = 16
)

var (
	schemaOnce   sync.Once
	schemaCache  map[string]json.RawMessage
	schemaFailed error
)

// InputSchema returns the operation's request schema as a self-contained JSON Schema: the component schema of the
// embedded management OpenAPI document (OpenAPI 3.1 schemas are JSON Schema 2020-12) with every $ref inlined. The
// HTTP contract and the MCP tool schema therefore come from one source.
func (o Operation) InputSchema() (json.RawMessage, error) {
	schemaOnce.Do(loadInputSchemas)

	if schemaFailed != nil {
		return nil, schemaFailed
	}

	schema, ok := schemaCache[o.Name]
	if !ok {
		return nil, fmt.Errorf("no input schema for %s", o.Name)
	}

	return append(json.RawMessage(nil), schema...), nil
}

// loadInputSchemas resolves every operation's request schema once.
func loadInputSchemas() {
	var document struct {
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}

	if schemaFailed = json.Unmarshal(openapi.ManagementJSON(), &document); schemaFailed != nil {
		return
	}

	schemaCache = make(map[string]json.RawMessage, len(operations))

	for _, operation := range operations {
		inlined, err := inlineSchema(document.Components.Schemas, document.Components.Schemas[operation.RequestSchema], 0)
		if err != nil {
			schemaFailed = fmt.Errorf("%s: %w", operation.Name, err)

			return
		}

		rendered, err := json.Marshal(inlined)
		if err != nil {
			schemaFailed = err

			return
		}

		schemaCache[operation.Name] = rendered
	}
}

// inlineSchema copies a schema node, replacing component references by their definitions and dropping OpenAPI
// extension keys.
func inlineSchema(components map[string]any, node any, depth int) (any, error) {
	if depth > maxSchemaDepth {
		return nil, fmt.Errorf("schema references nest deeper than %d", maxSchemaDepth)
	}

	switch typed := node.(type) {
	case map[string]any:
		return inlineObject(components, typed, depth)
	case []any:
		items := make([]any, len(typed))

		for index, item := range typed {
			inlined, err := inlineSchema(components, item, depth+1)
			if err != nil {
				return nil, err
			}

			items[index] = inlined
		}

		return items, nil
	case nil:
		return nil, fmt.Errorf("missing schema")
	default:
		return typed, nil
	}
}

// inlineObject inlines one schema object; sibling keywords of a $ref (such as description) are kept.
func inlineObject(components map[string]any, object map[string]any, depth int) (any, error) {
	result := map[string]any{}

	if reference, ok := object["$ref"].(string); ok {
		name, found := strings.CutPrefix(reference, componentSchemaPrefix)
		if !found {
			return nil, fmt.Errorf("unsupported reference %q", reference)
		}

		resolved, err := inlineSchema(components, components[name], depth+1)
		if err != nil {
			return nil, err
		}

		resolvedObject, ok := resolved.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("reference %q is not an object schema", reference)
		}

		for key, value := range resolvedObject {
			result[key] = value
		}
	}

	for key, value := range object {
		if key == "$ref" || strings.HasPrefix(key, "x-") {
			continue
		}

		inlined, err := inlineSchema(components, value, depth+1)
		if err != nil {
			return nil, err
		}

		result[key] = inlined
	}

	return result, nil
}

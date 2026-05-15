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
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

type openAPIContractDocument struct {
	publicOperations   map[operationExpectation]struct{}
	name               string
	content            []byte
	expectedOperations []operationExpectation
}

type openAPIContractGate struct {
	publicOperations map[operationExpectation]struct{}
}

type openAPIContractOperation struct {
	operation *openapi3.Operation
	path      string
	method    string
}

func (document openAPIContractDocument) validate() error {
	doc, err := loadParsedOpenAPIContract(document.content)
	if err != nil {
		return err
	}

	gate := openAPIContractGate{publicOperations: document.publicOperations}
	if err := gate.validate(doc); err != nil {
		return err
	}

	return document.validateExpectedOperations(doc)
}

func (document openAPIContractDocument) validateExpectedOperations(doc *openapi3.T) error {
	for _, expected := range document.expectedOperations {
		operation, ok, err := findOpenAPIOperation(doc, expected)
		if err != nil {
			return err
		}

		if !ok || operation == nil {
			return fmt.Errorf("%s: stable operation missing", expected.label())
		}
	}

	return nil
}

func loadParsedOpenAPIContract(content []byte) (*openapi3.T, error) {
	ctx := context.Background()
	loader := openapi3.NewLoader()
	loader.Context = ctx
	loader.IsExternalRefsAllowed = false

	doc, err := loader.LoadFromData(content)
	if err != nil {
		return nil, fmt.Errorf("parse OpenAPI document: %w", err)
	}

	if err := doc.Validate(ctx); err != nil {
		return nil, fmt.Errorf("validate OpenAPI document: %w", err)
	}

	return doc, nil
}

func (gate openAPIContractGate) validate(doc *openapi3.T) error {
	if err := validateOpenAPIServers(doc); err != nil {
		return err
	}

	definedTags, err := collectOpenAPITags(doc)
	if err != nil {
		return err
	}

	securitySchemes := collectOpenAPISecuritySchemes(doc)

	operationIDs := make(map[string]operationExpectation)

	for _, operation := range collectOpenAPIOperations(doc) {
		if err := gate.validateOperation(operation, definedTags, securitySchemes, operationIDs); err != nil {
			return err
		}
	}

	return nil
}

func validateOpenAPIServers(doc *openapi3.T) error {
	if len(doc.Servers) != 1 {
		return fmt.Errorf("servers has %d entries, want 1", len(doc.Servers))
	}

	server := doc.Servers[0]
	if server.URL != openAPIBaseURLTemplate {
		return fmt.Errorf("servers[0].url = %q, want %q", server.URL, openAPIBaseURLTemplate)
	}

	names, err := server.ParameterNames()
	if err != nil {
		return fmt.Errorf("servers[0].url has invalid variables: %w", err)
	}

	if len(names) != 1 || names[0] != openAPIBaseURLName {
		return fmt.Errorf("servers[0].url variables = %v, want [%s]", names, openAPIBaseURLName)
	}

	variable := server.Variables[openAPIBaseURLName]
	if variable == nil {
		return fmt.Errorf("servers[0].variables[%q] missing", openAPIBaseURLName)
	}

	if variable.Default != openAPIBaseURLDefault {
		return fmt.Errorf("servers[0].variables[%q].default = %q, want %q", openAPIBaseURLName, variable.Default, openAPIBaseURLDefault)
	}

	if !strings.Contains(variable.Description, "base URL") {
		return fmt.Errorf("servers[0].variables[%q].description = %q, want base URL guidance", openAPIBaseURLName, variable.Description)
	}

	return nil
}

func collectOpenAPITags(doc *openapi3.T) (map[string]struct{}, error) {
	if len(doc.Tags) == 0 {
		return nil, fmt.Errorf("tags missing")
	}

	definedTags := make(map[string]struct{}, len(doc.Tags))
	for _, tag := range doc.Tags {
		name := strings.TrimSpace(tag.Name)
		if name == "" {
			return nil, fmt.Errorf("tag name missing")
		}

		displayName, _ := tag.Extensions["x-displayName"].(string)
		if strings.TrimSpace(displayName) == "" {
			return nil, fmt.Errorf("tag %q missing x-displayName endpoint group", name)
		}

		definedTags[name] = struct{}{}
	}

	return definedTags, nil
}

func collectOpenAPISecuritySchemes(doc *openapi3.T) map[string]struct{} {
	if doc.Components == nil {
		return nil
	}

	securitySchemes := make(map[string]struct{}, len(doc.Components.SecuritySchemes))
	for name := range doc.Components.SecuritySchemes {
		securitySchemes[name] = struct{}{}
	}

	return securitySchemes
}

func collectOpenAPIOperations(doc *openapi3.T) []openAPIContractOperation {
	paths := doc.Paths.Keys()

	operations := make([]openAPIContractOperation, 0, len(paths))

	for _, path := range paths {
		pathItem := doc.Paths.Value(path)
		if pathItem == nil {
			continue
		}

		pathOperations := pathItem.Operations()

		methods := make([]string, 0, len(pathOperations))

		for method := range pathOperations {
			methods = append(methods, method)
		}

		sort.Strings(methods)

		for _, method := range methods {
			operations = append(operations, openAPIContractOperation{
				operation: pathOperations[method],
				path:      path,
				method:    strings.ToLower(method),
			})
		}
	}

	return operations
}

func (gate openAPIContractGate) validateOperation(
	current openAPIContractOperation,
	definedTags map[string]struct{},
	securitySchemes map[string]struct{},
	operationIDs map[string]operationExpectation,
) error {
	if strings.TrimSpace(current.operation.OperationID) == "" {
		return fmt.Errorf("%s: operationId missing", current.label())
	}

	key := operationExpectation{method: current.method, path: current.path}
	if previous, ok := operationIDs[current.operation.OperationID]; ok {
		return fmt.Errorf("%s: operationId %q already used by %s", current.label(), current.operation.OperationID, previous.label())
	}

	operationIDs[current.operation.OperationID] = key
	if err := validateOpenAPIOperationTags(current, definedTags); err != nil {
		return err
	}

	if current.operation.Responses == nil || current.operation.Responses.Len() == 0 {
		return fmt.Errorf("%s: responses missing", current.label())
	}

	return gate.validateOperationSecurity(key, current.operation.Security, securitySchemes)
}

func validateOpenAPIOperationTags(current openAPIContractOperation, definedTags map[string]struct{}) error {
	if len(current.operation.Tags) == 0 {
		return fmt.Errorf("%s: endpoint-group tag missing", current.label())
	}

	for _, tag := range current.operation.Tags {
		if _, ok := definedTags[tag]; !ok {
			return fmt.Errorf("%s: tag %q is not defined", current.label(), tag)
		}
	}

	return nil
}

func (gate openAPIContractGate) validateOperationSecurity(
	key operationExpectation,
	security *openapi3.SecurityRequirements,
	securitySchemes map[string]struct{},
) error {
	if security == nil {
		return fmt.Errorf("%s: explicit security requirements missing", key.label())
	}

	if _, public := gate.publicOperations[key]; public {
		if len(*security) != 0 {
			return fmt.Errorf("%s: intentionally public operation must declare security: []", key.label())
		}

		return nil
	}

	if len(*security) == 0 {
		return fmt.Errorf("%s: protected operation missing security requirements", key.label())
	}

	for _, requirement := range *security {
		if len(requirement) == 0 {
			return fmt.Errorf("%s: protected operation allows anonymous security requirement", key.label())
		}

		for scheme := range requirement {
			if _, ok := securitySchemes[scheme]; !ok {
				return fmt.Errorf("%s: security scheme %q is not defined", key.label(), scheme)
			}
		}
	}

	return nil
}

func findOpenAPIOperation(doc *openapi3.T, expected operationExpectation) (*openapi3.Operation, bool, error) {
	method, err := openAPIHTTPMethod(expected.method)
	if err != nil {
		return nil, false, err
	}

	pathItem := doc.Paths.Value(expected.path)
	if pathItem == nil {
		return nil, false, nil
	}

	return pathItem.GetOperation(method), true, nil
}

func openAPIHTTPMethod(method string) (string, error) {
	switch strings.ToLower(method) {
	case methodDelete:
		return http.MethodDelete, nil
	case methodGet:
		return http.MethodGet, nil
	case methodPost:
		return http.MethodPost, nil
	default:
		return "", fmt.Errorf("unsupported HTTP method %q", method)
	}
}

func openAPIOperationSet(operations ...operationExpectation) map[operationExpectation]struct{} {
	operationSet := make(map[operationExpectation]struct{}, len(operations))
	for _, operation := range operations {
		operationSet[operation] = struct{}{}
	}

	return operationSet
}

func (operation openAPIContractOperation) label() string {
	return operationExpectation{method: operation.method, path: operation.path}.label()
}

func (operation operationExpectation) label() string {
	return strings.ToUpper(operation.method) + " " + operation.path
}

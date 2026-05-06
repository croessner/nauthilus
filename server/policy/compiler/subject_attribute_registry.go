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

package compiler

import (
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/policy"
	policyregistry "github.com/croessner/nauthilus/server/policy/registry"
)

const subjectAttributeExportConfigPath = "auth.policy.attribute_exports"

func registerGeneratedSubjectAttributes(
	exports []config.PolicyAttributeExportConfig,
	registry *policyregistry.AttributeRegistry,
) error {
	if registry == nil {
		return nil
	}

	seen := make(map[string]string, len(exports))
	for index, exportConfig := range exports {
		path := indexedPath(subjectAttributeExportConfigPath, index)
		identifier, err := subjectAttributeIdentifier(exportConfig, path, seen)
		if err != nil {
			return err
		}

		valueType, err := subjectAttributeType(exportConfig.Type, childPath(path, "type"))
		if err != nil {
			return err
		}

		sensitivity, err := subjectAttributeSensitivity(exportConfig.Sensitivity, childPath(path, "sensitivity"))
		if err != nil {
			return err
		}

		definition := generatedSubjectAttribute(identifier, exportConfig, valueType, sensitivity)
		if err := registerGeneratedAttributes(registry, []policyregistry.AttributeDefinition{definition}); err != nil {
			return err
		}
	}

	return nil
}

func subjectAttributeIdentifier(
	exportConfig config.PolicyAttributeExportConfig,
	path string,
	seen map[string]string,
) (string, error) {
	name := strings.TrimSpace(exportConfig.Name)
	if name == "" {
		return "", configPathError(childPath(path, "name"), "must not be empty")
	}

	if strings.TrimSpace(exportConfig.Attribute) == "" {
		return "", configPathError(childPath(path, "attribute"), "must not be empty")
	}

	identifier := policy.IdentifierSegment(name)
	if previous, exists := seen[identifier]; exists {
		return "", configPathError(
			childPath(path, "name"),
			fmt.Sprintf("normalizes to policy identifier %q already used by attribute export %q", identifier, previous),
		)
	}

	seen[identifier] = name

	return identifier, nil
}

func subjectAttributeType(value string, path string) (policyregistry.AttributeType, error) {
	switch strings.TrimSpace(value) {
	case "bool":
		return policyregistry.AttributeTypeBool, nil
	case "string":
		return policyregistry.AttributeTypeString, nil
	case "string_list":
		return policyregistry.AttributeTypeStringList, nil
	case "number":
		return policyregistry.AttributeTypeNumber, nil
	default:
		return "", configPathError(path, "must be one of bool, string, string_list, or number")
	}
}

func subjectAttributeSensitivity(value string, path string) (string, error) {
	switch strings.TrimSpace(value) {
	case "", policyregistry.DetailSensitivityInternal:
		return policyregistry.DetailSensitivityInternal, nil
	case policyregistry.DetailSensitivityPublic:
		return policyregistry.DetailSensitivityPublic, nil
	case policyregistry.DetailSensitivitySecret:
		return policyregistry.DetailSensitivitySecret, nil
	default:
		return "", configPathError(path, "must be one of public, internal, or secret")
	}
}

func generatedSubjectAttribute(
	identifier string,
	exportConfig config.PolicyAttributeExportConfig,
	valueType policyregistry.AttributeType,
	sensitivity string,
) policyregistry.AttributeDefinition {
	return policyregistry.AttributeDefinition{
		ID:            policy.SubjectAttributeID(identifier),
		Description:   fmt.Sprintf("Backend attribute %q exported as policy subject fact.", exportConfig.Attribute),
		Stage:         policy.StageAuthBackend,
		Operations:    []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity},
		ProducerTypes: []string{policy.CheckTypeLDAPBackend, policy.CheckTypeLuaBackend},
		Category:      policyregistry.AttributeCategorySubject,
		Type:          policyregistry.AttributeTypeBool,
		Source:        policyregistry.SourceBuiltin,
		Details:       generatedSubjectAttributeDetails(valueType, sensitivity),
	}
}

func generatedSubjectAttributeDetails(
	valueType policyregistry.AttributeType,
	sensitivity string,
) map[string]policyregistry.DetailDefinition {
	details := map[string]policyregistry.DetailDefinition{
		"attribute": {Type: policyregistry.AttributeTypeString, Sensitivity: policyregistry.DetailSensitivityInternal},
		"count":     {Type: policyregistry.AttributeTypeNumber, Sensitivity: policyregistry.DetailSensitivityInternal},
	}

	switch valueType {
	case policyregistry.AttributeTypeStringList:
		details["values"] = policyregistry.DetailDefinition{Type: valueType, Sensitivity: sensitivity}
	default:
		details["value"] = policyregistry.DetailDefinition{Type: valueType, Sensitivity: sensitivity}
	}

	return details
}

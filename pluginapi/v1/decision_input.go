// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginapi

import "strings"

// ValidateDecisionProviderReference accepts one exact native provider identity without wildcard selectors.
func ValidateDecisionProviderReference(value string) error {
	namespace, component, found := strings.Cut(value, "/plugin.")
	if !found || !validDecisionNamespace(namespace) || ValidateQualifiedComponentName(component) != nil {
		return invalidDecisionContract("fact input provider", "requires one exact qualified native provider")
	}

	return nil
}

// validateDecisionFactInputs validates exact scalar or record-field input requirements.
func validateDecisionFactInputs(inputs []DecisionFactInputDescriptor) error {
	if len(inputs) > maximumDecisionDefinitions {
		return invalidDecisionContract("fact provider inputs", "exceeds the host bound")
	}

	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if input.Provider != "" {
			if err := ValidateDecisionProviderReference(input.Provider); err != nil {
				return err
			}
		}

		if !validDecisionFactName(input.ID) || !input.Category.IsValid() || !input.Kind.IsValid() {
			return invalidDecisionContract("fact provider input", "requires a canonical identity, category and kind")
		}

		if _, exists := seen[input.ID]; exists {
			return invalidDecisionContract("fact provider inputs", "contains a duplicate identity")
		}

		seen[input.ID] = struct{}{}
		if err := validateDecisionInputFields(input); err != nil {
			return err
		}
	}

	return nil
}

// validateDecisionInputFields bounds the visible scalar fields consumed from a record collection.
func validateDecisionInputFields(input DecisionFactInputDescriptor) error {
	if (input.Kind == DecisionValueKindRecords) != (len(input.Fields) > 0) || len(input.Fields) > maximumDecisionDefinitions {
		return invalidDecisionContract("fact provider input fields", "requires bounded fields exactly for record inputs")
	}

	seen := make(map[string]struct{}, len(input.Fields))
	for _, field := range input.Fields {
		if !validDecisionRecordFieldName(field.Name) || !field.Kind.IsValid() || field.Kind == DecisionValueKindRecords {
			return invalidDecisionContract("fact provider input field", "requires a canonical name and scalar kind")
		}

		if _, exists := seen[field.Name]; exists {
			return invalidDecisionContract("fact provider input fields", "contains a duplicate field")
		}

		seen[field.Name] = struct{}{}
	}

	return nil
}

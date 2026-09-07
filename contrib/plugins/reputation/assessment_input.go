package main

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"reflect"
	"slices"
	"sort"
	"strings"
)

// assessmentInputs freezes exact categories, kinds, upstream owners and record field visibility before activation.
func assessmentInputs(extractors []extractorConfig) ([]pluginapi.DecisionFactInputDescriptor, error) {
	inputs := make(map[string]pluginapi.DecisionFactInputDescriptor)

	for _, extractor := range extractors {
		current, err := assessmentInput(extractor)
		if err != nil {
			return nil, err
		}

		if previous, exists := inputs[current.ID]; exists {
			merged, err := mergeAssessmentInput(previous, current)
			if err != nil {
				return nil, err
			}

			current = merged
		}

		inputs[current.ID] = current
	}

	names := make([]string, 0, len(inputs))
	for name := range inputs {
		names = append(names, name)
	}

	sort.Strings(names)

	result := make([]pluginapi.DecisionFactInputDescriptor, 0, len(names))
	for _, name := range names {
		result = append(result, inputs[name])
	}

	return result, nil
}

// assessmentInput declares only explicitly configured provider provenance and typed correlation fields.
func assessmentInput(extractor extractorConfig) (pluginapi.DecisionFactInputDescriptor, error) {
	category := extractor.Category
	if category == "" {
		prefix, _, _ := strings.Cut(extractor.Attribute, ".")
		category = pluginapi.DecisionFactCategory(prefix)
	}

	if !category.IsValid() {
		return pluginapi.DecisionFactInputDescriptor{}, errConfiguration
	}

	if extractor.Provider != "" {
		if pluginapi.ValidateDecisionProviderReference(extractor.Provider) != nil || !strings.HasPrefix(extractor.Attribute, asnProviderFactPrefix(extractor.Provider)) {
			return pluginapi.DecisionFactInputDescriptor{}, errConfiguration
		}
	} else if strings.HasPrefix(extractor.Attribute, "plugin.") {
		return pluginapi.DecisionFactInputDescriptor{}, errConfiguration
	}

	kind := extractor.InputKind
	if kind == "" {
		kind = pluginapi.DecisionValueKindString
	}

	result := pluginapi.DecisionFactInputDescriptor{ID: extractor.Attribute, Category: category, Kind: kind, Provider: extractor.Provider}
	if extractor.Field != "" {
		fields, err := assessmentRecordInput(extractor, kind)
		if err != nil {
			return result, err
		}

		result.Kind = pluginapi.DecisionValueKindRecords
		result.Fields = fields
	}

	return result, nil
}

// mergeAssessmentInput allows repeated same-identity extraction while rejecting conflicting source or field contracts.
func mergeAssessmentInput(left, right pluginapi.DecisionFactInputDescriptor) (pluginapi.DecisionFactInputDescriptor, error) {
	fields := slices.Clone(left.Fields)
	left.Fields = nil
	rightFields := right.Fields

	right.Fields = nil
	if !reflect.DeepEqual(left, right) {
		return left, errConfiguration
	}

	for _, candidate := range rightFields {
		index := slices.IndexFunc(fields, func(field pluginapi.DecisionFactInputFieldDescriptor) bool { return field.Name == candidate.Name })
		if index >= 0 {
			if fields[index].Kind != candidate.Kind {
				return left, errConfiguration
			}

			continue
		}

		fields = append(fields, candidate)
	}

	sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
	left.Fields = fields

	return left, nil
}

// assessmentRecordInput declares each consumed correlation field once with its explicit scalar kind.
func assessmentRecordInput(extractor extractorConfig, kind pluginapi.DecisionValueKind) ([]pluginapi.DecisionFactInputFieldDescriptor, error) {
	fields := []pluginapi.DecisionFactInputFieldDescriptor{{Name: extractor.Field, Kind: kind}}
	for _, name := range extractor.CorrelationFields {
		fieldKind := extractor.CorrelationTypes[name]
		if !fieldKind.IsValid() || fieldKind == pluginapi.DecisionValueKindRecords {
			return nil, errConfiguration
		}

		if name == extractor.Field {
			if fieldKind != kind {
				return nil, errConfiguration
			}

			continue
		}

		fields = append(fields, pluginapi.DecisionFactInputFieldDescriptor{Name: name, Kind: fieldKind})
	}

	return fields, nil
}

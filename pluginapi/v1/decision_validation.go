// Copyright (C) 2026 Christian Roessner
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

package pluginapi

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	maximumDecisionNamespaceLength = 64
	maximumDecisionActionLength    = 64
	maximumDecisionFactNameLength  = 192
	maximumDecisionLocalFactLength = 121
	maximumDecisionEnumMembers     = 64
	maximumDecisionEnumBytes       = 64 * 1024
	decisionLuaFactQualifier       = "lua"
)

// ValidateDecisionTargetSelector checks one exact namespace/action capability reference.
func ValidateDecisionTargetSelector(target DecisionTargetSelector) error {
	return validateDecisionTargetSelector(target)
}

// ValidateDecisionFactProviderDescriptor checks one complete fact-provider capability.
func ValidateDecisionFactProviderDescriptor(descriptor DecisionFactProviderDescriptor) error {
	if !validDecisionNamespace(descriptor.Namespace) {
		return invalidDecisionContract("fact provider namespace", "must be an exact canonical namespace")
	}

	if err := ValidateComponentName(descriptor.Name); err != nil {
		return invalidDecisionContract("fact provider name", err.Error())
	}

	if descriptor.Timeout <= 0 || descriptor.Timeout > MaximumDecisionFactProviderTimeout {
		return invalidDecisionContract("fact provider timeout", "must be positive and host-bounded")
	}

	if err := validateDecisionTargets(descriptor.Targets, "fact provider targets"); err != nil {
		return err
	}

	return validateDecisionFactOutputs(descriptor.Outputs)
}

// ValidateDecisionEffectProviderDescriptor checks one complete effect-provider capability.
func ValidateDecisionEffectProviderDescriptor(descriptor DecisionEffectProviderDescriptor) error {
	if !validDecisionNamespace(descriptor.Namespace) {
		return invalidDecisionContract("effect provider namespace", "must be an exact canonical namespace")
	}

	if err := ValidateComponentName(descriptor.Name); err != nil {
		return invalidDecisionContract("effect provider name", err.Error())
	}

	if len(descriptor.Effects) == 0 || len(descriptor.Effects) > maximumDecisionDefinitions {
		return invalidDecisionContract("effects", "must contain a bounded non-empty definition set")
	}

	seen := make(map[string]struct{}, len(descriptor.Effects))
	for index, effect := range descriptor.Effects {
		if err := validateDecisionEffectDescriptor(effect, index); err != nil {
			return err
		}

		if _, exists := seen[effect.Name]; exists {
			return invalidDecisionContract("effects", "contains a duplicate local effect name")
		}

		seen[effect.Name] = struct{}{}
	}

	return nil
}

// ValidateDecisionFactResult checks local outputs against one declared provider capability.
func ValidateDecisionFactResult(descriptor DecisionFactProviderDescriptor, result DecisionFactResult) error {
	if err := ValidateDecisionFactProviderDescriptor(descriptor); err != nil {
		return err
	}

	if result.ErrorClass != "" {
		if !result.ErrorClass.IsValid() || len(result.Facts) != 0 {
			return invalidDecisionContract("fact result", "failure class must be valid and exclusive with facts")
		}

		return nil
	}

	if len(result.Facts) > len(descriptor.Outputs) {
		return invalidDecisionContract("fact result", "contains more values than declared outputs")
	}

	definitions := make(map[string]DecisionFactOutputDescriptor, len(descriptor.Outputs))
	for _, output := range descriptor.Outputs {
		definitions[output.Name] = output
	}

	return validateDecisionFactOutputValues(definitions, result.Facts)
}

// ValidateDecisionEffectResult checks the closed outcome and safe failure vocabulary.
func ValidateDecisionEffectResult(result DecisionEffectResult) error {
	if !result.Outcome.IsValid() {
		return invalidDecisionContract("effect result outcome", "must use a closed outcome value")
	}

	if result.Outcome == DecisionEffectOutcomeSucceeded {
		if result.ErrorClass != "" {
			return invalidDecisionContract("effect result", "successful outcomes cannot carry an error class")
		}

		return nil
	}

	if !result.ErrorClass.IsValid() {
		return invalidDecisionContract("effect result", "failed or unknown outcomes require a safe error class")
	}

	return nil
}

// validateDecisionTargetSelector checks one exact target without normalization.
func validateDecisionTargetSelector(target DecisionTargetSelector) error {
	if !validDecisionNamespace(target.Namespace) || !validDecisionAction(target.Action) {
		return invalidDecisionContract("target", "must contain an exact namespace and action")
	}

	return nil
}

// validateDecisionTargets checks a bounded de-duplicated capability allowlist.
func validateDecisionTargets(targets []DecisionTargetSelector, field string) error {
	if len(targets) == 0 || len(targets) > maximumDecisionDefinitions {
		return invalidDecisionContract(field, "must contain a bounded non-empty target set")
	}

	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if err := validateDecisionTargetSelector(target); err != nil {
			return err
		}

		identity := target.Namespace + "/" + target.Action
		if _, exists := seen[identity]; exists {
			return invalidDecisionContract(field, "contains a duplicate target")
		}

		seen[identity] = struct{}{}
	}

	return nil
}

// validateDecisionFactOutputs checks local names, categories, kinds, bounds, and duplicates.
func validateDecisionFactOutputs(outputs []DecisionFactOutputDescriptor) error {
	if len(outputs) == 0 || len(outputs) > maximumDecisionDefinitions {
		return invalidDecisionContract("fact outputs", "must contain a bounded non-empty output set")
	}

	seen := make(map[string]struct{}, len(outputs))
	for _, output := range outputs {
		if !validDecisionLocalFactName(output.Name) || !output.Category.IsValid() || !output.Kind.IsValid() {
			return invalidDecisionContract("fact outputs", "contains an invalid local name, category, or kind")
		}

		if !validDecisionValueBounds(output.Kind, output.MaxLength, output.MaxItems, output.MaxBytes) {
			return invalidDecisionContract("fact outputs", "contains bounds incompatible with its value kind")
		}

		if _, exists := seen[output.Name]; exists {
			return invalidDecisionContract("fact outputs", "contains a duplicate local output name")
		}

		seen[output.Name] = struct{}{}
	}

	return nil
}

// validateDecisionEffectDescriptor checks one local effect definition.
func validateDecisionEffectDescriptor(effect DecisionEffectDescriptor, index int) error {
	field := fmt.Sprintf("effects[%d]", index)
	if !validDecisionAction(effect.Name) || !effect.Execution.IsValid() {
		return invalidDecisionContract(field, "must declare an exact local name and host execution class")
	}

	if err := validateDecisionTargets(effect.Targets, field+".targets"); err != nil {
		return err
	}

	return validateDecisionEffectParameters(effect.Parameters, field+".parameters")
}

// validateDecisionEffectParameters checks typed parameter declarations and duplicates.
func validateDecisionEffectParameters(parameters []DecisionEffectParameterDescriptor, field string) error {
	if len(parameters) > maximumDecisionEffectParameters {
		return invalidDecisionContract(field, "contains too many parameter definitions")
	}

	seen := make(map[string]struct{}, len(parameters))
	for _, parameter := range parameters {
		if err := validateDecisionEffectParameter(parameter, field); err != nil {
			return err
		}

		if _, exists := seen[parameter.Name]; exists {
			return invalidDecisionContract(field, "contains a duplicate parameter name")
		}

		seen[parameter.Name] = struct{}{}
	}

	return nil
}

// validateDecisionEffectParameter checks one typed bounded parameter declaration.
func validateDecisionEffectParameter(parameter DecisionEffectParameterDescriptor, field string) error {
	if !validDecisionAction(parameter.Name) || !parameter.Kind.IsValid() || parameter.Kind == DecisionValueKindRecords {
		return invalidDecisionContract(field, "contains an invalid parameter name or kind")
	}

	if !validDecisionValueBounds(parameter.Kind, parameter.MaxLength, parameter.MaxItems, parameter.MaxBytes) {
		return invalidDecisionContract(field, "contains bounds incompatible with its value kind")
	}

	if (parameter.NonEmpty || len(parameter.AllowedStrings) > 0) && parameter.Kind != DecisionValueKindString {
		return invalidDecisionContract(field, "non-empty and enum constraints require string kind")
	}

	return validateDecisionAllowedStrings(parameter, field)
}

// validateDecisionAllowedStrings checks one exact bounded string enum.
func validateDecisionAllowedStrings(parameter DecisionEffectParameterDescriptor, field string) error {
	if len(parameter.AllowedStrings) > maximumDecisionEnumMembers {
		return invalidDecisionContract(field, "contains too many allowed string values")
	}

	seen := make(map[string]struct{}, len(parameter.AllowedStrings))
	totalBytes := 0

	for _, value := range parameter.AllowedStrings {
		if value == "" || !utf8.ValidString(value) || len(value) > parameter.MaxLength {
			return invalidDecisionContract(field, "contains an invalid or out-of-bounds allowed string")
		}

		if _, exists := seen[value]; exists {
			return invalidDecisionContract(field, "contains a duplicate allowed string")
		}

		if len(value) > maximumDecisionEnumBytes-totalBytes {
			return invalidDecisionContract(field, "allowed strings exceed the aggregate byte bound")
		}

		seen[value] = struct{}{}
		totalBytes += len(value)
	}

	return nil
}

// validateDecisionFactOutputValues checks declared names, duplicates, kinds, and size bounds.
func validateDecisionFactOutputValues(
	definitions map[string]DecisionFactOutputDescriptor,
	values []DecisionFactOutput,
) error {
	seen := make(map[string]struct{}, len(values))

	for _, output := range values {
		definition, exists := definitions[output.Name]
		if !exists || !validDecisionLocalFactName(output.Name) || !output.Value.valid() {
			return invalidDecisionContract("fact result", "contains an undeclared name or invalid value")
		}

		if _, duplicate := seen[output.Name]; duplicate {
			return invalidDecisionContract("fact result", "contains a duplicate output")
		}

		if output.Value.Kind() != definition.Kind || !decisionValueWithinBounds(output.Value, definition) {
			return invalidDecisionContract("fact result", "value does not match its declared kind and bounds")
		}

		seen[output.Name] = struct{}{}
	}

	return nil
}

// decisionValueWithinBounds checks one strict value against its fact output descriptor.
func decisionValueWithinBounds(value DecisionValue, descriptor DecisionFactOutputDescriptor) bool {
	switch descriptor.Kind {
	case DecisionValueKindString:
		text, _ := value.StringValue()

		return len(text) <= descriptor.MaxLength
	case DecisionValueKindStrings:
		values, _ := value.Strings()
		if len(values) > descriptor.MaxItems {
			return false
		}

		return !slices.ContainsFunc(values, func(text string) bool {
			return len(text) > descriptor.MaxLength
		})
	case DecisionValueKindBytes:
		bytes, _ := value.Bytes()

		return len(bytes) <= descriptor.MaxBytes
	default:
		return true
	}
}

// validDecisionValueBounds enforces exact kind-specific size bounds.
func validDecisionValueBounds(kind DecisionValueKind, maxLength int, maxItems int, maxBytes int) bool {
	if maxLength < 0 || maxItems < 0 || maxBytes < 0 {
		return false
	}

	switch kind {
	case DecisionValueKindString:
		return validDecisionStringBounds(maxLength, maxItems, maxBytes)
	case DecisionValueKindStrings:
		return validDecisionStringListBounds(maxLength, maxItems, maxBytes)
	case DecisionValueKindBytes:
		return validDecisionBytesBounds(maxLength, maxItems, maxBytes)
	case DecisionValueKindBoolean,
		DecisionValueKindInteger,
		DecisionValueKindDouble,
		DecisionValueKindTimestamp,
		DecisionValueKindRecords:
		return validDecisionScalarBounds(maxLength, maxItems, maxBytes)
	default:
		return false
	}
}

// validDecisionStringBounds requires only a positive string length bound.
func validDecisionStringBounds(maxLength int, maxItems int, maxBytes int) bool {
	return maxLength > 0 && maxItems == 0 && maxBytes == 0
}

// validDecisionStringListBounds requires positive list and member bounds.
func validDecisionStringListBounds(maxLength int, maxItems int, maxBytes int) bool {
	return maxLength > 0 && maxItems > 0 && maxBytes == 0
}

// validDecisionBytesBounds requires only a positive byte bound.
func validDecisionBytesBounds(maxLength int, maxItems int, maxBytes int) bool {
	return maxLength == 0 && maxItems == 0 && maxBytes > 0
}

// validDecisionScalarBounds rejects size bounds for scalar values.
func validDecisionScalarBounds(maxLength int, maxItems int, maxBytes int) bool {
	return maxLength == 0 && maxItems == 0 && maxBytes == 0
}

// validDecisionNamespace enforces exact lowercase dotted namespace grammar.
func validDecisionNamespace(value string) bool {
	return validDecisionSegments(value, '.', false, maximumDecisionNamespaceLength, false)
}

// validDecisionAction enforces exact lowercase action and local-name grammar.
func validDecisionAction(value string) bool {
	if len(value) == 0 || len(value) > maximumDecisionActionLength {
		return false
	}

	separator := false

	for index := range len(value) {
		current := value[index]
		switch {
		case decisionWordCharacter(current):
			separator = false
		case current == '-' || current == '_':
			if index == 0 || index == len(value)-1 || separator {
				return false
			}

			separator = true
		default:
			return false
		}
	}

	return true
}

// validDecisionFactName checks one full canonical admitted fact identity.
func validDecisionFactName(value string) bool {
	return validDecisionSegments(value, '.', true, maximumDecisionFactNameLength, true)
}

// validDecisionLocalFactName checks one unqualified provider-local fact name.
func validDecisionLocalFactName(value string) bool {
	if !validDecisionSegments(value, '.', true, maximumDecisionLocalFactLength, false) {
		return false
	}

	first, _, _ := strings.Cut(value, ".")

	return first != PluginPolicyAttributePrefix && first != decisionLuaFactQualifier
}

// validDecisionSegments checks bounded canonical lowercase identifier segments.
func validDecisionSegments(
	value string,
	delimiter byte,
	allowHyphen bool,
	maximumLength int,
	requireDelimiter bool,
) bool {
	if len(value) == 0 || len(value) > maximumLength || requireDelimiter && !strings.ContainsRune(value, rune(delimiter)) {
		return false
	}

	segments := strings.Split(value, string(delimiter))
	for _, segment := range segments {
		if !validDecisionSegment(segment, allowHyphen) {
			return false
		}
	}

	return true
}

// validDecisionSegment checks one lowercase ASCII identifier segment.
func validDecisionSegment(value string, allowHyphen bool) bool {
	if value == "" {
		return false
	}

	for index := range len(value) {
		current := value[index]
		if decisionWordCharacter(current) || current == '_' || allowHyphen && current == '-' {
			continue
		}

		return false
	}

	return true
}

// decisionWordCharacter reports whether one byte is a lowercase ASCII word character.
func decisionWordCharacter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

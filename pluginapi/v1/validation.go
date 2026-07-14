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
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
)

var (
	// ErrUnsupportedAPIVersion is returned when plugin metadata uses a different API version.
	ErrUnsupportedAPIVersion = errors.New("unsupported plugin API version")

	// ErrInvalidName is returned when a public plugin module or component name is invalid.
	ErrInvalidName = errors.New("invalid plugin name")

	// ErrInvalidMetadata is returned when plugin metadata is incomplete or invalid.
	ErrInvalidMetadata = errors.New("invalid plugin metadata")

	// ErrInvalidScope is returned when hook authorization contains an invalid OAuth scope token.
	ErrInvalidScope = errors.New("invalid OAuth scope token")

	// ErrInvalidMetricDefinition is returned when an exact compatibility metric contract is invalid.
	ErrInvalidMetricDefinition = errors.New("invalid compatibility metric definition")

	// ErrInvalidTraceScope is returned when an exact compatibility instrumentation scope is invalid.
	ErrInvalidTraceScope = errors.New("invalid compatibility trace scope")
)

var pluginNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,62}$`)

var metricNamePattern = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

var traceScopePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_./-]{0,254}$`)

var backendAttributeNamePattern = regexp.MustCompile(`^[!-~]+$`)

var reservedDebugModuleNames = map[string]struct{}{
	"account":                   {},
	"action":                    {},
	"all":                       {},
	"auth":                      {},
	"brute_force":               {},
	"cache":                     {},
	"cookie":                    {},
	"environment":               {},
	"http":                      {},
	"idp":                       {},
	"jwt":                       {},
	"ldap":                      {},
	"ldappool":                  {},
	"lua":                       {},
	"none":                      {},
	PluginPolicyAttributePrefix: {},
	"policy":                    {},
	"rbl":                       {},
	"statistics":                {},
	"subject":                   {},
	"tolerate":                  {},
	"webauthn":                  {},
	"whitelist":                 {},
}

// ValidateAPIVersion checks that version exactly matches this package contract.
func ValidateAPIVersion(version string) error {
	if version != APIVersion {
		return fmt.Errorf("%w: got %q, want %q", ErrUnsupportedAPIVersion, version, APIVersion)
	}

	return nil
}

// ValidateModuleName checks a configured plugin module instance name.
func ValidateModuleName(name string) error {
	return validatePluginName("module", name)
}

// ValidateComponentName checks a plugin-local component name.
func ValidateComponentName(name string) error {
	return validatePluginName("component", name)
}

// ValidateDebugModuleName checks a plugin-local debug module name.
func ValidateDebugModuleName(name string) error {
	if err := validatePluginName("debug module", name); err != nil {
		return err
	}

	if _, reserved := reservedDebugModuleNames[name]; reserved {
		return fmt.Errorf("%w: debug module %q is reserved", ErrInvalidName, name)
	}

	return nil
}

// ValidateBackendAttributeName checks a backend attribute name used in backend results.
func ValidateBackendAttributeName(name string) error {
	if !backendAttributeNamePattern.MatchString(name) {
		return fmt.Errorf("%w: backend attribute %q must be printable ASCII without spaces", ErrInvalidName, name)
	}

	return nil
}

// ValidateScopeToken checks the RFC 6749 scope-token grammar.
func ValidateScopeToken(scope string) error {
	if scope == "" {
		return fmt.Errorf("%w: scope must not be empty", ErrInvalidScope)
	}

	for _, character := range scope {
		if character < 0x21 || character > 0x7E || character == 0x22 || character == 0x5C {
			return fmt.Errorf("%w: scope %q contains a disallowed character", ErrInvalidScope, scope)
		}
	}

	return nil
}

// NormalizeHookRequiredScopes trims, validates, de-duplicates, and copies hook scopes.
func NormalizeHookRequiredScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, nil
	}

	if len(scopes) > MaxHookRequiredScopes {
		return nil, fmt.Errorf("%w: at most %d scopes are allowed", ErrInvalidScope, MaxHookRequiredScopes)
	}

	normalized := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))

	for index, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if err := ValidateScopeToken(scope); err != nil {
			return nil, fmt.Errorf("required scope %d: %w", index, err)
		}

		if _, exists := seen[scope]; exists {
			continue
		}

		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}

	return normalized, nil
}

// ValidateQualifiedComponentName checks a fully qualified module.component name.
func ValidateQualifiedComponentName(name string) error {
	module, component, ok := strings.Cut(name, ".")
	if !ok || module == "" || component == "" || strings.Contains(component, ".") {
		return fmt.Errorf("%w: qualified component name %q must use <module>.<component>", ErrInvalidName, name)
	}

	if err := ValidateModuleName(module); err != nil {
		return err
	}

	if err := ValidateComponentName(component); err != nil {
		return err
	}

	return nil
}

// ValidatePluginDebugSelector checks the operator-facing plugin debug selector grammar.
func ValidatePluginDebugSelector(selector string) error {
	parts := strings.Split(selector, ".")
	switch len(parts) {
	case 1:
		if selector == PluginPolicyAttributePrefix {
			return nil
		}
	case 2:
		if parts[0] == PluginPolicyAttributePrefix && ValidateModuleName(parts[1]) == nil {
			return nil
		}
	case 3:
		if parts[0] != PluginPolicyAttributePrefix {
			break
		}

		if err := ValidateModuleName(parts[1]); err != nil {
			return err
		}

		if err := ValidateDebugModuleName(parts[2]); err != nil {
			return err
		}

		return nil
	}

	return fmt.Errorf("%w: plugin debug selector %q must use plugin, plugin.<module>, or plugin.<module>.<debug_module>", ErrInvalidName, selector)
}

// IsPluginDebugSelector reports whether value starts with the plugin selector namespace.
func IsPluginDebugSelector(value string) bool {
	return value == PluginPolicyAttributePrefix || strings.HasPrefix(value, PluginPolicyAttributePrefix+".")
}

// PluginDebugModuleSelector joins and validates a module-level plugin debug selector.
func PluginDebugModuleSelector(module string) (string, error) {
	if err := ValidateModuleName(module); err != nil {
		return "", err
	}

	return PluginPolicyAttributePrefix + "." + module, nil
}

// PluginDebugSubmoduleSelector joins and validates a plugin-local debug selector.
func PluginDebugSubmoduleSelector(module string, name string) (string, error) {
	if err := ValidateModuleName(module); err != nil {
		return "", err
	}

	if err := ValidateDebugModuleName(name); err != nil {
		return "", err
	}

	return PluginPolicyAttributePrefix + "." + module + "." + name, nil
}

// QualifiedComponentName joins and validates a module-local component reference.
func QualifiedComponentName(module string, component string) (string, error) {
	if err := ValidateModuleName(module); err != nil {
		return "", err
	}

	if err := ValidateComponentName(component); err != nil {
		return "", err
	}

	return module + "." + component, nil
}

// ValidateMetadata checks the public metadata required before plugin registration.
func ValidateMetadata(metadata Metadata) error {
	if err := ValidateAPIVersion(metadata.APIVersion); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidMetadata, err)
	}

	if strings.TrimSpace(metadata.Name) == "" {
		return fmt.Errorf("%w: name is empty", ErrInvalidMetadata)
	}

	if strings.TrimSpace(metadata.Version) == "" {
		return fmt.Errorf("%w: version is empty", ErrInvalidMetadata)
	}

	return nil
}

// validatePluginName applies the strict public plugin name grammar.
func validatePluginName(kind string, name string) error {
	if !pluginNamePattern.MatchString(name) {
		return fmt.Errorf("%w: %s %q must match [a-z0-9][a-z0-9_]{0,62}", ErrInvalidName, kind, name)
	}

	return nil
}

// ValidateCompatibilityMetric validates one exact value-only collector contract.
func ValidateCompatibilityMetric(definition MetricDefinition) error {
	if !definition.Compatibility {
		return fmt.Errorf("%w: compatibility marker is required", ErrInvalidMetricDefinition)
	}

	if !validCompatibilityMetricType(definition.Type) {
		return fmt.Errorf("%w: unsupported type %q", ErrInvalidMetricDefinition, definition.Type)
	}

	if !metricNamePattern.MatchString(definition.Name) {
		return fmt.Errorf("%w: invalid name %q", ErrInvalidMetricDefinition, definition.Name)
	}

	if strings.TrimSpace(definition.Help) == "" {
		return fmt.Errorf("%w: help must not be empty", ErrInvalidMetricDefinition)
	}

	if err := validateCompatibilityMetricLabels(definition.Labels); err != nil {
		return err
	}

	return validateCompatibilityMetricBuckets(definition.Type, definition.Buckets)
}

// validCompatibilityMetricType reports whether the exact collector type is supported.
func validCompatibilityMetricType(metricType MetricType) bool {
	switch metricType {
	case MetricTypeCounter, MetricTypeGauge, MetricTypeHistogram, MetricTypeSummary:
		return true
	default:
		return false
	}
}

// validateCompatibilityMetricLabels checks exact label names and uniqueness.
func validateCompatibilityMetricLabels(labels []string) error {
	seen := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		if label == "plugin_scope" || !metricNamePattern.MatchString(label) {
			return fmt.Errorf("%w: invalid label %q", ErrInvalidMetricDefinition, label)
		}

		if _, exists := seen[label]; exists {
			return fmt.Errorf("%w: duplicate label %q", ErrInvalidMetricDefinition, label)
		}

		seen[label] = struct{}{}
	}

	return nil
}

// validateCompatibilityMetricBuckets checks histogram-only ordering and finite values.
func validateCompatibilityMetricBuckets(metricType MetricType, buckets []float64) error {
	if metricType != MetricTypeHistogram && len(buckets) > 0 {
		return fmt.Errorf("%w: buckets require histogram type", ErrInvalidMetricDefinition)
	}

	previous := 0.0
	for index, bucket := range buckets {
		if bucket <= 0 || math.IsNaN(bucket) || math.IsInf(bucket, 0) || (index > 0 && bucket <= previous) {
			return fmt.Errorf("%w: buckets must be finite, positive, and strictly increasing", ErrInvalidMetricDefinition)
		}

		previous = bucket
	}

	return nil
}

// ValidateCompatibilityTraceScope validates one exact instrumentation scope.
func ValidateCompatibilityTraceScope(scope string) error {
	if !traceScopePattern.MatchString(scope) {
		return fmt.Errorf("%w: scope %q must match [a-zA-Z0-9][a-zA-Z0-9_./-]{0,254}", ErrInvalidTraceScope, scope)
	}

	return nil
}

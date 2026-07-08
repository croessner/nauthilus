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
)

var pluginNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,62}$`)

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

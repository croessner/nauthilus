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

package runtime

import (
	"fmt"
	"sort"
	"strings"
)

// NativeComponentBindingInput carries one process-lifetime native component owner.
type NativeComponentBindingInput struct {
	Value         any
	QualifiedName string
	Kind          string
}

// NativeModuleBindingInput carries one immutable native module capability snapshot.
type NativeModuleBindingInput struct {
	Components     []NativeComponentBindingInput
	Capabilities   []string
	ModuleName     string
	ArtifactPath   string
	ArtifactDigest string
}

// NativeComponentBinding is one generation-owned native component reference.
type NativeComponentBinding struct {
	value         any
	qualifiedName string
	kind          string
}

// NativeModuleBinding owns detached capability metadata and process-lifetime component references.
type NativeModuleBinding struct {
	components     map[string]NativeComponentBinding
	capabilities   []string
	moduleName     string
	artifactPath   string
	artifactDigest string
}

// Value returns the already loaded process-lifetime component owner.
func (b NativeComponentBinding) Value() any {
	return b.value
}

// QualifiedName returns the stable host-qualified component identity.
func (b NativeComponentBinding) QualifiedName() string {
	return b.qualifiedName
}

// Kind returns the closed native extension-point kind.
func (b NativeComponentBinding) Kind() string {
	return b.kind
}

// ModuleName returns the configured module identity.
func (b NativeModuleBinding) ModuleName() string {
	return b.moduleName
}

// ArtifactPath returns the canonical process-loaded artifact path.
func (b NativeModuleBinding) ArtifactPath() string {
	return b.artifactPath
}

// ArtifactDigest returns the process-loaded artifact identity.
func (b NativeModuleBinding) ArtifactDigest() string {
	return b.artifactDigest
}

// Capabilities returns a detached sorted capability list.
func (b NativeModuleBinding) Capabilities() []string {
	return append([]string(nil), b.capabilities...)
}

// ComponentIDs returns deterministic captured component identities.
func (b NativeModuleBinding) ComponentIDs() []string {
	return sortedBindingIDs(b.components)
}

// Components returns a detached index over process-lifetime component owners.
func (b NativeModuleBinding) Components() map[string]NativeComponentBinding {
	return cloneMapValues(b.components)
}

// newNativeModuleBindings validates and deeply owns one module binding batch.
func newNativeModuleBindings(
	inputs []NativeModuleBindingInput,
) (map[string]NativeModuleBinding, error) {
	bindings := make(map[string]NativeModuleBinding, len(inputs))

	for _, input := range inputs {
		if strings.TrimSpace(input.ModuleName) == "" || strings.TrimSpace(input.ArtifactPath) == "" ||
			strings.TrimSpace(input.ArtifactDigest) == "" {
			return nil, fmt.Errorf("%w: native module identity is incomplete", ErrInvalidGenerationBinding)
		}

		if _, exists := bindings[input.ModuleName]; exists {
			return nil, fmt.Errorf(
				"%w: duplicate native module %q",
				ErrInvalidGenerationBinding,
				input.ModuleName,
			)
		}

		capabilities, err := normalizedNativeCapabilities(input.Capabilities)
		if err != nil {
			return nil, fmt.Errorf("native module %q: %w", input.ModuleName, err)
		}

		components, err := newNativeComponentBindings(input.Components)
		if err != nil {
			return nil, fmt.Errorf("native module %q: %w", input.ModuleName, err)
		}

		bindings[input.ModuleName] = NativeModuleBinding{
			components:     components,
			capabilities:   capabilities,
			moduleName:     input.ModuleName,
			artifactPath:   input.ArtifactPath,
			artifactDigest: input.ArtifactDigest,
		}
	}

	return bindings, nil
}

// newNativeComponentBindings validates and owns one native component index.
func newNativeComponentBindings(
	inputs []NativeComponentBindingInput,
) (map[string]NativeComponentBinding, error) {
	bindings := make(map[string]NativeComponentBinding, len(inputs))

	for _, input := range inputs {
		if nilInterface(input.Value) || strings.TrimSpace(input.QualifiedName) == "" ||
			strings.TrimSpace(input.Kind) == "" {
			return nil, fmt.Errorf("%w: native component is incomplete", ErrInvalidGenerationBinding)
		}

		if _, exists := bindings[input.QualifiedName]; exists {
			return nil, fmt.Errorf(
				"%w: duplicate native component %q",
				ErrInvalidGenerationBinding,
				input.QualifiedName,
			)
		}

		bindings[input.QualifiedName] = NativeComponentBinding{
			value:         input.Value,
			qualifiedName: input.QualifiedName,
			kind:          input.Kind,
		}
	}

	return bindings, nil
}

// normalizedNativeCapabilities validates, sorts, and owns one capability set.
func normalizedNativeCapabilities(capabilities []string) ([]string, error) {
	result := append([]string(nil), capabilities...)
	sort.Strings(result)

	for index, capability := range result {
		if strings.TrimSpace(capability) == "" {
			return nil, fmt.Errorf("%w: native capability is empty", ErrInvalidGenerationBinding)
		}

		if index > 0 && result[index-1] == capability {
			return nil, fmt.Errorf(
				"%w: duplicate native capability %q",
				ErrInvalidGenerationBinding,
				capability,
			)
		}
	}

	return result, nil
}

// cloneNativeModuleBindings detaches every mutable native binding index and slice.
func cloneNativeModuleBindings(
	bindings map[string]NativeModuleBinding,
) map[string]NativeModuleBinding {
	result := make(map[string]NativeModuleBinding, len(bindings))
	for id, binding := range bindings {
		binding.components = cloneMapValues(binding.components)
		binding.capabilities = append([]string(nil), binding.capabilities...)
		result[id] = binding
	}

	return result
}

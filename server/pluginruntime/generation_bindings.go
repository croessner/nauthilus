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

package pluginruntime

import (
	"fmt"
	"slices"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
)

// GenerationBindings is an immutable native module view captured from process-lifetime plugins.
type GenerationBindings struct {
	modules []GenerationModuleBinding
}

// GenerationModuleBinding owns one generation's detached capabilities and component bindings.
type GenerationModuleBinding struct {
	components       []pluginregistry.Component
	policyAttributes []policyregistry.AttributeDefinition
	capabilities     []pluginapi.Capability
	artifactPath     string
	configuredPath   string
	moduleName       string
	artifactDigest   pluginloader.ArtifactDigest
}

// CaptureGenerationBindings detaches loaded native capabilities from mutable loader slices.
func CaptureGenerationBindings(instances []pluginloader.ModuleInstance) (*GenerationBindings, error) {
	modules := make([]GenerationModuleBinding, 0, len(instances))
	seen := make(map[string]struct{}, len(instances))

	for _, instance := range instances {
		if !instance.IsRegistered() {
			continue
		}

		name := instance.ModuleName
		if name == "" {
			name = instance.Module.Name
		}

		if name == "" || instance.ArtifactPath == "" {
			return nil, fmt.Errorf("%w: native module identity is incomplete", ErrRestartRequired)
		}

		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("%w: duplicate native module %q", ErrRestartRequired, name)
		}

		seen[name] = struct{}{}

		digest := instance.ArtifactDigest
		if digest == (pluginloader.ArtifactDigest{}) {
			var err error

			digest, err = pluginloader.DigestArtifact(instance.ArtifactPath)
			if err != nil {
				return nil, fmt.Errorf("%w: native module %q artifact identity: %v", ErrRestartRequired, name, err)
			}
		}

		configuredPath := instance.Module.Path
		if configuredPath == "" {
			configuredPath = instance.ArtifactPath
		}

		modules = append(modules, GenerationModuleBinding{
			components:       cloneGenerationComponents(instance.Descriptors),
			policyAttributes: cloneGenerationPolicyAttributes(instance.PolicyAttributes),
			capabilities:     slices.Clone(instance.Capabilities),
			artifactPath:     instance.ArtifactPath,
			configuredPath:   configuredPath,
			moduleName:       name,
			artifactDigest:   digest,
		})
	}

	return &GenerationBindings{modules: modules}, nil
}

// Modules returns detached native module bindings in configured order.
func (b *GenerationBindings) Modules() []GenerationModuleBinding {
	if b == nil {
		return nil
	}

	modules := make([]GenerationModuleBinding, 0, len(b.modules))
	for _, module := range b.modules {
		modules = append(modules, module.clone())
	}

	return modules
}

// ValidateArtifacts rejects replacement or removal of process-lifetime native binaries.
func (b *GenerationBindings) ValidateArtifacts() error {
	if b == nil {
		return nil
	}

	for _, module := range b.modules {
		if err := module.validateArtifact(module.configuredPath); err != nil {
			return err
		}

		if module.configuredPath == module.artifactPath {
			continue
		}

		if err := module.validateArtifact(module.artifactPath); err != nil {
			return err
		}
	}

	return nil
}

// validateArtifact compares one configured or canonical path with the loaded binary identity.
func (b GenerationModuleBinding) validateArtifact(path string) error {
	digest, err := pluginloader.DigestArtifact(path)
	if err != nil {
		return fmt.Errorf(
			"%w: native module %q artifact is unavailable: %v",
			ErrRestartRequired,
			b.moduleName,
			err,
		)
	}

	if digest != b.artifactDigest {
		return fmt.Errorf(
			"%w: native module %q artifact was replaced",
			ErrRestartRequired,
			b.moduleName,
		)
	}

	return nil
}

// ModuleName returns the configured native module identity.
func (b GenerationModuleBinding) ModuleName() string {
	return b.moduleName
}

// ArtifactPath returns the canonical loaded artifact path.
func (b GenerationModuleBinding) ArtifactPath() string {
	return b.artifactPath
}

// ArtifactDigest returns the immutable loaded artifact identity.
func (b GenerationModuleBinding) ArtifactDigest() pluginloader.ArtifactDigest {
	return b.artifactDigest
}

// Capabilities returns a detached capability grant list.
func (b GenerationModuleBinding) Capabilities() []pluginapi.Capability {
	return slices.Clone(b.capabilities)
}

// Components returns detached descriptors over the same process-lifetime component owners.
func (b GenerationModuleBinding) Components() []pluginregistry.Component {
	return cloneGenerationComponents(b.components)
}

// PolicyAttributes returns detached native policy metadata captured with this module.
func (b GenerationModuleBinding) PolicyAttributes() []policyregistry.AttributeDefinition {
	return cloneGenerationPolicyAttributes(b.policyAttributes)
}

// clone detaches all mutable module binding metadata.
func (b GenerationModuleBinding) clone() GenerationModuleBinding {
	b.components = cloneGenerationComponents(b.components)
	b.policyAttributes = cloneGenerationPolicyAttributes(b.policyAttributes)
	b.capabilities = slices.Clone(b.capabilities)

	return b
}

// cloneGenerationPolicyAttributes detaches registry metadata from loader-owned slices and maps.
func cloneGenerationPolicyAttributes(
	attributes []policyregistry.AttributeDefinition,
) []policyregistry.AttributeDefinition {
	result := make([]policyregistry.AttributeDefinition, 0, len(attributes))
	for _, definition := range attributes {
		result = append(result, policyregistry.CloneDefinition(definition))
	}

	return result
}

// cloneGenerationComponents detaches descriptor slices while preserving process-lifetime values.
func cloneGenerationComponents(components []pluginregistry.Component) []pluginregistry.Component {
	result := make([]pluginregistry.Component, len(components))
	for index, component := range components {
		result[index] = component.Clone()
	}

	return result
}

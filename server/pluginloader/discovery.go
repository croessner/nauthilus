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

package pluginloader

import (
	"errors"
	"slices"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/pluginregistry"
)

// DiscoveryDocument is a machine-readable snapshot of registered native plugins.
type DiscoveryDocument struct {
	Modules []DiscoveryModule `json:"modules"`
}

// DiscoveryModule describes one configured plugin module without plugin-owned config.
type DiscoveryModule struct {
	Metadata             DiscoveryMetadata      `json:"metadata"`
	Components           []DiscoveryComponent   `json:"components,omitempty"`
	RequiredCapabilities []pluginapi.Capability `json:"required_capabilities,omitempty"`
	Name                 string                 `json:"name"`
	Type                 string                 `json:"type,omitempty"`
	Status               ModuleStatus           `json:"status"`
	ArtifactPath         string                 `json:"artifact_path,omitempty"`
	Signer               string                 `json:"signer,omitempty"`
	FailureStep          string                 `json:"failure_step,omitempty"`
	Optional             bool                   `json:"optional"`
	ChecksumConfigured   bool                   `json:"checksum_configured"`
	SignatureConfigured  bool                   `json:"signature_configured"`
}

// DiscoveryMetadata exposes plugin product metadata and build diagnostics.
type DiscoveryMetadata struct {
	Build        pluginapi.BuildInfo    `json:"build"`
	Name         string                 `json:"name,omitempty"`
	Version      string                 `json:"version,omitempty"`
	APIVersion   string                 `json:"api_version,omitempty"`
	Description  string                 `json:"description,omitempty"`
	DocsURL      string                 `json:"docs_url,omitempty"`
	Features     []pluginapi.Feature    `json:"features,omitempty"`
	Capabilities []pluginapi.Capability `json:"capabilities,omitempty"`
}

// DiscoveryComponent describes one registered component descriptor.
type DiscoveryComponent struct {
	Source        *DiscoverySourceDescriptor     `json:"source,omitempty"`
	Hook          *DiscoveryHookDescriptor       `json:"hook,omitempty"`
	QualifiedName string                         `json:"qualified_name"`
	ModuleName    string                         `json:"module_name"`
	Name          string                         `json:"name"`
	Kind          pluginregistry.ComponentKind   `json:"kind"`
	Origin        pluginregistry.ComponentOrigin `json:"origin"`
}

// DiscoverySourceDescriptor describes dependency-scheduled source metadata.
type DiscoverySourceDescriptor struct {
	Requires    []string              `json:"requires,omitempty"`
	After       []string              `json:"after,omitempty"`
	Name        string                `json:"name"`
	Timeout     time.Duration         `json:"timeout"`
	Priority    int                   `json:"priority"`
	AbortPolicy pluginapi.AbortPolicy `json:"abort_policy"`
}

// DiscoveryHookDescriptor describes HTTP hook routing metadata.
type DiscoveryHookDescriptor struct {
	Name         string              `json:"name"`
	Method       string              `json:"method"`
	Path         string              `json:"path"`
	Alias        string              `json:"alias,omitempty"`
	Scope        pluginapi.HookScope `json:"scope"`
	Auth         pluginapi.HookAuth  `json:"auth"`
	Timeout      time.Duration       `json:"timeout"`
	MaxBodyBytes int64               `json:"max_body_bytes"`
}

// Discovery returns registered native plugin metadata and component descriptors.
func (s *State) Discovery() DiscoveryDocument {
	if s == nil {
		return DiscoveryDocument{}
	}

	modules := make([]DiscoveryModule, 0, len(s.instances))
	for _, instance := range s.Instances() {
		modules = append(modules, discoveryModule(instance))
	}

	return DiscoveryDocument{Modules: modules}
}

// discoveryModule converts one module instance without exposing plugin-owned config.
func discoveryModule(instance ModuleInstance) DiscoveryModule {
	module := DiscoveryModule{
		Metadata:             discoveryMetadata(instance.Metadata),
		Components:           discoveryComponents(instance.Descriptors),
		RequiredCapabilities: slices.Clone(instance.Capabilities),
		Name:                 instance.ModuleName,
		Type:                 instance.Module.Type,
		Status:               instance.Status,
		ArtifactPath:         instance.ArtifactPath,
		Signer:               instance.Module.Signer,
		FailureStep:          moduleFailureStep(instance.RegistrationError),
		Optional:             instance.Optional,
		ChecksumConfigured:   instance.Module.Checksum != "",
		SignatureConfigured:  instance.Module.Signature != "",
	}
	if module.Name == "" {
		module.Name = instance.Module.Name
	}

	return module
}

// discoveryMetadata converts public metadata while preserving copy semantics.
func discoveryMetadata(metadata pluginapi.Metadata) DiscoveryMetadata {
	metadata.Build.BuildTags = slices.Clone(metadata.Build.BuildTags)

	return DiscoveryMetadata{
		Build:        metadata.Build,
		Name:         metadata.Name,
		Version:      metadata.Version,
		APIVersion:   metadata.APIVersion,
		Description:  metadata.Description,
		DocsURL:      metadata.DocsURL,
		Features:     slices.Clone(metadata.Features),
		Capabilities: slices.Clone(metadata.Capabilities),
	}
}

// discoveryComponents converts registered component descriptors into JSON-safe values.
func discoveryComponents(components []pluginregistry.Component) []DiscoveryComponent {
	if len(components) == 0 {
		return nil
	}

	discovered := make([]DiscoveryComponent, 0, len(components))
	for _, component := range components {
		discovered = append(discovered, discoveryComponent(component))
	}

	return discovered
}

// discoveryComponent converts one registered descriptor without retaining component code.
func discoveryComponent(component pluginregistry.Component) DiscoveryComponent {
	discovered := DiscoveryComponent{
		QualifiedName: component.QualifiedName,
		ModuleName:    component.ModuleName,
		Name:          component.LocalName,
		Kind:          component.Kind,
		Origin:        component.Origin,
	}

	switch component.Kind {
	case pluginregistry.ComponentKindEnvironmentSource, pluginregistry.ComponentKindSubjectSource:
		discovered.Source = discoverySourceDescriptor(component.SourceDescriptor)
	case pluginregistry.ComponentKindHook:
		discovered.Hook = discoveryHookDescriptor(component.HookDescriptor)
	}

	return discovered
}

// discoverySourceDescriptor converts source scheduling metadata for discovery output.
func discoverySourceDescriptor(descriptor pluginapi.SourceDescriptor) *DiscoverySourceDescriptor {
	return &DiscoverySourceDescriptor{
		Requires:    slices.Clone(descriptor.Requires),
		After:       slices.Clone(descriptor.After),
		Name:        descriptor.Name,
		Timeout:     descriptor.Timeout,
		Priority:    descriptor.Priority,
		AbortPolicy: descriptor.AbortPolicy,
	}
}

// discoveryHookDescriptor converts HTTP hook metadata for discovery output.
func discoveryHookDescriptor(descriptor pluginapi.HookDescriptor) *DiscoveryHookDescriptor {
	return &DiscoveryHookDescriptor{
		Name:         descriptor.Name,
		Method:       descriptor.Method,
		Path:         descriptor.Path,
		Alias:        descriptor.Alias,
		Scope:        descriptor.Scope,
		Auth:         descriptor.Auth,
		Timeout:      descriptor.Timeout,
		MaxBodyBytes: descriptor.MaxBodyBytes,
	}
}

// moduleFailureStep exposes the failed loader step without serializing raw plugin errors.
func moduleFailureStep(err error) string {
	var moduleErr *ModuleError
	if errors.As(err, &moduleErr) {
		return moduleErr.Step
	}

	return ""
}

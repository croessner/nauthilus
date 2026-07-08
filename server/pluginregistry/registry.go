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

// Package pluginregistry records native plugin declarations before runtime execution is enabled.
package pluginregistry

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
)

var (
	// ErrNilComponent is returned when a plugin registers a nil component.
	ErrNilComponent = errors.New("plugin component is nil")

	// ErrDuplicateComponent is returned when a fully qualified component name already exists.
	ErrDuplicateComponent = errors.New("duplicate plugin component")

	// ErrCapabilityNotAllowed is returned when module config does not allow a required capability.
	ErrCapabilityNotAllowed = errors.New("plugin capability is not allowed")

	// ErrInvalidDescriptor is returned when a registered component descriptor is invalid.
	ErrInvalidDescriptor = errors.New("invalid plugin component descriptor")

	// ErrInvalidPolicyAttribute is returned when a plugin policy attribute cannot be converted.
	ErrInvalidPolicyAttribute = errors.New("invalid plugin policy attribute")
)

// ComponentKind identifies one plugin extension point family.
type ComponentKind string

const (
	// ComponentKindInitTask identifies an init task component.
	ComponentKindInitTask ComponentKind = "init_task"

	// ComponentKindEnvironmentSource identifies an environment source component.
	ComponentKindEnvironmentSource ComponentKind = "environment_source"

	// ComponentKindSubjectSource identifies a subject source component.
	ComponentKindSubjectSource ComponentKind = "subject_source"

	// ComponentKindBackend identifies a backend component.
	ComponentKindBackend ComponentKind = "backend"

	// ComponentKindObligationTarget identifies an obligation target component.
	ComponentKindObligationTarget ComponentKind = "obligation_target"

	// ComponentKindPostActionTarget identifies a post-action target component.
	ComponentKindPostActionTarget ComponentKind = "post_action_target"

	// ComponentKindHook identifies a hook component.
	ComponentKindHook ComponentKind = "hook"
)

// ComponentOrigin identifies which integration surface registered a component.
type ComponentOrigin string

const (
	// ComponentOriginNative identifies components registered by native Go plugins.
	ComponentOriginNative ComponentOrigin = "go"

	// ComponentOriginLua identifies components adapted from existing Lua configuration.
	ComponentOriginLua ComponentOrigin = "lua"
)

const (
	defaultSourceAbortPolicy = pluginapi.AbortPolicyNone
)

// Component describes one registered plugin component without enabling execution.
type Component struct {
	Value            any
	SourceDescriptor pluginapi.SourceDescriptor
	HookDescriptor   pluginapi.HookDescriptor
	QualifiedName    string
	ModuleName       string
	LocalName        string
	Kind             ComponentKind
	Origin           ComponentOrigin
}

// PolicyAttributeRegistrar accepts converted policy attributes during registrar commit.
type PolicyAttributeRegistrar interface {
	Register(policyregistry.AttributeDefinition) error
}

// RegistryOption customizes a component registry.
type RegistryOption func(*Registry)

// Registry stores fully qualified plugin component declarations.
type Registry struct {
	policyAttributeRegistrar PolicyAttributeRegistrar
	components               map[string]Component
	byKind                   map[ComponentKind][]string
	policyAttributes         map[string]policyregistry.AttributeDefinition
	policyAttributeOrder     []string
	order                    []string
}

// NewRegistry returns an empty plugin component registry.
func NewRegistry(options ...RegistryOption) *Registry {
	registry := &Registry{
		components:       make(map[string]Component),
		byKind:           make(map[ComponentKind][]string),
		policyAttributes: make(map[string]policyregistry.AttributeDefinition),
	}
	for _, option := range options {
		option(registry)
	}

	return registry
}

// WithPolicyAttributeRegistrar forwards committed plugin policy attributes to the policy registry.
func WithPolicyAttributeRegistrar(registrar PolicyAttributeRegistrar) RegistryOption {
	return func(registry *Registry) {
		registry.policyAttributeRegistrar = registrar
	}
}

// NewRegistrar creates a registrar scoped to one configured module instance.
func (r *Registry) NewRegistrar(module config.PluginModule) *Registrar {
	if r == nil {
		r = NewRegistry()
	}

	return &Registrar{
		localNames: make(map[string]struct{}),
		registry:   r,
		module:     module,
		config:     NewConfigView(module.Config),
	}
}

// Components returns registered components in registration order.
func (r *Registry) Components() []Component {
	if r == nil || len(r.order) == 0 {
		return nil
	}

	components := make([]Component, 0, len(r.order))
	for _, name := range r.order {
		components = append(components, r.components[name])
	}

	return components
}

// ComponentsByKind returns registered components of one kind in registration order.
func (r *Registry) ComponentsByKind(kind ComponentKind) []Component {
	if r == nil {
		return nil
	}

	names := r.byKind[kind]
	if len(names) == 0 {
		return nil
	}

	components := make([]Component, 0, len(names))
	for _, name := range names {
		components = append(components, r.components[name])
	}

	return components
}

// InitTasks returns registered init task components.
func (r *Registry) InitTasks() []Component {
	return r.ComponentsByKind(ComponentKindInitTask)
}

// EnvironmentSources returns registered environment source components.
func (r *Registry) EnvironmentSources() []Component {
	return r.ComponentsByKind(ComponentKindEnvironmentSource)
}

// SubjectSources returns registered subject source components.
func (r *Registry) SubjectSources() []Component {
	return r.ComponentsByKind(ComponentKindSubjectSource)
}

// Backends returns registered backend components.
func (r *Registry) Backends() []Component {
	return r.ComponentsByKind(ComponentKindBackend)
}

// ObligationTargets returns registered obligation target components.
func (r *Registry) ObligationTargets() []Component {
	return r.ComponentsByKind(ComponentKindObligationTarget)
}

// PostActionTargets returns registered post-action target components.
func (r *Registry) PostActionTargets() []Component {
	return r.ComponentsByKind(ComponentKindPostActionTarget)
}

// Hooks returns registered hook components.
func (r *Registry) Hooks() []Component {
	return r.ComponentsByKind(ComponentKindHook)
}

// PolicyAttributes returns plugin-registered policy attributes in registration order.
func (r *Registry) PolicyAttributes() []policyregistry.AttributeDefinition {
	if r == nil || len(r.policyAttributeOrder) == 0 {
		return nil
	}

	attributes := make([]policyregistry.AttributeDefinition, 0, len(r.policyAttributeOrder))
	for _, id := range r.policyAttributeOrder {
		attributes = append(attributes, policyregistry.CloneDefinition(r.policyAttributes[id]))
	}

	return attributes
}

// Lookup returns a registered component by fully qualified name.
func (r *Registry) Lookup(qualifiedName string) (Component, bool) {
	if r == nil {
		return Component{}, false
	}

	component, ok := r.components[qualifiedName]

	return component, ok
}

// register stores one committed component after collision checks.
func (r *Registry) register(component Component) error {
	qualifiedName, err := pluginapi.QualifiedComponentName(component.ModuleName, component.LocalName)
	if err != nil {
		return err
	}

	if _, exists := r.components[qualifiedName]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateComponent, qualifiedName)
	}

	component.QualifiedName = qualifiedName
	r.components[qualifiedName] = component
	r.byKind[component.Kind] = append(r.byKind[component.Kind], qualifiedName)
	r.order = append(r.order, qualifiedName)

	return nil
}

// registerPolicyAttribute commits one converted plugin policy attribute.
func (r *Registry) registerPolicyAttribute(definition policyregistry.AttributeDefinition) error {
	if _, exists := r.policyAttributes[definition.ID]; exists {
		return fmt.Errorf("%w: %s", policyregistry.ErrDuplicateAttributeID, definition.ID)
	}

	if r.policyAttributeRegistrar != nil {
		if err := r.policyAttributeRegistrar.Register(definition); err != nil {
			return err
		}
	}

	r.policyAttributes[definition.ID] = policyregistry.CloneDefinition(definition)
	r.policyAttributeOrder = append(r.policyAttributeOrder, definition.ID)

	return nil
}

// Registrar records declarations for one module instance.
type Registrar struct {
	localNames       map[string]struct{}
	registry         *Registry
	config           *ConfigView
	module           config.PluginModule
	policyAttributes []policyregistry.AttributeDefinition
	capabilities     []pluginapi.Capability
	components       []Component
}

var _ pluginapi.Registrar = (*Registrar)(nil)

// Config returns the plugin-owned configuration subtree for the module instance.
func (r *Registrar) Config() pluginapi.ConfigView {
	if r == nil || r.config == nil {
		return NewConfigView(nil)
	}

	return r.config
}

// RequireCapability records one capability required by the module instance.
func (r *Registrar) RequireCapability(capability pluginapi.Capability) error {
	if r == nil {
		return fmt.Errorf("%w: registrar is nil", ErrCapabilityNotAllowed)
	}

	if !r.capabilityAllowed(capability) {
		return fmt.Errorf("%w: module %q requires %q", ErrCapabilityNotAllowed, r.module.Name, capability)
	}

	if !slices.Contains(r.capabilities, capability) {
		r.capabilities = append(r.capabilities, capability)
	}

	return nil
}

// RegisterInitTask records an init task declaration.
func (r *Registrar) RegisterInitTask(task pluginapi.InitTask) error {
	if task == nil {
		return ErrNilComponent
	}

	return r.registerComponent(Component{
		Value:      task,
		ModuleName: r.module.Name,
		LocalName:  task.Name(),
		Kind:       ComponentKindInitTask,
		Origin:     ComponentOriginNative,
	})
}

// RegisterEnvironmentSource records an environment source declaration.
func (r *Registrar) RegisterEnvironmentSource(source pluginapi.EnvironmentSource) error {
	if source == nil {
		return ErrNilComponent
	}

	return r.registerSourceComponent(source, source.Descriptor(), ComponentKindEnvironmentSource)
}

// RegisterSubjectSource records a subject source declaration.
func (r *Registrar) RegisterSubjectSource(source pluginapi.SubjectSource) error {
	if source == nil {
		return ErrNilComponent
	}

	return r.registerSourceComponent(source, source.Descriptor(), ComponentKindSubjectSource)
}

// registerSourceComponent records a dependency-scheduled source component.
func (r *Registrar) registerSourceComponent(
	source any,
	descriptor pluginapi.SourceDescriptor,
	kind ComponentKind,
) error {
	descriptor, err := validateSourceDescriptor(r.module.Name, descriptor)
	if err != nil {
		return err
	}

	return r.registerComponent(Component{
		Value:            source,
		SourceDescriptor: descriptor,
		ModuleName:       r.module.Name,
		LocalName:        descriptor.Name,
		Kind:             kind,
		Origin:           ComponentOriginNative,
	})
}

// RegisterBackend records a backend declaration.
func (r *Registrar) RegisterBackend(backend pluginapi.Backend) error {
	if backend == nil {
		return ErrNilComponent
	}

	return r.registerComponent(Component{
		Value:      backend,
		ModuleName: r.module.Name,
		LocalName:  backend.Name(),
		Kind:       ComponentKindBackend,
		Origin:     ComponentOriginNative,
	})
}

// RegisterObligationTarget records an obligation target declaration.
func (r *Registrar) RegisterObligationTarget(target pluginapi.ObligationTarget) error {
	if target == nil {
		return ErrNilComponent
	}

	return r.registerComponent(Component{
		Value:      target,
		ModuleName: r.module.Name,
		LocalName:  target.Name(),
		Kind:       ComponentKindObligationTarget,
		Origin:     ComponentOriginNative,
	})
}

// RegisterPostActionTarget records a post-action target declaration.
func (r *Registrar) RegisterPostActionTarget(target pluginapi.PostActionTarget) error {
	if target == nil {
		return ErrNilComponent
	}

	return r.registerComponent(Component{
		Value:      target,
		ModuleName: r.module.Name,
		LocalName:  target.Name(),
		Kind:       ComponentKindPostActionTarget,
		Origin:     ComponentOriginNative,
	})
}

// RegisterHook records a hook declaration.
func (r *Registrar) RegisterHook(hook pluginapi.Hook) error {
	if hook == nil {
		return ErrNilComponent
	}

	descriptor, err := validateHookDescriptor(hook.Descriptor())
	if err != nil {
		return err
	}

	return r.registerComponent(Component{
		Value:          hook,
		HookDescriptor: descriptor,
		ModuleName:     r.module.Name,
		LocalName:      descriptor.Name,
		Kind:           ComponentKindHook,
		Origin:         ComponentOriginNative,
	})
}

// RegisterPolicyAttribute records a native plugin policy attribute declaration.
func (r *Registrar) RegisterPolicyAttribute(definition pluginapi.AttributeDefinition) error {
	converted, err := convertPolicyAttribute(definition)
	if err != nil {
		return err
	}

	r.policyAttributes = append(r.policyAttributes, converted)

	return nil
}

// Capabilities returns capabilities required during registration.
func (r *Registrar) Capabilities() []pluginapi.Capability {
	if r == nil || len(r.capabilities) == 0 {
		return nil
	}

	return slices.Clone(r.capabilities)
}

// Components returns components declared through this registrar.
func (r *Registrar) Components() []Component {
	if r == nil || len(r.components) == 0 {
		return nil
	}

	return slices.Clone(r.components)
}

// PolicyAttributes returns policy attributes declared through this registrar.
func (r *Registrar) PolicyAttributes() []policyregistry.AttributeDefinition {
	if r == nil || len(r.policyAttributes) == 0 {
		return nil
	}

	attributes := make([]policyregistry.AttributeDefinition, 0, len(r.policyAttributes))
	for _, definition := range r.policyAttributes {
		attributes = append(attributes, policyregistry.CloneDefinition(definition))
	}

	return attributes
}

// Commit publishes staged registrar declarations to the shared registry.
func (r *Registrar) Commit() error {
	if r == nil || r.registry == nil {
		return errors.New("plugin registrar is not initialized")
	}

	if err := r.preflightComponents(); err != nil {
		return err
	}

	for _, definition := range r.policyAttributes {
		if err := r.registry.registerPolicyAttribute(definition); err != nil {
			return err
		}
	}

	for _, component := range r.components {
		if err := r.registry.register(component); err != nil {
			return err
		}
	}

	return nil
}

// capabilityAllowed applies allowlist and default-sensitive capability rules.
func (r *Registrar) capabilityAllowed(capability pluginapi.Capability) bool {
	if r.module.AllowCapabilities != nil {
		return slices.Contains(r.module.AllowCapabilities, capability)
	}

	return !sensitiveCapability(capability)
}

// registerComponent records a component in module-local state.
func (r *Registrar) registerComponent(component Component) error {
	if r == nil || r.registry == nil {
		return errors.New("plugin registrar is not initialized")
	}

	qualifiedName, err := pluginapi.QualifiedComponentName(component.ModuleName, component.LocalName)
	if err != nil {
		return err
	}

	if _, exists := r.registry.Lookup(qualifiedName); exists {
		return fmt.Errorf("%w: %s", ErrDuplicateComponent, qualifiedName)
	}

	if _, exists := r.localNames[qualifiedName]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateComponent, qualifiedName)
	}

	component.QualifiedName = qualifiedName
	r.localNames[qualifiedName] = struct{}{}
	r.components = append(r.components, component)

	return nil
}

// preflightComponents checks global component collisions before commit mutates the registry.
func (r *Registrar) preflightComponents() error {
	for _, component := range r.components {
		qualifiedName, err := pluginapi.QualifiedComponentName(component.ModuleName, component.LocalName)
		if err != nil {
			return err
		}

		if _, exists := r.registry.Lookup(qualifiedName); exists {
			return fmt.Errorf("%w: %s", ErrDuplicateComponent, qualifiedName)
		}
	}

	return nil
}

// sensitiveCapability reports whether a capability is default-deny without an allowlist.
func sensitiveCapability(capability pluginapi.Capability) bool {
	return capability == pluginapi.CapabilityCredentials || capability == pluginapi.CapabilityMail
}

// validateSourceDescriptor checks a dependency-scheduled source descriptor.
func validateSourceDescriptor(module string, descriptor pluginapi.SourceDescriptor) (pluginapi.SourceDescriptor, error) {
	if err := pluginapi.ValidateComponentName(descriptor.Name); err != nil {
		return pluginapi.SourceDescriptor{}, fmt.Errorf("%w: %w", ErrInvalidDescriptor, err)
	}

	if descriptor.Timeout < 0 {
		return pluginapi.SourceDescriptor{}, fmt.Errorf("%w: source %q timeout must not be negative", ErrInvalidDescriptor, descriptor.Name)
	}

	if descriptor.AbortPolicy == "" {
		descriptor.AbortPolicy = defaultSourceAbortPolicy
	}

	if !abortPolicyValid(descriptor.AbortPolicy) {
		return pluginapi.SourceDescriptor{}, fmt.Errorf("%w: source %q abort policy %q is not supported", ErrInvalidDescriptor, descriptor.Name, descriptor.AbortPolicy)
	}

	var err error
	if descriptor.Requires, err = qualifyDependencyNames(module, descriptor.Requires); err != nil {
		return pluginapi.SourceDescriptor{}, err
	}

	if descriptor.After, err = qualifyDependencyNames(module, descriptor.After); err != nil {
		return pluginapi.SourceDescriptor{}, err
	}

	return descriptor, nil
}

// validateHookDescriptor checks HTTP hook routing metadata.
func validateHookDescriptor(descriptor pluginapi.HookDescriptor) (pluginapi.HookDescriptor, error) {
	if err := pluginapi.ValidateComponentName(descriptor.Name); err != nil {
		return pluginapi.HookDescriptor{}, fmt.Errorf("%w: %w", ErrInvalidDescriptor, err)
	}

	if strings.TrimSpace(descriptor.Method) == "" {
		return pluginapi.HookDescriptor{}, fmt.Errorf("%w: hook %q method must not be empty", ErrInvalidDescriptor, descriptor.Name)
	}

	if !strings.HasPrefix(descriptor.Path, "/") {
		return pluginapi.HookDescriptor{}, fmt.Errorf("%w: hook %q path must be absolute", ErrInvalidDescriptor, descriptor.Name)
	}

	if descriptor.Alias != "" && !strings.HasPrefix(descriptor.Alias, "/") {
		return pluginapi.HookDescriptor{}, fmt.Errorf("%w: hook %q alias must be absolute", ErrInvalidDescriptor, descriptor.Name)
	}

	if descriptor.Timeout < 0 {
		return pluginapi.HookDescriptor{}, fmt.Errorf("%w: hook %q timeout must not be negative", ErrInvalidDescriptor, descriptor.Name)
	}

	if descriptor.MaxBodyBytes < 0 {
		return pluginapi.HookDescriptor{}, fmt.Errorf("%w: hook %q max body bytes must not be negative", ErrInvalidDescriptor, descriptor.Name)
	}

	if !hookScopeValid(descriptor.Scope) {
		return pluginapi.HookDescriptor{}, fmt.Errorf("%w: hook %q scope %q is not supported", ErrInvalidDescriptor, descriptor.Name, descriptor.Scope)
	}

	if !hookAuthValid(descriptor.Auth) {
		return pluginapi.HookDescriptor{}, fmt.Errorf("%w: hook %q auth %q is not supported", ErrInvalidDescriptor, descriptor.Name, descriptor.Auth)
	}

	return descriptor, nil
}

// qualifyDependencyNames resolves module-local dependencies to fully qualified names.
func qualifyDependencyNames(module string, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}

	qualified := make([]string, 0, len(names))
	for _, name := range names {
		qualifiedName, err := qualifyDependencyName(module, name)
		if err != nil {
			return nil, err
		}

		qualified = append(qualified, qualifiedName)
	}

	return qualified, nil
}

// qualifyDependencyName resolves one dependency name without normalizing invalid input.
func qualifyDependencyName(module string, name string) (string, error) {
	if strings.Contains(name, ".") {
		if err := pluginapi.ValidateQualifiedComponentName(name); err != nil {
			return "", fmt.Errorf("%w: dependency %q: %w", ErrInvalidDescriptor, name, err)
		}

		return name, nil
	}

	qualifiedName, err := pluginapi.QualifiedComponentName(module, name)
	if err != nil {
		return "", fmt.Errorf("%w: dependency %q: %w", ErrInvalidDescriptor, name, err)
	}

	return qualifiedName, nil
}

// abortPolicyValid reports whether a source abort policy is supported.
func abortPolicyValid(policy pluginapi.AbortPolicy) bool {
	switch policy {
	case pluginapi.AbortPolicyNone,
		pluginapi.AbortPolicySource,
		pluginapi.AbortPolicyRequest:
		return true
	default:
		return false
	}
}

// hookScopeValid reports whether a hook scope is supported.
func hookScopeValid(scope pluginapi.HookScope) bool {
	switch scope {
	case pluginapi.HookScopePublic,
		pluginapi.HookScopeInternal,
		pluginapi.HookScopeAdmin:
		return true
	default:
		return false
	}
}

// hookAuthValid reports whether a hook auth mode is supported.
func hookAuthValid(auth pluginapi.HookAuth) bool {
	switch auth {
	case pluginapi.HookAuthNone,
		pluginapi.HookAuthToken,
		pluginapi.HookAuthSession,
		pluginapi.HookAuthAdmin:
		return true
	default:
		return false
	}
}

// convertPolicyAttribute converts public plugin policy metadata to the internal registry type.
func convertPolicyAttribute(definition pluginapi.AttributeDefinition) (policyregistry.AttributeDefinition, error) {
	id := strings.TrimSpace(definition.ID)
	if id == "" {
		return policyregistry.AttributeDefinition{}, fmt.Errorf("%w: id must not be empty", ErrInvalidPolicyAttribute)
	}

	stage, err := convertPolicyStage(definition.Stage)
	if err != nil {
		return policyregistry.AttributeDefinition{}, fmt.Errorf("%w: attribute %s: %w", ErrInvalidPolicyAttribute, id, err)
	}

	operations, err := convertPolicyOperations(definition.Operations)
	if err != nil {
		return policyregistry.AttributeDefinition{}, fmt.Errorf("%w: attribute %s: %w", ErrInvalidPolicyAttribute, id, err)
	}

	category, err := convertAttributeCategory(definition.Category)
	if err != nil {
		return policyregistry.AttributeDefinition{}, fmt.Errorf("%w: attribute %s: %w", ErrInvalidPolicyAttribute, id, err)
	}

	valueType, err := convertAttributeType(definition.Type)
	if err != nil {
		return policyregistry.AttributeDefinition{}, fmt.Errorf("%w: attribute %s: %w", ErrInvalidPolicyAttribute, id, err)
	}

	details, err := convertDetails(definition.Details)
	if err != nil {
		return policyregistry.AttributeDefinition{}, fmt.Errorf("%w: attribute %s: %w", ErrInvalidPolicyAttribute, id, err)
	}

	return policyregistry.AttributeDefinition{
		ID:            id,
		Description:   definition.Description,
		Stage:         stage,
		Operations:    operations,
		ProducerTypes: slices.Clone(definition.ProducerTypes),
		ProducerCheck: definition.ProducerCheck,
		Category:      category,
		Type:          valueType,
		Source:        policyregistry.SourcePlugin,
		Details:       details,
	}, nil
}

// convertPolicyStage maps a public plugin policy stage to the internal policy stage.
func convertPolicyStage(stage pluginapi.PolicyStage) (policy.Stage, error) {
	switch stage {
	case pluginapi.PolicyStagePreAuth:
		return policy.StagePreAuth, nil
	case pluginapi.PolicyStageAuthBackend:
		return policy.StageAuthBackend, nil
	case pluginapi.PolicyStageSubjectAnalysis:
		return policy.StageSubjectAnalysis, nil
	case pluginapi.PolicyStageAccountProvider:
		return policy.StageAccountProvider, nil
	case pluginapi.PolicyStageAuthDecision:
		return policy.StageAuthDecision, nil
	default:
		return "", fmt.Errorf("stage %q is not supported", stage)
	}
}

// convertPolicyOperations maps public plugin operations to internal policy operations.
func convertPolicyOperations(operations []pluginapi.PolicyOperation) ([]policy.Operation, error) {
	if len(operations) == 0 {
		return nil, fmt.Errorf("operations must not be empty")
	}

	converted := make([]policy.Operation, 0, len(operations))

	seen := make(map[pluginapi.PolicyOperation]struct{}, len(operations))
	for _, operation := range operations {
		if _, exists := seen[operation]; exists {
			return nil, fmt.Errorf("operation %q is duplicated", operation)
		}

		seen[operation] = struct{}{}

		switch operation {
		case pluginapi.PolicyOperationAuthenticate:
			converted = append(converted, policy.OperationAuthenticate)
		case pluginapi.PolicyOperationLookupIdentity:
			converted = append(converted, policy.OperationLookupIdentity)
		case pluginapi.PolicyOperationListAccounts:
			converted = append(converted, policy.OperationListAccounts)
		default:
			return nil, fmt.Errorf("operation %q is not supported", operation)
		}
	}

	return converted, nil
}

// convertAttributeCategory maps public plugin categories to internal categories.
func convertAttributeCategory(category pluginapi.AttributeCategory) (policyregistry.AttributeCategory, error) {
	switch category {
	case pluginapi.AttributeCategoryEnvironment:
		return policyregistry.AttributeCategoryEnvironment, nil
	case pluginapi.AttributeCategorySubject:
		return policyregistry.AttributeCategorySubject, nil
	case pluginapi.AttributeCategoryResource:
		return policyregistry.AttributeCategoryResource, nil
	default:
		return "", fmt.Errorf("category %q is not supported", category)
	}
}

// convertAttributeType maps public plugin attribute types to internal attribute types.
func convertAttributeType(valueType pluginapi.AttributeType) (policyregistry.AttributeType, error) {
	switch valueType {
	case pluginapi.AttributeTypeBool:
		return policyregistry.AttributeTypeBool, nil
	case pluginapi.AttributeTypeString:
		return policyregistry.AttributeTypeString, nil
	case pluginapi.AttributeTypeStringList:
		return policyregistry.AttributeTypeStringList, nil
	case pluginapi.AttributeTypeNumber:
		return policyregistry.AttributeTypeNumber, nil
	case pluginapi.AttributeTypeIP:
		return policyregistry.AttributeTypeIP, nil
	case pluginapi.AttributeTypeCIDR:
		return policyregistry.AttributeTypeCIDR, nil
	case pluginapi.AttributeTypeDateTime:
		return policyregistry.AttributeTypeDateTime, nil
	default:
		return "", fmt.Errorf("type %q is not supported", valueType)
	}
}

// convertDetails maps public plugin detail metadata to internal detail definitions.
func convertDetails(details map[string]pluginapi.DetailDefinition) (map[string]policyregistry.DetailDefinition, error) {
	if len(details) == 0 {
		return nil, nil
	}

	converted := make(map[string]policyregistry.DetailDefinition, len(details))
	for name, detail := range details {
		valueType, err := convertAttributeType(detail.Type)
		if err != nil {
			return nil, fmt.Errorf("detail %s: %w", name, err)
		}

		sensitivity, err := convertDetailSensitivity(detail.Sensitivity)
		if err != nil {
			return nil, fmt.Errorf("detail %s: %w", name, err)
		}

		converted[name] = policyregistry.DetailDefinition{
			Type:        valueType,
			Sensitivity: sensitivity,
			Purpose:     detail.Purpose,
			MaxLength:   detail.MaxLength,
		}
	}

	return converted, nil
}

// convertDetailSensitivity maps public plugin detail sensitivity to internal values.
func convertDetailSensitivity(sensitivity pluginapi.DetailSensitivity) (string, error) {
	switch sensitivity {
	case "":
		return policyregistry.DetailSensitivityInternal, nil
	case pluginapi.DetailSensitivityPublic:
		return policyregistry.DetailSensitivityPublic, nil
	case pluginapi.DetailSensitivityInternal:
		return policyregistry.DetailSensitivityInternal, nil
	case pluginapi.DetailSensitivitySecret:
		return policyregistry.DetailSensitivitySecret, nil
	default:
		return "", fmt.Errorf("sensitivity %q is not supported", sensitivity)
	}
}

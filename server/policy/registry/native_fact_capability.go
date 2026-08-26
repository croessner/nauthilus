// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package registry

import (
	"time"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/internal/identifier"
)

const nativeFactAuthorityPrefix = "plugin."

// NativeFactOutputCapabilityInput carries one descriptor-owned local output through the inward boundary.
type NativeFactOutputCapabilityInput struct {
	Name      string
	Category  decision.FactCategory
	Kind      decision.ValueKind
	MaxLength int
	MaxItems  int
	MaxBytes  int
}

// NativeFactProviderCapabilityInput carries one captured generic native descriptor without plugin runtime types.
type NativeFactProviderCapabilityInput struct {
	Targets        []decision.Target
	Outputs        []NativeFactOutputCapabilityInput
	ModuleName     string
	Namespace      string
	ComponentName  string
	MaximumTimeout time.Duration
}

// NativeFactProviderSelectionInput carries the exact operator-owned subset of one captured capability.
type NativeFactProviderSelectionInput struct {
	Targets       []decision.Target
	Requires      []string
	ProducedFacts []string
	Failure       ProviderFailureBehavior
	Timeout       time.Duration
	DiagnosticID  string
}

// NativeFactProviderCapability is one immutable descriptor-derived generic native fact boundary.
type NativeFactProviderCapability struct {
	targets        []decision.Target
	outputs        []ProviderFactOutput
	moduleName     string
	namespace      string
	componentName  string
	providerID     string
	maximumTimeout time.Duration
}

// NewNativeFactProviderCapability validates and owns one captured descriptor projection.
func NewNativeFactProviderCapability(
	input NativeFactProviderCapabilityInput,
) (NativeFactProviderCapability, error) {
	providerID := nativeFactProviderID(input.Namespace, input.ModuleName, input.ComponentName)
	if !identifier.Namespace(input.Namespace) || !identifier.Provider(input.ModuleName) ||
		!identifier.Provider(input.ComponentName) || !validProviderID(providerID) {
		return NativeFactProviderCapability{}, invalidNativeFactCapability(
			providerID,
			"must declare an exact namespace, module, component, and derived provider identity",
		)
	}

	if input.MaximumTimeout <= 0 || input.MaximumTimeout > maximumProviderTimeout {
		return NativeFactProviderCapability{}, invalidNativeFactCapability(
			providerID,
			"must declare a positive host-bounded maximum timeout",
		)
	}

	targets, err := cloneUniqueTargets(input.Targets, providerID+".capability.targets")
	if err != nil || len(targets) == 0 {
		return NativeFactProviderCapability{}, invalidNativeFactCapability(
			providerID,
			"must declare a non-empty exact target capability",
		)
	}

	outputs, err := nativeFactCapabilityOutputs(input.ModuleName, providerID, input.Outputs)
	if err != nil {
		return NativeFactProviderCapability{}, err
	}

	return NativeFactProviderCapability{
		targets: targets, outputs: outputs,
		moduleName: input.ModuleName, namespace: input.Namespace,
		componentName: input.ComponentName, providerID: providerID,
		maximumTimeout: input.MaximumTimeout,
	}, nil
}

// nativeFactCapabilityOutputs qualifies and validates descriptor-local output shapes.
func nativeFactCapabilityOutputs(
	moduleName string,
	providerID string,
	input []NativeFactOutputCapabilityInput,
) ([]ProviderFactOutput, error) {
	if len(input) == 0 || len(input) > maximumContributionDefinitions {
		return nil, invalidNativeFactCapability(providerID, "must declare a bounded non-empty output capability")
	}

	outputs := make([]ProviderFactOutput, 0, len(input))
	seen := make(map[string]struct{}, len(input))

	for _, configured := range input {
		factID := nativeFactPrefix(moduleName) + configured.Name
		if _, exists := seen[factID]; exists {
			return nil, newValidationError(
				ErrDuplicateDefinition,
				providerID+".capability.outputs",
				factID,
				"descriptor output occurs more than once",
			)
		}

		output, err := NewProviderFactOutput(ProviderFactOutputInput{
			ID: factID, Category: configured.Category, Kind: configured.Kind,
			MaxLength: configured.MaxLength, MaxItems: configured.MaxItems, MaxBytes: configured.MaxBytes,
		})
		if err != nil {
			return nil, err
		}

		seen[factID] = struct{}{}

		outputs = append(outputs, output)
	}

	return outputs, nil
}

// Select validates one operator schedule against this exact descriptor-derived capability.
func (c NativeFactProviderCapability) Select(
	input NativeFactProviderSelectionInput,
) (ExtensionProviderDefinition, error) {
	if !c.valid() {
		return ExtensionProviderDefinition{}, invalidNativeFactCapability(
			c.providerID,
			"capability was not constructed by its validating owner",
		)
	}

	if input.Timeout <= 0 || input.Timeout > c.maximumTimeout {
		return ExtensionProviderDefinition{}, invalidNativeFactCapability(
			c.providerID,
			"configured timeout exceeds the captured maximum",
		)
	}

	if !nativeFactTargetsCovered(input.Targets, c.targets) {
		return ExtensionProviderDefinition{}, invalidNativeFactCapability(
			c.providerID,
			"configured targets exceed the captured capability",
		)
	}

	outputs, err := c.selectedOutputs(input.ProducedFacts)
	if err != nil {
		return ExtensionProviderDefinition{}, err
	}

	definition, err := NewProviderDefinition(ProviderDefinitionInput{
		ID: c.providerID, Targets: input.Targets, Requires: input.Requires,
		ProducedFacts: input.ProducedFacts, Outputs: outputs,
		Failure: input.Failure, Timeout: input.Timeout, DiagnosticID: input.DiagnosticID,
	})
	if err != nil {
		return ExtensionProviderDefinition{}, err
	}

	return ExtensionProviderDefinition{
		Definition: definition, ProducedFactPrefix: nativeFactPrefix(c.moduleName),
	}, nil
}

// selectedOutputs resolves only exact configured output identities while preserving their order.
func (c NativeFactProviderCapability) selectedOutputs(
	producedFacts []string,
) ([]ProviderFactOutput, error) {
	if len(producedFacts) == 0 {
		return nil, invalidNativeFactCapability(c.providerID, "configured output selection is empty")
	}

	available := make(map[string]ProviderFactOutput, len(c.outputs))
	for _, output := range c.outputs {
		available[output.ID()] = output
	}

	selected := make([]ProviderFactOutput, 0, len(producedFacts))
	seen := make(map[string]struct{}, len(producedFacts))

	for _, factID := range producedFacts {
		output, exists := available[factID]
		if !exists {
			return nil, invalidNativeFactCapability(
				c.providerID,
				"configured output "+factID+" is not registered by the captured descriptor",
			)
		}

		if _, duplicate := seen[factID]; duplicate {
			return nil, newValidationError(
				ErrDuplicateDefinition,
				c.providerID+".outputs",
				factID,
				"configured output occurs more than once",
			)
		}

		seen[factID] = struct{}{}

		selected = append(selected, output)
	}

	return selected, nil
}

// ModuleName returns the exact captured native module identity.
func (c NativeFactProviderCapability) ModuleName() string {
	return c.moduleName
}

// Namespace returns the provider definition namespace owned by the captured descriptor.
func (c NativeFactProviderCapability) Namespace() string {
	return c.namespace
}

// ComponentName returns the exact captured generic fact-provider component identity.
func (c NativeFactProviderCapability) ComponentName() string {
	return c.componentName
}

// ProviderID returns the host-derived canonical provider identity.
func (c NativeFactProviderCapability) ProviderID() string {
	return c.providerID
}

// Targets returns the detached target capability allowlist.
func (c NativeFactProviderCapability) Targets() []decision.Target {
	return append([]decision.Target(nil), c.targets...)
}

// Validate confirms the immutable capability was constructed through the exact descriptor boundary.
func (c NativeFactProviderCapability) Validate() error {
	if !c.valid() {
		return invalidNativeFactCapability(
			c.providerID,
			"capability was not constructed by its validating owner",
		)
	}

	return nil
}

// valid reports whether the immutable value still satisfies its constructor identity boundary.
func (c NativeFactProviderCapability) valid() bool {
	return c.providerID == nativeFactProviderID(c.namespace, c.moduleName, c.componentName) &&
		validProviderID(c.providerID) && identifier.Provider(c.moduleName) &&
		identifier.Provider(c.componentName) && identifier.Namespace(c.namespace) &&
		len(c.targets) > 0 && len(c.outputs) > 0 &&
		c.maximumTimeout > 0 && c.maximumTimeout <= maximumProviderTimeout
}

// nativeFactTargetsCovered reports whether every configured target belongs to the descriptor capability.
func nativeFactTargetsCovered(selected []decision.Target, available []decision.Target) bool {
	if len(selected) == 0 {
		return false
	}

	allowed := make(map[string]struct{}, len(available))
	for _, target := range available {
		allowed[target.String()] = struct{}{}
	}

	seen := make(map[string]struct{}, len(selected))
	for _, target := range selected {
		validated, err := decision.NewTarget(target.Namespace(), target.Action())
		if err != nil {
			return false
		}

		if _, exists := allowed[validated.String()]; !exists {
			return false
		}

		if _, duplicate := seen[validated.String()]; duplicate {
			return false
		}

		seen[validated.String()] = struct{}{}
	}

	return true
}

// nativeFactProviderID derives one generic native provider identity without public plugin types.
func nativeFactProviderID(namespace string, moduleName string, componentName string) string {
	return namespace + "/" + nativeFactPrefix(moduleName) + componentName
}

// nativeFactPrefix returns the host-assigned fact authority prefix for one native module.
func nativeFactPrefix(moduleName string) string {
	return nativeFactAuthorityPrefix + moduleName + "."
}

// invalidNativeFactCapability returns one stable registry validation class.
func invalidNativeFactCapability(providerID string, reason string) error {
	return newValidationError(
		ErrInvalidProviderDefinition,
		"native.fact_capability",
		providerID,
		reason,
	)
}

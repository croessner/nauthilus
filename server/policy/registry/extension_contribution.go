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

package registry

import (
	"strings"

	"github.com/croessner/nauthilus/v3/server/policy/internal/identifier"
)

// ExtensionProviderDefinition binds one internal provider to its host-assigned fact authority prefix.
type ExtensionProviderDefinition struct {
	Definition         ProviderDefinition
	ProducedFactPrefix string
}

// ExtensionDefinitionContributionInput carries only extension-owned provider and effect definitions inward.
type ExtensionDefinitionContributionInput struct {
	Ownership NamespaceOwnership
	Providers []ExtensionProviderDefinition
	Effects   []EffectDefinition
}

// NewExtensionDefinitionContribution validates extension authority without exposing catalog structure.
func NewExtensionDefinitionContribution(input ExtensionDefinitionContributionInput) (DefinitionContribution, error) {
	providers, err := cloneExtensionProviders(input.Providers)
	if err != nil {
		return DefinitionContribution{}, err
	}

	return NewCompleteDefinitionContribution(DefinitionContributionInput{
		Ownership: input.Ownership,
		Providers: providers,
		Effects:   input.Effects,
	})
}

// cloneExtensionProviders validates host-assigned fact authority and detaches provider definitions.
func cloneExtensionProviders(input []ExtensionProviderDefinition) ([]ProviderDefinition, error) {
	providers := make([]ProviderDefinition, 0, len(input))
	for _, extensionProvider := range input {
		provider, err := extensionProvider.Definition.validatedClone()
		if err != nil {
			return nil, err
		}

		if err = validateProducedFactPrefix(provider, extensionProvider.ProducedFactPrefix); err != nil {
			return nil, err
		}

		providers = append(providers, provider)
	}

	return providers, nil
}

// validateProducedFactPrefix binds declared outputs to one exact host-assigned Lua or native authority.
func validateProducedFactPrefix(provider ProviderDefinition, prefix string) error {
	producedFacts := provider.ProducedFacts()
	outputs := provider.Outputs()

	if len(producedFacts) == 0 && prefix == "" {
		return nil
	}

	if len(producedFacts) == 0 || !providerOutputIDsMatch(producedFacts, outputs) || !validProducedFactPrefix(prefix) {
		return newValidationError(
			ErrInvalidProviderDefinition,
			provider.ID()+".facts",
			prefix,
			"must preserve typed outputs under one exact host-assigned Lua or native fact authority prefix",
		)
	}

	_, localIdentity, found := strings.Cut(provider.ID(), "/")
	if !found || !strings.HasPrefix(localIdentity, prefix) {
		return newValidationError(
			ErrInvalidProviderDefinition,
			provider.ID()+".facts",
			prefix,
			"must match the provider local identity authority",
		)
	}

	for _, factID := range producedFacts {
		if !strings.HasPrefix(factID, prefix) {
			return newValidationError(
				ErrInvalidProviderDefinition,
				provider.ID()+".facts",
				factID,
				"must belong to the exact host-assigned fact authority prefix "+prefix,
			)
		}
	}

	return nil
}

// validProducedFactPrefix accepts one exact lua.<authority>. or plugin.<authority>. prefix.
func validProducedFactPrefix(prefix string) bool {
	trimmed, found := strings.CutSuffix(prefix, ".")

	if !found || !identifier.Fact(trimmed+".value") {
		return false
	}

	source, authority, found := strings.Cut(trimmed, ".")

	if !found || strings.Contains(authority, ".") || !identifier.Provider(authority) {
		return false
	}

	return source == "lua" || source == "plugin"
}

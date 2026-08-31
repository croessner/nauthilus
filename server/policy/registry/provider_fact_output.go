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
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/internal/identifier"
)

// ProviderFactOutputInput carries one typed provider output through its immutable constructor.
type ProviderFactOutputInput struct {
	ID        string
	Category  decision.FactCategory
	Kind      decision.ValueKind
	MaxLength int
	MaxItems  int
	MaxBytes  int
}

// ProviderFactOutput preserves capability metadata; the active target schema remains catalog authority.
type ProviderFactOutput struct {
	id        string
	category  decision.FactCategory
	kind      decision.ValueKind
	maxLength int
	maxItems  int
	maxBytes  int
}

// NewProviderFactOutput validates one qualified provider output without activating a catalog schema.
func NewProviderFactOutput(input ProviderFactOutputInput) (ProviderFactOutput, error) {
	if !identifier.Fact(input.ID) || !input.Category.IsValid() || !input.Kind.IsValid() {
		return ProviderFactOutput{}, newValidationError(
			ErrInvalidProviderDefinition,
			"provider.outputs",
			input.ID,
			"must declare a canonical fact identity, category, and value kind",
		)
	}

	if err := validateFactBounds(FactSchemaInput{
		ID:        input.ID,
		Kind:      input.Kind,
		MaxLength: input.MaxLength,
		MaxItems:  input.MaxItems,
		MaxBytes:  input.MaxBytes,
	}); err != nil {
		return ProviderFactOutput{}, newValidationError(
			ErrInvalidProviderDefinition,
			"provider.outputs."+input.ID,
			input.ID,
			"bounds must match the exact value kind",
		)
	}

	return ProviderFactOutput{
		id:        input.ID,
		category:  input.Category,
		kind:      input.Kind,
		maxLength: input.MaxLength,
		maxItems:  input.MaxItems,
		maxBytes:  input.MaxBytes,
	}, nil
}

// ID returns the fully qualified canonical fact identity.
func (o ProviderFactOutput) ID() string {
	return o.id
}

// Category returns the immutable policy fact category.
func (o ProviderFactOutput) Category() decision.FactCategory {
	return o.category
}

// Kind returns the immutable strict value kind.
func (o ProviderFactOutput) Kind() decision.ValueKind {
	return o.kind
}

// MaxLength returns the configured string or string-member bound.
func (o ProviderFactOutput) MaxLength() int {
	return o.maxLength
}

// MaxItems returns the configured list item bound.
func (o ProviderFactOutput) MaxItems() int {
	return o.maxItems
}

// MaxBytes returns the configured byte-sequence bound.
func (o ProviderFactOutput) MaxBytes() int {
	return o.maxBytes
}

// input returns the complete constructor state for validation and cloning.
func (o ProviderFactOutput) input() ProviderFactOutputInput {
	return ProviderFactOutputInput{
		ID:        o.id,
		Category:  o.category,
		Kind:      o.kind,
		MaxLength: o.maxLength,
		MaxItems:  o.maxItems,
		MaxBytes:  o.maxBytes,
	}
}

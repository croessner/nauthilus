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
	"errors"
	"fmt"
	"slices"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

var (
	// ErrDuplicateCompiledTarget identifies repeated target records in one candidate.
	ErrDuplicateCompiledTarget = errors.New("duplicate compiled policy target")

	// ErrUnknownCompiledTarget identifies fact validation for an inactive target.
	ErrUnknownCompiledTarget = errors.New("unknown compiled policy target")
)

// TargetCatalogRecord carries one activated exact target/schema pair into the runtime candidate.
type TargetCatalogRecord struct {
	Target decision.Target
	Schema registry.SchemaDefinition
}

// CompiledSchema is an immutable request-time exact fact schema.
type CompiledSchema struct {
	identity registry.SchemaIdentity
	facts    map[string]registry.FactSchema
	ordered  []string
}

// Identity returns the exact compiled schema identity.
func (s CompiledSchema) Identity() registry.SchemaIdentity {
	return s.identity
}

// Facts returns detached fact definitions in deterministic declaration order.
func (s CompiledSchema) Facts() []registry.FactSchema {
	result := make([]registry.FactSchema, 0, len(s.ordered))
	for _, id := range s.ordered {
		result = append(result, s.facts[id])
	}

	return result
}

// ValidateFacts verifies one immutable fact set against this exact schema version.
func (s CompiledSchema) ValidateFacts(facts decision.FactSet) error {
	for _, fact := range facts.Facts() {
		definition, ok := s.facts[fact.ID()]
		if !ok {
			return schemaFactError(s.identity, fact.ID(), "fact is not declared by the selected exact schema")
		}

		if err := validateCompiledFact(definition, fact); err != nil {
			return schemaFactError(s.identity, fact.ID(), err.Error())
		}
	}

	for _, id := range s.ordered {
		definition := s.facts[id]
		if !definition.Required() {
			continue
		}

		if _, ok := facts.Get(id); !ok {
			return schemaFactError(s.identity, id, "required fact is missing")
		}
	}

	return nil
}

// clone returns a detached compiled schema.
func (s CompiledSchema) clone() CompiledSchema {
	return newCompiledSchema(s.identity, s.Facts())
}

// CompiledTarget is one immutable activated target and selected exact schema.
type CompiledTarget struct {
	target decision.Target
	schema CompiledSchema
}

// Target returns the exact activated namespace/action pair.
func (t CompiledTarget) Target() decision.Target {
	return t.target
}

// Schema returns a detached immutable selected schema.
func (t CompiledTarget) Schema() CompiledSchema {
	return t.schema.clone()
}

// clone returns a detached compiled target.
func (t CompiledTarget) clone() CompiledTarget {
	return CompiledTarget{target: t.target, schema: t.schema.clone()}
}

// TargetCatalog is an immutable off-side candidate of explicitly activated targets.
type TargetCatalog struct {
	targets map[string]CompiledTarget
}

// NewTargetCatalog validates and deeply owns activated target records.
func NewTargetCatalog(records []TargetCatalogRecord) (*TargetCatalog, error) {
	targets := make(map[string]CompiledTarget, len(records))

	for _, record := range records {
		target, err := decision.NewTarget(record.Target.Namespace(), record.Target.Action())
		if err != nil {
			return nil, err
		}

		identity := record.Schema.Identity()
		if identity.Namespace() != target.Namespace() || identity.Name() != target.Action() {
			return nil, fmt.Errorf(
				"%w: target %s cannot select schema %s",
				registry.ErrTargetSchemaMismatch,
				target.String(),
				identity.String(),
			)
		}

		if _, exists := targets[target.String()]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateCompiledTarget, target.String())
		}

		targets[target.String()] = CompiledTarget{
			target: target,
			schema: newCompiledSchema(identity, record.Schema.Facts()),
		}
	}

	return &TargetCatalog{targets: targets}, nil
}

// Len returns the number of explicitly activated targets.
func (c *TargetCatalog) Len() int {
	if c == nil {
		return 0
	}

	return len(c.targets)
}

// Lookup returns a detached compiled target by exact identity.
func (c *TargetCatalog) Lookup(target decision.Target) (CompiledTarget, bool) {
	if c == nil {
		return CompiledTarget{}, false
	}

	compiled, ok := c.targets[target.String()]
	if !ok {
		return CompiledTarget{}, false
	}

	return compiled.clone(), true
}

// ValidateFacts resolves one activated target and validates only its selected exact schema.
func (c *TargetCatalog) ValidateFacts(target decision.Target, facts decision.FactSet) error {
	compiled, ok := c.Lookup(target)
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownCompiledTarget, target.String())
	}

	return compiled.schema.ValidateFacts(facts)
}

// Clone returns a deeply detached immutable catalog candidate.
func (c *TargetCatalog) Clone() *TargetCatalog {
	if c == nil {
		return nil
	}

	targets := make(map[string]CompiledTarget, len(c.targets))
	for identity, target := range c.targets {
		targets[identity] = target.clone()
	}

	return &TargetCatalog{targets: targets}
}

// newCompiledSchema constructs a private exact-schema index from validated definitions.
func newCompiledSchema(identity registry.SchemaIdentity, facts []registry.FactSchema) CompiledSchema {
	index := make(map[string]registry.FactSchema, len(facts))
	ordered := make([]string, 0, len(facts))

	for _, fact := range facts {
		index[fact.ID()] = fact
		ordered = append(ordered, fact.ID())
	}

	return CompiledSchema{identity: identity, facts: index, ordered: ordered}
}

// validateCompiledFact enforces type, category, source, and declared bounds.
func validateCompiledFact(definition registry.FactSchema, fact decision.Fact) error {
	if fact.Category() != definition.Category() {
		return fmt.Errorf("category %q does not match %q", fact.Category(), definition.Category())
	}

	if fact.Value().Kind() != definition.Kind() {
		return fmt.Errorf("value kind %q does not match %q", fact.Value().Kind(), definition.Kind())
	}

	if !slices.Contains(definition.AllowedSources(), fact.Provenance().Source()) {
		return fmt.Errorf("source %q is not allowed", fact.Provenance().Source())
	}

	return validateCompiledFactBounds(definition, fact.Value())
}

// validateCompiledFactBounds enforces the selected definition's exact size limits.
func validateCompiledFactBounds(definition registry.FactSchema, value decision.Value) error {
	switch definition.Kind() {
	case decision.ValueKindString:
		stringValue, _ := value.StringValue()
		if len(stringValue) > definition.MaxLength() {
			return fmt.Errorf("string exceeds maximum length %d", definition.MaxLength())
		}
	case decision.ValueKindStrings:
		stringsValue, _ := value.Strings()
		if len(stringsValue) > definition.MaxItems() {
			return fmt.Errorf("string list exceeds maximum items %d", definition.MaxItems())
		}

		for _, item := range stringsValue {
			if len(item) > definition.MaxLength() {
				return fmt.Errorf("string list member exceeds maximum length %d", definition.MaxLength())
			}
		}
	case decision.ValueKindBytes:
		bytesValue, _ := value.Bytes()
		if len(bytesValue) > definition.MaxBytes() {
			return fmt.Errorf("bytes exceed maximum size %d", definition.MaxBytes())
		}
	}

	return nil
}

// schemaFactError binds validation failure to the selected exact schema identity.
func schemaFactError(identity registry.SchemaIdentity, factID string, reason string) error {
	return fmt.Errorf("%w: schema %s fact %s: %s", registry.ErrFactSchemaMismatch, identity.String(), factID, reason)
}

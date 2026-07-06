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

// Package registry contains internal policy attribute registry primitives.
package registry

import (
	"errors"
	"fmt"
	"maps"
	"sync"

	"github.com/croessner/nauthilus/v3/server/policy"
)

var (
	// ErrEmptyAttributeID is returned when an attribute definition has no ID.
	ErrEmptyAttributeID = errors.New("policy attribute ID is empty")

	// ErrDuplicateAttributeID is returned when an attribute ID is registered twice.
	ErrDuplicateAttributeID = errors.New("policy attribute ID already registered")
)

// AttributeType is the declared value type of a policy attribute or detail.
type AttributeType string

const (
	// AttributeTypeBool identifies boolean attribute values.
	AttributeTypeBool AttributeType = "bool"

	// AttributeTypeString identifies string attribute values.
	AttributeTypeString AttributeType = "string"

	// AttributeTypeStringList identifies string-list attribute values.
	AttributeTypeStringList AttributeType = "string_list"

	// AttributeTypeNumber identifies numeric attribute values.
	AttributeTypeNumber AttributeType = "number"

	// AttributeTypeIP identifies IP address attribute values.
	AttributeTypeIP AttributeType = "ip"

	// AttributeTypeCIDR identifies CIDR attribute values.
	AttributeTypeCIDR AttributeType = "cidr"

	// AttributeTypeDateTime identifies datetime attribute values.
	AttributeTypeDateTime AttributeType = "datetime"
)

// AttributeCategory identifies the XACML-style attribute category.
type AttributeCategory string

const (
	// AttributeCategoryEnvironment identifies environment attributes.
	AttributeCategoryEnvironment AttributeCategory = "environment"

	// AttributeCategorySubject identifies subject attributes.
	AttributeCategorySubject AttributeCategory = "subject"

	// AttributeCategoryResource identifies resource attributes.
	AttributeCategoryResource AttributeCategory = "resource"
)

// AttributeSource identifies the component that owns an attribute definition.
type AttributeSource string

const (
	// SourceBuiltin identifies Go-owned built-in attributes.
	SourceBuiltin AttributeSource = "builtin"

	// SourceLua identifies Lua-registered attributes.
	SourceLua AttributeSource = "lua"

	// SourcePlugin identifies native Go plugin-registered attributes.
	SourcePlugin AttributeSource = "plugin"
)

const (
	// DetailSensitivityPublic marks detail values safe for selected public output.
	DetailSensitivityPublic = "public"

	// DetailSensitivityInternal marks detail values for internal diagnostics.
	DetailSensitivityInternal = "internal"

	// DetailSensitivitySecret marks detail values that must never be exposed.
	DetailSensitivitySecret = "secret"
)

const (
	// DetailPurposeResponseMessage marks details suitable as response-message sources.
	DetailPurposeResponseMessage = "response_message"
)

// DetailDefinition describes a typed attribute detail.
type DetailDefinition struct {
	Type        AttributeType
	Sensitivity string
	Purpose     string
	MaxLength   int
}

// AttributeDefinition describes one registered policy attribute.
type AttributeDefinition struct {
	ID          string
	Description string
	Stage       policy.Stage
	Operations  []policy.Operation
	// ProducerTypes names compatible check types that can emit this attribute.
	ProducerTypes []string
	// ProducerCheck names one compiled policy check that must be active.
	ProducerCheck string
	Category      AttributeCategory
	Type          AttributeType
	Source        AttributeSource
	Details       map[string]DetailDefinition
}

// AttributeRegistry stores policy attribute definitions for snapshot building.
type AttributeRegistry struct {
	mu        sync.RWMutex
	attribute map[string]AttributeDefinition
}

// NewAttributeRegistry returns an empty attribute registry.
func NewAttributeRegistry() *AttributeRegistry {
	return &AttributeRegistry{
		attribute: make(map[string]AttributeDefinition),
	}
}

// Register adds one attribute definition.
func (r *AttributeRegistry) Register(definition AttributeDefinition) error {
	if definition.ID == "" {
		return ErrEmptyAttributeID
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.attribute[definition.ID]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateAttributeID, definition.ID)
	}

	r.attribute[definition.ID] = CloneDefinition(definition)

	return nil
}

// Lookup returns a registered attribute definition by ID.
func (r *AttributeRegistry) Lookup(id string) (AttributeDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	definition, ok := r.attribute[id]
	if !ok {
		return AttributeDefinition{}, false
	}

	return CloneDefinition(definition), true
}

// Snapshot returns a detached copy of all registered definitions.
func (r *AttributeRegistry) Snapshot() map[string]AttributeDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snapshot := make(map[string]AttributeDefinition, len(r.attribute))
	for id, definition := range r.attribute {
		snapshot[id] = CloneDefinition(definition)
	}

	return snapshot
}

// CloneDefinition returns a detached copy of an attribute definition.
func CloneDefinition(definition AttributeDefinition) AttributeDefinition {
	cloned := definition
	cloned.Operations = append([]policy.Operation(nil), definition.Operations...)
	cloned.ProducerTypes = append([]string(nil), definition.ProducerTypes...)

	if definition.Details != nil {
		cloned.Details = make(map[string]DetailDefinition, len(definition.Details))
		maps.Copy(cloned.Details, definition.Details)
	}

	return cloned
}

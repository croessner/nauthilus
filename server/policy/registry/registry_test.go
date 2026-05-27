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
	"testing"

	"github.com/croessner/nauthilus/server/policy"
)

func TestRegistryRejectsDuplicateAttributeIDs(t *testing.T) {
	registry := NewAttributeRegistry()
	definition := AttributeDefinition{
		ID:         "request.operation",
		Stage:      policy.StagePreAuth,
		Operations: []policy.Operation{policy.OperationAuthenticate},
		Type:       AttributeTypeString,
		Source:     SourceBuiltin,
	}

	if err := registry.Register(definition); err != nil {
		t.Fatalf("first register failed: %v", err)
	}

	if err := registry.Register(definition); err == nil {
		t.Fatal("second register succeeded, want duplicate error")
	}
}

func TestRegistrySnapshotIsImmutableCopy(t *testing.T) {
	registry := NewAttributeRegistry()
	definition := AttributeDefinition{
		ID:         "request.operation",
		Stage:      policy.StagePreAuth,
		Operations: []policy.Operation{policy.OperationAuthenticate},
		Type:       AttributeTypeString,
		Source:     SourceBuiltin,
	}

	if err := registry.Register(definition); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	snapshot := registry.Snapshot()
	snapshot["request.operation"] = AttributeDefinition{ID: "changed"}

	got, ok := registry.Lookup("request.operation")
	if !ok {
		t.Fatal("registered attribute missing")
	}

	if got.ID != "request.operation" {
		t.Fatalf("registry attribute ID = %q, want request.operation", got.ID)
	}
}

func TestBuiltinRequestContextAttributesAreTyped(t *testing.T) {
	registry, err := NewBuiltinAttributeRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinAttributeRegistry() error = %v", err)
	}

	tests := map[string]AttributeType{
		"request.client.ip":          AttributeTypeIP,
		"request.client.ip.present":  AttributeTypeBool,
		"request.client.ip.trusted":  AttributeTypeBool,
		"request.client.ip.source":   AttributeTypeString,
		"request.caller.ip":          AttributeTypeIP,
		"request.caller.ip.present":  AttributeTypeBool,
		"request.caller.ip.source":   AttributeTypeString,
		"request.local.ip":           AttributeTypeIP,
		"request.local.ip.present":   AttributeTypeBool,
		"request.local.port":         AttributeTypeString,
		"request.local.port.present": AttributeTypeBool,
		"request.transport.kind":     AttributeTypeString,
		"request.listener.name":      AttributeTypeString,
		"request.connection.tls":     AttributeTypeBool,
		"request.initiator.kind":     AttributeTypeString,
		"request.http.route":         AttributeTypeString,
		"request.grpc.method":        AttributeTypeString,
		"request.idp.client_id":      AttributeTypeString,
		"request.saml.sp_entity_id":  AttributeTypeString,
	}

	for attribute, want := range tests {
		t.Run(attribute, func(t *testing.T) {
			definition, ok := registry.Lookup(attribute)
			if !ok {
				t.Fatalf("missing builtin attribute %s", attribute)
			}

			if definition.Type != want {
				t.Fatalf("attribute type = %q, want %q", definition.Type, want)
			}
		})
	}
}

func TestBuiltinMasterUserAttributeIsTyped(t *testing.T) {
	registry, err := NewBuiltinAttributeRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinAttributeRegistry() error = %v", err)
	}

	definition, ok := registry.Lookup(policy.AttributeMasterUserActive)
	if !ok {
		t.Fatalf("missing builtin attribute %s", policy.AttributeMasterUserActive)
	}

	if definition.Type != AttributeTypeBool {
		t.Fatalf("attribute type = %q, want %q", definition.Type, AttributeTypeBool)
	}

	if definition.Stage != policy.StageAuthBackend {
		t.Fatalf("attribute stage = %q, want %q", definition.Stage, policy.StageAuthBackend)
	}

	if definition.Details["master_user"].Type != AttributeTypeString {
		t.Fatalf("master_user detail type = %q, want string", definition.Details["master_user"].Type)
	}
}

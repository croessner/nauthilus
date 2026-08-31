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

package lualib

import (
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	policycollection "github.com/croessner/nauthilus/v4/server/policy/collection"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyregistry "github.com/croessner/nauthilus/v4/server/policy/registry"
	"github.com/croessner/nauthilus/v4/server/policy/report"

	lua "github.com/yuin/gopher-lua"
)

func TestPolicyEmitterRecordsRegisteredLuaAttribute(t *testing.T) {
	policyCtx := policyEmitterTestContext(t, map[string]policyregistry.AttributeDefinition{
		"lua.plugin.blocklist.matched": {
			ID:         "lua.plugin.blocklist.matched",
			Stage:      policy.StagePreAuth,
			Operations: []policy.Operation{policy.OperationAuthenticate},
			Type:       policyregistry.AttributeTypeBool,
			Source:     policyregistry.SourceLua,
			Details: map[string]policyregistry.DetailDefinition{
				"status_message": {
					Type:        policyregistry.AttributeTypeString,
					Sensitivity: string(report.SensitivityPublic),
					Purpose:     string(report.PurposeResponseMessage),
					MaxLength:   128,
				},
			},
		},
	})

	L := lua.NewState()
	defer L.Close()

	L.PreloadModule(definitions.LuaModPolicy, LoaderModPolicy(policyCtx, policy.StagePreAuth))

	if err := L.DoString(`
local policy = require("nauthilus_policy")
policy.emit_attribute({
  id = "lua.plugin.blocklist.matched",
  value = true,
  details = {
    status_message = "IP address blocked",
  },
})
`); err != nil {
		t.Fatalf("policy emitter failed: %v", err)
	}

	attributeValue, ok := policyCtx.Report().Attributes["lua.plugin.blocklist.matched"]
	if !ok {
		t.Fatal("emitted attribute missing")
	}

	if attributeValue.Value != true {
		t.Fatalf("attribute value = %#v, want true", attributeValue.Value)
	}

	detail := attributeValue.Details["status_message"]
	if detail.Value != "IP address blocked" {
		t.Fatalf("status_message detail = %#v, want IP address blocked", detail.Value)
	}

	if detail.Sensitivity != report.SensitivityPublic || detail.Purpose != report.PurposeResponseMessage {
		t.Fatalf("detail metadata = %#v, want public response_message", detail)
	}
}

func TestPolicyEmitterRejectsUnknownLuaAttribute(t *testing.T) {
	policyCtx := policyEmitterTestContext(t, nil)

	L := lua.NewState()
	defer L.Close()

	L.PreloadModule(definitions.LuaModPolicy, LoaderModPolicy(policyCtx, policy.StagePreAuth))

	err := L.DoString(`
local policy = require("nauthilus_policy")
policy.emit_attribute({
  id = "lua.plugin.blocklist.matched",
  value = true,
})
`)
	if err == nil {
		t.Fatal("policy emitter error = nil, want unknown attribute rejection")
	}

	if !strings.Contains(err.Error(), "is not registered") {
		t.Fatalf("policy emitter error = %q, want registration error", err)
	}
}

func TestPolicyEmitterRejectsStageMismatch(t *testing.T) {
	policyCtx := policyEmitterTestContext(t, map[string]policyregistry.AttributeDefinition{
		"lua.plugin.geoip.rejected": {
			ID:         "lua.plugin.geoip.rejected",
			Stage:      policy.StageSubjectAnalysis,
			Operations: []policy.Operation{policy.OperationAuthenticate},
			Type:       policyregistry.AttributeTypeBool,
			Source:     policyregistry.SourceLua,
		},
	})

	L := lua.NewState()
	defer L.Close()

	L.PreloadModule(definitions.LuaModPolicy, LoaderModPolicy(policyCtx, policy.StagePreAuth))

	err := L.DoString(`
local policy = require("nauthilus_policy")
policy.emit_attribute({
  id = "lua.plugin.geoip.rejected",
  value = true,
})
`)
	if err == nil {
		t.Fatal("policy emitter error = nil, want stage rejection")
	}

	if !strings.Contains(err.Error(), "cannot be emitted from stage") {
		t.Fatalf("policy emitter error = %q, want stage error", err)
	}
}

func TestPolicyEmitterRecordsRegisteredLuaAttributesBatch(t *testing.T) {
	policyCtx := policyEmitterTestContext(t, map[string]policyregistry.AttributeDefinition{
		"lua.plugin.batch.triggered": policyEmitterAttributeDefinition("lua.plugin.batch.triggered", policyregistry.AttributeTypeBool),
		"lua.plugin.batch.count":     policyEmitterAttributeDefinition("lua.plugin.batch.count", policyregistry.AttributeTypeNumber),
	})

	L := lua.NewState()
	defer L.Close()

	L.PreloadModule(definitions.LuaModPolicy, LoaderModPolicy(policyCtx, policy.StagePreAuth))

	if err := L.DoString(`
local policy = require("nauthilus_policy")
policy.emit_attributes({
  { id = "lua.plugin.batch.triggered", value = true },
  { id = "lua.plugin.batch.count", value = 12 },
})
`); err != nil {
		t.Fatalf("policy batch emitter failed: %v", err)
	}

	attributes := policyCtx.Report().Attributes
	if got := attributes["lua.plugin.batch.triggered"].Value; got != true {
		t.Fatalf("triggered attribute value = %#v, want true", got)
	}

	if got := attributes["lua.plugin.batch.count"].Value; got != float64(12) {
		t.Fatalf("count attribute value = %#v, want 12", got)
	}
}

func TestPolicyEmitterBatchRejectsAtomically(t *testing.T) {
	policyCtx := policyEmitterTestContext(t, map[string]policyregistry.AttributeDefinition{
		"lua.plugin.batch.triggered": policyEmitterAttributeDefinition("lua.plugin.batch.triggered", policyregistry.AttributeTypeBool),
	})

	L := lua.NewState()
	defer L.Close()

	L.PreloadModule(definitions.LuaModPolicy, LoaderModPolicy(policyCtx, policy.StagePreAuth))

	err := L.DoString(`
local policy = require("nauthilus_policy")
policy.emit_attributes({
  { id = "lua.plugin.batch.triggered", value = true },
  { id = "lua.plugin.batch.unknown", value = true },
})
`)
	if err == nil {
		t.Fatal("policy batch emitter error = nil, want unknown attribute rejection")
	}

	if !strings.Contains(err.Error(), "is not registered") {
		t.Fatalf("policy batch emitter error = %q, want registration error", err)
	}

	if len(policyCtx.Report().Attributes) != 0 {
		t.Fatalf("policy batch emitter recorded attributes after rejection: %#v", policyCtx.Report().Attributes)
	}
}

func TestPolicyEmitterRecordsMasterUserAttribute(t *testing.T) {
	policyCtx := policyEmitterTestContext(t, map[string]policyregistry.AttributeDefinition{
		policy.AttributeMasterUserActive: {
			ID:         policy.AttributeMasterUserActive,
			Stage:      policy.StageAuthBackend,
			Operations: []policy.Operation{policy.OperationAuthenticate},
			Type:       policyregistry.AttributeTypeBool,
			Source:     policyregistry.SourceBuiltin,
			Details: map[string]policyregistry.DetailDefinition{
				luaPolicyDetailBackend:    {Type: policyregistry.AttributeTypeString},
				luaPolicyDetailMasterUser: {Type: policyregistry.AttributeTypeString},
				luaPolicyDetailTargetUser: {Type: policyregistry.AttributeTypeString},
			},
		},
	})

	L := lua.NewState()
	defer L.Close()

	L.PreloadModule(definitions.LuaModPolicy, LoaderModPolicy(policyCtx, policy.StageAuthBackend))

	if err := L.DoString(`
local policy = require("nauthilus_policy")
policy.emit_master_user({
  master_user = "admin@example.test",
  target_user = "alice@example.test",
})
`); err != nil {
		t.Fatalf("master-user policy emission failed: %v", err)
	}

	attributeValue, ok := policyCtx.Report().Attributes[policy.AttributeMasterUserActive]
	if !ok {
		t.Fatal("master-user attribute missing")
	}

	if attributeValue.Value != true {
		t.Fatalf("master-user attribute value = %#v, want true", attributeValue.Value)
	}

	if got := attributeValue.Details[luaPolicyDetailBackend].Value; got != luaPolicyBackendLua {
		t.Fatalf("backend detail = %#v, want %s", got, luaPolicyBackendLua)
	}

	if got := attributeValue.Details[luaPolicyDetailMasterUser].Value; got != "admin@example.test" {
		t.Fatalf("master_user detail = %#v, want admin@example.test", got)
	}

	if got := attributeValue.Details[luaPolicyDetailTargetUser].Value; got != "alice@example.test" {
		t.Fatalf("target_user detail = %#v, want alice@example.test", got)
	}
}

func policyEmitterTestContext(
	t *testing.T,
	definitions map[string]policyregistry.AttributeDefinition,
) *policycollection.DecisionContext {
	t.Helper()

	policyCtx := policycollection.NewDecisionContext(policy.OperationAuthenticate, nil, 1)

	declarations := make([]policyregistry.AuthnLuaFactDeclaration, 0, len(definitions))
	for _, definition := range definitions {
		if definition.Source != policyregistry.SourceLua {
			continue
		}

		kind, ok := policyEmitterValueKind(definition.Type)
		if !ok {
			t.Fatalf("unsupported policy emitter attribute type %q", definition.Type)
		}

		actions := make([]string, 0, len(definition.Operations))
		for _, operation := range definition.Operations {
			actions = append(actions, string(operation))
		}

		declaration, err := policyregistry.NewAuthnLuaFactDeclaration(
			policyregistry.AuthnLuaFactDeclarationInput{
				Details: definition.Details, ID: definition.ID, Description: definition.Description,
				Stage: string(definition.Stage), Actions: actions,
				Category: decision.FactCategoryEnvironment, Kind: kind, DeclaredType: definition.Type,
			},
		)
		if err != nil {
			t.Fatalf("NewAuthnLuaFactDeclaration(%s) error = %v", definition.ID, err)
		}

		declarations = append(declarations, declaration)
	}

	if err := policyCtx.AddAuthnLuaFactDeclarations(declarations); err != nil {
		t.Fatalf("AddAuthnLuaFactDeclarations() error = %v", err)
	}

	return policyCtx
}

// policyEmitterValueKind maps the closed Lua emitter type vocabulary into Decision facts.
func policyEmitterValueKind(attributeType policyregistry.AttributeType) (decision.ValueKind, bool) {
	switch attributeType {
	case policyregistry.AttributeTypeBool:
		return decision.ValueKindBoolean, true
	case policyregistry.AttributeTypeString:
		return decision.ValueKindString, true
	case policyregistry.AttributeTypeStringList:
		return decision.ValueKindStrings, true
	case policyregistry.AttributeTypeNumber:
		return decision.ValueKindDouble, true
	case policyregistry.AttributeTypeDateTime:
		return decision.ValueKindTimestamp, true
	default:
		return "", false
	}
}

// policyEmitterAttributeDefinition builds a Lua-owned attribute definition for emitter tests.
func policyEmitterAttributeDefinition(id string, attributeType policyregistry.AttributeType) policyregistry.AttributeDefinition {
	return policyregistry.AttributeDefinition{
		ID:         id,
		Stage:      policy.StagePreAuth,
		Operations: []policy.Operation{policy.OperationAuthenticate},
		Type:       attributeType,
		Source:     policyregistry.SourceLua,
	}
}

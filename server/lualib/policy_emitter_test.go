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

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	policycollection "github.com/croessner/nauthilus/v3/server/policy/collection"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"

	lua "github.com/yuin/gopher-lua"
)

func TestPolicyEmitterRecordsRegisteredLuaAttribute(t *testing.T) {
	policyCtx := policyEmitterTestContext(map[string]policyregistry.AttributeDefinition{
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
	policyCtx := policyEmitterTestContext(nil)
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
	policyCtx := policyEmitterTestContext(map[string]policyregistry.AttributeDefinition{
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

func TestPolicyEmitterRecordsMasterUserAttribute(t *testing.T) {
	policyCtx := policyEmitterTestContext(map[string]policyregistry.AttributeDefinition{
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

func policyEmitterTestContext(definitions map[string]policyregistry.AttributeDefinition) *policycollection.DecisionContext {
	if definitions == nil {
		definitions = map[string]policyregistry.AttributeDefinition{}
	}

	snapshot := &policyruntime.Snapshot{AttributeRegistry: definitions}

	return policycollection.NewDecisionContext(snapshot, policy.OperationAuthenticate, nil)
}

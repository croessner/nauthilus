// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package collection

import (
	"sync"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy"
	policyregistry "github.com/croessner/nauthilus/v4/server/policy/registry"
	"github.com/croessner/nauthilus/v4/server/policy/report"
)

func TestDecisionContextSharesBuiltinsAndIsolatesExtensions(t *testing.T) {
	first := NewDecisionContext(policy.OperationAuthenticate, nil, 1)
	second := NewDecisionContext(policy.OperationAuthenticate, nil, 1)

	extension := capturedPolicyAttribute("policy.contract.captured_marker")
	if err := first.AddAuthnPolicyAttributes(map[string]policyregistry.AttributeDefinition{extension.ID: extension}); err != nil {
		t.Fatalf("AddAuthnPolicyAttributes() error = %v", err)
	}

	if _, found := first.AttributeDefinition(extension.ID); !found {
		t.Fatal("captured extension was not installed")
	}

	if _, found := second.AttributeDefinition(extension.ID); found {
		t.Fatal("captured extension leaked into another request context")
	}

	builtin := capturedPolicyAttribute(policy.AttributeBruteForceTriggered)
	if err := first.AddAuthnPolicyAttributes(map[string]policyregistry.AttributeDefinition{builtin.ID: builtin}); err == nil {
		t.Fatal("extension shadowing a builtin definition was accepted")
	}

	definition, found := first.AttributeDefinition(policy.AttributeBruteForceTriggered)
	if !found || len(definition.Operations) == 0 || len(definition.Details) == 0 {
		t.Fatalf("builtin definition = %#v, found %v", definition, found)
	}

	definition.Operations[0] = "mutated"
	for key := range definition.Details {
		delete(definition.Details, key)
	}

	again, _ := second.AttributeDefinition(policy.AttributeBruteForceTriggered)
	if again.Operations[0] == "mutated" || len(again.Details) == 0 {
		t.Fatal("builtin definition changed through a returned copy")
	}
}

func TestNewDecisionContextDoesNotRebuildBuiltins(t *testing.T) {
	_ = NewDecisionContext(policy.OperationAuthenticate, nil, 1)

	allocs := testing.AllocsPerRun(50, func() {
		_ = NewDecisionContext(policy.OperationAuthenticate, nil, 1)
	})
	if allocs > 20 {
		t.Fatalf("NewDecisionContext() allocations = %.0f, want at most 20", allocs)
	}
}

func TestDecisionContextReadsExtensionsWhileTheyAreAdded(t *testing.T) {
	ctx := NewDecisionContext(policy.OperationAuthenticate, nil, 1)

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 200 {
			_, _ = ctx.AttributeDefinition("policy.contract.concurrent_marker")
			_, _ = ctx.AttributeDefinition(policy.AttributeBruteForceTriggered)
		}
	})

	extension := capturedPolicyAttribute("policy.contract.concurrent_marker")
	if err := ctx.AddAuthnPolicyAttributes(map[string]policyregistry.AttributeDefinition{extension.ID: extension}); err != nil {
		t.Fatalf("AddAuthnPolicyAttributes() error = %v", err)
	}

	wg.Wait()
}

// capturedPolicyAttribute builds one generation-owned extension definition.
func capturedPolicyAttribute(id string) policyregistry.AttributeDefinition {
	return policyregistry.AttributeDefinition{
		ID:         id,
		Stage:      policy.StagePreAuth,
		Operations: []policy.Operation{policy.OperationAuthenticate},
		Category:   policyregistry.AttributeCategoryEnvironment,
		Type:       policyregistry.AttributeTypeBool,
		Source:     policyregistry.SourceLua,
	}
}

func TestDecisionContextRevisionTracksAttributesAndDefinitions(t *testing.T) {
	ctx := NewDecisionContext(policy.OperationAuthenticate, nil, 1)
	id := "policy.contract.late_marker"

	ctx.RecordAttribute(AttributeValue{ID: id, Stage: policy.StagePreAuth, Value: true})

	recorded, ok := ctx.AttributeRevision(id)
	if !ok || recorded == 0 || ctx.Revision() != recorded {
		t.Fatalf("revision after recording = %d/%d (%v)", recorded, ctx.Revision(), ok)
	}

	// A definition installed after the value was recorded must invalidate work derived without it.
	extension := capturedPolicyAttribute(id)
	if err := ctx.AddAuthnPolicyAttributes(map[string]policyregistry.AttributeDefinition{extension.ID: extension}); err != nil {
		t.Fatalf("AddAuthnPolicyAttributes() error = %v", err)
	}

	installed, _ := ctx.AttributeRevision(id)
	if installed <= recorded || ctx.Revision() != installed {
		t.Fatalf("revision after installing the definition = %d/%d, want above %d", installed, ctx.Revision(), recorded)
	}

	ctx.RecordAttribute(AttributeValue{ID: policy.AttributeBruteForceTriggered, Stage: policy.StagePreAuth, Value: true})

	if unchanged, _ := ctx.AttributeRevision(id); unchanged != installed || ctx.Revision() <= installed {
		t.Fatalf("another attribute changed revision %d to %d or left the context revision at %d",
			installed, unchanged, ctx.Revision())
	}
}

func TestDecisionContextMarksDetailsWithoutChangingSnapshots(t *testing.T) {
	ctx := NewDecisionContext(policy.OperationAuthenticate, nil, 1)
	id := policy.AttributeBruteForceTriggered

	ctx.RecordAttribute(AttributeValue{
		ID: id, Stage: policy.StagePreAuth, Value: true,
		Details: map[string]report.DetailValue{"message": {Value: "blocked"}},
	})

	before := ctx.AttributeSnapshot()

	ctx.MarkAttributeDetailSelected(id, "message")

	after := ctx.AttributeSnapshot()

	if before.Attributes[id].Details["message"].Selected {
		t.Fatal("marking a detail changed a value taken in an earlier snapshot")
	}

	if !after.Attributes[id].Details["message"].Selected {
		t.Fatal("the selected detail was not recorded")
	}

	if after.Revisions[id] <= before.Revisions[id] || after.Revision != after.Revisions[id] {
		t.Fatalf("revision after marking = %d/%d, want above %d", after.Revisions[id], after.Revision, before.Revisions[id])
	}

	ctx.MarkAttributeDetailSelected(id, "message")

	if again := ctx.AttributeSnapshot(); again.Revision != after.Revision {
		t.Fatal("marking an already selected detail changed the revision")
	}
}

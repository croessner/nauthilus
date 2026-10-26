// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/configinput"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
	"github.com/croessner/nauthilus/v4/server/policy/testsupport"
)

const (
	recordReferenceAssessmentID = "inventory/plugin.inspector.assessment"
	recordReferenceLocatorID    = "inventory/plugin.locator.origin"
	recordReferenceDockIP       = "203.0.113.77"
	recordReferenceCarrier      = "sensitive-carrier.example"
	recordReferenceTrusted      = "trusted-carrier.example"
	recordReferencePermitRule   = "permit_current_trusted_carrier"
)

// recordReferenceCase describes one deterministic provider output and its expected ordered Policy outcome.
type recordReferenceCase struct {
	name, wantRule string
	legs           []map[string]any
	facts          map[string]any
	complete       *bool
	providerError  bool
	permit         bool
}

// TestRecordReferenceOrderedPolicyScenarios evaluates the compiled scheduler and ordered record rules end to end.
func TestRecordReferenceOrderedPolicyScenarios(t *testing.T) {
	catalog, target := compileRecordReferenceCatalog(t)
	compiled, _ := catalog.Lookup(target)

	for _, tc := range recordReferenceCases() {
		t.Run(tc.name, func(t *testing.T) {
			outputs := recordReferenceOutputs(t, compiled.Schema(), tc)
			assertRecordReferenceProviderFacts(t, compiled.Schema(), outputs)

			provider := &countingFactProvider{facts: outputs}
			if tc.providerError {
				provider.err = errors.New("deterministic unavailable provider")
			}

			outcome := evaluateRecordReference(t, catalog, target, provider, tc.facts)

			expected := decision.EffectDeny
			if tc.permit {
				expected = decision.EffectPermit
			}

			if tc.providerError {
				expected = decision.EffectIndeterminate
			}

			response := outcome.response
			if response.Effect() != expected || response.Policy().Rule() != tc.wantRule {
				t.Fatalf("got %s/%s (%s), want %s/%s", response.Effect(), response.Policy().Rule(), response.Status().Code(), expected, tc.wantRule)
			}

			if tc.providerError && !response.Status().Retryable() {
				t.Fatal("required provider outage is not retryable")
			}

			assertRecordReferenceDiagnosticsDoNotLeak(t, response)
		})
	}
}

// recordReferenceCases fixes positive, same-record, historical-only, availability and precedence vectors.
func recordReferenceCases() []recordReferenceCase {
	incomplete := false

	return []recordReferenceCase{
		{name: "current trusted carrier", permit: true, wantRule: recordReferencePermitRule},
		{
			name:     "suspicious carrier and repack on one leg",
			legs:     []map[string]any{{"carrier_band": "suspicious", "change_classes": []string{"content.repack"}}},
			wantRule: "deny_suspicious_carrier_repack",
		},
		{
			name:   "suspicious carrier and repack split across legs",
			legs:   []map[string]any{{"carrier_band": "suspicious"}, {"change_classes": []string{"content.repack"}}},
			permit: true, wantRule: recordReferencePermitRule,
		},
		{
			name: "trusted carrier only historical",
			legs: []map[string]any{{"carrier": recordReferenceTrusted}, {"carrier": "other-carrier.example"}},
		},
		{name: "broken seal", legs: []map[string]any{{"seal_state": "broken"}}, wantRule: "deny_broken_seal"},
		{name: "incomplete assessment", complete: &incomplete, wantRule: "deny_incomplete_assessment"},
		{
			name:     "unverified shipment",
			facts:    map[string]any{"resource.inventory.verification_state": "pending"},
			wantRule: "deny_unverified_shipment",
		},
		{name: "required provider fails", providerError: true},
	}
}

// recordReferenceOutputs supplies deterministic provider facts for one scenario.
func recordReferenceOutputs(t *testing.T, schema policyruntime.CompiledSchema, tc recordReferenceCase) []providedFact {
	t.Helper()

	fact, _ := recordReferenceSchemaFact(schema.Facts(), "plugin.inspector.assessed_legs")
	recordSchema, _ := fact.RecordSchema()

	records := make([]decision.Record, 0, 2)

	for index := range 2 {
		values := recordReferenceLegBaseline(index)
		if index < len(tc.legs) {
			for key, value := range tc.legs[index] {
				values[key] = value
			}
		}

		records = append(records, recordReferenceRecord(t, recordSchema, values))
	}

	complete := true
	if tc.complete != nil {
		complete = *tc.complete
	}

	return []providedFact{
		{id: "plugin.inspector.assessed_legs", category: decision.FactCategoryResource, value: recordReferenceRecordList(t, records)},
		{id: "plugin.inspector.assessment_complete", category: decision.FactCategoryResource, value: recordReferenceValue(t, complete)},
	}
}

// recordReferenceLegBaseline returns safe values for a historical leg (index 0) or the current leg (index 1).
func recordReferenceLegBaseline(index int) map[string]any {
	values := map[string]any{
		"sequence": int64(index + 1), "carrier": "origin-carrier.example", "is_current": false,
		"seal_state": "intact", "carrier_band": "neutral", "change_classes": []string{}, "carrier_confidence": .9,
	}
	if index == 1 {
		values["carrier"] = recordReferenceTrusted
		values["is_current"] = true
	}

	return values
}

// assertRecordReferenceProviderFacts verifies the fake provider uses the configured output contract.
func assertRecordReferenceProviderFacts(t *testing.T, schema policyruntime.CompiledSchema, outputs []providedFact) {
	t.Helper()

	provenance, err := decision.NewProvenance(decision.FactSourcePlugin, "inspector", recordReferenceAssessmentID)
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	for _, output := range outputs {
		normalized, err := schema.NormalizeValue(output.id, output.value)
		if err != nil {
			t.Fatalf("NormalizeValue(%s) error = %v", output.id, err)
		}

		fact, err := decision.NewFact(output.id, output.category, normalized, provenance)
		if err != nil {
			t.Fatalf("NewFact(%s) error = %v", output.id, err)
		}

		facts, err := decision.NewFactSet([]decision.Fact{fact})
		if err != nil {
			t.Fatalf("NewFactSet(%s) error = %v", output.id, err)
		}

		if err := schema.ValidatePresentFacts(facts); err != nil {
			t.Fatalf("ValidatePresentFacts(%s) error = %v", output.id, err)
		}
	}
}

// assertRecordReferenceDiagnosticsDoNotLeak verifies that public diagnostics never project request values.
func assertRecordReferenceDiagnosticsDoNotLeak(t *testing.T, response decision.DecisionResponse) {
	t.Helper()

	diagnostics := response.Diagnostics()
	if diagnostics == nil {
		t.Fatal("diagnostics are missing")
	}

	payload := fmt.Sprint(diagnostics.Entries().Values())

	for _, secret := range []string{recordReferenceDockIP, recordReferenceCarrier} {
		if strings.Contains(payload, secret) {
			t.Fatalf("diagnostics leak %q: %s", secret, payload)
		}
	}
}

// evaluateRecordReference runs one configured final-decision checkpoint with deterministic providers.
func evaluateRecordReference(
	t *testing.T,
	catalog *policyruntime.TargetCatalog,
	target decision.Target,
	provider *countingFactProvider,
	factOverrides map[string]any,
) runtimeEvaluation {
	t.Helper()

	evaluator, err := newCheckpointRuntime(checkpointRuntimeConfig{
		catalog: catalog,
		factProviders: map[string]factProviderBinding{
			recordReferenceAssessmentID: {
				provider: provider, source: decision.FactSourcePlugin, authority: "inspector", component: recordReferenceAssessmentID,
			},
			recordReferenceLocatorID: {
				provider: &countingFactProvider{}, source: decision.FactSourcePlugin, authority: "locator", component: recordReferenceLocatorID,
			},
		},
		ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newCheckpointRuntime() error = %v", err)
	}

	compiled, _ := catalog.Lookup(target)
	overrides := map[string]any{
		"resource.inventory.verification_state": "verified",
		"environment.warehouse.dock_ip":         recordReferenceDockIP,
	}

	for id, value := range factOverrides {
		overrides[id] = value
	}

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion, RequestID: "record-reference", Target: target,
		Options: decision.EvaluationOptions{IncludeDiagnostics: true},
	}, mustAuthorityCaller(t, false))
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	empty, _ := decision.NewFactSet(nil)
	checkpoint, _ := decision.NewCheckpoint(decision.CheckpointFinalDecision, empty)

	outcome, err := evaluator.Evaluate(context.Background(), checkpointEvaluation{
		request: request, checkpoint: checkpoint, facts: recordReferenceCallerFacts(t, compiled.Schema().Facts(), overrides),
		supervisor: &recordingEffectAcceptor{}, generation: 1,
		finalization: decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	return outcome
}

// compileRecordReferenceCatalog compiles the tracked operator-owned record configuration.
func compileRecordReferenceCatalog(t *testing.T) (*policyruntime.TargetCatalog, decision.Target) {
	t.Helper()

	document, err := policyconfig.Decode("yaml", bytes.NewReader(testsupport.TrackedRecordPolicyBytes(t)))
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("configinput.Normalize() error = %v", err)
	}

	catalog, err := input.Compile(context.Background(), &recordingEffectAcceptor{})
	if err != nil {
		t.Fatalf("UnifiedPolicyInput.Compile() error = %v", err)
	}

	target, err := decision.NewTarget("inventory", "inspect-shipment")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return catalog, target
}

// recordReferenceCallerFacts constructs schema-valid required caller facts with explicit overrides.
func recordReferenceCallerFacts(t *testing.T, schema []registry.FactSchema, overrides map[string]any) decision.FactSet {
	t.Helper()

	provenance, err := decision.NewProvenance(decision.FactSourceCaller, "inventory-scanner", "policy-test")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	facts := make([]decision.Fact, 0, len(schema))
	for _, definition := range schema {
		if !definition.Required() || !recordReferenceAllowsCaller(definition.AllowedSources()) {
			continue
		}

		value := recordReferenceFactValue(t, definition, overrides)

		fact, err := decision.NewFact(definition.ID(), definition.Category(), value, provenance)
		if err != nil {
			t.Fatalf("NewFact(%s) error = %v", definition.ID(), err)
		}

		facts = append(facts, fact)
	}

	result, err := decision.NewFactSet(facts)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	return result
}

// recordReferenceAllowsCaller reports whether one schema source list admits caller facts.
func recordReferenceAllowsCaller(sources []decision.FactSource) bool {
	for _, source := range sources {
		if source == decision.FactSourceCaller {
			return true
		}
	}

	return false
}

// recordReferenceFactValue builds an overridden or smallest type-correct value for one fact schema.
func recordReferenceFactValue(t *testing.T, definition registry.FactSchema, overrides map[string]any) decision.Value {
	t.Helper()

	if value, exists := overrides[definition.ID()]; exists {
		return recordReferenceValue(t, value)
	}

	if definition.Kind() != decision.ValueKindRecords {
		return recordReferenceScalar(t, definition.Kind())
	}

	recordSchema, _ := definition.RecordSchema()
	record := recordReferenceRecord(t, recordSchema, map[string]any{"carrier": recordReferenceCarrier})

	return recordReferenceRecordList(t, []decision.Record{record})
}

// recordReferenceRecord supplies declared fields only, preserving the host's immutable schema checks.
func recordReferenceRecord(t *testing.T, schema registry.RecordSchema, values map[string]any) decision.Record {
	t.Helper()

	fields := make([]decision.RecordField, 0, len(schema.Fields()))

	for _, definition := range schema.Fields() {
		input, exists := values[definition.Name()]
		if !exists && !definition.Required() {
			continue
		}

		value := recordReferenceScalar(t, definition.Kind())
		if exists {
			value = recordReferenceValue(t, input)
		}

		fieldValue, err := decision.NewRecordFieldValueFromValue(value)
		if err != nil {
			t.Fatalf("NewRecordFieldValueFromValue(%s) error = %v", definition.Name(), err)
		}

		field, err := decision.NewRecordField(definition.Name(), fieldValue)
		if err != nil {
			t.Fatalf("NewRecordField(%s) error = %v", definition.Name(), err)
		}

		fields = append(fields, field)
	}

	record, err := decision.NewRecord(fields)
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}

	return record
}

// recordReferenceRecordList wraps records as one immutable fact value.
func recordReferenceRecordList(t *testing.T, input []decision.Record) decision.Value {
	t.Helper()

	records, err := decision.NewRecordList(input)
	if err != nil {
		t.Fatalf("NewRecordList() error = %v", err)
	}

	value, err := decision.NewValue(decision.ValueInput{Records: &records})
	if err != nil {
		t.Fatalf("NewValue(records) error = %v", err)
	}

	return value
}

// recordReferenceScalar builds the smallest constructed scalar or list value of one kind.
func recordReferenceScalar(t *testing.T, kind decision.ValueKind) decision.Value {
	t.Helper()

	defaults := map[decision.ValueKind]any{
		decision.ValueKindString: "x", decision.ValueKindBoolean: false, decision.ValueKindInteger: int64(1),
		decision.ValueKindDouble: 1.0, decision.ValueKindStrings: []string{}, decision.ValueKindBytes: []byte{0},
	}

	input, ok := defaults[kind]
	if !ok {
		t.Fatalf("unsupported reference scalar kind %q", kind)
	}

	return recordReferenceValue(t, input)
}

// recordReferenceValue converts explicit test inputs without integer-to-double inference.
func recordReferenceValue(t *testing.T, input any) decision.Value {
	t.Helper()

	value := decision.ValueInput{}

	switch typed := input.(type) {
	case string:
		value.String = &typed
	case bool:
		value.Boolean = &typed
	case int64:
		value.Integer = &typed
	case float64:
		value.Double = &typed
	case []string:
		value.Strings = typed
	case []byte:
		value.Bytes = typed
	default:
		t.Fatalf("unsupported Policy fixture value %T", input)
	}

	result, err := decision.NewValue(value)
	if err != nil {
		t.Fatal(err)
	}

	return result
}

// recordReferenceSchemaFact resolves one exact compiled schema fact.
func recordReferenceSchemaFact(facts []registry.FactSchema, id string) (registry.FactSchema, bool) {
	for _, fact := range facts {
		if fact.ID() == id {
			return fact, true
		}
	}

	return registry.FactSchema{}, false
}

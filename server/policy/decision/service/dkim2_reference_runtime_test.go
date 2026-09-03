// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/configinput"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

const dkim2AssessmentProviderID = "dkim2/plugin.dkim2_reputation.assessment"

const (
	dkim2TestSMTPPeerIP   = "203.0.113.77"
	dkim2TestSignerDomain = "sensitive-signer.example"
)

type dkim2AssessmentState struct {
	complete   bool
	acceptable bool
}

type dkim2RuntimeCase struct {
	name            string
	verification    string
	factOverrides   map[string]string
	providerFacts   []providedFact
	wantRule        string
	wantEffect      decision.Effect
	wantStatus      decision.StatusCode
	wantProviderRun bool
	providerErr     error
}

func TestDKIM2ReferenceRuntimeBoundary(t *testing.T) {
	catalog, target := compileDKIM2ReferenceCatalog(t)
	compiled, _ := catalog.Lookup(target)
	assessmentSchema, _ := schemaFactByID(compiled.Schema().Facts(), "plugin.dkim2_reputation.assessed_chain")

	tests := dkim2ReferenceRuntimeCases(t, assessmentSchema)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertDKIM2RuntimeCase(t, catalog, target, compiled.Schema(), test)
		})
	}
}

// dkim2ReferenceRuntimeCases defines the verifier and provider boundary matrix.
func dkim2ReferenceRuntimeCases(t *testing.T, assessmentSchema registry.FactSchema) []dkim2RuntimeCase {
	t.Helper()

	return []dkim2RuntimeCase{
		{
			name: "TEMPERROR remains verifier-owned", verification: "TEMPERROR",
			wantEffect: decision.EffectDeny, wantRule: "deny_nonpass_verifier_state",
		},
		{
			name: "strict PASS permits a complete acceptable assessment", verification: "PASS",
			providerFacts: dkim2ReferenceAssessmentFact(t, assessmentSchema, true),
			wantEffect:    decision.EffectPermit, wantRule: "permit_strict_pass", wantProviderRun: true,
		},
		{
			name: "strict PASS permits an acceptable current projection", verification: "PASS",
			factOverrides: map[string]string{
				"resource.dkim2.scope":                 "current",
				"resource.dkim2.historical_content":    "not_evaluated",
				"resource.dkim2.historical_signatures": "not_evaluated",
				"resource.dkim2.do_not_modify_state":   "not_evaluated",
				"resource.dkim2.do_not_explode_state":  "not_evaluated",
			},
			providerFacts: dkim2ReferenceAssessmentFact(t, assessmentSchema, true),
			wantEffect:    decision.EffectPermit, wantRule: "permit_strict_pass", wantProviderRun: true,
		},
		{
			name: "strict PASS denies an unacceptable assessment", verification: "PASS",
			providerFacts: dkim2ReferenceAssessmentFact(t, assessmentSchema, false),
			wantEffect:    decision.EffectDeny, wantRule: "deny_unacceptable_assessment", wantProviderRun: true,
		},
		{
			name: "strict PASS denies when a non-target hop is unacceptable", verification: "PASS",
			providerFacts: dkim2ReferenceAssessmentFacts(t, assessmentSchema,
				dkim2AssessmentState{complete: true, acceptable: false},
				dkim2AssessmentState{complete: true, acceptable: true},
			),
			wantEffect: decision.EffectDeny, wantRule: "deny_unacceptable_assessment", wantProviderRun: true,
		},
		{
			name: "strict PASS denies a vacuous incomplete assessment", verification: "PASS",
			providerFacts: dkim2ReferenceAssessmentFacts(t, assessmentSchema,
				dkim2AssessmentState{complete: false, acceptable: false},
			),
			wantEffect: decision.EffectDeny, wantRule: "deny_incomplete_assessment", wantProviderRun: true,
		},
		{
			name: "strict PASS retries a required provider failure", verification: "PASS",
			providerErr: errors.New("reference provider unavailable"), wantEffect: decision.EffectIndeterminate,
			wantStatus: decision.StatusCodeProviderUnavailable, wantProviderRun: true,
		},
	}
}

// assertDKIM2RuntimeCase evaluates and verifies one reference-policy case.
func assertDKIM2RuntimeCase(
	t *testing.T,
	catalog *policyruntime.TargetCatalog,
	target decision.Target,
	schema policyruntime.CompiledSchema,
	test dkim2RuntimeCase,
) {
	t.Helper()
	assertDKIM2ReferenceProviderFacts(t, schema, test.providerFacts)

	provider := &countingFactProvider{facts: test.providerFacts, err: test.providerErr}
	outcome := evaluateDKIM2Reference(t, catalog, target, provider, test.verification, test.factOverrides)
	wantCalls := 0

	if test.wantProviderRun {
		wantCalls = 1
	}

	if provider.callCount() != wantCalls {
		t.Fatalf("assessment provider calls = %d, want %d", provider.callCount(), wantCalls)
	}

	if outcome.response.Effect() != test.wantEffect || outcome.response.Policy().Rule() != test.wantRule {
		t.Fatalf("response = %q/%q status=%q providers=%#v, want %q/%q", outcome.response.Effect(),
			outcome.response.Policy().Rule(), outcome.response.Status().Code(), outcome.report.runtime.providers,
			test.wantEffect, test.wantRule)
	}

	if test.wantStatus != "" && (outcome.response.Status().Code() != test.wantStatus || !outcome.response.Status().Retryable()) {
		t.Fatalf("status = %q retryable=%v, want %q retryable", outcome.response.Status().Code(), outcome.response.Status().Retryable(), test.wantStatus)
	}

	assertDKIM2DiagnosticsDoNotLeak(t, outcome.response)
}

// assertDKIM2DiagnosticsDoNotLeak verifies that public diagnostics never project request identities.
func assertDKIM2DiagnosticsDoNotLeak(t *testing.T, response decision.DecisionResponse) {
	t.Helper()

	diagnostics := response.Diagnostics()
	if diagnostics == nil {
		t.Fatal("diagnostics are missing")
	}

	payload := fmt.Sprint(diagnostics.Entries().Values())

	for _, secret := range []string{dkim2TestSMTPPeerIP, dkim2TestSignerDomain} {
		if strings.Contains(payload, secret) {
			t.Fatalf("diagnostics leak %q: %s", secret, payload)
		}
	}
}

// assertDKIM2ReferenceProviderFacts verifies the fake provider uses the configured output contract.
func assertDKIM2ReferenceProviderFacts(
	t *testing.T,
	schema policyruntime.CompiledSchema,
	outputs []providedFact,
) {
	t.Helper()

	provenance, err := decision.NewProvenance(decision.FactSourcePlugin, "dkim2_reputation", dkim2AssessmentProviderID)
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	for _, output := range outputs {
		normalized, normalizeErr := schema.NormalizeValue(output.id, output.value)
		if normalizeErr != nil {
			t.Fatalf("NormalizeValue(%s) error = %v", output.id, normalizeErr)
		}

		fact, factErr := decision.NewFact(output.id, output.category, normalized, provenance)
		if factErr != nil {
			t.Fatalf("NewFact(%s) error = %v", output.id, factErr)
		}

		facts, factsErr := decision.NewFactSet([]decision.Fact{fact})
		if factsErr != nil {
			t.Fatalf("NewFactSet(%s) error = %v", output.id, factsErr)
		}

		if validateErr := schema.ValidatePresentFacts(facts); validateErr != nil {
			t.Fatalf("ValidatePresentFacts(%s) error = %v", output.id, validateErr)
		}
	}
}

// evaluateDKIM2Reference runs one configured final-decision checkpoint.
func evaluateDKIM2Reference(
	t *testing.T,
	catalog *policyruntime.TargetCatalog,
	target decision.Target,
	provider *countingFactProvider,
	verificationState string,
	factOverrides map[string]string,
) runtimeEvaluation {
	t.Helper()

	evaluator, err := newCheckpointRuntime(checkpointRuntimeConfig{
		catalog: catalog,
		factProviders: map[string]factProviderBinding{
			dkim2AssessmentProviderID: {
				provider: provider, source: decision.FactSourcePlugin,
				authority: "dkim2_reputation", component: dkim2AssessmentProviderID,
			},
		},
		ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newCheckpointRuntime() error = %v", err)
	}

	compiled, _ := catalog.Lookup(target)
	overrides := map[string]string{
		"resource.dkim2.verification_state":    verificationState,
		"resource.dkim2.authentication_state":  "PASS",
		"resource.dkim2.scope":                 "chain",
		"resource.dkim2.historical_content":    "complete",
		"resource.dkim2.historical_signatures": "complete",
		"resource.dkim2.custody_structure":     "not_present",
		"resource.dkim2.replay_class":          "first_seen",
		"resource.dkim2.local_policy_verdict":  "continue",
		"resource.dkim2.disposition":           "continue",
		"environment.rspamd.smtp_client_ip":    dkim2TestSMTPPeerIP,
	}
	for id, value := range factOverrides {
		overrides[id] = value
	}

	facts := dkim2ReferenceCallerFacts(t, compiled.Schema().Facts(), overrides)

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion, RequestID: "dkim2-reference", Target: target,
		Options: decision.EvaluationOptions{IncludeDiagnostics: true},
	}, mustAuthorityCaller(t, false))
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	empty, _ := decision.NewFactSet(nil)
	checkpoint, _ := decision.NewCheckpoint(decision.CheckpointFinalDecision, empty)

	outcome, err := evaluator.Evaluate(context.Background(), checkpointEvaluation{
		request: request, checkpoint: checkpoint, facts: facts,
		supervisor: &recordingEffectAcceptor{}, generation: 1,
		finalization: decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	return outcome
}

// compileDKIM2ReferenceCatalog compiles the operator-owned reference configuration.
func compileDKIM2ReferenceCatalog(t *testing.T) (*policyruntime.TargetCatalog, decision.Target) {
	t.Helper()

	path := filepath.Join("..", "..", "..", "docs", "examples", "policy_dkim2_rspamd_verifier.yml")

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(%s) error = %v", path, err)
	}

	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("Close(%s) error = %v", path, closeErr)
		}
	}()

	document, err := policyconfig.Decode("yaml", file)
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

	target, err := decision.NewTarget("dkim2", "accept-message-instance")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return catalog, target
}

// dkim2ReferenceCallerFacts constructs schema-valid caller facts for one verifier state.
func dkim2ReferenceCallerFacts(
	t *testing.T,
	schema []registry.FactSchema,
	stringOverrides map[string]string,
) decision.FactSet {
	t.Helper()

	provenance, err := decision.NewProvenance(decision.FactSourceCaller, "rspamd-verifier", "policy-test")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	facts := make([]decision.Fact, 0, len(schema))
	for _, definition := range schema {
		if !definition.Required() || !containsFactSource(definition.AllowedSources(), decision.FactSourceCaller) {
			continue
		}

		value := dkim2ReferenceFactValue(t, definition, stringOverrides)

		fact, factErr := decision.NewFact(definition.ID(), definition.Category(), value, provenance)
		if factErr != nil {
			t.Fatalf("NewFact(%s) error = %v", definition.ID(), factErr)
		}

		facts = append(facts, fact)
	}

	result, err := decision.NewFactSet(facts)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	return result
}

// containsFactSource reports whether one schema source list contains the caller authority.
func containsFactSource(sources []decision.FactSource, source decision.FactSource) bool {
	for _, candidate := range sources {
		if candidate == source {
			return true
		}
	}

	return false
}

// dkim2ReferenceFactValue builds a smallest type-correct value for one fact schema.
func dkim2ReferenceFactValue(
	t *testing.T,
	definition registry.FactSchema,
	stringOverrides map[string]string,
) decision.Value {
	t.Helper()

	if value, exists := stringOverrides[definition.ID()]; exists {
		return runtimeStringValue(t, value)
	}

	if definition.Kind() == decision.ValueKindRecords {
		recordSchema, _ := definition.RecordSchema()

		return dkim2ReferenceRecordValue(t, recordSchema)
	}

	return dkim2ReferenceScalarValue(t, definition.Kind())
}

// dkim2ReferenceAssessmentFact constructs the native provider's exact v1 output shape.
func dkim2ReferenceAssessmentFact(
	t *testing.T,
	definition registry.FactSchema,
	acceptable bool,
) []providedFact {
	t.Helper()

	return dkim2ReferenceAssessmentFacts(t, definition, dkim2AssessmentState{complete: true, acceptable: acceptable})
}

// dkim2ReferenceAssessmentFacts constructs a complete native multi-hop assessment.
func dkim2ReferenceAssessmentFacts(
	t *testing.T,
	definition registry.FactSchema,
	states ...dkim2AssessmentState,
) []providedFact {
	t.Helper()

	recordSchema, ok := definition.RecordSchema()
	if !ok {
		t.Fatal("assessed_chain record schema is missing")
	}

	records := make([]decision.Record, 0, len(states))
	for _, state := range states {
		fields := dkim2ReferenceAssessmentFields(t, recordSchema, state)
		records = append(records, dkim2ReferenceRecord(t, fields))
	}

	value := dkim2ReferenceRecordListValue(t, records)

	return []providedFact{{
		id: definition.ID(), category: definition.Category(), value: value,
	}}
}

// dkim2ReferenceAssessmentFields constructs exact native assessment fields.
func dkim2ReferenceAssessmentFields(
	t *testing.T,
	recordSchema registry.RecordSchema,
	state dkim2AssessmentState,
) []decision.RecordField {
	t.Helper()

	stringValues := map[string]string{
		"signer_reputation":    "neutral",
		"smtp_peer_reputation": "neutral",
		"contract_state":       "matched",
		"recipe_authorization": "permitted",
	}
	booleanValues := map[string]bool{"assessment_complete": state.complete, "acceptable": state.acceptable}
	fields := make([]decision.RecordField, 0, len(recordSchema.Fields()))

	for _, fieldSchema := range recordSchema.Fields() {
		value := dkim2ReferenceAssessmentFieldValue(t, fieldSchema, stringValues, booleanValues)
		fields = append(fields, dkim2ReferenceRecordField(t, fieldSchema.Name(), value))
	}

	return fields
}

// dkim2ReferenceAssessmentFieldValue selects configured assessment values or a type-correct default.
func dkim2ReferenceAssessmentFieldValue(
	t *testing.T,
	fieldSchema registry.RecordFieldSchema,
	stringValues map[string]string,
	booleanValues map[string]bool,
) decision.Value {
	t.Helper()

	if text, exists := stringValues[fieldSchema.Name()]; exists {
		return runtimeStringValue(t, text)
	}

	if flag, exists := booleanValues[fieldSchema.Name()]; exists {
		return dkim2ReferenceBooleanValue(t, flag)
	}

	return dkim2ReferenceScalarValue(t, fieldSchema.Kind())
}

// dkim2ReferenceBooleanValue constructs one boolean fact value.
func dkim2ReferenceBooleanValue(t *testing.T, input bool) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{Boolean: &input})
	if err != nil {
		t.Fatalf("NewValue(boolean) error = %v", err)
	}

	return value
}

// schemaFactByID resolves one exact compiled schema fact.
func schemaFactByID(facts []registry.FactSchema, id string) (registry.FactSchema, bool) {
	for _, fact := range facts {
		if fact.ID() == id {
			return fact, true
		}
	}

	return registry.FactSchema{}, false
}

// dkim2ReferenceRecordValue builds one complete record from a closed schema.
func dkim2ReferenceRecordValue(t *testing.T, schema registry.RecordSchema) decision.Value {
	t.Helper()

	fields := make([]decision.RecordField, 0, len(schema.Fields()))
	for _, definition := range schema.Fields() {
		value := dkim2ReferenceScalarValue(t, definition.Kind())
		if definition.Name() == "signer_domain" {
			value = runtimeStringValue(t, dkim2TestSignerDomain)
		}

		fields = append(fields, dkim2ReferenceRecordField(t, definition.Name(), value))
	}

	return dkim2ReferenceRecordsValue(t, fields)
}

// dkim2ReferenceRecordField constructs one named immutable record field.
func dkim2ReferenceRecordField(t *testing.T, name string, value decision.Value) decision.RecordField {
	t.Helper()

	fieldValue, err := decision.NewRecordFieldValueFromValue(value)
	if err != nil {
		t.Fatalf("NewRecordFieldValueFromValue(%s) error = %v", name, err)
	}

	field, err := decision.NewRecordField(name, fieldValue)
	if err != nil {
		t.Fatalf("NewRecordField(%s) error = %v", name, err)
	}

	return field
}

// dkim2ReferenceRecordsValue wraps one complete field list as a single-record value.
func dkim2ReferenceRecordsValue(t *testing.T, fields []decision.RecordField) decision.Value {
	t.Helper()

	return dkim2ReferenceRecordListValue(t, []decision.Record{dkim2ReferenceRecord(t, fields)})
}

// dkim2ReferenceRecord constructs one immutable record.
func dkim2ReferenceRecord(t *testing.T, fields []decision.RecordField) decision.Record {
	t.Helper()

	record, err := decision.NewRecord(fields)
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}

	return record
}

// dkim2ReferenceRecordListValue wraps records as one immutable fact value.
func dkim2ReferenceRecordListValue(t *testing.T, input []decision.Record) decision.Value {
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

// dkim2ReferenceScalarValue builds one constructed scalar or list value.
func dkim2ReferenceScalarValue(t *testing.T, kind decision.ValueKind) decision.Value {
	t.Helper()

	text := "x"
	boolean := false
	integer := int64(1)
	double := 1.0
	stringsValue := []string{}
	bytesValue := []byte{0}
	input := decision.ValueInput{}

	switch kind {
	case decision.ValueKindString:
		input.String = &text
	case decision.ValueKindBoolean:
		input.Boolean = &boolean
	case decision.ValueKindInteger:
		input.Integer = &integer
	case decision.ValueKindDouble:
		input.Double = &double
	case decision.ValueKindStrings:
		input.Strings = stringsValue
	case decision.ValueKindBytes:
		input.Bytes = bytesValue
	default:
		t.Fatalf("unsupported reference scalar kind %q", kind)
	}

	value, err := decision.NewValue(input)
	if err != nil {
		t.Fatalf("NewValue(%s) error = %v", kind, err)
	}

	return value
}

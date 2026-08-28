// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

func TestSelectedEffectReceivesSchemaFilteredRecordFacts(t *testing.T) {
	factSchema := serviceProtectedRecordSchema(t, 2)
	target, _ := decision.NewTarget("mail", "submit")
	providerID := "mail/plugin.other.audit"
	effect := decisionRuntimeEffect(t, target, "mail/audit", providerID, registry.EffectKindObligation, registry.ExecutionHostSync)
	provider := decisionRuntimeHostProvider(t, target, providerID, registry.ExecutionHostSync, nil)
	catalog, target := decisionRuntimeCatalogWithSelections(
		t, decision.EffectPermit, registry.NoMatchDeny,
		[]registry.FactSchema{factSchema}, []registry.ProviderDefinition{provider},
		[]registry.EffectDefinition{effect}, []registry.EffectUse{decisionRuntimeEffectUse(t, effect.ID())}, nil,
	)
	syncProvider := &recordingSyncEffectProvider{result: effectsupervisor.Succeeded()}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
		syncEffects: map[string]syncEffectBinding{providerID: {provider: syncProvider}},
	}).(*checkpointRuntime)
	compiled, _ := catalog.Lookup(target)

	facts, err := compiled.Schema().NormalizeFacts(serviceProtectedRecordFacts(t, "pass"))
	if err != nil {
		t.Fatalf("NormalizeFacts() error = %v", err)
	}

	caller := mustAuthorityCaller(t, false)

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion, RequestID: "record-effect", Target: target,
	}, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	planned, _, selected, err := evaluator.prepareObligation(
		checkpointEvaluation{request: request, generation: 1},
		compiled,
		"decision-record-effect",
		facts,
		decisionRuntimeEffectUse(t, effect.ID()),
		1,
	)
	if err != nil || !selected {
		t.Fatalf("prepareObligation() selected/error = %t/%v", selected, err)
	}

	fact, _ := planned.execution.facts.Get("resource.chain")
	records, _ := fact.Value().Records()
	fields := records.Records()[0].Fields()

	if len(fields) != 1 || fields[0].Name() != "result" {
		t.Fatalf("selected effect received protected fields: %#v", fields)
	}
}

func TestRecordLimitsRejectBeforeProviderExecution(t *testing.T) {
	providerID := "mail/plugin.other.reader"
	provider := decisionRuntimeProvider(t, providerID, "plugin.other.assessed", registry.ProviderFailureIndeterminate, nil)
	output := decisionRuntimeFactSchema(t, "plugin.other.assessed", decision.FactSourcePlugin, false)
	catalog, target := decisionRuntimeCatalog(
		t, decision.EffectPermit, registry.NoMatchDeny,
		[]registry.FactSchema{serviceProtectedRecordSchema(t, 1), output},
		[]registry.ProviderDefinition{provider}, nil,
	)
	recorder := &countingFactProvider{}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
		factProviders: map[string]factProviderBinding{
			providerID: decisionRuntimeFactBinding(recorder, "other"),
		},
	})
	caller := mustAuthorityCaller(t, false)

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion, RequestID: "record-limit", Target: target,
	}, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	empty, _ := decision.NewFactSet(nil)
	checkpoint, _ := decision.NewCheckpoint(decision.CheckpointFinalDecision, empty)

	outcome, err := evaluator.Evaluate(context.Background(), checkpointEvaluation{
		request: request, checkpoint: checkpoint, facts: serviceProtectedRecordFacts(t, "one", "two"),
		supervisor: &recordingEffectAcceptor{}, generation: 1,
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if outcome.response.Effect() != decision.EffectIndeterminate || recorder.callCount() != 0 {
		t.Fatalf("limit rejection effect/provider calls = %q/%d", outcome.response.Effect(), recorder.callCount())
	}
}

// serviceProtectedRecordSchema constructs one record fact with an exact protected payload field.
func serviceProtectedRecordSchema(t *testing.T, maxRecords int) registry.FactSchema {
	t.Helper()

	result, _ := registry.NewRecordFieldSchema(registry.RecordFieldSchemaInput{
		Name: "result", Kind: decision.ValueKindString, MaxLength: 16, ExpressionVisible: true,
	})
	payload, _ := registry.NewRecordFieldSchema(registry.RecordFieldSchemaInput{
		Name: "payload", Kind: decision.ValueKindBytes, MaxBytes: 16,
		ProviderVisibility: []string{"mail/plugin.reputation.assessor"},
	})
	records, _ := registry.NewRecordSchema(registry.RecordSchemaInput{
		ID: "chain", Version: "v1", Fields: []registry.RecordFieldSchema{result, payload},
		MaxRecords: maxRecords, MaxFields: 2, MaxAggregateBytes: 64,
	})

	fact, err := registry.NewFactSchema(registry.FactSchemaInput{
		ID: "resource.chain", Category: decision.FactCategoryResource, Kind: decision.ValueKindRecords,
		AllowedSources: []decision.FactSource{decision.FactSourceCaller}, RecordSchema: &records,
	})
	if err != nil {
		t.Fatalf("NewFactSchema() error = %v", err)
	}

	return fact
}

// serviceProtectedRecordFacts constructs caller-owned records with one protected payload.
func serviceProtectedRecordFacts(t *testing.T, results ...string) decision.FactSet {
	t.Helper()

	records := make([]decision.Record, 0, len(results))

	for _, result := range results {
		resultLeaf, _ := decision.NewRecordFieldValueFromValue(mustServiceValue(t, result))
		payloadValue, _ := decision.NewValue(decision.ValueInput{Bytes: []byte("secret")})
		payloadLeaf, _ := decision.NewRecordFieldValueFromValue(payloadValue)
		resultField, _ := decision.NewRecordField("result", resultLeaf)
		payloadField, _ := decision.NewRecordField("payload", payloadLeaf)
		record, _ := decision.NewRecord([]decision.RecordField{resultField, payloadField})
		records = append(records, record)
	}

	list, _ := decision.NewRecordList(records)
	value, _ := decision.NewValue(decision.ValueInput{Records: &list})
	provenance, _ := decision.NewProvenance(decision.FactSourceCaller, "client", "request")
	fact, _ := decision.NewFact("resource.chain", decision.FactCategoryResource, value, provenance)
	facts, _ := decision.NewFactSet([]decision.Fact{fact})

	return facts
}

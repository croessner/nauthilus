// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"fmt"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

//nolint:funlen // The single table keeps the complete negative provider boundary reviewable.
func TestCollectRejectsMalformedSealedProjectionWithoutEmittingFacts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest
	}{
		{name: "missing fact", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			return removeRequestFact(t, request, factProjectionSchema)
		}},
		{name: "unknown fact", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			return appendRequestFact(t, request, testFact(
				t, "resource.dkim2.unknown", pluginapi.DecisionFactCategoryResource, testStringValue(t, "unknown"),
			))
		}},
		{name: "wrong kind", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			return replaceRequestFact(t, request, "environment.rspamd.smtp_client_ip", testBooleanValue(t, true))
		}},
		{name: "over limit list", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			values := make([]string, 21)
			for index := range values {
				values[index] = fmt.Sprintf("signal.%02d", index)
			}

			return replaceRequestFact(
				t, request, "environment.rspamd.normalized_signals", testStringsValue(t, values),
			)
		}},
		{name: "sequence mismatch", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			return replaceChainField(t, request, fieldSequence, testIntegerValue(t, 2))
		}},
		{name: "count mismatch", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			return replaceRequestFact(t, request, "resource.dkim2.claimed_hop_count", testIntegerValue(t, 2))
		}},
		{name: "target mismatch", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			return replaceRequestFact(t, request, "resource.dkim2.target_sequence", testIntegerValue(t, 2))
		}},
		{name: "projection binding mismatch", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			return replaceRequestFact(t, request, "resource.dkim2.projection_binding", testBytesValue(t, make([]byte, 32)))
		}},
		{name: "noncanonical domain", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			return replaceChainField(t, request, "signer_domain", testStringValue(t, "Relay.Example"))
		}},
		{name: "noncanonical IP", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			return replaceRequestFact(t, request, "environment.rspamd.smtp_client_ip", testStringValue(t, "192.0.2.025"))
		}},
		{name: "Recipe incoherence", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			return replaceChainField(t, request, "recipe_mode", testStringValue(t, "applied"))
		}},
		{name: "reordered list", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			return replaceRequestFact(t, request, "environment.rspamd.normalized_signals", testStringsValue(
				t, []string{"spf.softfail", "dmarc.fail"},
			))
		}},
		{name: "double prefix", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			return renameRequestFact(t, request, factProjectionSchema, "resource.resource.dkim2.projection_schema")
		}},
		{name: "incomplete history", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			return replaceRequestFact(t, request, factHistoricalContent, testStringValue(t, stateUnavailable))
		}},
		{name: "wrong target", mutate: func(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
			target := pluginapi.DecisionTargetSelector{Namespace: "dkim2", Action: "different-action"}

			return rebuildDecisionFactRequest(t, request, target, request.Facts())
		}},
	}

	plugin := NewPlugin()
	plugin.swapConfig(mustTestConfig(t))
	provider := decisionFactProvider{plugin: plugin}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := test.mutate(t, testDecisionRequest(t, "192.0.2.25"))

			result, err := provider.Collect(context.Background(), request)
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}

			if result.ErrorClass != pluginapi.DecisionErrorClassInvalidInput || len(result.Facts) != 0 {
				t.Fatalf("Collect() = %#v, want invalid_input without assessed facts", result)
			}
		})
	}
}

func TestCollectReportsUnavailableWithoutConfigurationAndEmitsNoFacts(t *testing.T) {
	result, err := (decisionFactProvider{plugin: NewPlugin()}).Collect(
		context.Background(), testDecisionRequest(t, "192.0.2.25"),
	)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if result.ErrorClass != pluginapi.DecisionErrorClassUnavailable || len(result.Facts) != 0 {
		t.Fatalf("Collect() = %#v, want unavailable without assessed facts", result)
	}
}

// rebuildDecisionFactRequest owns one mutated fact slice behind the original redacted caller.
func rebuildDecisionFactRequest(
	t *testing.T,
	request pluginapi.DecisionFactRequest,
	target pluginapi.DecisionTargetSelector,
	facts []pluginapi.DecisionFactView,
) pluginapi.DecisionFactRequest {
	t.Helper()

	result, err := pluginapi.NewDecisionFactRequest(target, request.Caller(), facts)
	if err != nil {
		t.Fatalf("NewDecisionFactRequest() error = %v", err)
	}

	return result
}

// replaceRequestFact replaces one required fact value without changing its identity or category.
func replaceRequestFact(
	t *testing.T,
	request pluginapi.DecisionFactRequest,
	id string,
	value pluginapi.DecisionValue,
) pluginapi.DecisionFactRequest {
	t.Helper()

	facts := request.Facts()
	for index, fact := range facts {
		if fact.ID() == id {
			facts[index] = testFact(t, id, fact.Category(), value)

			return rebuildDecisionFactRequest(t, request, request.Target(), facts)
		}
	}

	t.Fatalf("fact %s is missing from test request", id)

	return pluginapi.DecisionFactRequest{}
}

// removeRequestFact removes one exact admitted fact from the immutable request.
func removeRequestFact(
	t *testing.T,
	request pluginapi.DecisionFactRequest,
	id string,
) pluginapi.DecisionFactRequest {
	t.Helper()

	facts := request.Facts()
	for index, fact := range facts {
		if fact.ID() == id {
			facts = append(facts[:index], facts[index+1:]...)

			return rebuildDecisionFactRequest(t, request, request.Target(), facts)
		}
	}

	t.Fatalf("fact %s is missing from test request", id)

	return pluginapi.DecisionFactRequest{}
}

// appendRequestFact appends one independently constructed admitted fact.
func appendRequestFact(
	t *testing.T,
	request pluginapi.DecisionFactRequest,
	fact pluginapi.DecisionFactView,
) pluginapi.DecisionFactRequest {
	t.Helper()

	facts := append(request.Facts(), fact)

	return rebuildDecisionFactRequest(t, request, request.Target(), facts)
}

// renameRequestFact replaces one exact fact identity while retaining its category and value.
func renameRequestFact(
	t *testing.T,
	request pluginapi.DecisionFactRequest,
	oldID string,
	newID string,
) pluginapi.DecisionFactRequest {
	t.Helper()

	facts := request.Facts()
	for index, fact := range facts {
		if fact.ID() == oldID {
			facts[index] = testFact(t, newID, fact.Category(), fact.Value())

			return rebuildDecisionFactRequest(t, request, request.Target(), facts)
		}
	}

	t.Fatalf("fact %s is missing from test request", oldID)

	return pluginapi.DecisionFactRequest{}
}

// replaceChainField rebuilds the single-hop sealed fixture with one mutated record field.
func replaceChainField(
	t *testing.T,
	request pluginapi.DecisionFactRequest,
	name string,
	value pluginapi.DecisionValue,
) pluginapi.DecisionFactRequest {
	t.Helper()

	for _, fact := range request.Facts() {
		if fact.ID() != "resource.dkim2.chain" {
			continue
		}

		list, ok := fact.Value().Records()
		if !ok || len(list.Records()) != 1 {
			t.Fatal("test chain must contain exactly one record")
		}

		record := replaceRecordField(t, list.Records()[0], name, value)

		updatedList, err := pluginapi.NewDecisionRecordList([]pluginapi.DecisionRecord{record})
		if err != nil {
			t.Fatalf("NewDecisionRecordList() error = %v", err)
		}

		updatedValue, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Records: &updatedList})
		if err != nil {
			t.Fatalf("NewDecisionValue() error = %v", err)
		}

		return replaceRequestFact(t, request, fact.ID(), updatedValue)
	}

	t.Fatal("chain fact is missing from test request")

	return pluginapi.DecisionFactRequest{}
}

// replaceRecordField owns one rebuilt record with one exact field value replacement.
func replaceRecordField(
	t *testing.T,
	record pluginapi.DecisionRecord,
	name string,
	value pluginapi.DecisionValue,
) pluginapi.DecisionRecord {
	t.Helper()

	fields := record.Fields()
	for index, field := range fields {
		if field.Name() != name {
			continue
		}

		leaf, err := pluginapi.NewDecisionRecordFieldValue(value)
		if err != nil {
			t.Fatalf("NewDecisionRecordFieldValue() error = %v", err)
		}

		fields[index], err = pluginapi.NewDecisionRecordField(name, leaf)
		if err != nil {
			t.Fatalf("NewDecisionRecordField() error = %v", err)
		}

		updated, err := pluginapi.NewDecisionRecord(fields)
		if err != nil {
			t.Fatalf("NewDecisionRecord() error = %v", err)
		}

		return updated
	}

	t.Fatalf("record field %s is missing", name)

	return pluginapi.DecisionRecord{}
}

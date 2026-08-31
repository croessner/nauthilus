// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// testDecisionRequest creates one complete admitted v1 request.
func testDecisionRequest(t *testing.T, clientIP string) pluginapi.DecisionFactRequest {
	t.Helper()

	return testDecisionRequestWithFlagStates(
		t, clientIP, false, false, stateNotRequested, stateNotRequested,
	)
}

// testDecisionRequestWithFlagStates constructs a binding-valid request with explicit hop and aggregate flag states.
//
//nolint:funlen // The complete admitted fact fixture remains visible as one reviewable contract.
func testDecisionRequestWithFlagStates(
	t *testing.T,
	clientIP string,
	doNotModify bool,
	doNotExplode bool,
	doNotModifyState string,
	doNotExplodeState string,
) pluginapi.DecisionFactRequest {
	t.Helper()

	projectionBinding, hopBinding, recipeDigest := testProjectionBindingsWithFlags(doNotModify, doNotExplode)

	facts := []pluginapi.DecisionFactView{
		testFact(t, "resource.dkim2.projection_schema", pluginapi.DecisionFactCategoryResource, testStringValue(t, projectionSchema)),
		testFact(t, "resource.dkim2.draft", pluginapi.DecisionFactCategoryResource, testStringValue(t, draftVersion)),
		testFact(t, "resource.dkim2.projection_binding_algorithm", pluginapi.DecisionFactCategoryResource, testStringValue(t, "sha-256")),
		testFact(t, "resource.dkim2.projection_binding", pluginapi.DecisionFactCategoryResource, testBytesValue(t, projectionBinding)),
		testFact(t, "resource.dkim2.verification_state", pluginapi.DecisionFactCategoryResource, testStringValue(t, "PASS")),
		testFact(t, "resource.dkim2.verification_reason", pluginapi.DecisionFactCategoryResource, testStringValue(t, "none")),
		testFact(t, "resource.dkim2.scope", pluginapi.DecisionFactCategoryResource, testStringValue(t, "chain")),
		testFact(t, "resource.dkim2.historical_content", pluginapi.DecisionFactCategoryResource, testStringValue(t, "complete")),
		testFact(t, "resource.dkim2.historical_signatures", pluginapi.DecisionFactCategoryResource, testStringValue(t, "complete")),
		testFact(t, "resource.dkim2.custody_structure", pluginapi.DecisionFactCategoryResource, testStringValue(t, "not_present")),
		testFact(t, "resource.dkim2.target_sequence", pluginapi.DecisionFactCategoryResource, testIntegerValue(t, 1)),
		testFact(t, "resource.dkim2.target_message_instance", pluginapi.DecisionFactCategoryResource, testIntegerValue(t, 1)),
		testFact(t, "resource.dkim2.claimed_hop_count", pluginapi.DecisionFactCategoryResource, testIntegerValue(t, 1)),
		testFact(t, "resource.dkim2.authentication_state", pluginapi.DecisionFactCategoryResource, testStringValue(t, "PASS")),
		testFact(t, "resource.dkim2.authentication_reason", pluginapi.DecisionFactCategoryResource, testStringValue(t, "none")),
		testFact(t, "resource.dkim2.replay_class", pluginapi.DecisionFactCategoryResource, testStringValue(t, "first_seen")),
		testFact(t, "resource.dkim2.local_policy_mode", pluginapi.DecisionFactCategoryResource, testStringValue(t, "strict")),
		testFact(t, "resource.dkim2.local_policy_verdict", pluginapi.DecisionFactCategoryResource, testStringValue(t, "continue")),
		testFact(t, "resource.dkim2.local_policy_reason", pluginapi.DecisionFactCategoryResource, testStringValue(t, "protocol_pass")),
		testFact(t, "resource.dkim2.do_not_modify_state", pluginapi.DecisionFactCategoryResource, testStringValue(t, doNotModifyState)),
		testFact(t, "resource.dkim2.do_not_explode_state", pluginapi.DecisionFactCategoryResource, testStringValue(t, doNotExplodeState)),
		testFact(t, "resource.dkim2.dns_testing_effective", pluginapi.DecisionFactCategoryResource, testBooleanValue(t, false)),
		testFact(t, "resource.dkim2.disposition", pluginapi.DecisionFactCategoryResource, testStringValue(t, "continue")),
		testFact(t, "resource.dkim2.chain", pluginapi.DecisionFactCategoryResource, testChainValueWithFlags(
			t, hopBinding, recipeDigest, doNotModify, doNotExplode,
		)),
		testFact(t, "environment.rspamd.scan_action_before_policy", pluginapi.DecisionFactCategoryEnvironment, testStringValue(t, "greylist")),
		testFact(t, "environment.rspamd.metric_score", pluginapi.DecisionFactCategoryEnvironment, testDoubleValue(t, 6.2)),
		testFact(t, "environment.rspamd.reject_threshold", pluginapi.DecisionFactCategoryEnvironment, testDoubleValue(t, 15)),
		testFact(t, "environment.rspamd.greylist_threshold", pluginapi.DecisionFactCategoryEnvironment, testDoubleValue(t, 4)),
		testFact(t, "environment.rspamd.normalized_signals", pluginapi.DecisionFactCategoryEnvironment, testStringsValue(t, []string{"dmarc.fail", "spf.softfail"})),
		testFact(t, "environment.rspamd.smtp_client_ip", pluginapi.DecisionFactCategoryEnvironment, testStringValue(t, clientIP)),
		testFact(t, "environment.rspamd.client_class", pluginapi.DecisionFactCategoryEnvironment, testStringValue(t, "untrusted")),
		testFact(t, "environment.rspamd.mail_from_class", pluginapi.DecisionFactCategoryEnvironment, testStringValue(t, "external")),
		testFact(t, "environment.rspamd.recipient_classes", pluginapi.DecisionFactCategoryEnvironment, testStringsValue(t, []string{"local"})),
		testFact(t, "environment.rspamd.smtp_authenticated", pluginapi.DecisionFactCategoryEnvironment, testBooleanValue(t, false)),
		testFact(t, "environment.rspamd.recipient_count", pluginapi.DecisionFactCategoryEnvironment, testIntegerValue(t, 1)),
		testFact(t, "environment.rspamd.message_size", pluginapi.DecisionFactCategoryEnvironment, testIntegerValue(t, 48312)),
		testFact(t, "environment.rspamd.message_fidelity", pluginapi.DecisionFactCategoryEnvironment, testStringValue(t, "milter_reconstructed_crlf")),
	}

	caller, err := pluginapi.NewDecisionCallerView(pluginapi.DecisionCallerViewInput{
		Principal: "rspamd", ClientID: "rspamd", AuthenticationKind: "policy_basic",
	})
	if err != nil {
		t.Fatalf("NewDecisionCallerView() error = %v", err)
	}

	request, err := pluginapi.NewDecisionFactRequest(exactTarget, caller, facts)
	if err != nil {
		t.Fatalf("NewDecisionFactRequest() error = %v", err)
	}

	return request
}

// testChainValueWithFlags constructs one coherent origin record with explicit protection flags.
//
//nolint:funlen // The exact wire record is intentionally visible in one test fixture.
func testChainValueWithFlags(
	t *testing.T,
	hopBinding []byte,
	recipeDigest []byte,
	doNotModify bool,
	doNotExplode bool,
) pluginapi.DecisionValue {
	t.Helper()

	fields := []struct {
		name  string
		value pluginapi.DecisionValue
	}{
		{"sequence", testIntegerValue(t, 1)},
		{"message_instance", testIntegerValue(t, 1)},
		{"hop_binding", testBytesValue(t, hopBinding)},
		{"signer_domain", testStringValue(t, "relay.example")},
		{"signature_algorithms", testStringsValue(t, []string{"ed25519-sha256"})},
		{"signature_state", testStringValue(t, "pass")},
		{"custody_transition", testStringValue(t, "origin")},
		{"do_not_modify", testBooleanValue(t, doNotModify)},
		{"do_not_explode", testBooleanValue(t, doNotExplode)},
		{"feedback", testBooleanValue(t, false)},
		{"feed_here", testBooleanValue(t, false)},
		{"exploded", testBooleanValue(t, false)},
		{"recipe_mode", testStringValue(t, "unchanged")},
		{"recipe_has_header_changes", testBooleanValue(t, false)},
		{"recipe_body_mode", testStringValue(t, "absent")},
		{"recipe_digest", testBytesValue(t, recipeDigest)},
		{"change_classes", testStringsValue(t, []string{})},
		{"affected_headers", testStringsValue(t, []string{})},
		{"history_header_state", testStringValue(t, "matched")},
		{"history_body_state", testStringValue(t, "matched")},
		{"body_availability", testStringValue(t, "known")},
		{"change_count", testIntegerValue(t, 0)},
		{"affected_header_count", testIntegerValue(t, 0)},
	}

	recordFields := make([]pluginapi.DecisionRecordField, 0, len(fields))
	for _, field := range fields {
		leaf, err := pluginapi.NewDecisionRecordFieldValue(field.value)
		if err != nil {
			t.Fatalf("NewDecisionRecordFieldValue() error = %v", err)
		}

		value, err := pluginapi.NewDecisionRecordField(field.name, leaf)
		if err != nil {
			t.Fatalf("NewDecisionRecordField() error = %v", err)
		}

		recordFields = append(recordFields, value)
	}

	record, err := pluginapi.NewDecisionRecord(recordFields)
	if err != nil {
		t.Fatalf("NewDecisionRecord() error = %v", err)
	}

	list, err := pluginapi.NewDecisionRecordList([]pluginapi.DecisionRecord{record})
	if err != nil {
		t.Fatalf("NewDecisionRecordList() error = %v", err)
	}

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Records: &list})
	if err != nil {
		t.Fatalf("NewDecisionValue(records) error = %v", err)
	}

	return value
}

// testProjectionBindingsWithFlags returns producer-compatible bindings for explicit protection flags.
func testProjectionBindingsWithFlags(doNotModify bool, doNotExplode bool) ([]byte, []byte, []byte) {
	hop := verifierHop{
		signerDomain: "relay.example", signatureAlgorithms: []string{"ed25519-sha256"}, signatureState: "pass",
		custodyTransition: custodyOrigin, recipeMode: "unchanged", recipeBodyMode: recipeBodyAbsent,
		historyHeaderState: historyMatched, historyBodyState: historyMatched, bodyAvailability: "known",
		sequence: 1, messageInstance: 1, doNotModify: doNotModify, doNotExplode: doNotExplode,
	}
	recipe := calculateRecipeDescriptorDigest(hop)
	hop.recipeDigest = recipe[:]
	projection := calculateProjectionBinding([]verifierHop{hop})
	bound := calculateBoundHopBinding(projection, hop)

	return projection[:], bound[:], recipe[:]
}

// testFact constructs one admitted immutable fact view.
func testFact(t *testing.T, id string, category pluginapi.DecisionFactCategory, value pluginapi.DecisionValue) pluginapi.DecisionFactView {
	t.Helper()

	fact, err := pluginapi.NewDecisionFactView(pluginapi.DecisionFactViewInput{ID: id, Category: category, Value: value})
	if err != nil {
		t.Fatalf("NewDecisionFactView(%s) error = %v", id, err)
	}

	return fact
}

// testStringValue constructs one strict test string.
func testStringValue(t *testing.T, input string) pluginapi.DecisionValue {
	t.Helper()

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{String: &input})
	if err != nil {
		t.Fatalf("NewDecisionValue(string) error = %v", err)
	}

	return value
}

// testStringsValue constructs one strict test string list.
func testStringsValue(t *testing.T, input []string) pluginapi.DecisionValue {
	t.Helper()

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Strings: input})
	if err != nil {
		t.Fatalf("NewDecisionValue(strings) error = %v", err)
	}

	return value
}

// testBytesValue constructs one strict test byte value.
func testBytesValue(t *testing.T, input []byte) pluginapi.DecisionValue {
	t.Helper()

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Bytes: input})
	if err != nil {
		t.Fatalf("NewDecisionValue(bytes) error = %v", err)
	}

	return value
}

// testIntegerValue constructs one strict test integer.
func testIntegerValue(t *testing.T, input int64) pluginapi.DecisionValue {
	t.Helper()

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Integer: &input})
	if err != nil {
		t.Fatalf("NewDecisionValue(integer) error = %v", err)
	}

	return value
}

// testDoubleValue constructs one strict test double.
func testDoubleValue(t *testing.T, input float64) pluginapi.DecisionValue {
	t.Helper()

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Double: &input})
	if err != nil {
		t.Fatalf("NewDecisionValue(double) error = %v", err)
	}

	return value
}

// testBooleanValue constructs one strict test boolean.
func testBooleanValue(t *testing.T, input bool) pluginapi.DecisionValue {
	t.Helper()

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Boolean: &input})
	if err != nil {
		t.Fatalf("NewDecisionValue(boolean) error = %v", err)
	}

	return value
}

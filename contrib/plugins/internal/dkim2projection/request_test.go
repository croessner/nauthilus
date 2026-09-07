// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package dkim2projection

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// testDecisionRequest creates one complete admitted v1 request.
func testDecisionRequest(t *testing.T, ClientIP string) pluginapi.DecisionFactRequest {
	t.Helper()

	return testDecisionRequestWithFlagStates(
		t, ClientIP, false, false, StateNotRequested, StateNotRequested,
	)
}

// testDecisionRequestWithFlagStates constructs a binding-valid request with explicit hop and aggregate flag states.
//
//nolint:funlen // The complete admitted fact fixture remains visible as one reviewable contract.
func testDecisionRequestWithFlagStates(
	t *testing.T,
	ClientIP string,
	DoNotModify bool,
	DoNotExplode bool,
	DoNotModifyState string,
	DoNotExplodeState string,
) pluginapi.DecisionFactRequest {
	t.Helper()

	ProjectionBinding, HopBinding, RecipeDigest := testProjectionBindingsWithFlags(DoNotModify, DoNotExplode)

	facts := []pluginapi.DecisionFactView{
		testFact(t, "resource.dkim2.projection_schema", pluginapi.DecisionFactCategoryResource, testStringValue(t, ProjectionSchema)),
		testFact(t, "resource.dkim2.draft", pluginapi.DecisionFactCategoryResource, testStringValue(t, DraftVersion)),
		testFact(t, "resource.dkim2.projection_binding_algorithm", pluginapi.DecisionFactCategoryResource, testStringValue(t, "sha-256")),
		testFact(t, "resource.dkim2.projection_binding", pluginapi.DecisionFactCategoryResource, testBytesValue(t, ProjectionBinding)),
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
		testFact(t, "resource.dkim2.do_not_modify_state", pluginapi.DecisionFactCategoryResource, testStringValue(t, DoNotModifyState)),
		testFact(t, "resource.dkim2.do_not_explode_state", pluginapi.DecisionFactCategoryResource, testStringValue(t, DoNotExplodeState)),
		testFact(t, "resource.dkim2.dns_testing_effective", pluginapi.DecisionFactCategoryResource, testBooleanValue(t, false)),
		testFact(t, "resource.dkim2.disposition", pluginapi.DecisionFactCategoryResource, testStringValue(t, "continue")),
		testFact(t, "resource.dkim2.chain", pluginapi.DecisionFactCategoryResource, testChainValueWithFlags(
			t, HopBinding, RecipeDigest, DoNotModify, DoNotExplode,
		)),
		testFact(t, "environment.rspamd.scan_action_before_policy", pluginapi.DecisionFactCategoryEnvironment, testStringValue(t, "greylist")),
		testFact(t, "environment.rspamd.metric_score", pluginapi.DecisionFactCategoryEnvironment, testDoubleValue(t, 6.2)),
		testFact(t, "environment.rspamd.reject_threshold", pluginapi.DecisionFactCategoryEnvironment, testDoubleValue(t, 15)),
		testFact(t, "environment.rspamd.greylist_threshold", pluginapi.DecisionFactCategoryEnvironment, testDoubleValue(t, 4)),
		testFact(t, "environment.rspamd.normalized_signals", pluginapi.DecisionFactCategoryEnvironment, testStringsValue(t, []string{"dmarc.fail", "spf.softfail"})),
		testFact(t, "environment.rspamd.smtp_client_ip", pluginapi.DecisionFactCategoryEnvironment, testStringValue(t, ClientIP)),
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

	request, err := pluginapi.NewDecisionFactRequest(ExactTarget, caller, facts)
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
	HopBinding []byte,
	RecipeDigest []byte,
	DoNotModify bool,
	DoNotExplode bool,
) pluginapi.DecisionValue {
	t.Helper()

	return testChainValue(t, []Hop{{
		SignerDomain: "relay.example", SignatureAlgorithms: []string{"ed25519-sha256"}, HopBinding: HopBinding,
		RecipeDigest: RecipeDigest, SignatureState: "pass", CustodyTransition: CustodyOrigin, RecipeMode: "unchanged",
		RecipeBodyMode: RecipeBodyAbsent, ChangeClasses: []string{}, AffectedHeaders: []string{},
		HistoryHeaderState: HistoryMatched, HistoryBodyState: HistoryMatched,
		BodyAvailability: "known", Sequence: 1, MessageInstance: 1, DoNotModify: DoNotModify,
		DoNotExplode: DoNotExplode,
	}})
}

// testChainValue constructs an exact wire record list from binding-valid semantic hops.
func testChainValue(t *testing.T, hops []Hop) pluginapi.DecisionValue {
	t.Helper()

	records := make([]pluginapi.DecisionRecord, 0, len(hops))
	for _, hop := range hops {
		records = append(records, testChainRecord(t, hop))
	}

	list, err := pluginapi.NewDecisionRecordList(records)
	if err != nil {
		t.Fatalf("NewDecisionRecordList() error = %v", err)
	}

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Records: &list})
	if err != nil {
		t.Fatalf("NewDecisionValue(records) error = %v", err)
	}

	return value
}

// testChainRecord maps one semantic hop into the exact public record contract.
func testChainRecord(t *testing.T, hop Hop) pluginapi.DecisionRecord {
	t.Helper()

	fields := []struct {
		name  string
		value pluginapi.DecisionValue
	}{
		{"sequence", testIntegerValue(t, hop.Sequence)},
		{"message_instance", testIntegerValue(t, hop.MessageInstance)},
		{"hop_binding", testBytesValue(t, hop.HopBinding)},
		{"signer_domain", testStringValue(t, hop.SignerDomain)},
		{"signature_algorithms", testStringsValue(t, hop.SignatureAlgorithms)},
		{"signature_state", testStringValue(t, hop.SignatureState)},
		{"custody_transition", testStringValue(t, hop.CustodyTransition)},
		{"do_not_modify", testBooleanValue(t, hop.DoNotModify)},
		{"do_not_explode", testBooleanValue(t, hop.DoNotExplode)},
		{"feedback", testBooleanValue(t, hop.Feedback)},
		{"feed_here", testBooleanValue(t, hop.FeedHere)},
		{"exploded", testBooleanValue(t, hop.Exploded)},
		{"recipe_mode", testStringValue(t, hop.RecipeMode)},
		{"recipe_has_header_changes", testBooleanValue(t, hop.RecipeHasHeaders)},
		{"recipe_body_mode", testStringValue(t, hop.RecipeBodyMode)},
		{"recipe_digest", testBytesValue(t, hop.RecipeDigest)},
		{"change_classes", testStringsValue(t, hop.ChangeClasses)},
		{"affected_headers", testStringsValue(t, hop.AffectedHeaders)},
		{"history_header_state", testStringValue(t, hop.HistoryHeaderState)},
		{"history_body_state", testStringValue(t, hop.HistoryBodyState)},
		{"body_availability", testStringValue(t, hop.BodyAvailability)},
		{"change_count", testIntegerValue(t, hop.ChangeCount)},
		{"affected_header_count", testIntegerValue(t, hop.AffectedHeaderCount)},
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

	return record
}

// testProjectionBindingsWithFlags returns producer-compatible bindings for explicit protection flags.
func testProjectionBindingsWithFlags(DoNotModify bool, DoNotExplode bool) ([]byte, []byte, []byte) {
	hop := Hop{
		SignerDomain: "relay.example", SignatureAlgorithms: []string{"ed25519-sha256"}, SignatureState: "pass",
		CustodyTransition: CustodyOrigin, RecipeMode: "unchanged", RecipeBodyMode: RecipeBodyAbsent,
		HistoryHeaderState: HistoryMatched, HistoryBodyState: HistoryMatched, BodyAvailability: "known",
		Sequence: 1, MessageInstance: 1, DoNotModify: DoNotModify, DoNotExplode: DoNotExplode,
	}
	recipe := CalculateRecipeDescriptorDigest(hop)
	hop.RecipeDigest = recipe[:]
	projection := CalculateProjectionBinding([]Hop{hop})
	bound := CalculateBoundHopBinding(projection, hop)

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

// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
)

// TestAuthnNativePublicFactsExposePublicRecordLists reproduces the reputation analytics gap: record-valued plugin
// facts reached public post-actions as the server-internal decision.RecordList, which public plugins cannot decode.
func TestAuthnNativePublicFactsExposePublicRecordLists(t *testing.T) {
	facts := authnNativePublicFacts(newRecordFactSet(t, "plugin.reputation.auth_subjects", "ip", "neutral"))
	if len(facts) != 1 {
		t.Fatalf("public facts = %d, want 1", len(facts))
	}

	records, ok := facts[0].Value.(pluginapi.DecisionRecordList)
	if !ok {
		t.Fatalf("record fact value type = %T, want pluginapi.DecisionRecordList", facts[0].Value)
	}

	got := publicRecordStrings(t, records)
	if got["kind"] != "ip" || got["band"] != "neutral" {
		t.Fatalf("public record fields = %#v, want kind=ip band=neutral", got)
	}
}

// newRecordFactSet builds one plugin-sourced record fact with string fields.
func newRecordFactSet(t *testing.T, id string, kind string, band string) decision.FactSet {
	t.Helper()

	fields := make([]decision.RecordField, 0, 2)

	for _, pair := range [][2]string{{"kind", kind}, {"band", band}} {
		value := pair[1]

		fieldValue, err := decision.NewRecordFieldValue(decision.RecordFieldValueInput{String: &value})
		if err != nil {
			t.Fatalf("NewRecordFieldValue() error = %v", err)
		}

		field, err := decision.NewRecordField(pair[0], fieldValue)
		if err != nil {
			t.Fatalf("NewRecordField() error = %v", err)
		}

		fields = append(fields, field)
	}

	record, err := decision.NewRecord(fields)
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}

	list, err := decision.NewRecordList([]decision.Record{record})
	if err != nil {
		t.Fatalf("NewRecordList() error = %v", err)
	}

	value, err := decision.NewValue(decision.ValueInput{Records: &list})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	provenance, err := decision.NewProvenance(decision.FactSourcePlugin, "reputation", "authentication")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	fact, err := decision.NewFact(id, decision.FactCategoryResource, value, provenance)
	if err != nil {
		t.Fatalf("NewFact() error = %v", err)
	}

	set, err := decision.NewFactSet([]decision.Fact{fact})
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	return set
}

// publicRecordStrings flattens the string fields of the first public record.
func publicRecordStrings(t *testing.T, records pluginapi.DecisionRecordList) map[string]string {
	t.Helper()

	result := make(map[string]string)

	list := records.Records()
	if len(list) == 0 {
		return result
	}

	for _, field := range list[0].Fields() {
		value, ok := field.Value().Any()
		if text, isString := value.(string); ok && isString {
			result[field.Name()] = text
		}
	}

	return result
}

// TestAuthnNativePostActionBoundsTrimRecordFactsInsteadOfFailing reproduces the work-bound risk of record facts: a
// post-action request carrying the four reputation profile views for many subjects exceeds DefaultWorkBounds, which
// would turn the authentication decision indeterminate. The host drops the largest record facts until the request
// fits, keeps scalar facts, and reports the trim.
func TestAuthnNativePostActionBoundsTrimRecordFactsInsteadOfFailing(t *testing.T) {
	facts := []pluginapi.PolicyFact{{Attribute: "plugin.geoip.country_iso", Value: "DE"}}
	for _, view := range []string{"", "_fast", "_operational", "_baseline"} {
		facts = append(facts, pluginapi.PolicyFact{
			Attribute: "plugin.reputation.auth_subjects" + view,
			Value:     newPublicAssessmentRecords(t, 40),
		})
	}

	request := pluginapi.PostActionRequest{Facts: facts}
	if effectsupervisor.ValidateBoundedValue(request, effectsupervisor.DefaultWorkBounds()) == nil {
		t.Fatal("reproducer request fits the work bound; increase the subject count")
	}

	if err := boundAuthnNativePostActionRequest(&request); err != nil {
		t.Fatalf("boundAuthnNativePostActionRequest() error = %v, want trimmed request", err)
	}

	if !request.FactsTrimmed || len(request.Facts) == 0 || request.Facts[0].Attribute != "plugin.geoip.country_iso" {
		t.Fatalf("trimmed request = trimmed:%v facts:%d, want trim flag and kept scalar fact",
			request.FactsTrimmed, len(request.Facts))
	}
}

// TestAuthnNativePostActionBoundsKeepFittingRequestsUntouched pins that requests within the bound are not trimmed.
func TestAuthnNativePostActionBoundsKeepFittingRequestsUntouched(t *testing.T) {
	request := pluginapi.PostActionRequest{Facts: []pluginapi.PolicyFact{{
		Attribute: "plugin.reputation.auth_subjects", Value: newPublicAssessmentRecords(t, 1),
	}}}

	if err := boundAuthnNativePostActionRequest(&request); err != nil || request.FactsTrimmed || len(request.Facts) != 1 {
		t.Fatalf("bound result = %v trimmed:%v facts:%d, want untouched", err, request.FactsTrimmed, len(request.Facts))
	}
}

// newPublicAssessmentRecords builds public reputation-shaped records with the twelve measured assessment fields.
func newPublicAssessmentRecords(t *testing.T, subjects int) pluginapi.DecisionRecordList {
	t.Helper()

	records := make([]pluginapi.DecisionRecord, 0, subjects)

	for range subjects {
		fields := make([]pluginapi.DecisionRecordField, 0, 12)

		for _, name := range []string{"role", "kind", "state", "profile", "band", "override"} {
			text := "value"
			fields = append(fields, newPublicRecordField(t, name, pluginapi.DecisionValueInput{String: &text}))
		}

		for _, name := range []string{"risk_score", "trust_score", "confidence", "samples"} {
			number := 0.5
			fields = append(fields, newPublicRecordField(t, name, pluginapi.DecisionValueInput{Double: &number}))
		}

		for _, name := range []string{"source_diversity", "age_seconds"} {
			integer := int64(1)
			fields = append(fields, newPublicRecordField(t, name, pluginapi.DecisionValueInput{Integer: &integer}))
		}

		record, err := pluginapi.NewDecisionRecord(fields)
		if err != nil {
			t.Fatalf("NewDecisionRecord() error = %v", err)
		}

		records = append(records, record)
	}

	list, err := pluginapi.NewDecisionRecordList(records)
	if err != nil {
		t.Fatalf("NewDecisionRecordList() error = %v", err)
	}

	return list
}

// newPublicRecordField builds one public record field from a strict value input.
func newPublicRecordField(t *testing.T, name string, input pluginapi.DecisionValueInput) pluginapi.DecisionRecordField {
	t.Helper()

	value, err := pluginapi.NewDecisionValue(input)
	if err != nil {
		t.Fatalf("NewDecisionValue() error = %v", err)
	}

	fieldValue, err := pluginapi.NewDecisionRecordFieldValue(value)
	if err != nil {
		t.Fatalf("NewDecisionRecordFieldValue() error = %v", err)
	}

	field, err := pluginapi.NewDecisionRecordField(name, fieldValue)
	if err != nil {
		t.Fatalf("NewDecisionRecordField() error = %v", err)
	}

	return field
}

// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/pluginapi/v1/exchange"
)

var privacyColumnContract = []struct {
	fieldName string
	jsonName  string
	sqlType   string
}{
	{"GeoIPPrivacyLookupState", "geoip_privacy_lookup_state", "LowCardinality(String)"},
	{"GeoIPPrivacyDetected", "geoip_privacy_detected", "Nullable(Bool)"},
	{"GeoIPPrivacyClasses", "geoip_privacy_classes", "Array(String)"},
	{"GeoIPPrivacyPrimaryClass", "geoip_privacy_primary_class", "LowCardinality(String)"},
	{"GeoIPPrivacyConfidence", "geoip_privacy_confidence", "Nullable(Float64)"},
	{"GeoIPPrivacySourceAuthorities", "geoip_privacy_source_authorities", "Array(String)"},
	{"GeoIPPrivacyDataStale", "geoip_privacy_data_stale", "Nullable(Bool)"},
	{"GeoIPPrivacyDataAgeSeconds", "geoip_privacy_data_age_seconds", "Nullable(UInt64)"},
	{"GeoIPIsTorExitNode", "geoip_is_tor_exit_node", "Nullable(Bool)"},
	{"GeoIPIsKnownVPNExit", "geoip_is_known_vpn_exit", "Nullable(Bool)"},
	{"GeoIPIsCommunityVPNExit", "geoip_is_community_vpn_exit", "Nullable(Bool)"},
	{"GeoIPIsPublicProxy", "geoip_is_public_proxy", "Nullable(Bool)"},
	{"GeoIPIsPrivacyRelay", "geoip_is_privacy_relay", "Nullable(Bool)"},
	{"GeoIPIsHostingNetwork", "geoip_is_hosting_network", "Nullable(Bool)"},
	{"GeoIPIsSharedEgress", "geoip_is_shared_egress", "Nullable(Bool)"},
}

func TestPrivacyExchangePopulatesEveryJSONEachRowField(t *testing.T) {
	row := singleRowForRequest(t, requestOptions{
		runtimeValues: map[string]any{
			exchange.KeyGeoIP: map[string]any{
				"country_iso":                          "DE",
				exchange.FieldPrivacyLookupState:       "evaluated",
				exchange.FieldPrivacyDetected:          true,
				exchange.FieldPrivacyClasses:           []any{"tor_exit", "vpn", "tor_exit"},
				exchange.FieldPrivacyPrimaryClass:      "tor_exit",
				exchange.FieldPrivacyConfidence:        float64(100),
				exchange.FieldPrivacySourceAuthorities: []string{"official", "community", "official"},
				exchange.FieldPrivacyDataStale:         false,
				exchange.FieldPrivacyDataAgeSeconds:    float64(0),
				exchange.FieldIsTorExitNode:            true,
				exchange.FieldIsKnownVPNExit:           false,
				exchange.FieldIsCommunityVPNExit:       false,
				exchange.FieldIsPublicProxy:            false,
				exchange.FieldIsPrivacyRelay:           false,
				exchange.FieldIsHostingNetwork:         true,
				exchange.FieldIsSharedEgress:           true,
			},
			exchange.KeyGeoIPReputation: map[string]any{"score": 0.25},
		},
	})

	assertCompletePrivacyRow(t, row)
	assertStringField(t, row, "geoip_country", "DE")
	assertNumberField(t, row, "reputation_score", 0.25)
	assertStringField(t, row, "decision_sources", "")
}

func TestPrivacyFactsPopulateEveryMissingExchangeField(t *testing.T) {
	row := singleRowForRequest(t, requestOptions{
		runtimeValues: map[string]any{
			exchange.KeyGeoIP: map[string]any{"country_iso": "DE"},
		},
		facts: completePrivacyFacts(),
	})

	assertCompletePrivacyRow(t, row)
	assertStringField(t, row, "geoip_country", "DE")
	assertStringField(t, row, "decision_sources", "")
}

func TestPrivacyMalformedExchangeFallsBackToFactsWithoutDiscardingRow(t *testing.T) {
	row := singleRowForRequest(t, requestOptions{
		runtimeValues: map[string]any{
			exchange.KeyGeoIP: map[string]any{
				exchange.FieldPrivacyDetected:       false,
				exchange.FieldPrivacyConfidence:     "not-a-number",
				exchange.FieldPrivacyDataAgeSeconds: -1,
				exchange.FieldIsTorExitNode:         "not-a-bool",
			},
			"rt": map[string]any{
				exchange.FieldPrivacyDetected: true,
			},
		},
		facts: []pluginapi.PolicyFact{
			{Attribute: privacyFactAttribute(exchange.FieldPrivacyLookupState), Value: "evaluated"},
			{Attribute: privacyFactAttribute(exchange.FieldPrivacyDetected), Value: true},
			{Attribute: privacyFactAttribute(exchange.FieldPrivacyClasses), Value: []string{"vpn", "vpn"}},
			{Attribute: privacyFactAttribute(exchange.FieldPrivacyConfidence), Value: float64(0)},
			{Attribute: privacyFactAttribute(exchange.FieldPrivacyDataAgeSeconds), Value: float64(0)},
			{Attribute: privacyFactAttribute(exchange.FieldIsTorExitNode), Value: true},
		},
	})

	assertStringField(t, row, "session", "sess-1")
	assertStringField(t, row, "geoip_privacy_lookup_state", "evaluated")
	assertBoolField(t, row, "geoip_privacy_detected", false)
	assertStringSliceField(t, row, "geoip_privacy_classes", []string{"vpn"})
	assertNumberField(t, row, "geoip_privacy_confidence", 0)
	assertNumberField(t, row, "geoip_privacy_data_age_seconds", 0)
	assertBoolField(t, row, "geoip_is_tor_exit_node", true)
	assertStringField(t, row, "decision_sources", "")
}

func TestPrivacyUnavailableUsesNullScalarsAndNonNullEmptyArrays(t *testing.T) {
	row := singleRowForRequest(t, requestOptions{
		facts: []pluginapi.PolicyFact{
			{Attribute: privacyFactAttribute(exchange.FieldPrivacyLookupState), Value: "unavailable"},
		},
	})

	assertStringField(t, row, "geoip_privacy_lookup_state", "unavailable")
	assertStringSliceField(t, row, "geoip_privacy_classes", []string{})
	assertStringSliceField(t, row, "geoip_privacy_source_authorities", []string{})

	for _, key := range []string{
		"geoip_privacy_detected",
		"geoip_privacy_confidence",
		"geoip_privacy_data_age_seconds",
		"geoip_is_tor_exit_node",
		"geoip_is_known_vpn_exit",
	} {
		if row[key] != nil {
			t.Fatalf("row[%s] = %#v, want null", key, row[key])
		}
	}
}

func TestPrivacyClickHouseRowAndSchemaStayInParity(t *testing.T) {
	schemaBytes, err := os.ReadFile("../../clickhouse-kubernetes/schema.sql")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}

	schema := string(schemaBytes)

	jobBytes, err := os.ReadFile("../../clickhouse-kubernetes/k8s-job.yaml")
	if err != nil {
		t.Fatalf("read Kubernetes schema job: %v", err)
	}

	jobSchema := string(jobBytes)
	rowType := reflect.TypeOf(clickHouseRow{})

	for _, column := range privacyColumnContract {
		field, ok := rowType.FieldByName(column.fieldName)
		if !ok {
			t.Fatalf("clickHouseRow missing %s", column.fieldName)
		}

		if got := field.Tag.Get("json"); got != column.jsonName {
			t.Fatalf("%s JSON name = %q, want %q", column.fieldName, got, column.jsonName)
		}

		definition := column.jsonName + " " + column.sqlType
		if count := strings.Count(normalizedSQL(schema), normalizedSQL(definition)); count < 2 {
			t.Fatalf("schema definition %q occurs %d times, want create and upgrade definitions", definition, count)
		}

		migration := "ADD COLUMN IF NOT EXISTS " + definition
		if !strings.Contains(normalizedSQL(schema), normalizedSQL(migration)) {
			t.Fatalf("schema missing repeatable migration %q", migration)
		}

		if !strings.Contains(normalizedSQL(jobSchema), normalizedSQL(definition)) {
			t.Fatalf("Kubernetes schema job missing definition %q", definition)
		}
	}
}

// privacyFactAttribute returns the native GeoIP policy fact ID for a field.
func privacyFactAttribute(field string) string {
	return "plugin.environment.geoip." + field
}

// completePrivacyFacts returns one value for every privacy analytics field.
func completePrivacyFacts() []pluginapi.PolicyFact {
	values := []struct {
		field string
		value any
	}{
		{exchange.FieldPrivacyLookupState, "evaluated"},
		{exchange.FieldPrivacyDetected, true},
		{exchange.FieldPrivacyClasses, []string{"tor_exit", "vpn", "tor_exit"}},
		{exchange.FieldPrivacyPrimaryClass, "tor_exit"},
		{exchange.FieldPrivacyConfidence, float64(100)},
		{exchange.FieldPrivacySourceAuthorities, []string{"official", "community", "official"}},
		{exchange.FieldPrivacyDataStale, false},
		{exchange.FieldPrivacyDataAgeSeconds, float64(0)},
		{exchange.FieldIsTorExitNode, true},
		{exchange.FieldIsKnownVPNExit, false},
		{exchange.FieldIsCommunityVPNExit, false},
		{exchange.FieldIsPublicProxy, false},
		{exchange.FieldIsPrivacyRelay, false},
		{exchange.FieldIsHostingNetwork, true},
		{exchange.FieldIsSharedEgress, true},
	}

	facts := make([]pluginapi.PolicyFact, 0, len(values))
	for _, value := range values {
		facts = append(facts, pluginapi.PolicyFact{Attribute: privacyFactAttribute(value.field), Value: value.value})
	}

	return facts
}

// assertCompletePrivacyRow checks the complete typed privacy column contract.
func assertCompletePrivacyRow(t *testing.T, row map[string]any) {
	t.Helper()

	assertStringField(t, row, "geoip_privacy_lookup_state", "evaluated")
	assertBoolField(t, row, "geoip_privacy_detected", true)
	assertStringSliceField(t, row, "geoip_privacy_classes", []string{"tor_exit", "vpn"})
	assertStringField(t, row, "geoip_privacy_primary_class", "tor_exit")
	assertNumberField(t, row, "geoip_privacy_confidence", 100)
	assertStringSliceField(t, row, "geoip_privacy_source_authorities", []string{"official", "community"})
	assertBoolField(t, row, "geoip_privacy_data_stale", false)
	assertNumberField(t, row, "geoip_privacy_data_age_seconds", 0)
	assertBoolField(t, row, "geoip_is_tor_exit_node", true)
	assertBoolField(t, row, "geoip_is_known_vpn_exit", false)
	assertBoolField(t, row, "geoip_is_community_vpn_exit", false)
	assertBoolField(t, row, "geoip_is_public_proxy", false)
	assertBoolField(t, row, "geoip_is_privacy_relay", false)
	assertBoolField(t, row, "geoip_is_hosting_network", true)
	assertBoolField(t, row, "geoip_is_shared_egress", true)
}

// assertStringSliceField checks a non-null JSON string array.
func assertStringSliceField(t *testing.T, row map[string]any, key string, want []string) {
	t.Helper()

	values, ok := row[key].([]any)
	if !ok {
		t.Fatalf("row[%s] = %#v, want JSON array", key, row[key])
	}

	got := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("row[%s] member = %#v, want string", key, value)
		}

		got = append(got, text)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("row[%s] = %#v, want %#v", key, got, want)
	}
}

// normalizedSQL collapses formatting so schema parity checks remain layout-independent.
func normalizedSQL(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

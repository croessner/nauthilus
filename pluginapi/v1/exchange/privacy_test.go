// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package exchange

import (
	"math"
	"reflect"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

func TestGeoIPAnalyticsPrefersValidRuntimeAndFallsBackFromMalformedValues(t *testing.T) {
	snapshot := NewSnapshotFromValues(map[string]any{
		KeyGeoIP: map[string]any{
			FieldPrivacyLookupState:       "evaluated",
			FieldPrivacyDetected:          false,
			FieldPrivacyClasses:           []any{"tor_exit", "vpn", "tor_exit", " "},
			FieldPrivacyConfidence:        "invalid",
			FieldPrivacyDataAgeSeconds:    -1,
			FieldIsTorExitNode:            "invalid",
			FieldPrivacySourceAuthorities: []string{"official", "community", "official"},
			"country_iso":                 "DE",
		},
	}, []pluginapi.PolicyFact{
		{Attribute: privacyFact(FieldPrivacyDetected), Value: true},
		{Attribute: privacyFact(FieldPrivacyConfidence), Value: float64(0)},
		{Attribute: privacyFact(FieldPrivacyDataAgeSeconds), Value: float64(0)},
		{Attribute: privacyFact(FieldIsTorExitNode), Value: true},
	})

	got := snapshot.GeoIPAnalytics()
	if got.Fields["country_iso"] != "DE" {
		t.Fatalf("GeoIP fields = %#v, want existing country", got.Fields)
	}

	if got.Privacy.Detected == nil || *got.Privacy.Detected {
		t.Fatalf("Detected = %#v, want explicit runtime false", got.Privacy.Detected)
	}

	if got.Privacy.Confidence == nil || *got.Privacy.Confidence != 0 {
		t.Fatalf("Confidence = %#v, want fact fallback zero", got.Privacy.Confidence)
	}

	if got.Privacy.DataAgeSeconds == nil || *got.Privacy.DataAgeSeconds != 0 {
		t.Fatalf("DataAgeSeconds = %#v, want fact fallback zero", got.Privacy.DataAgeSeconds)
	}

	if got.Privacy.IsTorExitNode == nil || !*got.Privacy.IsTorExitNode {
		t.Fatalf("IsTorExitNode = %#v, want fact fallback true", got.Privacy.IsTorExitNode)
	}

	wantClasses := []string{"tor_exit", "vpn"}
	if !reflect.DeepEqual(got.Privacy.Classes, wantClasses) {
		t.Fatalf("Classes = %#v, want %#v", got.Privacy.Classes, wantClasses)
	}

	wantAuthorities := []string{"official", "community"}
	if !reflect.DeepEqual(got.Privacy.SourceAuthorities, wantAuthorities) {
		t.Fatalf("SourceAuthorities = %#v, want %#v", got.Privacy.SourceAuthorities, wantAuthorities)
	}

	wantMalformed := []string{FieldPrivacyConfidence, FieldPrivacyDataAgeSeconds, FieldIsTorExitNode}
	assertPrivacyMalformedFields(t, got.MalformedFields, wantMalformed)
}

func TestGeoIPAnalyticsRejectsNonFiniteAndPreservesUnavailableSemantics(t *testing.T) {
	snapshot := NewSnapshotFromValues(map[string]any{
		KeyGeoIP: map[string]any{
			FieldPrivacyLookupState: "unavailable",
			FieldPrivacyConfidence:  math.Inf(1),
			FieldPrivacyDetected:    false,
			FieldIsKnownVPNExit:     false,
		},
	}, nil)

	got := snapshot.GeoIPAnalytics()
	if got.Privacy.LookupState != "unavailable" {
		t.Fatalf("LookupState = %q, want unavailable", got.Privacy.LookupState)
	}

	if got.Privacy.Detected != nil || got.Privacy.Confidence != nil || got.Privacy.IsKnownVPNExit != nil {
		t.Fatalf("unavailable privacy values were fabricated: %#v", got.Privacy)
	}

	if got.Privacy.Classes == nil || got.Privacy.SourceAuthorities == nil {
		t.Fatalf("lists must be non-nil: classes=%#v authorities=%#v", got.Privacy.Classes, got.Privacy.SourceAuthorities)
	}
}

func TestGeoIPAnalyticsDoesNotFabricateClassificationsWithoutEvaluatedState(t *testing.T) {
	snapshot := NewSnapshotFromValues(map[string]any{
		KeyGeoIP: map[string]any{
			FieldPrivacyDetected: false,
			FieldIsTorExitNode:   false,
		},
	}, nil)

	got := snapshot.GeoIPAnalytics()
	if got.Privacy.Detected != nil || got.Privacy.IsTorExitNode != nil {
		t.Fatalf("classification values without evaluated state = %#v", got.Privacy)
	}
}

func TestGeoIPAnalyticsCarriesSharedEgressClassification(t *testing.T) {
	snapshot := NewSnapshotFromValues(map[string]any{
		KeyGeoIP: map[string]any{
			FieldPrivacyLookupState: "evaluated",
			FieldIsSharedEgress:     true,
		},
	}, nil)

	got := snapshot.GeoIPAnalytics()
	if got.Privacy.IsSharedEgress == nil || !*got.Privacy.IsSharedEgress {
		t.Fatalf("IsSharedEgress = %#v, want true", got.Privacy)
	}
}

func TestGeoIPAnalyticsProjectsCanonicalGenericFactsWithoutRuntime(t *testing.T) {
	snapshot := NewSnapshotFromValues(nil, []pluginapi.PolicyFact{
		{Attribute: genericGeoIPFact("matched"), Value: true},
		{Attribute: genericGeoIPFact("country_iso"), Value: "DE"},
		{Attribute: genericGeoIPFact("asn"), Value: int64(64500)},
		{Attribute: genericGeoIPFact(FieldPrivacyLookupState), Value: "evaluated"},
		{Attribute: genericGeoIPFact(FieldPrivacyDetected), Value: true},
		{Attribute: genericGeoIPFact(FieldPrivacyClasses), Value: []string{"tor_exit"}},
		{Attribute: genericGeoIPFact(FieldPrivacyConfidence), Value: float64(100)},
		{Attribute: genericGeoIPFact(FieldIsTorExitNode), Value: true},
	})

	got := snapshot.GeoIPAnalytics()
	if got.Fields["matched"] != true || got.Fields["country_iso"] != "DE" || got.Fields["asn"] != int64(64500) {
		t.Fatalf("GeoIP fields = %#v, want canonical generic fact projection", got.Fields)
	}

	if got.Privacy.LookupState != "evaluated" || got.Privacy.Detected == nil || !*got.Privacy.Detected ||
		got.Privacy.Confidence == nil || *got.Privacy.Confidence != 100 ||
		got.Privacy.IsTorExitNode == nil || !*got.Privacy.IsTorExitNode {
		t.Fatalf("GeoIP privacy = %#v, want canonical generic fact projection", got.Privacy)
	}

	if !reflect.DeepEqual(got.Privacy.Classes, []string{"tor_exit"}) {
		t.Fatalf("GeoIP privacy classes = %#v, want tor_exit", got.Privacy.Classes)
	}
}

func TestGeoIPAnalyticsReportsMalformedFactWithoutRawValue(t *testing.T) {
	snapshot := NewSnapshotFromValues(nil, []pluginapi.PolicyFact{
		{Attribute: privacyFact(FieldPrivacyLookupState), Value: "evaluated"},
		{Attribute: privacyFact(FieldPrivacyConfidence), Value: "secret-invalid-value"},
	})

	got := snapshot.GeoIPAnalytics()
	if got.Privacy.Confidence != nil {
		t.Fatalf("Confidence = %#v, want unavailable", got.Privacy.Confidence)
	}

	wantMalformed := []string{FieldPrivacyConfidence}
	assertPrivacyMalformedFields(t, got.MalformedFields, wantMalformed)
}

// assertPrivacyMalformedFields checks bounded diagnostic field names.
func assertPrivacyMalformedFields(t *testing.T, got []string, want []string) {
	t.Helper()

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MalformedFields = %#v, want bounded field names %#v", got, want)
	}
}

// privacyFact returns the native GeoIP policy fact ID for a field.
func privacyFact(field string) string {
	return "plugin.environment.geoip." + field
}

// genericGeoIPFact returns the canonical generic GeoIP fact ID for a field.
func genericGeoIPFact(field string) string {
	return "plugin.geoip." + field
}

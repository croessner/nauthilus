// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/pluginapi/v1/exchange"
	"github.com/croessner/nauthilus/v3/server/config"
)

func TestPrivacyPolicyAttributeContract(t *testing.T) {
	want := map[string]pluginapi.AttributeType{
		"plugin.environment.geoip.privacy_lookup_state":       pluginapi.AttributeTypeString,
		"plugin.environment.geoip.privacy_detected":           pluginapi.AttributeTypeBool,
		"plugin.environment.geoip.privacy_classes":            pluginapi.AttributeTypeStringList,
		"plugin.environment.geoip.privacy_primary_class":      pluginapi.AttributeTypeString,
		"plugin.environment.geoip.privacy_confidence":         pluginapi.AttributeTypeNumber,
		"plugin.environment.geoip.privacy_source_authorities": pluginapi.AttributeTypeStringList,
		"plugin.environment.geoip.privacy_data_stale":         pluginapi.AttributeTypeBool,
		"plugin.environment.geoip.privacy_data_age_seconds":   pluginapi.AttributeTypeNumber,
		"plugin.environment.geoip.is_tor_exit_node":           pluginapi.AttributeTypeBool,
		"plugin.environment.geoip.is_known_vpn_exit":          pluginapi.AttributeTypeBool,
		"plugin.environment.geoip.is_community_vpn_exit":      pluginapi.AttributeTypeBool,
		"plugin.environment.geoip.is_public_proxy":            pluginapi.AttributeTypeBool,
		"plugin.environment.geoip.is_privacy_relay":           pluginapi.AttributeTypeBool,
		"plugin.environment.geoip.is_hosting_network":         pluginapi.AttributeTypeBool,
		"plugin.environment.geoip.is_shared_egress":           pluginapi.AttributeTypeBool,
	}

	definitions := geoIPPolicyAttributes()
	for id, valueType := range want {
		definition, found := findPolicyDefinition(definitions, id)
		if !found {
			t.Fatalf("policy attribute %q is not registered", id)
		}

		if definition.Type != valueType || definition.Stage != pluginapi.PolicyStagePreAuth || definition.Category != pluginapi.AttributeCategoryEnvironment {
			t.Fatalf("policy attribute %q = %#v, want type %q pre_auth environment", id, definition, valueType)
		}

		if !reflect.DeepEqual(definition.Operations, []pluginapi.PolicyOperation{pluginapi.PolicyOperationAuthenticate, pluginapi.PolicyOperationLookupIdentity}) {
			t.Fatalf("policy attribute %q operations = %#v", id, definition.Operations)
		}

		if !reflect.DeepEqual(definition.ProducerTypes, []string{policyProducer}) || definition.ProducerCheck != "" {
			t.Fatalf("policy attribute %q producer contract = %#v/%q", id, definition.ProducerTypes, definition.ProducerCheck)
		}
	}
}

func TestPrivacyEvaluatedNegativeEmitsTriStateFactsAndPreservesGeoIPExchange(t *testing.T) {
	result := evaluatePrivacyFixture(t, privacyLookupResult{State: privacyLookupStateEvaluated}, geoRecord{CountryISO: testCountryDE, ASNOrg: testASNOrg, ASN: 64500}, true)

	assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.privacy_lookup_state", privacyLookupStateEvaluated)
	assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.privacy_detected", false)
	assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.privacy_classes", []string{})
	assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.is_tor_exit_node", false)
	assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.is_known_vpn_exit", false)
	assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.is_public_proxy", false)
	assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.is_hosting_network", false)
	assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.is_shared_egress", false)

	values := result.RuntimeDelta.Set[exchange.KeyGeoIP].(map[string]any)
	if values[geoValueCountry] != testCountryDE || values[geoValueASN] != 64500 || values[exchange.FieldPrivacyDetected] != false {
		t.Fatalf("runtime GeoIP exchange = %#v, want preserved GeoIP and explicit privacy negative", values)
	}

	if result.Triggered || result.Abort {
		t.Fatalf("privacy evidence triggered=%t abort=%t, want false/false", result.Triggered, result.Abort)
	}
}

func TestPrivacySharedEgressRemainsPolicyEvidenceOnly(t *testing.T) {
	result := evaluatePrivacyFixture(t, privacyLookupResult{
		Classes:      []privacyClass{privacyClassSharedEgress},
		Authorities:  []privacyAuthority{privacyAuthorityOperator},
		PrimaryClass: privacyClassSharedEgress,
		State:        privacyLookupStateEvaluated,
		Confidence:   90,
	}, geoRecord{}, true)

	assertPrivacyFact(t, result.Facts, factIsSharedEgress, true)
	assertPrivacyFact(t, result.Facts, factPrivacyDetected, true)
	assertLogField(t, result.Logs, "policy_fact_geoip_is_shared_egress", true)

	values := result.RuntimeDelta.Set[exchange.KeyGeoIP].(map[string]any)
	if values[exchange.FieldIsSharedEgress] != true {
		t.Fatalf("runtime shared-egress value = %#v, want true", values[exchange.FieldIsSharedEgress])
	}

	if result.Triggered || result.Abort {
		t.Fatalf("shared-egress evidence triggered=%t abort=%t, want false/false", result.Triggered, result.Abort)
	}
}

func TestPrivacyUnavailableAndInvalidDoNotFabricateNegativeClassifications(t *testing.T) {
	for _, state := range []string{privacyLookupStateUnavailable, privacyLookupStateInvalidIP, privacyLookupStateNoSources} {
		t.Run(state, func(t *testing.T) {
			result := evaluatePrivacyFixture(t, privacyLookupResult{State: state}, geoRecord{}, true)

			assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.privacy_lookup_state", state)
			assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.privacy_data_stale", false)
			assertPrivacyFactMissing(t, result.Facts, "plugin.environment.geoip.privacy_detected")
			assertPrivacyFactMissing(t, result.Facts, "plugin.environment.geoip.is_tor_exit_node")
			assertLogFieldMissing(t, result.Logs, "policy_fact_geoip_privacy_data_stale")
		})
	}
}

func TestPrivacyOfficialTorAndStaleValuesRemainPolicyEvidenceOnly(t *testing.T) {
	result := evaluatePrivacyFixture(t, privacyLookupResult{
		Classes:      []privacyClass{privacyClassTor},
		Authorities:  []privacyAuthority{privacyAuthorityOfficial},
		PrimaryClass: privacyClassTor,
		State:        privacyLookupStateStale,
		Confidence:   100,
		DataAge:      2 * time.Hour,
		Stale:        true,
	}, geoRecord{}, true)

	assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.is_tor_exit_node", true)
	assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.privacy_data_stale", true)
	assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.privacy_confidence", float64(100))
	assertLogField(t, result.Logs, "policy_fact_geoip_is_tor_exit_node", true)
	assertLogField(t, result.Logs, "policy_fact_geoip_privacy_data_stale", true)

	if result.Triggered || result.Abort {
		t.Fatalf("Tor evidence triggered=%t abort=%t, want false/false", result.Triggered, result.Abort)
	}
}

func TestPrivacyCommunityAndOperatorEvidenceUsesTypedBoundedValues(t *testing.T) {
	result := evaluatePrivacyFixture(t, privacyLookupResult{
		Classes:      []privacyClass{privacyClassKnownVPN, privacyClassCommunityVPN, privacyClassRelay},
		Authorities:  []privacyAuthority{privacyAuthorityOperator, privacyAuthorityCommunity},
		PrimaryClass: privacyClassKnownVPN,
		State:        privacyLookupStateEvaluated,
		Confidence:   80,
		DataAge:      90 * time.Second,
	}, geoRecord{}, true)

	assertPrivacyFact(t, result.Facts, factIsKnownVPNExit, true)
	assertPrivacyFact(t, result.Facts, factIsCommunityVPNExit, true)
	assertPrivacyFact(t, result.Facts, factIsPrivacyRelay, true)
	assertPrivacyFact(t, result.Facts, factPrivacyClasses, []string{"known_vpn_exit", "community_vpn_exit", "privacy_relay"})
	assertPrivacyFact(t, result.Facts, factPrivacySourceAuthorities, []string{"operator", "community"})
	assertPrivacyFact(t, result.Facts, factPrivacyDataAgeSeconds, float64(90))

	for _, forbidden := range []string{"provider", "source", "url", "override", "reason", "community_vpn_exit", "privacy_relay"} {
		for _, field := range result.Logs {
			if field.Key == "policy_fact_geoip_"+forbidden {
				t.Fatalf("forbidden public evidence field %q present", field.Key)
			}
		}
	}
}

func TestPrivacyPublicLogsAreOptionalWithoutRemovingFacts(t *testing.T) {
	lookup := privacyLookupResult{Classes: []privacyClass{privacyClassPublicProxy}, PrimaryClass: privacyClassPublicProxy, State: privacyLookupStateEvaluated, Confidence: 70}
	result := evaluatePrivacyFixture(t, lookup, geoRecord{}, false)

	assertPrivacyFact(t, result.Facts, "plugin.environment.geoip.is_public_proxy", true)

	for _, field := range result.Logs {
		if field.Key == "policy_fact_geoip_is_public_proxy" {
			t.Fatalf("privacy public log field present while disabled: %#v", result.Logs)
		}
	}
}

func TestPrivacyHostingRulesUseGeoIPASNAndOrganizationWithoutImplyingVPN(t *testing.T) {
	engine := &privacyEngine{
		state: &privacyLookupState{
			snapshots: map[string]privacySnapshot{
				"hosting": {SourceID: "hosting", ConfirmedAt: mustPrivacyTime(t, testPrivacyNow), MaxAge: 24 * time.Hour},
			},
			index: newPrivacyLookupIndex(nil),
			hosting: privacyHostingConfig{
				ASNs:       []int{64500},
				Patterns:   []string{"example access"},
				Confidence: 50,
				Enabled:    true,
			},
			configured: 1,
		},
		now: func() time.Time { return mustPrivacyTime(t, testPrivacyNow) },
	}

	for name, record := range map[string]geoRecord{
		"asn":          {ASN: 64500, ASNOrg: "Unrelated Network"},
		"organization": {ASN: 64501, ASNOrg: testASNOrg},
	} {
		t.Run(name, func(t *testing.T) {
			lookup := engine.LookupWithRecord(netip.MustParseAddr(testClientIP), record)
			result := evaluatePrivacyFixture(t, lookup, geoRecord{}, true)

			assertPrivacyFact(t, result.Facts, factIsHostingNetwork, true)
			assertPrivacyFact(t, result.Facts, factIsKnownVPNExit, false)
			assertPrivacyFact(t, result.Facts, factIsCommunityVPNExit, false)
			assertPrivacyFact(t, result.Facts, factPrivacyDetected, false)
		})
	}
}

func TestEnvironmentPrivacyLookupUsesOneRuntimeMapForLocationAndTor(t *testing.T) {
	module := privacyModuleWithLocalTor(t, testClientIP, true)

	runner, _, _ := startedTestRunner(t, module)
	defer stopRunner(t, runner)

	result, err := runner.EvaluateEnvironment(context.Background(), "geoip.environment", environmentRequest(testClientIP))
	if err != nil {
		t.Fatalf("EvaluateEnvironment() error = %v", err)
	}

	values := result.RuntimeDelta.Set[exchange.KeyGeoIP].(map[string]any)
	if values[geoValueCountry] != testCountryDE || values[exchange.FieldIsTorExitNode] != true {
		t.Fatalf("runtime GeoIP exchange = %#v, want location and Tor values", values)
	}
}

func TestEnvironmentPrivacyInvalidIPStateOmitsClassificationBooleans(t *testing.T) {
	runner, _, _ := startedTestRunner(t, privacyModuleWithLocalTor(t, testClientIP, true))
	defer stopRunner(t, runner)

	result, err := runner.EvaluateEnvironment(context.Background(), "geoip.environment", environmentRequest("not-an-ip"))
	if err != nil {
		t.Fatalf("EvaluateEnvironment() error = %v", err)
	}

	assertPrivacyFact(t, result.Facts, factPrivacyLookupState, privacyLookupStateInvalidIP)
	assertPrivacyFactMissing(t, result.Facts, factIsTorExitNode)

	values := result.RuntimeDelta.Set[exchange.KeyGeoIP].(map[string]any)
	if _, found := values[exchange.FieldIsTorExitNode]; found {
		t.Fatalf("invalid-IP runtime exchange fabricates Tor negative: %#v", values)
	}
}

func TestPrivacyLookupHonorsExistingRequestDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	source := geoIPEnvironmentSource{plugin: &Plugin{privacy: &privacyEngine{}}}

	_, err := source.lookupPrivacy(ctx, privacyConfig{LookupTimeout: time.Second}, netip.MustParseAddr(testClientIP), geoRecord{})
	if err == nil {
		t.Fatal("lookupPrivacy() error = nil, want canceled request deadline")
	}
}

// findPolicyDefinition locates one policy attribute in a test definition slice.
func findPolicyDefinition(definitions []pluginapi.AttributeDefinition, id string) (pluginapi.AttributeDefinition, bool) {
	for _, definition := range definitions {
		if definition.ID == id {
			return definition, true
		}
	}

	return pluginapi.AttributeDefinition{}, false
}

// evaluatePrivacyFixture applies one privacy lookup to a deterministic base result.
func evaluatePrivacyFixture(t *testing.T, lookup privacyLookupResult, record geoRecord, publicLogs bool) pluginapi.EnvironmentResult {
	t.Helper()

	result := matchResult(record, testGeoIPSession)

	return enrichPrivacyResult(result, lookup, publicLogs)
}

// privacyModuleWithLocalTor builds an enabled hermetic privacy module fixture.
func privacyModuleWithLocalTor(t *testing.T, address string, publicLogs bool) config.PluginModule {
	t.Helper()

	torPath := filepath.Join(t.TempDir(), "tor-exits.txt")
	if err := os.WriteFile(torPath, []byte(address+"\n"), 0o600); err != nil {
		t.Fatalf("write Tor fixture: %v", err)
	}

	module := testModule(testDatabasePath(t, "geoip.json"))
	module.Config["privacy_intelligence"] = map[string]any{
		"enabled":           true,
		"public_log_fields": publicLogs,
		"sources": []map[string]any{{
			"id":        "tor_exit",
			"kind":      "tor_exit_list",
			"authority": "official",
			"path":      torPath,
			"required":  true,
		}},
	}

	return module
}

// assertPrivacyFact compares one possibly composite policy fact value.
func assertPrivacyFact(t *testing.T, facts []pluginapi.PolicyFact, attribute string, want any) {
	t.Helper()

	for _, fact := range facts {
		if fact.Attribute == attribute {
			if !reflect.DeepEqual(fact.Value, want) {
				t.Fatalf("fact %s = %#v, want %#v", attribute, fact.Value, want)
			}

			return
		}
	}

	t.Fatalf("fact %s missing in %#v", attribute, facts)
}

// assertPrivacyFactMissing verifies tri-state omissions.
func assertPrivacyFactMissing(t *testing.T, facts []pluginapi.PolicyFact, attribute string) {
	t.Helper()

	if slices.ContainsFunc(facts, func(fact pluginapi.PolicyFact) bool { return fact.Attribute == attribute }) {
		t.Fatalf("fact %s unexpectedly present in %#v", attribute, facts)
	}
}

// assertLogFieldMissing verifies that unavailable privacy values stay out of public logs.
func assertLogFieldMissing(t *testing.T, fields []pluginapi.LogField, key string) {
	t.Helper()

	if slices.ContainsFunc(fields, func(field pluginapi.LogField) bool { return field.Key == key }) {
		t.Fatalf("log field %s unexpectedly present in %#v", key, fields)
	}
}

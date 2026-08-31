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

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

func TestPrivacyDecisionOutputContract(t *testing.T) {
	want := map[string]pluginapi.DecisionValueKind{
		factPrivacyLookupState:       pluginapi.DecisionValueKindString,
		factPrivacyDetected:          pluginapi.DecisionValueKindBoolean,
		factPrivacyClasses:           pluginapi.DecisionValueKindStrings,
		factPrivacyPrimaryClass:      pluginapi.DecisionValueKindString,
		factPrivacyConfidence:        pluginapi.DecisionValueKindDouble,
		factPrivacySourceAuthorities: pluginapi.DecisionValueKindStrings,
		factPrivacyDataStale:         pluginapi.DecisionValueKindBoolean,
		factPrivacyDataAgeSeconds:    pluginapi.DecisionValueKindDouble,
		factIsTorExitNode:            pluginapi.DecisionValueKindBoolean,
		factIsKnownVPNExit:           pluginapi.DecisionValueKindBoolean,
		factIsCommunityVPNExit:       pluginapi.DecisionValueKindBoolean,
		factIsPublicProxy:            pluginapi.DecisionValueKindBoolean,
		factIsPrivacyRelay:           pluginapi.DecisionValueKindBoolean,
		factIsHostingNetwork:         pluginapi.DecisionValueKindBoolean,
		factIsSharedEgress:           pluginapi.DecisionValueKindBoolean,
	}

	outputs := (geoIPDecisionFactProvider{}).Descriptor().Outputs
	for name, kind := range want {
		output, found := findDecisionOutput(outputs, name)
		if !found {
			t.Fatalf("generic output %q is not registered", name)
		}

		if output.Kind != kind || output.Category != pluginapi.DecisionFactCategoryEnvironment {
			t.Fatalf("generic output %q = %#v, want %q environment", name, output, kind)
		}
	}
}

func TestGenericProviderRejectsEnvironmentOnlyPublicLogConfig(t *testing.T) {
	_, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{
		"database_path": testDatabasePath(t, "geoip.json"),
		"privacy_intelligence": map[string]any{
			"public_log_fields": true,
		},
	}))
	if err == nil {
		t.Fatal("decodeModuleConfig() error = nil, want unsupported environment-only log field rejection")
	}
}

func TestPrivacyEvaluatedNegativeEmitsTriStateFactsAndPreservesLocationFacts(t *testing.T) {
	result := evaluatePrivacyFixture(t, privacyLookupResult{State: privacyLookupStateEvaluated}, geoRecord{CountryISO: testCountryDE, ASNOrg: testASNOrg, ASN: 64500})

	assertPrivacyFact(t, result.Facts, factPrivacyLookupState, privacyLookupStateEvaluated)
	assertPrivacyFact(t, result.Facts, factPrivacyDetected, false)
	assertPrivacyFact(t, result.Facts, factPrivacyClasses, []string{})
	assertPrivacyFact(t, result.Facts, factIsTorExitNode, false)
	assertPrivacyFact(t, result.Facts, factIsKnownVPNExit, false)
	assertPrivacyFact(t, result.Facts, factIsPublicProxy, false)
	assertPrivacyFact(t, result.Facts, factIsHostingNetwork, false)
	assertPrivacyFact(t, result.Facts, factIsSharedEgress, false)
	assertPrivacyFact(t, result.Facts, factCountryISO, testCountryDE)
	assertPrivacyFact(t, result.Facts, factASN, 64500)
}

func TestPrivacySharedEgressRemainsPolicyEvidenceOnly(t *testing.T) {
	result := evaluatePrivacyFixture(t, privacyLookupResult{
		Classes:      []privacyClass{privacyClassSharedEgress},
		Authorities:  []privacyAuthority{privacyAuthorityOperator},
		PrimaryClass: privacyClassSharedEgress,
		State:        privacyLookupStateEvaluated,
		Confidence:   90,
	}, geoRecord{})

	assertPrivacyFact(t, result.Facts, factIsSharedEgress, true)
	assertPrivacyFact(t, result.Facts, factPrivacyDetected, true)
}

func TestPrivacyUnavailableAndInvalidDoNotFabricateNegativeClassifications(t *testing.T) {
	for _, state := range []string{privacyLookupStateUnavailable, privacyLookupStateInvalidIP, privacyLookupStateNoSources} {
		t.Run(state, func(t *testing.T) {
			result := evaluatePrivacyFixture(t, privacyLookupResult{State: state}, geoRecord{})

			assertPrivacyFact(t, result.Facts, factPrivacyLookupState, state)
			assertPrivacyFact(t, result.Facts, factPrivacyDataStale, false)
			assertPrivacyFactMissing(t, result.Facts, factPrivacyDetected)
			assertPrivacyFactMissing(t, result.Facts, factIsTorExitNode)
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
	}, geoRecord{})

	assertPrivacyFact(t, result.Facts, factIsTorExitNode, true)
	assertPrivacyFact(t, result.Facts, factPrivacyDataStale, true)
	assertPrivacyFact(t, result.Facts, factPrivacyConfidence, float64(100))
}

func TestPrivacyCommunityAndOperatorEvidenceUsesTypedBoundedValues(t *testing.T) {
	result := evaluatePrivacyFixture(t, privacyLookupResult{
		Classes:      []privacyClass{privacyClassKnownVPN, privacyClassCommunityVPN, privacyClassRelay},
		Authorities:  []privacyAuthority{privacyAuthorityOperator, privacyAuthorityCommunity},
		PrimaryClass: privacyClassKnownVPN,
		State:        privacyLookupStateEvaluated,
		Confidence:   80,
		DataAge:      90 * time.Second,
	}, geoRecord{})

	assertPrivacyFact(t, result.Facts, factIsKnownVPNExit, true)
	assertPrivacyFact(t, result.Facts, factIsCommunityVPNExit, true)
	assertPrivacyFact(t, result.Facts, factIsPrivacyRelay, true)
	assertPrivacyFact(t, result.Facts, factPrivacyClasses, []string{"known_vpn_exit", "community_vpn_exit", "privacy_relay"})
	assertPrivacyFact(t, result.Facts, factPrivacySourceAuthorities, []string{"operator", "community"})
	assertPrivacyFact(t, result.Facts, factPrivacyDataAgeSeconds, float64(90))
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
			result := evaluatePrivacyFixture(t, lookup, geoRecord{})

			assertPrivacyFact(t, result.Facts, factIsHostingNetwork, true)
			assertPrivacyFact(t, result.Facts, factIsKnownVPNExit, false)
			assertPrivacyFact(t, result.Facts, factIsCommunityVPNExit, false)
			assertPrivacyFact(t, result.Facts, factPrivacyDetected, false)
		})
	}
}

func TestInternalPrivacyLookupCombinesLocationAndTorFacts(t *testing.T) {
	module := privacyModuleWithLocalTor(t, testClientIP)

	runner, plugin, _, _ := startedTestRunnerWithPlugin(t, module)
	defer stopRunner(t, runner)

	result := lookupGeoIP(t, plugin, testClientIP)

	assertPrivacyFact(t, result.Facts, factCountryISO, testCountryDE)
	assertPrivacyFact(t, result.Facts, factIsTorExitNode, true)
}

func TestInternalPrivacyInvalidIPStateOmitsClassificationBooleans(t *testing.T) {
	runner, plugin, _, _ := startedTestRunnerWithPlugin(t, privacyModuleWithLocalTor(t, testClientIP))
	defer stopRunner(t, runner)

	result := lookupGeoIP(t, plugin, "not-an-ip")

	assertPrivacyFact(t, result.Facts, factPrivacyLookupState, privacyLookupStateInvalidIP)
	assertPrivacyFactMissing(t, result.Facts, factIsTorExitNode)
}

func TestPrivacyLookupHonorsExistingRequestDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	lookup := geoIPLookupService{plugin: &Plugin{privacy: &privacyEngine{}}}

	_, err := lookup.lookupPrivacy(ctx, privacyConfig{LookupTimeout: time.Second}, netip.MustParseAddr(testClientIP), geoRecord{})
	if err == nil {
		t.Fatal("lookupPrivacy() error = nil, want canceled request deadline")
	}
}

// findDecisionOutput locates one generic descriptor output by local name.
func findDecisionOutput(
	outputs []pluginapi.DecisionFactOutputDescriptor,
	name string,
) (pluginapi.DecisionFactOutputDescriptor, bool) {
	for _, output := range outputs {
		if output.Name == name {
			return output, true
		}
	}

	return pluginapi.DecisionFactOutputDescriptor{}, false
}

// evaluatePrivacyFixture applies one privacy lookup to a deterministic base result.
func evaluatePrivacyFixture(t *testing.T, lookup privacyLookupResult, record geoRecord) geoIPLookupResult {
	t.Helper()

	result := matchResult(record)

	return enrichPrivacyResult(result, lookup)
}

// privacyModuleWithLocalTor builds an enabled hermetic privacy module fixture.
func privacyModuleWithLocalTor(t *testing.T, address string) config.PluginModule {
	t.Helper()

	torPath := filepath.Join(t.TempDir(), "tor-exits.txt")
	if err := os.WriteFile(torPath, []byte(address+"\n"), 0o600); err != nil {
		t.Fatalf("write Tor fixture: %v", err)
	}

	module := testModule(testDatabasePath(t, "geoip.json"))
	module.Config["privacy_intelligence"] = map[string]any{
		"enabled": true,
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

// assertPrivacyFact compares one possibly composite generic fact value.
func assertPrivacyFact(t *testing.T, facts []geoIPLookupFact, name string, want any) {
	t.Helper()

	for _, fact := range facts {
		if fact.Name == name {
			if !reflect.DeepEqual(fact.Value, want) {
				t.Fatalf("fact %s = %#v, want %#v", name, fact.Value, want)
			}

			return
		}
	}

	t.Fatalf("fact %s missing in %#v", name, facts)
}

// assertPrivacyFactMissing verifies tri-state omissions.
func assertPrivacyFactMissing(t *testing.T, facts []geoIPLookupFact, name string) {
	t.Helper()

	if slices.ContainsFunc(facts, func(fact geoIPLookupFact) bool { return fact.Name == name }) {
		t.Fatalf("fact %s unexpectedly present in %#v", name, facts)
	}
}

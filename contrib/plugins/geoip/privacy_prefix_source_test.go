// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
)

func TestPrivacyPrefixSourceModuleConfig(t *testing.T) {
	config, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{
		testConfigDatabasePath: testDatabasePath(t, "geoip.json"),
		"privacy_intelligence": map[string]any{
			"enabled": true,
			"sources": []map[string]any{{
				"id": "official_relay", "kind": "cidr_csv", "authority": "official",
				"url": "https://feeds.example.test/relay.csv", "provider": "example_relay",
				"classes": []string{"privacy_relay", "shared_egress"}, "cidr_column": 2, "has_header": true,
			}},
		},
	}))
	if err != nil {
		t.Fatalf("decodeModuleConfig() error = %v", err)
	}

	source := config.Privacy.Sources[0]
	if source.Kind != privacySourceKindCIDRCSV || source.CIDRColumn != 2 || !source.HasHeader || len(source.Classes) != 2 {
		t.Fatalf("decoded prefix source = %#v", source)
	}
}

func TestPrivacyPrefixSourceConfigContracts(t *testing.T) {
	refresh := privacyRefreshConfig{
		DefaultRefreshInterval:    6 * time.Hour,
		DefaultMinRefreshInterval: time.Hour,
		DefaultMaxRefreshBackoff:  24 * time.Hour,
	}
	tests := []struct {
		name       string
		kind       privacySourceKind
		classes    []string
		provider   string
		wantErr    string
		cidrColumn int
		hasHeader  bool
	}{
		{name: "CIDR list", kind: privacySourceKindCIDRList, classes: []string{string(privacyClassCommunityVPN)}, provider: "example_vpn"},
		{name: "CIDR CSV", kind: privacySourceKindCIDRCSV, classes: []string{string(privacyClassCommunityVPN)}, provider: "example_vpn", cidrColumn: 2, hasHeader: true},
		{name: "missing classes", kind: privacySourceKindCIDRList, provider: "example_vpn", wantErr: "classes"},
		{name: "invalid provider", kind: privacySourceKindCIDRList, classes: []string{string(privacyClassCommunityVPN)}, provider: "invalid provider", wantErr: "provider"},
		{name: "negative CSV column", kind: privacySourceKindCIDRCSV, classes: []string{string(privacyClassCommunityVPN)}, provider: "example_vpn", cidrColumn: -1, wantErr: "cidr_column"},
		{name: "CSV options on line source", kind: privacySourceKindCIDRList, classes: []string{string(privacyClassCommunityVPN)}, provider: "example_vpn", hasHeader: true, wantErr: "has_header"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := rawPrivacySourceConfig{
				ID:         "community_vpn",
				Authority:  string(privacyAuthorityCommunity),
				URL:        "https://feeds.example.test/prefixes",
				License:    "MIT",
				LicenseURL: "https://feeds.example.test/license",
				Kind:       string(test.kind),
				Provider:   test.provider,
				Classes:    test.classes,
				Confidence: 55,
				CIDRColumn: test.cidrColumn,
				HasHeader:  test.hasHeader,
			}

			source, err := parsePrivacySourceConfig(raw, refresh, 100, 1024)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parsePrivacySourceConfig() error = %v, want substring %q", err, test.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("parsePrivacySourceConfig() error = %v", err)
			}

			if len(source.Classes) != 1 || source.Classes[0] != privacyClassCommunityVPN || source.Provider != test.provider {
				t.Fatalf("parsed prefix source = %#v", source)
			}
		})
	}
}

func TestCIDRListSnapshotCompactsEquivalentPrefixes(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)
	config := privacySourceConfig{
		ID:         "community_vpn",
		Kind:       privacySourceKindCIDRList,
		Authority:  privacyAuthorityCommunity,
		Provider:   "example_vpn",
		Classes:    []privacyClass{privacyClassCommunityVPN},
		MaxAge:     24 * time.Hour,
		MaxEntries: 10,
		Confidence: 55,
	}
	raw := []byte("# generated prefix list\n8.8.8.0/25\n8.8.8.128/25 # adjacent half\n2001:4860:4860::/65\n2001:4860:4860:0:8000::/65\n")

	snapshot, err := parseCIDRListPrivacySnapshot(raw, config, now)
	if err != nil {
		t.Fatalf("parseCIDRListPrivacySnapshot() error = %v", err)
	}

	if len(snapshot.Entries) != 2 {
		t.Fatalf("compacted entries = %d, want 2: %#v", len(snapshot.Entries), snapshot.Entries)
	}

	assertPrivacyPrefixMatch(t, snapshot, "8.8.8.42", privacyClassCommunityVPN)
	assertPrivacyPrefixMatch(t, snapshot, "8.8.8.200", privacyClassCommunityVPN)
	assertPrivacyPrefixMatch(t, snapshot, "2001:4860:4860::8888", privacyClassCommunityVPN)
}

func TestCIDRCSVSnapshotUsesConfiguredColumnAndClasses(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)
	config := privacySourceConfig{
		ID:         "official_relays",
		Kind:       privacySourceKindCIDRCSV,
		Authority:  privacyAuthorityOfficial,
		Provider:   "example_relay",
		Classes:    []privacyClass{privacyClassRelay, privacyClassSharedEgress},
		CIDRColumn: 1,
		HasHeader:  true,
		MaxAge:     24 * time.Hour,
		MaxEntries: 10,
		Confidence: 100,
	}
	raw := []byte("location,network,note\nBerlin,8.8.4.0/24,primary\nFrankfurt,2001:4860:4860::/64,\n")

	snapshot, err := parseCIDRCSVPrivacySnapshot(raw, config, now)
	if err != nil {
		t.Fatalf("parseCIDRCSVPrivacySnapshot() error = %v", err)
	}

	if len(snapshot.Entries) != 4 {
		t.Fatalf("expanded entries = %d, want 4", len(snapshot.Entries))
	}

	index := newPrivacyLookupIndex([]privacySnapshot{snapshot})
	evidence := index.Lookup(netip.MustParseAddr("8.8.4.4"))

	if len(evidence) != 2 || evidence[0].Class != privacyClassRelay || evidence[1].Class != privacyClassSharedEgress {
		t.Fatalf("CSV evidence = %#v", evidence)
	}
}

func TestGenericPrefixParsersAcceptPublishedFeedShapes(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)

	tests := []struct {
		name  string
		parse func() (privacySnapshot, error)
		want  int
	}{
		{
			name: "CSV with trailing field",
			parse: func() (privacySnapshot, error) {
				config := privacySourceConfig{
					ID: "official_relay", Kind: privacySourceKindCIDRCSV, Authority: privacyAuthorityOfficial,
					Provider: "official_relay", Classes: []privacyClass{privacyClassRelay, privacyClassSharedEgress},
					CIDRColumn: 0, MaxEntries: 10, Confidence: 100,
				}

				return parseCIDRCSVPrivacySnapshot([]byte("17.0.0.0/25,US,US-CA,Los Angeles,\n17.0.0.128/25,US,US-CA,San Jose,\n"), config, now)
			},
			want: 2,
		},
		{
			name: "plain CIDR lines",
			parse: func() (privacySnapshot, error) {
				config := privacySourceConfig{
					ID: "community_vpn", Kind: privacySourceKindCIDRList, Authority: privacyAuthorityCommunity,
					Provider: "community_vpn", Classes: []privacyClass{privacyClassCommunityVPN},
					MaxEntries: 10, Confidence: 55,
				}

				return parseCIDRListPrivacySnapshot([]byte("2.26.157.0/24\n2.26.164.0/24\n"), config, now)
			},
			want: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := test.parse()
			if err != nil {
				t.Fatalf("parse published shape: %v", err)
			}

			if len(snapshot.Entries) != test.want {
				t.Fatalf("entries = %d, want %d", len(snapshot.Entries), test.want)
			}
		})
	}
}

func TestPrivacyPrefixSourceUsesSharedRefreshCoordinator(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)
	client := &sequencePrivacyHTTPClient{responses: []pluginapi.HTTPResponse{{
		StatusCode: http.StatusOK,
		Body:       []byte("region,network\nEU,8.8.8.0/24\n"),
	}}}
	coordinator := newPrivacySourceCoordinator(privacySourceConfig{
		ID: "official_relay", Kind: privacySourceKindCIDRCSV, Authority: privacyAuthorityOfficial,
		URL: "https://feeds.example.test/relay.csv", Provider: "official_relay",
		Classes: []privacyClass{privacyClassRelay}, CIDRColumn: 1, HasHeader: true,
		MaxEntries: 10, MaxDownloadBytes: 1024, Confidence: 100, MaxAge: 24 * time.Hour,
		RefreshInterval: 6 * time.Hour, MinRefreshInterval: time.Hour, MaxRefreshBackoff: 24 * time.Hour,
	}, client, nil)
	coordinator.now = func() time.Time { return now }

	if err := coordinator.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	snapshot := coordinator.Snapshot()
	assertPrivacyPrefixMatch(t, snapshot, "8.8.8.8", privacyClassRelay)
}

func TestPrivacyPrefixSourcesRejectCandidatesAtomically(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)
	listConfig := privacySourceConfig{
		ID: "vpn", Kind: privacySourceKindCIDRList, Authority: privacyAuthorityCommunity,
		Provider: "vpn", Classes: []privacyClass{privacyClassCommunityVPN}, MaxEntries: 10, Confidence: 50,
	}
	csvConfig := privacySourceConfig{
		ID: "relay", Kind: privacySourceKindCIDRCSV, Authority: privacyAuthorityOfficial,
		Provider: "relay", Classes: []privacyClass{privacyClassRelay}, CIDRColumn: 1, MaxEntries: 10, Confidence: 100,
	}
	limitedListConfig := listConfig
	limitedListConfig.MaxEntries = 1
	expandedCSVConfig := csvConfig
	expandedCSVConfig.CIDRColumn = 0
	expandedCSVConfig.Classes = []privacyClass{privacyClassRelay, privacyClassSharedEgress}
	expandedCSVConfig.MaxEntries = 1

	tests := []struct {
		name   string
		raw    []byte
		config privacySourceConfig
		csv    bool
	}{
		{name: "invalid list prefix", raw: []byte("8.8.8.0/24\nnot-a-prefix\n"), config: listConfig},
		{name: "private list prefix", raw: []byte("8.8.8.0/24\n10.0.0.0/8\n"), config: listConfig},
		{name: "missing CSV column", raw: []byte("only-one-column\n"), config: csvConfig, csv: true},
		{name: "malformed CSV", raw: []byte("broken,\"8.8.8.0/24\n"), config: csvConfig, csv: true},
		{name: "raw work exceeds limit before compaction", raw: []byte("8.8.8.0/24\n8.8.8.0/24\n"), config: limitedListConfig},
		{name: "class expansion exceeds limit", raw: []byte("8.8.8.0/24\n"), config: expandedCSVConfig, csv: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				snapshot privacySnapshot
				err      error
			)

			if test.csv {
				snapshot, err = parseCIDRCSVPrivacySnapshot(test.raw, test.config, now)
			} else {
				snapshot, err = parseCIDRListPrivacySnapshot(test.raw, test.config, now)
			}

			if err == nil || len(snapshot.Entries) != 0 {
				t.Fatalf("candidate = %#v, error = %v, want atomic rejection", snapshot, err)
			}
		})
	}
}

// assertPrivacyPrefixMatch verifies one class against a parsed immutable snapshot.
func assertPrivacyPrefixMatch(t *testing.T, snapshot privacySnapshot, address string, class privacyClass) {
	t.Helper()

	evidence := newPrivacyLookupIndex([]privacySnapshot{snapshot}).Lookup(netip.MustParseAddr(address))
	if len(evidence) != 1 || evidence[0].Class != class {
		t.Fatalf("evidence for %s = %#v, want %q", address, evidence, class)
	}
}

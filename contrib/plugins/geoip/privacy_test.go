// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
)

const testPrivacyNow = "2026-07-11T12:00:00Z"

func TestPrivacyConfigValidationAndDefaults(t *testing.T) {
	config, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{
		testConfigDatabasePath: testDatabasePath(t, "geoip.json"),
		"privacy_intelligence": map[string]any{
			"enabled": true,
			"refresh": map[string]any{"cache_dir": t.TempDir()},
			"sources": []map[string]any{{
				"id": "tor_exit", "kind": "tor_exit_list", "authority": "official",
				"url": "https://onionoo.torproject.org/details?type=relay&running=true&flag=Exit&fields=exit_addresses%2Crunning%2Cflags", "required": true,
			}},
		},
	}))
	if err != nil {
		t.Fatalf("decodeModuleConfig() error = %v", err)
	}

	source := config.Privacy.Sources[0]
	if source.RefreshInterval != time.Hour || source.MinRefreshInterval != 30*time.Minute {
		t.Fatalf("Tor refresh defaults = %s/%s", source.RefreshInterval, source.MinRefreshInterval)
	}

	_, err = decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{
		testConfigDatabasePath: testDatabasePath(t, "geoip.json"),
		"privacy_intelligence": map[string]any{
			"enabled": true,
			"sources": []map[string]any{{
				"id": "community", "kind": "normalized_json", "authority": "community",
				"url": "http://feeds.example.test/list.json", "confidence": 90,
			}},
		},
	}))
	if err == nil {
		t.Fatal("decodeModuleConfig() error = nil, want insecure URL or confidence-cap failure")
	}
}

func TestPrivacyConfigRejectsUnimplementedDestinationMetadata(t *testing.T) {
	_, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{
		testConfigDatabasePath: testDatabasePath(t, "geoip.json"),
		"privacy_intelligence": map[string]any{
			"enabled": true,
			"sources": []map[string]any{{
				"id": "tor_exit", "kind": "tor_exit_list", "authority": "official",
				"url": "https://check.torproject.org/api/bulk", "required": true,
				"destinations": []map[string]any{{"address": "203.0.113.10", "ports": []int{443}}},
			}},
		},
	}))
	if err == nil {
		t.Fatal("decodeModuleConfig() error = nil, want unsupported destination metadata rejection")
	}
}

func TestNormalizedPrivacySnapshotAcceptsSharedEgressClass(t *testing.T) {
	raw := []byte(`{"schema_version":1,"source":{"id":"operator_shared_egress","authority":"operator","generated_at":"2026-07-11T12:00:00Z"},"entries":[{"network":"203.0.113.0/24","classes":["shared_egress"],"confidence":90}]}`)
	config := privacySourceConfig{ID: "operator_shared_egress", Kind: privacySourceKindNormalized, Authority: privacyAuthorityOperator, MaxAge: 24 * time.Hour, MaxEntries: 10}

	snapshot, err := parseNormalizedPrivacySnapshot(raw, config, mustPrivacyTime(t, testPrivacyNow))
	if err != nil {
		t.Fatalf("parseNormalizedPrivacySnapshot() error = %v", err)
	}

	evidence := newPrivacyLookupIndex([]privacySnapshot{snapshot}).Lookup(netip.MustParseAddr("203.0.113.7"))
	if len(evidence) != 1 || evidence[0].Class != privacyClassSharedEgress {
		t.Fatalf("shared-egress evidence = %#v", evidence)
	}
}

func TestNormalizedPrivacySnapshotAndPrefixLookup(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)
	raw := []byte(`{
  "schema_version": 1,
  "source": {"id":"provider_relays","description":"Provider relays","authority":"official","license":"CC0-1.0","license_url":"https://example.test/license","generated_at":"2026-07-11T10:00:00Z","valid_until":"2026-07-12T10:00:00Z"},
  "entries": [
    {"network":"203.0.113.0/24","classes":["known_vpn_exit"],"provider":"example","confidence":100},
    {"network":"203.0.113.7/32","classes":["privacy_relay"],"provider":"example","confidence":100},
    {"network":"2001:db8:42::/48","classes":["known_vpn_exit"],"provider":"example","confidence":100}
  ]
}`)

	snapshot, err := parseNormalizedPrivacySnapshot(raw, privacySourceConfig{
		ID: "provider_relays", Kind: privacySourceKindNormalized, Authority: privacyAuthorityOfficial,
		MaxAge: 6 * time.Hour, MaxEntries: 10,
	}, now)
	if err != nil {
		t.Fatalf("parseNormalizedPrivacySnapshot() error = %v", err)
	}

	index := newPrivacyLookupIndex([]privacySnapshot{snapshot})

	evidence := index.Lookup(netip.MustParseAddr("203.0.113.7"))
	if len(evidence) != 2 || evidence[0].Class != privacyClassKnownVPN || evidence[1].Class != privacyClassRelay {
		t.Fatalf("IPv4 overlapping evidence = %#v", evidence)
	}

	if got := index.Lookup(netip.MustParseAddr("2001:db8:42::7")); len(got) != 1 || got[0].Class != privacyClassKnownVPN {
		t.Fatalf("IPv6 evidence = %#v", got)
	}
}

func TestPrivacyParsersRejectNonPublicFeedEntries(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)
	normalizedConfig := privacySourceConfig{ID: "provider_relays", Kind: privacySourceKindNormalized, Authority: privacyAuthorityOfficial, MaxEntries: 10, MaxAge: 6 * time.Hour}
	normalized := []byte(`{"schema_version":1,"source":{"id":"provider_relays","authority":"official","generated_at":"2026-07-11T10:00:00Z"},"entries":[{"network":"10.0.0.0/8","classes":["known_vpn_exit"],"confidence":100}]}`)

	if _, err := parseNormalizedPrivacySnapshot(normalized, normalizedConfig, now); err == nil {
		t.Fatal("parseNormalizedPrivacySnapshot() error = nil, want private prefix rejection")
	}

	torConfig := privacySourceConfig{ID: "tor_exit", Kind: privacySourceKindTor, Authority: privacyAuthorityOfficial, MaxEntries: 10, MaxAge: 6 * time.Hour}
	if _, err := parseTorPrivacySnapshot([]byte("127.0.0.1\n"), torConfig, now); err == nil {
		t.Fatal("parseTorPrivacySnapshot() error = nil, want loopback rejection")
	}
}

func TestOfficialTorParserRejectsPartialCandidate(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)
	config := privacySourceConfig{ID: "tor_exit", Kind: privacySourceKindTor, Authority: privacyAuthorityOfficial, MaxEntries: 10, MaxAge: 6 * time.Hour}

	snapshot, err := parseTorPrivacySnapshot([]byte(
		"@type tordnsel 1.0\n"+
			"ExitNode 0123456789ABCDEF0123456789ABCDEF01234567\n"+
			"Published 2026-07-11 09:59:00\n"+
			"LastStatus 2026-07-11 10:00:00\n"+
			"ExitAddress 192.0.2.44 2026-07-11 10:00:00\n"+
			"2001:db8::44\n",
	), config, now)
	if err != nil {
		t.Fatalf("parseTorPrivacySnapshot() error = %v", err)
	}

	if len(newPrivacyLookupIndex([]privacySnapshot{snapshot}).Lookup(netip.MustParseAddr("192.0.2.44"))) != 1 {
		t.Fatal("Tor IPv4 address did not match")
	}

	if _, err := parseTorPrivacySnapshot([]byte("192.0.2.44\nnot-an-address\n"), config, now); err == nil {
		t.Fatal("parseTorPrivacySnapshot() error = nil, want atomic candidate rejection")
	}
}

func TestOfficialTorParserAcceptsBoundedOnionooDetails(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)
	config := privacySourceConfig{ID: "tor_exit", Kind: privacySourceKindTor, Authority: privacyAuthorityOfficial, MaxEntries: 10, MaxAge: 6 * time.Hour}
	raw := []byte(`{"relays":[{"exit_addresses":["192.0.2.44","2001:db8::44"],"flags":["Running","Exit"],"running":true},{"exit_addresses":["198.51.100.8"],"flags":["Exit"],"running":false}]}`)

	snapshot, err := parseTorPrivacySnapshot(raw, config, now)
	if err != nil {
		t.Fatalf("parseTorPrivacySnapshot(Onionoo) error = %v", err)
	}

	index := newPrivacyLookupIndex([]privacySnapshot{snapshot})
	if len(index.Lookup(netip.MustParseAddr("192.0.2.44"))) != 1 || len(index.Lookup(netip.MustParseAddr("2001:db8::44"))) != 1 {
		t.Fatal("Onionoo running exit addresses did not match")
	}

	if len(index.Lookup(netip.MustParseAddr("198.51.100.8"))) != 0 {
		t.Fatal("Onionoo non-running relay was included")
	}
}

func TestPrivacyOverrideMayOnlySuppressClasses(t *testing.T) {
	overrides, err := parsePrivacyOverrides([]rawPrivacyOverrideConfig{{
		Network:         "198.51.100.12/32",
		SuppressClasses: []string{string(privacyClassCommunityVPN)},
	}})
	if err != nil {
		t.Fatalf("parsePrivacyOverrides() error = %v", err)
	}

	if len(overrides) != 1 || len(overrides[0].AddClasses) != 0 || len(overrides[0].SuppressClasses) != 1 {
		t.Fatalf("overrides = %#v", overrides)
	}
}

func TestNormalizedPrivacyFixtureLoads(t *testing.T) {
	raw, err := os.ReadFile(testDatabasePath(t, "privacy-normalized-v1.json"))
	if err != nil {
		t.Fatalf("read normalized fixture: %v", err)
	}

	snapshot, err := parseNormalizedPrivacySnapshot(raw, privacySourceConfig{
		ID: "provider_relays", Kind: privacySourceKindNormalized, Authority: privacyAuthorityOfficial,
		MaxAge: 6 * time.Hour, MaxEntries: 10,
	}, mustPrivacyTime(t, testPrivacyNow))
	if err != nil {
		t.Fatalf("parseNormalizedPrivacySnapshot() error = %v", err)
	}

	if len(snapshot.Entries) != 2 {
		t.Fatalf("normalized fixture entries = %d, want 2", len(snapshot.Entries))
	}
}

func TestPrivacyEvidenceMergePrecedenceAndFreshness(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)
	evidence := []privacyEvidence{
		{Class: privacyClassCommunityVPN, Authority: privacyAuthorityCommunity, SourceID: "community", Confidence: 70, ConfirmedAt: now.Add(-7 * time.Hour), MaxAge: 6 * time.Hour},
		{Class: privacyClassTor, Authority: privacyAuthorityOfficial, SourceID: "tor", Confidence: 100, ConfirmedAt: now.Add(-time.Hour), MaxAge: 6 * time.Hour},
		{Class: privacyClassHosting, Authority: privacyAuthorityDerived, SourceID: "hosting", Confidence: 50, ConfirmedAt: now, MaxAge: 24 * time.Hour},
	}

	result := mergePrivacyEvidence(evidence, now)
	if result.PrimaryClass != privacyClassTor || result.Confidence != 100 {
		t.Fatalf("primary evidence = %q/%d", result.PrimaryClass, result.Confidence)
	}

	if !result.Stale {
		t.Fatal("result stale = false, want stale contributing community evidence")
	}
}

func TestPrivacyRefreshCoalescesAndKeepsLastKnownGood(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)
	client := &blockingPrivacyHTTPClient{started: make(chan struct{}), release: make(chan struct{})}
	coordinator := newPrivacySourceCoordinator(privacySourceConfig{
		ID: "tor_exit", Kind: privacySourceKindTor, Authority: privacyAuthorityOfficial,
		URL: "https://check.torproject.org/api/bulk", MaxEntries: 10, MaxDownloadBytes: 1024,
		RefreshInterval: time.Hour, MinRefreshInterval: 30 * time.Minute, MaxRefreshBackoff: 12 * time.Hour, MaxAge: 6 * time.Hour,
	}, client, nil)
	coordinator.now = func() time.Time { return now }

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- coordinator.Refresh(context.Background())
	}()

	<-client.started

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- coordinator.Refresh(context.Background())
	}()

	select {
	case err := <-secondDone:
		t.Fatalf("coalesced Refresh() completed before the in-flight call: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(client.release)

	if err := <-firstDone; err != nil {
		t.Fatalf("first Refresh() error = %v", err)
	}

	if err := <-secondDone; err != nil {
		t.Fatalf("second Refresh() error = %v", err)
	}

	if client.calls != 1 {
		t.Fatalf("HTTP calls = %d, want 1", client.calls)
	}

	good := coordinator.Snapshot()

	client.err = errors.New("upstream unavailable")
	if err := coordinator.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() error = nil, want upstream failure")
	}

	if coordinator.Snapshot().LoadedAt != good.LoadedAt || len(coordinator.Snapshot().Entries) != len(good.Entries) {
		t.Fatal("failed refresh replaced last-known-good snapshot")
	}
}

func TestPrivacyRefreshUsesConditionalValidatorsAndConfirmsNotModified(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)
	client := &sequencePrivacyHTTPClient{responses: []pluginapi.HTTPResponse{
		{StatusCode: http.StatusOK, Body: []byte("192.0.2.44\n"), Headers: map[string][]string{
			"ETag": {`"v1"`}, "Last-Modified": {now.Add(-time.Hour).Format(http.TimeFormat)},
		}},
		{StatusCode: http.StatusNotModified},
	}}
	coordinator := newPrivacySourceCoordinator(privacySourceConfig{
		ID: "tor_exit", Kind: privacySourceKindTor, Authority: privacyAuthorityOfficial,
		URL: "https://check.torproject.org/api/bulk", MaxEntries: 10, MaxDownloadBytes: 1024,
		RefreshInterval: time.Hour, MinRefreshInterval: 30 * time.Minute, MaxRefreshBackoff: 12 * time.Hour, MaxAge: 6 * time.Hour,
	}, client, nil)

	coordinator.now = func() time.Time { return now }

	if err := coordinator.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh() error = %v", err)
	}

	now = now.Add(time.Hour)

	if err := coordinator.Refresh(context.Background()); err != nil {
		t.Fatalf("conditional Refresh() error = %v", err)
	}

	second := client.requests[1]
	if privacyHeader(second.Headers, "If-None-Match") != `"v1"` || privacyHeader(second.Headers, "If-Modified-Since") == "" {
		t.Fatalf("conditional headers = %#v", second.Headers)
	}

	if !coordinator.Snapshot().ConfirmedAt.Equal(now) {
		t.Fatalf("confirmed_at = %s, want %s", coordinator.Snapshot().ConfirmedAt, now)
	}
}

func TestPrivacyPersistentCacheRoundTrip(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)
	path := filepath.Join(t.TempDir(), "tor.cache.json")

	snapshot, err := parseTorPrivacySnapshot([]byte("192.0.2.44\n"), privacySourceConfig{
		ID: "tor_exit", Kind: privacySourceKindTor, Authority: privacyAuthorityOfficial, MaxEntries: 10, MaxAge: 6 * time.Hour,
	}, now)
	if err != nil {
		t.Fatalf("parseTorPrivacySnapshot() error = %v", err)
	}

	cache := privacySnapshotCache{path: path}
	if err := cache.Store(snapshot); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	loaded, err := cache.Load(privacySourceConfig{ID: "tor_exit", Kind: privacySourceKindTor, Authority: privacyAuthorityOfficial, MaxEntries: 10, MaxAge: 6 * time.Hour}, now)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(loaded.Entries) != 1 || loaded.SourceID != "tor_exit" {
		t.Fatalf("cached snapshot = %#v", loaded)
	}
}

func TestPrivacyRefreshSchedulingHonorsUpstreamAndBackoff(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)

	cacheDelay := privacyCacheDelay(map[string][]string{
		"Cache-Control": {"public, max-age=7200"},
		"Expires":       {now.Add(3 * time.Hour).Format(http.TimeFormat)},
	}, now)
	if cacheDelay != 3*time.Hour {
		t.Fatalf("cache delay = %s, want 3h", cacheDelay)
	}

	retryDelay := privacyRetryAfter(map[string][]string{"Retry-After": {"14400"}}, now)
	if retryDelay != 4*time.Hour {
		t.Fatalf("retry delay = %s, want 4h", retryDelay)
	}
}

func TestPrivacyEngineLoadsLocalSourceWithoutRequestIO(t *testing.T) {
	config := privacyConfig{
		Enabled: true,
		Refresh: privacyRefreshConfig{MaxConcurrentDownloads: 1},
		Sources: []privacySourceConfig{{
			ID: "tor_exit", Kind: privacySourceKindTor, Authority: privacyAuthorityOfficial,
			Path: testDatabasePath(t, "privacy-tor-exits.txt"), MaxEntries: 10,
			MaxDownloadBytes: 1024, MaxAge: 6 * time.Hour, Required: true,
		}},
	}

	engine, err := loadPrivacyEngine(context.Background(), config, nil)
	if err != nil {
		t.Fatalf("loadPrivacyEngine() error = %v", err)
	}

	result := engine.Lookup(netip.MustParseAddr("192.0.2.44"))
	if result.State != privacyLookupStateEvaluated || result.PrimaryClass != privacyClassTor || result.Confidence != 100 {
		t.Fatalf("local engine result = %#v", result)
	}
}

func TestPluginLifecyclePublishesLocalPrivacyEngine(t *testing.T) {
	module := testModule(testDatabasePath(t, "geoip.json"))
	module.Config["privacy_intelligence"] = map[string]any{
		"enabled": true,
		"sources": []map[string]any{{
			"id": "tor_exit", "kind": "tor_exit_list", "authority": "official",
			"path": testDatabasePath(t, "privacy-tor-exits.txt"), "required": true, "max_age": "6h",
		}},
	}

	runner, plugin, _, _ := startedTestRunnerWithPlugin(t, module)
	defer stopRunner(t, runner)

	plugin.mu.RLock()
	engine := plugin.privacy
	plugin.mu.RUnlock()

	if engine == nil || engine.Lookup(netip.MustParseAddr("192.0.2.44")).PrimaryClass != privacyClassTor {
		t.Fatal("plugin lifecycle did not publish local privacy engine")
	}
}

func TestPrivacyEngineDistinguishesUnavailableAndStale(t *testing.T) {
	now := mustPrivacyTime(t, testPrivacyNow)

	unavailable := &privacyEngine{
		snapshots:  make(map[string]privacySnapshot),
		required:   map[string]struct{}{"required": {}},
		index:      newPrivacyLookupIndex(nil),
		now:        func() time.Time { return now },
		configured: 1,
	}
	if result := unavailable.Lookup(netip.MustParseAddr("192.0.2.1")); result.State != privacyLookupStateUnavailable {
		t.Fatalf("unavailable state = %q", result.State)
	}

	staleSnapshot := privacySnapshot{SourceID: "required", ConfirmedAt: now.Add(-7 * time.Hour), MaxAge: 6 * time.Hour}

	stale := &privacyEngine{
		snapshots:  map[string]privacySnapshot{"required": staleSnapshot},
		required:   map[string]struct{}{"required": {}},
		index:      newPrivacyLookupIndex([]privacySnapshot{staleSnapshot}),
		now:        func() time.Time { return now },
		configured: 1,
	}
	if result := stale.Lookup(netip.MustParseAddr("192.0.2.1")); result.State != privacyLookupStateStale || !result.Stale {
		t.Fatalf("stale result = %#v", result)
	}
}

func TestPrivacyRefreshFailureLogDoesNotExposeSourceURLOrRawError(t *testing.T) {
	logger := &recordingPrivacyLogger{}
	plugin := &Plugin{logger: logger}

	plugin.logPrivacyRefreshFailure(context.Background(), "tor_exit")

	serialized := strings.Join(logger.values, " ")
	for _, secret := range []string{"https://", "token=", "transport secret"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("privacy refresh log leaked %q: %s", secret, serialized)
		}
	}

	if !strings.Contains(serialized, "tor_exit") {
		t.Fatalf("privacy refresh log lacks bounded source ID: %s", serialized)
	}
}

func TestPrivacyRefreshErrorDoesNotExposeSourceURLOrTransportDetail(t *testing.T) {
	coordinator := newPrivacySourceCoordinator(privacySourceConfig{
		ID: "tor_exit", Kind: privacySourceKindTor, Authority: privacyAuthorityOfficial,
		URL: "https://feeds.example.test/list?token=secret", MaxEntries: 10, MaxDownloadBytes: 1024,
		RefreshInterval: time.Hour, MinRefreshInterval: 30 * time.Minute, MaxRefreshBackoff: 12 * time.Hour,
	}, privacyHTTPErrorClient{}, nil)

	err := coordinator.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh() error = nil, want transport failure")
	}

	for _, secret := range []string{"https://", "token=", "transport secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("Refresh() error leaked %q: %v", secret, err)
		}
	}
}

// mustPrivacyTime parses a fixed fixture timestamp.
func mustPrivacyTime(t *testing.T, value string) time.Time {
	t.Helper()

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse fixture time: %v", err)
	}

	return parsed
}

type blockingPrivacyHTTPClient struct {
	started chan struct{}
	release chan struct{}
	err     error
	calls   int
	mu      sync.Mutex
}

type recordingPrivacyLogger struct {
	values []string
}

type privacyHTTPErrorClient struct{}

// Do returns a deliberately secret-bearing transport error for redaction tests.
func (privacyHTTPErrorClient) Do(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	return pluginapi.HTTPResponse{}, errors.New("GET https://feeds.example.test/list?token=secret: transport secret")
}

// Debug ignores debug records in this focused privacy log fixture.
func (l *recordingPrivacyLogger) Debug(context.Context, string, ...pluginapi.LogField) {}

// Info ignores info records in this focused privacy log fixture.
func (l *recordingPrivacyLogger) Info(context.Context, string, ...pluginapi.LogField) {}

// Warn ignores warning records in this focused privacy log fixture.
func (l *recordingPrivacyLogger) Warn(context.Context, string, ...pluginapi.LogField) {}

// Error records only the structured values exposed by the plugin.
func (l *recordingPrivacyLogger) Error(_ context.Context, message string, fields ...pluginapi.LogField) {
	l.values = append(l.values, message)
	for _, field := range fields {
		l.values = append(l.values, field.Key, fmt.Sprint(field.Value))
	}
}

type sequencePrivacyHTTPClient struct {
	responses []pluginapi.HTTPResponse
	requests  []pluginapi.HTTPRequest
}

// Do records requests and returns one configured response in sequence.
func (c *sequencePrivacyHTTPClient) Do(_ context.Context, request pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	c.requests = append(c.requests, request)
	if len(c.requests) > len(c.responses) {
		return pluginapi.HTTPResponse{}, errors.New("response fixture exhausted")
	}

	return c.responses[len(c.requests)-1], nil
}

// Do blocks the first HTTP request so concurrent refresh behavior is observable.
func (c *blockingPrivacyHTTPClient) Do(ctx context.Context, _ pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	c.mu.Lock()
	c.calls++
	call := c.calls
	err := c.err
	c.mu.Unlock()

	if err != nil {
		return pluginapi.HTTPResponse{}, err
	}

	if call == 1 {
		close(c.started)

		select {
		case <-c.release:
		case <-ctx.Done():
			return pluginapi.HTTPResponse{}, ctx.Err()
		}
	}

	return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte("192.0.2.44\n"), Headers: map[string][]string{"ETag": {`"fixture"`}}}, nil
}

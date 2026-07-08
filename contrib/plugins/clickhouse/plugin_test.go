// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/pluginapi/v1/exchange"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/pluginruntime"
	"github.com/croessner/nauthilus/v3/server/rediscli"

	"github.com/go-redis/redismock/v9"
)

const (
	testInsertURL     = "http://clickhouse.local:8123/?query=INSERT%20INTO%20nauthilus.logins%20FORMAT%20JSONEachRow"
	testCacheKey      = "clickhouse:batch:test"
	testClientIP      = "203.0.113.10"
	testUsername      = "alice@example.test"
	testAccount       = "alice"
	testSecret        = "top-secret"
	testDedupRedisKey = "clickhouse:authdedup:" + testUsername + ":" + testClientIP
)

func TestPluginMetadataAndRegistrationExposePostActionTarget(t *testing.T) {
	metadata := NewPlugin().Metadata()
	if metadata.Name != pluginName {
		t.Fatalf("metadata name = %q, want %q", metadata.Name, pluginName)
	}

	if metadata.APIVersion != pluginapi.APIVersion {
		t.Fatalf("metadata API version = %q, want %q", metadata.APIVersion, pluginapi.APIVersion)
	}

	if !slices.Contains(metadata.Features, pluginapi.Feature("post_action")) {
		t.Fatalf("metadata features = %#v, want post_action", metadata.Features)
	}

	registry, _ := registerTestPlugin(t, testModule(map[string]any{}))
	targets := registry.PostActionTargets()

	if len(targets) != 1 {
		t.Fatalf("post-action targets = %d, want 1", len(targets))
	}

	if targets[0].QualifiedName != "clickhouse.post_action" {
		t.Fatalf("qualified target = %q, want clickhouse.post_action", targets[0].QualifiedName)
	}

	debugModules := registry.DebugModulesByModule(pluginName)
	if !hasDebugSelector(debugModules, "plugin.clickhouse") || !hasDebugSelector(debugModules, "plugin.clickhouse."+debugModuleBatch) {
		t.Fatalf("debug modules = %#v, want module and batch selectors", debugModules)
	}
}

func TestDecodeModuleConfigDefaultsAndValidation(t *testing.T) { //nolint:gocyclo // Validation cases are intentionally colocated for config parity.
	cfg, err := decodeModuleConfig(pluginregistry.NewConfigView(nil))
	if err != nil {
		t.Fatalf("decodeModuleConfig(defaults) error = %v", err)
	}

	if cfg.InsertURL != "" || cfg.BatchSize != defaultBatchSize || cfg.CacheKey != defaultCacheKey {
		t.Fatalf("defaults = %#v, want empty URL, batch %d, cache %q", cfg, defaultBatchSize, defaultCacheKey)
	}

	if cfg.Timeout != defaultTimeout || cfg.MaxResponseBytes != defaultMaxResponseBytes || cfg.AuthDedupTTL != defaultAuthDedupTTL {
		t.Fatalf("duration/limit defaults = %#v", cfg)
	}

	valid, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{
		"insert_url":         testInsertURL,
		"batch_size":         2,
		"cache_key":          testCacheKey,
		"timeout":            "250ms",
		"max_response_bytes": int64(128),
		"auth_dedup_ttl":     "5m",
	}))
	if err != nil {
		t.Fatalf("decodeModuleConfig(valid) error = %v", err)
	}

	if valid.InsertURL != testInsertURL || valid.BatchSize != 2 || valid.Timeout != 250*time.Millisecond || valid.AuthDedupTTL != 5*time.Minute {
		t.Fatalf("valid config = %#v", valid)
	}

	invalidCases := []map[string]any{
		{"insert_url": "file:///tmp/clickhouse"},
		{"batch_size": -1},
		{"timeout": "-1s"},
		{"max_response_bytes": int64(-1)},
		{"auth_dedup_ttl": "nope"},
	}
	for _, invalid := range invalidCases {
		if _, err := decodeModuleConfig(pluginregistry.NewConfigView(invalid)); err == nil {
			t.Fatalf("decodeModuleConfig(%#v) error = nil, want validation error", invalid)
		}
	}
}

func TestNoAuthNonOIDCRequestSkipsWithoutHTTP(t *testing.T) {
	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url": testInsertURL,
		"batch_size": 1,
	}), testRunnerOptions{})
	defer harness.stop(t)

	result, err := harness.runner.EnqueuePostAction(context.Background(), "clickhouse.post_action", testRequest(t, requestOptions{
		noAuth:   true,
		protocol: "imap",
		service:  "imap",
	}))
	if err != nil {
		t.Fatalf("EnqueuePostAction() error = %v", err)
	}

	if result.Enqueued {
		t.Fatal("no-auth non-OIDC request was enqueued")
	}

	if got := len(harness.transport.requests); got != 0 {
		t.Fatalf("HTTP calls = %d, want 0", got)
	}
}

func TestOIDCTokenPostActionRowContainsIDPFields(t *testing.T) {
	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url": testInsertURL,
		"batch_size": 1,
	}), testRunnerOptions{})
	defer harness.stop(t)

	_, err := harness.runner.EnqueuePostAction(context.Background(), "clickhouse.post_action", testRequest(t, requestOptions{
		noAuth:        true,
		authenticated: true,
		protocol:      "oidc",
		service:       "idp",
		grantType:     "client_credentials",
		samlEntityID:  "https://sp.example.com/metadata",
		mfaMethod:     "webauthn",
		disableRedis:  true,
	}))
	if err != nil {
		t.Fatalf("EnqueuePostAction() error = %v", err)
	}

	row := decodeFirstRow(t, harness.transport.onlyRequest().body)
	assertStringField(t, row, "grant_type", "client_credentials")
	assertStringField(t, row, "saml_entity_id", "https://sp.example.com/metadata")
	assertStringField(t, row, "mfa_method", "webauthn")
}

func TestRepresentativeRowFieldsMatchLuaNamesAndValues(t *testing.T) { //nolint:funlen // The test enumerates the Lua-compatible row contract in one place.
	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url": testInsertURL,
		"batch_size": 1,
	}), testRunnerOptions{})
	defer harness.stop(t)

	_, err := harness.runner.EnqueuePostAction(context.Background(), "clickhouse.post_action", testRequest(t, requestOptions{
		protocol: "imap",
		service:  "imap",
		runtimeValues: map[string]any{
			exchange.KeyDecisionSources: []any{"custom", exchange.FeatureBlocklist},
			exchange.KeyHaveIBeenPwned:  exchange.HIBPValue(exchange.HIBPResult{HashInfo: "abc123"}),
			exchange.KeyGeoIP: map[string]any{
				"matched":         true,
				"country_iso":     "DE",
				"country_name":    "Germany",
				"city_name":       "Berlin",
				"asn":             64500,
				"asn_org":         "Example Access GmbH",
				"asn_prefix":      "203.0.113.0/24",
				"asn_registry":    "ripencc",
				"asn_country_iso": "DE",
				"asn_allocated":   "2024-01-01",
				"asn_status":      "allocated",
			},
			exchange.KeyFailedLoginHotspot: map[string]any{
				"count":              7,
				"rank":               2,
				"recognized_account": true,
			},
			exchange.KeyGeoIPReputation: map[string]any{
				"score":             0.375,
				"positive_score":    0.82,
				"negative_score":    0.14,
				"ip_score":          0.71,
				"asn_score":         0.48,
				"country_score":     0.22,
				"asn_country_score": 0.19,
				"samples":           42,
				"source":            "redis",
				"decision":          "neutral",
			},
			exchange.KeyAccountProtection: map[string]any{
				"active":        true,
				"reason":        "spray",
				"backoff_level": 3,
				"delay_ms":      250,
			},
			exchange.KeyDynamicResponse: map[string]any{
				"threat_level": 4,
				"response":     "slow",
			},
			exchange.KeyGlobalPattern: map[string]any{
				"attempts":     11,
				"unique_ips":   5,
				"unique_users": 3,
				"ips_per_user": 1.66,
			},
		},
		facts: []pluginapi.PolicyFact{
			{Attribute: "lua.plugin.failed_login_hotspot.triggered", Value: true},
		},
		passwordHash: "password-short",
	}))
	if err != nil {
		t.Fatalf("EnqueuePostAction() error = %v", err)
	}

	row := decodeFirstRow(t, harness.transport.onlyRequest().body)
	assertStringField(t, row, "session", "sess-1")
	assertStringField(t, row, "service", "imap")
	assertStringField(t, row, "client_ip", testClientIP)
	assertStringField(t, row, "proto", "imap")
	assertStringField(t, row, "method", "plain")
	assertStringField(t, row, "account", testAccount)
	assertStringField(t, row, "username", testUsername)
	assertStringField(t, row, "password_hash", "password-short")
	assertStringField(t, row, "pwnd_info", "abc123")
	assertStringField(t, row, "brute_force_bucket", "bucket-a")
	assertStringField(t, row, "decision_sources", "custom,blocklist,account_protection,failed_login_hotspot")
	assertNumberField(t, row, "brute_force_counter", 9)
	assertNumberField(t, row, "failed_login_count", 7)
	assertBoolField(t, row, "failed_login_recognized", true)
	assertStringField(t, row, "geoip_country", "DE")
	assertStringField(t, row, "geoip_source", "native_geoip")
	assertNumberField(t, row, "geoip_asn", 64500)
	assertStringField(t, row, "geoip_asn_org", "Example Access GmbH")
	assertNumberField(t, row, "reputation_score", 0.375)
	assertStringField(t, row, "reputation_source", "redis")
	assertNumberField(t, row, "gp_attempts", 11)
	assertBoolField(t, row, "prot_active", true)
	assertStringField(t, row, "dyn_response", "slow")
	assertBoolField(t, row, "repeating", true)
	assertBoolField(t, row, "rwp", true)
	assertStringField(t, row, "xssl_protocol", "TLSv1.3")
	assertNumberField(t, row, "latency", 12)
	assertNumberField(t, row, "http_status", 200)
	assertStringField(t, row, "status_msg", "OK")
}

func TestDecisionSourcesIncludeGeoIPReputationSignal(t *testing.T) {
	cases := []struct {
		runtimeValues map[string]any
		facts         []pluginapi.PolicyFact
		name          string
	}{
		{
			name: "standard exchange reputation decision",
			runtimeValues: exchange.GeoIPReputationRuntimeDelta(map[string]any{
				exchange.FieldDecision: "suspicious",
			}).Set,
		},
		{
			name: "policy fact reputation decision",
			facts: []pluginapi.PolicyFact{
				{Attribute: "lua.plugin.geoip_reputation.decision", Value: "suspicious"},
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			harness := startTestRunner(t, testModule(map[string]any{
				"insert_url": testInsertURL,
				"batch_size": 1,
			}), testRunnerOptions{})
			defer harness.stop(t)

			_, err := harness.runner.EnqueuePostAction(context.Background(), "clickhouse.post_action", testRequest(t, requestOptions{
				runtimeValues: testCase.runtimeValues,
				facts:         testCase.facts,
			}))
			if err != nil {
				t.Fatalf("EnqueuePostAction() error = %v", err)
			}

			row := decodeFirstRow(t, harness.transport.onlyRequest().body)
			assertStringField(t, row, "decision_sources", exchange.FeatureGeoIPReputation)
		})
	}
}

func TestHIBPRuntimeOrderControlsPwndInfo(t *testing.T) {
	cases := []struct {
		runtimeValues map[string]any
		name          string
		wantPwndInfo  string
	}{
		{
			name: "HIBP before ClickHouse",
			runtimeValues: map[string]any{
				exchange.KeyHaveIBeenPwned: exchange.HIBPValue(exchange.HIBPResult{HashInfo: "abcde42"}),
			},
			wantPwndInfo: "abcde42",
		},
		{
			name:         "ClickHouse before HIBP",
			wantPwndInfo: "",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			harness := startTestRunner(t, testModule(map[string]any{
				"insert_url": testInsertURL,
				"batch_size": 1,
			}), testRunnerOptions{})
			defer harness.stop(t)

			_, err := harness.runner.EnqueuePostAction(context.Background(), "clickhouse.post_action", testRequest(t, requestOptions{
				runtimeValues: testCase.runtimeValues,
			}))
			if err != nil {
				t.Fatalf("EnqueuePostAction() error = %v", err)
			}

			row := decodeFirstRow(t, harness.transport.onlyRequest().body)
			assertStringField(t, row, "pwnd_info", testCase.wantPwndInfo)
		})
	}
}

func TestCacheOnlyPathBelowBatchThreshold(t *testing.T) {
	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url": testInsertURL,
		"batch_size": 2,
		"cache_key":  testCacheKey,
	}), testRunnerOptions{})
	defer harness.stop(t)

	_, err := harness.runner.EnqueuePostAction(context.Background(), "clickhouse.post_action", testRequest(t, requestOptions{}))
	if err != nil {
		t.Fatalf("EnqueuePostAction() error = %v", err)
	}

	if got := len(harness.transport.requests); got != 0 {
		t.Fatalf("HTTP calls = %d, want 0", got)
	}

	rows := popCachedRows(t, harness.host, testCacheKey)
	if len(rows) != 1 {
		t.Fatalf("cached rows = %d, want 1", len(rows))
	}
}

func TestThresholdFlushEmitsOneNDJSONBody(t *testing.T) {
	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url": testInsertURL,
		"batch_size": 2,
		"cache_key":  testCacheKey,
	}), testRunnerOptions{})
	defer harness.stop(t)

	for range 2 {
		if _, err := harness.runner.EnqueuePostAction(context.Background(), "clickhouse.post_action", testRequest(t, requestOptions{})); err != nil {
			t.Fatalf("EnqueuePostAction() error = %v", err)
		}
	}

	body := strings.TrimSpace(string(harness.transport.onlyRequest().body))
	if lines := strings.Split(body, "\n"); len(lines) != 2 {
		t.Fatalf("NDJSON lines = %d, want 2: %q", len(lines), body)
	}
}

func TestFailedInsertRequeuesRows(t *testing.T) {
	transport := &recordingTransport{statusCode: http.StatusInternalServerError}

	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url": testInsertURL,
		"batch_size": 1,
		"cache_key":  testCacheKey,
	}), testRunnerOptions{transport: transport})
	defer harness.stop(t)

	_, err := harness.runner.EnqueuePostAction(context.Background(), "clickhouse.post_action", testRequest(t, requestOptions{}))
	if err == nil {
		t.Fatal("EnqueuePostAction() error = nil, want status failure")
	}

	rows := popCachedRows(t, harness.host, testCacheKey)
	if len(rows) != 1 {
		t.Fatalf("requeued rows = %d, want 1", len(rows))
	}
}

func TestAuthenticatedRedisDedupSkipsDuplicates(t *testing.T) {
	db, mock := redismock.NewClientMock()
	mock.ExpectSetNX(testDedupRedisKey, "1", defaultAuthDedupTTL).SetVal(false)

	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url": testInsertURL,
		"batch_size": 1,
	}), testRunnerOptions{redis: pluginruntime.NewRedisFacade(rediscli.NewTestClient(db))})
	defer harness.stop(t)

	result, err := harness.runner.EnqueuePostAction(context.Background(), "clickhouse.post_action", testRequest(t, requestOptions{
		authenticated: true,
	}))
	if err != nil {
		t.Fatalf("EnqueuePostAction() error = %v", err)
	}

	if result.Enqueued {
		t.Fatal("duplicate authenticated request was enqueued")
	}

	if got := len(harness.transport.requests); got != 0 {
		t.Fatalf("HTTP calls = %d, want 0", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestRedisDedupErrorFailsOpen(t *testing.T) {
	db, mock := redismock.NewClientMock()
	mock.ExpectSetNX(testDedupRedisKey, "1", defaultAuthDedupTTL).SetErr(errors.New("redis unavailable"))

	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url": testInsertURL,
		"batch_size": 1,
	}), testRunnerOptions{redis: pluginruntime.NewRedisFacade(rediscli.NewTestClient(db))})
	defer harness.stop(t)

	result, err := harness.runner.EnqueuePostAction(context.Background(), "clickhouse.post_action", testRequest(t, requestOptions{
		authenticated: true,
	}))
	if err != nil {
		t.Fatalf("EnqueuePostAction() error = %v", err)
	}

	if !result.Enqueued {
		t.Fatal("dedup error should fail open and enqueue")
	}

	if got := len(harness.transport.requests); got != 1 {
		t.Fatalf("HTTP calls = %d, want 1", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestClickHouseAuthHeadersAreBuiltWithoutLoggingSecrets(t *testing.T) {
	var logs bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url": testInsertURL,
		"batch_size": 1,
		"user":       "clickhouse-user",
		"password":   testSecret,
	}), testRunnerOptions{logger: logger})
	defer harness.stop(t)

	if _, err := harness.runner.EnqueuePostAction(context.Background(), "clickhouse.post_action", testRequest(t, requestOptions{})); err != nil {
		t.Fatalf("EnqueuePostAction() error = %v", err)
	}

	request := harness.transport.onlyRequest()
	wantAuth := "Basic " + base64.RawStdEncoding.EncodeToString([]byte("clickhouse-user:"+testSecret))

	if got := request.header.Get(headerAuthorization); got != wantAuth {
		t.Fatalf("Authorization header = %q, want Basic credentials", got)
	}

	if strings.Contains(logs.String(), testSecret) || strings.Contains(logs.String(), wantAuth) {
		t.Fatalf("logs leaked ClickHouse secret material: %s", logs.String())
	}
}

func TestStartRegistersBoundedConnectionTarget(t *testing.T) {
	targets := &recordingConnectionTargetRegistrar{}

	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url": testInsertURL,
	}), testRunnerOptions{targets: targets})
	defer harness.stop(t)

	if len(targets.records) != 1 {
		t.Fatalf("connection target records = %#v, want one", targets.records)
	}

	record := targets.records[0]
	if record.address != "clickhouse.local:8123" || record.direction != string(pluginapi.ConnectionTargetDirectionRemote) {
		t.Fatalf("connection target = %#v, want remote clickhouse.local:8123", record)
	}
}

type testRunnerOptions struct {
	transport *recordingTransport
	redis     pluginapi.Redis
	logger    *slog.Logger
	targets   *recordingConnectionTargetRegistrar
}

type testHarness struct {
	runner    *pluginruntime.Runner
	host      *pluginruntime.Host
	transport *recordingTransport
}

// startTestRunner registers, starts, and returns a ClickHouse plugin runtime.
func startTestRunner(t *testing.T, module config.PluginModule, options testRunnerOptions) testHarness {
	t.Helper()

	registry, plugin := registerTestPlugin(t, module)
	transport := options.transport

	if transport == nil {
		transport = &recordingTransport{statusCode: http.StatusOK}
	}

	targets := options.targets
	if targets == nil {
		targets = &recordingConnectionTargetRegistrar{}
	}

	metrics := newRecordingMetrics()
	tracer := &recordingTracer{}

	hostOptions := []pluginruntime.HostOption{
		pluginruntime.WithHTTPClient(&http.Client{Transport: transport}),
		pluginruntime.WithConnectionTargets(pluginruntime.NewConnectionTargetFacade(targets)),
		pluginruntime.WithMetricsFactory(func(string) pluginapi.Metrics {
			return metrics
		}),
		pluginruntime.WithTracerFactory(func(string) pluginapi.Tracer {
			return tracer
		}),
	}
	if options.redis != nil {
		hostOptions = append(hostOptions, pluginruntime.WithRedis(options.redis))
	}

	if options.logger != nil {
		hostOptions = append(hostOptions, pluginruntime.WithLogger(options.logger))
	}

	host := pluginruntime.NewHost(hostOptions...)
	instances := []pluginloader.ModuleInstance{
		{
			Plugin:     plugin,
			Module:     module,
			ModuleName: module.Name,
			Status:     pluginloader.ModuleStatusRegistered,
		},
	}

	runner := pluginruntime.NewRunnerFromInstances(
		registry,
		instances,
		pluginruntime.WithHost(host),
		pluginruntime.WithPluginConfig(&config.PluginsSection{Modules: []config.PluginModule{module}}),
	)
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	return testHarness{runner: runner, host: host, transport: transport}
}

// stop stops a started test runner.
func (h testHarness) stop(t *testing.T) {
	t.Helper()

	if err := h.runner.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

// registerTestPlugin registers a ClickHouse plugin in the real component registry.
func registerTestPlugin(t *testing.T, module config.PluginModule) (*pluginregistry.Registry, *Plugin) {
	t.Helper()

	registry := pluginregistry.NewRegistry()
	plugin := NewPlugin()
	registrar := registry.NewRegistrar(module)

	if err := plugin.Register(registrar); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	return registry, plugin
}

func hasDebugSelector(debugModules []pluginregistry.DebugModule, selector string) bool {
	for _, debugModule := range debugModules {
		if debugModule.Selector == selector {
			return true
		}
	}

	return false
}

// testModule returns a native ClickHouse plugin module config for tests.
func testModule(pluginConfig map[string]any) config.PluginModule {
	return config.PluginModule{
		Config: pluginConfig,
		Name:   pluginName,
		Type:   config.PluginModuleTypeGo,
		Path:   "/plugins/clickhouse.so",
	}
}

type requestOptions struct {
	runtimeValues map[string]any
	facts         []pluginapi.PolicyFact
	passwordHash  string
	protocol      string
	service       string
	grantType     string
	samlEntityID  string
	mfaMethod     string
	authenticated bool
	noAuth        bool
	disableRedis  bool
}

// testRequest builds one representative post-action request.
//
//nolint:funlen // The fixture keeps the representative post-action snapshot visible to row parity tests.
func testRequest(t *testing.T, options requestOptions) pluginapi.PostActionRequest {
	t.Helper()

	runtimeContext, err := pluginruntime.NewRuntimeContext(options.runtimeValues)
	if err != nil {
		t.Fatalf("NewRuntimeContext() error = %v", err)
	}

	protocol := options.protocol
	if protocol == "" {
		protocol = "imap"
	}

	service := options.service
	if service == "" {
		service = protocol
	}

	username := testUsername
	if options.disableRedis {
		username = ""
	}

	return pluginapi.PostActionRequest{
		Snapshot: pluginapi.RequestSnapshot{
			Session:      "sess-1",
			Service:      service,
			Protocol:     protocol,
			Method:       "plain",
			Username:     username,
			Account:      testAccount,
			ClientIP:     testClientIP,
			ClientPort:   "12345",
			ClientNet:    "203.0.113.0/24",
			ClientID:     "client-1",
			ClientHost:   "host.example.test",
			UserAgent:    "Nauthilus Test",
			LocalIP:      "127.0.0.1",
			LocalPort:    "8080",
			OIDCCID:      "oidc-client-1",
			SAMLEntityID: options.samlEntityID,
			IDP: pluginapi.IDPInfo{
				GrantType: options.grantType,
				MFAMethod: options.mfaMethod,
			},
			TLS: pluginapi.TLSInfo{
				Legacy: pluginapi.TLSLegacyInfo{
					Protocol:    "TLSv1.3",
					CipherSuite: "TLS_AES_256_GCM_SHA384",
					Fingerprint: "fingerprint-1",
				},
			},
			Diagnostics: pluginapi.RequestDiagnostics{
				StatusMessage:     "OK",
				BruteForceName:    "bucket-a",
				LatencyMillis:     12,
				BruteForceCounter: 9,
				HTTPStatus:        200,
			},
			Runtime: pluginapi.RuntimeFlags{
				NoAuth:        options.noAuth,
				Authenticated: options.authenticated,
				UserFound:     true,
				Repeating:     true,
				RWP:           true,
			},
		},
		Runtime:      runtimeContext,
		PasswordHash: options.passwordHash,
		Facts:        options.facts,
	}
}

type recordedHTTPRequest struct {
	header http.Header
	body   []byte
}

type recordingTransport struct {
	err        error
	requests   []recordedHTTPRequest
	statusCode int
}

// RoundTrip records request bodies and returns the configured response.
func (t *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(request.Body)
	t.requests = append(t.requests, recordedHTTPRequest{
		header: request.Header.Clone(),
		body:   append([]byte(nil), body...),
	})

	if t.err != nil {
		return nil, t.err
	}

	statusCode := t.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	return &http.Response{
		StatusCode: statusCode,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    request,
	}, nil
}

// onlyRequest returns the single captured request or fails the test.
func (t *recordingTransport) onlyRequest() recordedHTTPRequest {
	if len(t.requests) != 1 {
		panic("expected exactly one captured HTTP request")
	}

	return t.requests[0]
}

// decodeFirstRow decodes the first JSONEachRow line from a request body.
func decodeFirstRow(t *testing.T, body []byte) map[string]any {
	t.Helper()

	line := strings.TrimSpace(strings.Split(string(body), "\n")[0])
	if line == "" {
		t.Fatal("empty JSONEachRow body")
	}

	row := map[string]any{}
	if err := json.Unmarshal([]byte(line), &row); err != nil {
		t.Fatalf("decode row: %v", err)
	}

	return row
}

// popCachedRows returns and clears the ClickHouse module cache key.
func popCachedRows(t *testing.T, host *pluginruntime.Host, key string) []any {
	t.Helper()

	cache, err := host.Cache(pluginName)
	if err != nil {
		t.Fatalf("Cache(%s) error = %v", pluginName, err)
	}

	return cache.PopAll(context.Background(), key)
}

// assertStringField checks one string row field.
func assertStringField(t *testing.T, row map[string]any, key string, want string) {
	t.Helper()

	got, ok := row[key].(string)
	if !ok || got != want {
		t.Fatalf("row[%s] = %#v, want %q", key, row[key], want)
	}
}

// assertNumberField checks one JSON number row field.
func assertNumberField(t *testing.T, row map[string]any, key string, want float64) {
	t.Helper()

	got, ok := row[key].(float64)
	if !ok || got != want {
		t.Fatalf("row[%s] = %#v, want %v", key, row[key], want)
	}
}

// assertBoolField checks one bool row field.
func assertBoolField(t *testing.T, row map[string]any, key string, want bool) {
	t.Helper()

	got, ok := row[key].(bool)
	if !ok || got != want {
		t.Fatalf("row[%s] = %#v, want %v", key, row[key], want)
	}
}

type recordingMetrics struct {
	observations []metricObservation
}

type metricObservation struct {
	name   string
	result string
}

// newRecordingMetrics creates a metrics fake for plugin tests.
func newRecordingMetrics() *recordingMetrics {
	return &recordingMetrics{}
}

// Counter returns a recording counter.
func (m *recordingMetrics) Counter(definition pluginapi.MetricDefinition) (pluginapi.Counter, error) {
	return recordingMetric{name: definition.Name, metrics: m}, nil
}

// Gauge returns a recording gauge.
func (m *recordingMetrics) Gauge(definition pluginapi.MetricDefinition) (pluginapi.Gauge, error) {
	return recordingMetric{name: definition.Name, metrics: m}, nil
}

// Histogram returns a recording histogram.
func (m *recordingMetrics) Histogram(definition pluginapi.MetricDefinition) (pluginapi.Histogram, error) {
	return recordingMetric{name: definition.Name, metrics: m}, nil
}

// Summary returns a recording summary.
func (m *recordingMetrics) Summary(definition pluginapi.MetricDefinition) (pluginapi.Summary, error) {
	return recordingMetric{name: definition.Name, metrics: m}, nil
}

type recordingMetric struct {
	metrics *recordingMetrics
	name    string
}

// Add records counter and gauge observations.
func (m recordingMetric) Add(_ context.Context, _ float64, labels ...pluginapi.LabelValue) {
	m.record(labels...)
}

// Set records gauge observations.
func (m recordingMetric) Set(_ context.Context, _ float64, labels ...pluginapi.LabelValue) {
	m.record(labels...)
}

// Observe records histogram and summary observations.
func (m recordingMetric) Observe(_ context.Context, _ float64, labels ...pluginapi.LabelValue) {
	m.record(labels...)
}

// record stores one metric observation with bounded labels.
func (m recordingMetric) record(labels ...pluginapi.LabelValue) {
	result := ""

	for _, label := range labels {
		if label.Name == metricLabelResult {
			result = label.Value
		}
	}

	m.metrics.observations = append(m.metrics.observations, metricObservation{name: m.name, result: result})
}

type recordingTracer struct {
	spans []recordedSpan
}

type recordedSpan struct {
	attrs map[string]any
	name  string
}

// Start records a span and returns a recording span handle.
func (t *recordingTracer) Start(ctx context.Context, name string, attrs ...pluginapi.TraceAttribute) (context.Context, pluginapi.Span) {
	span := recordedSpan{name: name, attrs: make(map[string]any, len(attrs))}
	for _, attr := range attrs {
		span.attrs[attr.Key] = attr.Value
	}

	t.spans = append(t.spans, span)

	return ctx, recordingSpan{tracer: t, index: len(t.spans) - 1}
}

type recordingSpan struct {
	tracer *recordingTracer
	index  int
}

// AddEvent ignores events for these tests.
func (s recordingSpan) AddEvent(string, ...pluginapi.TraceAttribute) {}

// SetAttributes records attributes on an existing span.
func (s recordingSpan) SetAttributes(attrs ...pluginapi.TraceAttribute) {
	for _, attr := range attrs {
		s.tracer.spans[s.index].attrs[attr.Key] = attr.Value
	}
}

// RecordError records error presence without exposing error text.
func (s recordingSpan) RecordError(error) {
	s.tracer.spans[s.index].attrs["error"] = true
}

// End finishes the recording span.
func (s recordingSpan) End() {}

type connectionRecord struct {
	address     string
	direction   string
	description string
}

type recordingConnectionTargetRegistrar struct {
	records []connectionRecord
}

// Register records one connection target registration.
func (r *recordingConnectionTargetRegistrar) Register(_ context.Context, address string, direction string, description string) {
	r.records = append(r.records, connectionRecord{
		address:     address,
		direction:   direction,
		description: description,
	})
}

// Count returns no live connection count in tests.
func (r *recordingConnectionTargetRegistrar) Count(string) (int, bool) {
	return 0, false
}

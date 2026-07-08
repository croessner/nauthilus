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
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/pluginapi/v1/exchange"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/pluginruntime"
)

const (
	testASNLookupLogURL      = "https://routing.example.test/routeviews-prefix2as/pfx2as-creation.log"
	testASNLookupSnapshotURL = "https://routing.example.test/routeviews-prefix2as/2026/06/routeviews-rv2-20260615-1200.pfx2as.gz"
	testASNLookupSourceURL   = "https://routing.example.test/pfx2as"
	testASNOrg               = "Example Access GmbH"
	testASNPrefix            = "203.0.113.0/24"
	testCityNameBerlin       = "Berlin"
	testConfigASNDatabaseKey = "asn_database_path"
	testClientIP             = "203.0.113.7"
	testConfigDatabasePath   = "database_path"
	testConfigEnabledKey     = "enabled"
	testCountryDE            = "DE"
	testCountryNameGermany   = "Germany"
	testCountryUS            = "US"
	testProtocolIMAP         = "imap"
	testRegistryARIN         = "arin"
	testRegistryRIPENCC      = "ripencc"
	testRegistrySourceURL    = "https://registry.example.test/delegated"
	testReloadedASN          = 64510
	testReloadedCountry      = "US"
)

func TestPluginMetadataAndAPIVersion(t *testing.T) {
	metadata := NewPlugin().Metadata()

	if metadata.Name != pluginName {
		t.Fatalf("metadata name = %q, want %q", metadata.Name, pluginName)
	}

	if metadata.APIVersion != pluginapi.APIVersion {
		t.Fatalf("metadata API version = %q, want %q", metadata.APIVersion, pluginapi.APIVersion)
	}

	if !slices.Contains(metadata.Features, pluginapi.Feature("environment_source")) {
		t.Fatalf("metadata features = %#v, want environment_source", metadata.Features)
	}
}

func TestPluginRegistersInitTaskEnvironmentSourceAndPolicyAttributes(t *testing.T) {
	registry, plugin := registerTestPlugin(t, testModule(testDatabasePath(t, "geoip.json")))

	if len(registry.InitTasks()) != 1 {
		t.Fatalf("init tasks = %d, want 1", len(registry.InitTasks()))
	}

	if len(registry.EnvironmentSources()) != 1 {
		t.Fatalf("environment sources = %d, want 1", len(registry.EnvironmentSources()))
	}

	attributes := registry.PolicyAttributes()
	if len(attributes) != len(geoIPPolicyAttributes()) {
		t.Fatalf("policy attributes = %d, want %d", len(attributes), len(geoIPPolicyAttributes()))
	}

	if attributes[0].ID != factMatched {
		t.Fatalf("first policy attribute = %q, want %q", attributes[0].ID, factMatched)
	}

	if plugin == nil {
		t.Fatal("registered plugin is nil")
	}
}

func TestEnvironmentSourceEmitsExpectedFactsRuntimeDeltaMetricsAndTrace(t *testing.T) {
	runner, metrics, tracer := startedTestRunner(t, testModule(testDatabasePath(t, "geoip.json")))
	defer stopRunner(t, runner)

	result, err := runner.EvaluateEnvironment(context.Background(), "geoip.environment", environmentRequest(testClientIP))
	if err != nil {
		t.Fatalf("EvaluateEnvironment() error = %v", err)
	}

	assertFact(t, result.Facts, factMatched, true)
	assertFact(t, result.Facts, factCountryISO, testCountryDE)
	assertFact(t, result.Facts, factASN, 64500)
	assertLogField(t, result.Logs, "policy_fact_geoip_country_iso", testCountryDE)
	assertLogField(t, result.Logs, "policy_fact_geoip_asn", 64500)

	runtimeValue := result.RuntimeDelta.Set[exchange.KeyGeoIP].(map[string]any)
	if runtimeValue["country_iso"] != testCountryDE || runtimeValue["asn"] != 64500 {
		t.Fatalf("runtime delta = %#v, want DE/64500", runtimeValue)
	}

	if got := metrics.observationCount(metricLookupTotal, resultMatched); got != 1 {
		t.Fatalf("matched counter observations = %d, want 1", got)
	}

	if !tracer.sawSpan("geoip.environment.evaluate", traceAttrModule, pluginName) {
		t.Fatalf("spans = %#v, want geoip.environment.evaluate with module attr", tracer.spans)
	}
}

func TestMissingDatabaseFailsStartupForRequiredModule(t *testing.T) {
	module := testModule(filepath.Join(t.TempDir(), "missing.json"))
	registry, plugin := registerTestPlugin(t, module)
	runner := newRunnerForPlugin(registry, plugin, module, nil, nil)

	err := runner.Start(context.Background())
	if err == nil {
		t.Fatal("Start() error = nil, want missing database error")
	}

	if !errors.Is(err, pluginruntime.ErrLifecycleFailed) {
		t.Fatalf("Start() error = %v, want lifecycle failure", err)
	}
}

func TestReconfigureSuccessSwapsDatabaseState(t *testing.T) {
	module := testModule(testDatabasePath(t, "geoip.json"))
	runner, _, _ := startedTestRunner(t, module)

	defer stopRunner(t, runner)

	next := testConfigFile(testModule(testDatabasePath(t, "geoip-reload.json")))
	if err := runner.Reconfigure(context.Background(), next); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}

	result, err := runner.EvaluateEnvironment(context.Background(), "geoip.environment", environmentRequest(testClientIP))
	if err != nil {
		t.Fatalf("EvaluateEnvironment() error = %v", err)
	}

	assertFact(t, result.Facts, factCountryISO, testReloadedCountry)
	assertFact(t, result.Facts, factASN, testReloadedASN)
}

func TestReconfigureFailureKeepsPreviousDatabaseState(t *testing.T) {
	module := testModule(testDatabasePath(t, "geoip.json"))
	runner, _, _ := startedTestRunner(t, module)

	defer stopRunner(t, runner)

	err := runner.Reconfigure(context.Background(), testConfigFile(testModule(filepath.Join(t.TempDir(), "missing.json"))))
	if err == nil {
		t.Fatal("Reconfigure() error = nil, want missing database error")
	}

	result, evalErr := runner.EvaluateEnvironment(context.Background(), "geoip.environment", environmentRequest(testClientIP))
	if evalErr != nil {
		t.Fatalf("EvaluateEnvironment() error = %v", evalErr)
	}

	assertFact(t, result.Facts, factCountryISO, testCountryDE)
	assertFact(t, result.Facts, factASN, 64500)
}

func TestInvalidDatabaseFailsValidation(t *testing.T) {
	_, err := loadFileDatabase(context.Background(), testDatabasePath(t, "geoip-invalid.json"))
	if err == nil {
		t.Fatal("loadFileDatabase() error = nil, want invalid CIDR error")
	}
}

func TestDecodeModuleConfigInfersMMDBAndASNRegistryDefaults(t *testing.T) {
	config, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{
		testConfigDatabasePath: testDatabasePath(t, "geoip-test.mmdb"),
		"asn_registry": map[string]any{
			testConfigEnabledKey: true,
		},
	}))
	if err != nil {
		t.Fatalf("decodeModuleConfig() error = %v", err)
	}

	if config.DatabaseFormat != databaseFormatMMDB {
		t.Fatalf("database format = %q, want %q", config.DatabaseFormat, databaseFormatMMDB)
	}

	if config.ASNRegistry.RefreshInterval != defaultASNRegistryRefreshInterval {
		t.Fatalf("ASN refresh interval = %s, want %s", config.ASNRegistry.RefreshInterval, defaultASNRegistryRefreshInterval)
	}

	if len(config.ASNRegistry.SourceURLs) != len(defaultASNRegistrySourceURLs()) {
		t.Fatalf("ASN registry sources = %d, want defaults", len(config.ASNRegistry.SourceURLs))
	}
}

func TestDecodeModuleConfigEnablesASNLookupRoutingDefaults(t *testing.T) {
	config, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{
		testConfigDatabasePath: testDatabasePath(t, "geoip.json"),
		"asn_lookup": map[string]any{
			testConfigEnabledKey: true,
		},
	}))
	if err != nil {
		t.Fatalf("decodeModuleConfig() error = %v", err)
	}

	if !config.ASNLookup.Enabled {
		t.Fatal("ASN lookup should be enabled")
	}

	if config.ASNLookup.RefreshInterval != defaultASNLookupRefreshInterval {
		t.Fatalf("ASN lookup refresh interval = %s, want %s", config.ASNLookup.RefreshInterval, defaultASNLookupRefreshInterval)
	}

	if config.ASNLookup.Timeout != defaultASNLookupTimeout {
		t.Fatalf("ASN lookup timeout = %s, want %s", config.ASNLookup.Timeout, defaultASNLookupTimeout)
	}

	if len(config.ASNLookup.SourceURLs) != len(defaultASNLookupSourceURLs()) {
		t.Fatalf("ASN lookup sources = %d, want defaults", len(config.ASNLookup.SourceURLs))
	}
}

func TestFakeMMDBFixtureIsNotARealMaxMindDatabase(t *testing.T) {
	_, err := loadConfiguredDatabase(context.Background(), moduleConfig{
		DatabasePath:   testDatabasePath(t, "geoip-test.mmdb"),
		DatabaseFormat: databaseFormatMMDB,
	})
	if err == nil {
		t.Fatal("loadConfiguredDatabase() error = nil, want fake mmdb rejection")
	}
}

func TestPluginSupportsMMDBConfigThroughDatabaseLoader(t *testing.T) {
	module := testModule(testDatabasePath(t, "geoip-test.mmdb"))
	module.Config["database_format"] = databaseFormatMMDB

	plugin := NewPlugin()
	plugin.databaseLoad = func(_ context.Context, config moduleConfig) (geoDatabase, error) {
		if config.DatabaseFormat != databaseFormatMMDB {
			t.Fatalf("database format = %q, want %q", config.DatabaseFormat, databaseFormatMMDB)
		}

		return &fileDatabase{records: []geoRecord{
			{
				CountryISO:  testCountryDE,
				CountryName: testCountryNameGermany,
				CityName:    testCityNameBerlin,
				ASNOrg:      "Example Access GmbH",
				Prefix:      mustPrefix(t, "203.0.113.0/24"),
				ASN:         64500,
			},
		}}, nil
	}

	registry, registeredPlugin := registerTestPluginInstance(t, plugin, module)

	runner := newRunnerForPlugin(registry, registeredPlugin, module, nil, nil)
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer stopRunner(t, runner)

	result, err := runner.EvaluateEnvironment(context.Background(), "geoip.environment", environmentRequest(testClientIP))
	if err != nil {
		t.Fatalf("EvaluateEnvironment() error = %v", err)
	}

	assertFact(t, result.Facts, factMatched, true)
	assertFact(t, result.Facts, factASN, 64500)
}

func TestEnvironmentSourceUsesASNDatabaseForOrganization(t *testing.T) {
	primaryDatabasePath := testDatabasePath(t, "geoip-test.mmdb")
	asnDatabasePath := testDatabasePath(t, "geoip-asn.mmdb")
	module := testModule(primaryDatabasePath)
	module.Config["database_format"] = databaseFormatMMDB
	module.Config[testConfigASNDatabaseKey] = asnDatabasePath
	module.Config["asn_database_format"] = databaseFormatMMDB

	var loadedPaths []string

	plugin := newASNDatabaseTestPlugin(t, primaryDatabasePath, asnDatabasePath, &loadedPaths)

	registry, registeredPlugin := registerTestPluginInstance(t, plugin, module)

	runner := newRunnerForPlugin(registry, registeredPlugin, module, nil, nil)
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer stopRunner(t, runner)

	if !slices.Contains(loadedPaths, asnDatabasePath) {
		t.Fatalf("loaded database paths = %#v, want ASN database path %q", loadedPaths, asnDatabasePath)
	}

	result, err := runner.EvaluateEnvironment(context.Background(), "geoip.environment", environmentRequest(testClientIP))
	if err != nil {
		t.Fatalf("EvaluateEnvironment() error = %v", err)
	}

	assertFact(t, result.Facts, factCountryISO, testCountryDE)
	assertFact(t, result.Facts, factCityName, testCityNameBerlin)
	assertFact(t, result.Facts, factASN, 64500)
	assertFact(t, result.Facts, factASNOrg, testASNOrg)

	runtimeValue := result.RuntimeDelta.Set[exchange.KeyGeoIP].(map[string]any)
	if runtimeValue["asn_org"] != testASNOrg {
		t.Fatalf("runtime ASN org = %#v, want %q", runtimeValue["asn_org"], testASNOrg)
	}
}

func TestASNLookupUsesLocalRoutingSnapshotLongestPrefix(t *testing.T) {
	snapshot, err := buildASNLookupSnapshot([][]byte{[]byte(
		"203.0.113.0/24 64500 DE ripencc 20240101\n" +
			"203.0.113.0/25 64510 US arin 20240202\n",
	)})
	if err != nil {
		t.Fatalf("buildASNLookupSnapshot() error = %v", err)
	}

	lookup := newASNLookupService()
	lookup.Swap(snapshot)

	record, ok, err := lookup.Lookup(context.Background(), netip.MustParseAddr(testClientIP))
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}

	if !ok {
		t.Fatal("Lookup() did not match local ASN routing snapshot")
	}

	if record.ASN != 64510 || record.ASNPrefix != "203.0.113.0/25" || record.ASNCountryISO != testCountryUS || record.ASNRegistry != testRegistryARIN {
		t.Fatalf("ASN record = %#v", record)
	}
}

func TestASNLookupFetchesLatestCreationLogSnapshot(t *testing.T) {
	fetcher := fakeASNRouteFetcher{
		data: map[string][]byte{
			testASNLookupLogURL: []byte(
				"# Fields: seqnum timestamp path\n" +
					"6648\t1781540054\t2026/06/routeviews-rv2-20260614-1200.pfx2as.gz\n" +
					"6649\t1781626448\t2026/06/routeviews-rv2-20260615-1200.pfx2as.gz\n",
			),
			testASNLookupSnapshotURL: []byte("203.0.113.0\t24\t64500\n"),
		},
	}

	snapshot, err := fetchASNLookupSnapshot(context.Background(), fetcher, []string{testASNLookupLogURL}, time.Second)
	if err != nil {
		t.Fatalf("fetchASNLookupSnapshot() error = %v", err)
	}

	record, ok := snapshot.Lookup(netip.MustParseAddr(testClientIP))

	if !ok || record.ASN != 64500 || record.ASNPrefix != testASNPrefix {
		t.Fatalf("snapshot lookup = %#v/%v, want ASN 64500 prefix %s", record, ok, testASNPrefix)
	}
}

func TestEnvironmentSourceUsesASNRoutingSnapshotForRecordsWithoutASN(t *testing.T) {
	module := testModule(testDatabasePath(t, "geoip-test.mmdb"))
	module.Config["database_format"] = databaseFormatMMDB
	module.Config["asn_lookup"] = map[string]any{
		testConfigEnabledKey: true,
		"refresh_interval":   "1h",
		"source_urls":        []string{testASNLookupSourceURL},
		"timeout":            "1s",
	}

	plugin := NewPlugin()
	plugin.asnRouteFetch = fakeASNRouteFetcher{
		data: map[string][]byte{
			testASNLookupSourceURL: []byte("203.0.113.0/24 64500 DE ripencc 20240101\n"),
		},
	}
	plugin.databaseLoad = func(_ context.Context, config moduleConfig) (geoDatabase, error) {
		if len(config.ASNLookup.SourceURLs) != 1 || config.ASNLookup.SourceURLs[0] != testASNLookupSourceURL {
			t.Fatalf("ASN lookup sources = %#v", config.ASNLookup.SourceURLs)
		}

		return &fileDatabase{records: []geoRecord{
			{
				CountryISO:  testCountryDE,
				CountryName: testCountryNameGermany,
				CityName:    testCityNameBerlin,
				Prefix:      mustPrefix(t, "203.0.113.0/24"),
			},
		}}, nil
	}

	registry, registeredPlugin := registerTestPluginInstance(t, plugin, module)

	runner := newRunnerForPlugin(registry, registeredPlugin, module, nil, nil)
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer stopRunner(t, runner)

	config, _ := plugin.currentConfig()
	plugin.refreshASNLookupOnce(context.Background(), config.ASNLookup)

	result, err := runner.EvaluateEnvironment(context.Background(), "geoip.environment", environmentRequest(testClientIP))
	if err != nil {
		t.Fatalf("EvaluateEnvironment() error = %v", err)
	}

	assertFact(t, result.Facts, factASN, 64500)
	assertFact(t, result.Facts, factASNPrefix, testASNPrefix)
	assertFact(t, result.Facts, factASNRegistry, testRegistryRIPENCC)
}

func TestASNRegistrySnapshotParsesDelegatedStats(t *testing.T) {
	snapshot := mustASNRegistrySnapshot(t, []byte(
		"2|arin|20260616|2|19830701|20260616|+0000\n"+
			"arin|US|asn|64500|4|20240101|allocated\n"+
			"ripencc|DE|asn|64510|1|20240202|assigned\n"+
			"arin|US|ipv4|203.0.113.0|256|20240101|assigned\n",
	))

	record, ok := snapshot.Lookup(64502)
	if !ok {
		t.Fatal("Lookup(64502) did not match delegated ASN range")
	}

	if record.Registry != testRegistryARIN || record.CountryISO != testCountryUS || record.Allocated != "20240101" {
		t.Fatalf("Lookup(64502) = %#v, want ARIN US allocation", record)
	}

	record, ok = snapshot.Lookup(64510)
	if !ok || record.Registry != "ripencc" || record.CountryISO != "DE" {
		t.Fatalf("Lookup(64510) = %#v/%v, want RIPE NCC DE allocation", record, ok)
	}

	if _, ok := snapshot.Lookup(64599); ok {
		t.Fatal("Lookup(64599) matched outside delegated ranges")
	}
}

func TestEnvironmentSourceEmitsASNRegistryFacts(t *testing.T) {
	module := testModule(testDatabasePath(t, "geoip.json"))

	runner, plugin, _, _ := startedTestRunnerWithPlugin(t, module)
	defer stopRunner(t, runner)

	plugin.mu.Lock()
	plugin.asnRegistry = mustASNRegistrySnapshot(t, []byte(testRegistryARIN+"|"+testCountryUS+"|asn|64500|1|20240101|allocated\n"))
	plugin.mu.Unlock()

	result, err := runner.EvaluateEnvironment(context.Background(), "geoip.environment", environmentRequest(testClientIP))
	if err != nil {
		t.Fatalf("EvaluateEnvironment() error = %v", err)
	}

	assertFact(t, result.Facts, factASNRegistry, testRegistryARIN)
	assertFact(t, result.Facts, factASNCountryISO, testCountryUS)
	assertFact(t, result.Facts, factASNAllocated, "20240101")
	assertLogField(t, result.Logs, "policy_fact_geoip_country_iso", testCountryDE)
	assertLogField(t, result.Logs, "policy_fact_geoip_asn_country_iso", testCountryUS)
}

func TestASNRegistryRefreshPublishesSnapshot(t *testing.T) {
	plugin := NewPlugin()
	plugin.asnFetch = fakeASNRegistryFetcher{
		data: map[string][]byte{
			testRegistrySourceURL: []byte(testRegistryARIN + "|" + testCountryUS + "|asn|64500|1|20240101|allocated\n"),
		},
	}

	plugin.refreshASNRegistryOnce(context.Background(), asnRegistryConfig{
		Enabled:         true,
		RefreshInterval: time.Hour,
		Timeout:         time.Second,
		SourceURLs:      []string{testRegistrySourceURL},
	})

	plugin.mu.RLock()
	snapshot := plugin.asnRegistry
	plugin.mu.RUnlock()

	record, ok := snapshot.Lookup(64500)
	if !ok || record.Registry != testRegistryARIN {
		t.Fatalf("ASN registry snapshot lookup = %#v/%v, want ARIN record", record, ok)
	}
}

func TestPluginSmokeBuildsAndLoadsSharedObject(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOARCH == "wasm" {
		t.Skipf("Go plugins are not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	artifact := filepath.Join(t.TempDir(), "geoip.so")
	cmd := exec.Command("go", "build", "-buildmode=plugin", "-o", artifact, ".")
	cmd.Env = goCommandEnv()

	output, err := cmd.CombinedOutput()
	if err != nil {
		if bytes.Contains(output, []byte("buildmode=plugin not supported")) {
			t.Skipf("Go plugin build mode is not supported on %s/%s: %s", runtime.GOOS, runtime.GOARCH, output)
		}

		t.Fatalf("build plugin: %v\n%s", err, output)
	}

	loadCmd := exec.Command("go", "run", "./testdata/loadplugin", artifact)
	loadCmd.Env = goCommandEnv()

	loadOutput, err := loadCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("load plugin helper: %v\n%s", err, loadOutput)
	}
}

// registerTestPlugin registers a plugin against the real component registry.
func registerTestPlugin(t *testing.T, module config.PluginModule) (*pluginregistry.Registry, *Plugin) {
	t.Helper()

	return registerTestPluginInstance(t, NewPlugin(), module)
}

// registerTestPluginInstance registers the supplied plugin against the real component registry.
func registerTestPluginInstance(t *testing.T, plugin *Plugin, module config.PluginModule) (*pluginregistry.Registry, *Plugin) {
	t.Helper()

	registry := pluginregistry.NewRegistry()
	registrar := registry.NewRegistrar(module)

	if err := plugin.Register(registrar); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	return registry, plugin
}

// startedTestRunner starts a plugin runtime for the configured test module.
func startedTestRunner(t *testing.T, module config.PluginModule) (*pluginruntime.Runner, *recordingMetrics, *recordingTracer) {
	t.Helper()

	runner, _, metrics, tracer := startedTestRunnerWithPlugin(t, module)

	return runner, metrics, tracer
}

// startedTestRunnerWithPlugin starts a runtime and returns the underlying plugin instance.
func startedTestRunnerWithPlugin(
	t *testing.T,
	module config.PluginModule,
) (*pluginruntime.Runner, *Plugin, *recordingMetrics, *recordingTracer) {
	t.Helper()

	registry, plugin := registerTestPlugin(t, module)
	metrics := newRecordingMetrics()
	tracer := &recordingTracer{}
	runner := newRunnerForPlugin(registry, plugin, module, metrics, tracer)

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	return runner, plugin, metrics, tracer
}

// newASNDatabaseTestPlugin builds a plugin loader with separate primary and ASN fixtures.
func newASNDatabaseTestPlugin(
	t *testing.T,
	primaryDatabasePath string,
	asnDatabasePath string,
	loadedPaths *[]string,
) *Plugin {
	t.Helper()

	plugin := NewPlugin()
	plugin.databaseLoad = func(_ context.Context, config moduleConfig) (geoDatabase, error) {
		*loadedPaths = append(*loadedPaths, config.DatabasePath)

		switch config.DatabasePath {
		case primaryDatabasePath:
			return &fileDatabase{records: []geoRecord{
				{
					CountryISO:  testCountryDE,
					CountryName: testCountryNameGermany,
					CityName:    testCityNameBerlin,
					Prefix:      mustPrefix(t, testASNPrefix),
				},
			}}, nil
		case asnDatabasePath:
			return &fileDatabase{records: []geoRecord{
				{
					ASNOrg: testASNOrg,
					Prefix: mustPrefix(t, testASNPrefix),
					ASN:    64500,
				},
			}}, nil
		default:
			t.Fatalf("unexpected database path %q", config.DatabasePath)

			return nil, nil
		}
	}

	return plugin
}

// newRunnerForPlugin creates a runtime runner for one registered plugin instance.
func newRunnerForPlugin(
	registry *pluginregistry.Registry,
	plugin *Plugin,
	module config.PluginModule,
	metrics *recordingMetrics,
	tracer *recordingTracer,
) *pluginruntime.Runner {
	hostOptions := []pluginruntime.HostOption{}
	if metrics != nil {
		hostOptions = append(hostOptions, pluginruntime.WithMetricsFactory(func(string) pluginapi.Metrics {
			return metrics
		}))
	}

	if tracer != nil {
		hostOptions = append(hostOptions, pluginruntime.WithTracerFactory(func(string) pluginapi.Tracer {
			return tracer
		}))
	}

	instances := []pluginloader.ModuleInstance{
		{
			Plugin:     plugin,
			Module:     module,
			ModuleName: module.Name,
			Status:     pluginloader.ModuleStatusRegistered,
		},
	}

	return pluginruntime.NewRunnerFromInstances(
		registry,
		instances,
		pluginruntime.WithHost(pluginruntime.NewHost(hostOptions...)),
		pluginruntime.WithPluginConfig(&config.PluginsSection{Modules: []config.PluginModule{module}}),
	)
}

// stopRunner stops a started runner and fails the test on shutdown errors.
func stopRunner(t *testing.T, runner *pluginruntime.Runner) {
	t.Helper()

	if err := runner.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

// testModule returns a native plugin module config for tests.
func testModule(databasePath string) config.PluginModule {
	return config.PluginModule{
		Config: map[string]any{
			"database_path": databasePath,
		},
		Name: "geoip",
		Type: config.PluginModuleTypeGo,
		Path: "/plugins/geoip.so",
	}
}

// testConfigFile wraps one plugin module in a config file.
func testConfigFile(module config.PluginModule) *config.FileSettings {
	return &config.FileSettings{
		Plugins: &config.PluginsSection{
			Modules: []config.PluginModule{module},
		},
	}
}

// testDatabasePath resolves a checked-in fixture database path.
func testDatabasePath(t *testing.T, name string) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("resolve test database path: %v", err)
	}

	return path
}

// mustPrefix parses a CIDR prefix and fails the test on invalid input.
func mustPrefix(t *testing.T, value string) netip.Prefix {
	t.Helper()

	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", value, err)
	}

	return prefix.Masked()
}

// mustASNRegistrySnapshot builds a registry snapshot and fails the test on invalid data.
func mustASNRegistrySnapshot(t *testing.T, raw []byte) *asnRegistrySnapshot {
	t.Helper()

	snapshot, err := buildASNRegistrySnapshot([][]byte{raw})
	if err != nil {
		t.Fatalf("buildASNRegistrySnapshot() error = %v", err)
	}

	return snapshot
}

// environmentRequest returns a minimal request snapshot for source evaluation.
func environmentRequest(clientIP string) pluginapi.EnvironmentRequest {
	runtimeContext, _ := pluginruntime.NewRuntimeContext(nil)

	return pluginapi.EnvironmentRequest{
		Snapshot: pluginapi.RequestSnapshot{
			ClientIP: clientIP,
			Protocol: testProtocolIMAP,
			Service:  testProtocolIMAP,
		},
		Runtime: runtimeContext,
	}
}

// assertFact checks one policy fact value by attribute ID.
func assertFact(t *testing.T, facts []pluginapi.PolicyFact, attribute string, want any) {
	t.Helper()

	for _, fact := range facts {
		if fact.Attribute == attribute {
			if fact.Value != want {
				t.Fatalf("fact %s = %#v, want %#v", attribute, fact.Value, want)
			}

			return
		}
	}

	t.Fatalf("fact %s missing in %#v", attribute, facts)
}

// assertLogField checks one public plugin log field by key.
func assertLogField(t *testing.T, fields []pluginapi.LogField, key string, want any) {
	t.Helper()

	for _, field := range fields {
		if field.Key == key {
			if field.Value != want {
				t.Fatalf("log field %s = %#v, want %#v", key, field.Value, want)
			}

			return
		}
	}

	t.Fatalf("log field %s missing in %#v", key, fields)
}

// goCommandEnv returns the environment for nested Go build commands.
func goCommandEnv() []string {
	env := append([]string{}, os.Environ()...)
	env = append(env, "GOEXPERIMENT=runtimesecret")

	if os.Getenv("GOCACHE") == "" {
		env = append(env, "GOCACHE=/tmp/nauthilus-go-cache")
	}

	return env
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

// observationCount counts metric observations by name and result label.
func (m *recordingMetrics) observationCount(name string, result string) int {
	count := 0

	for _, observation := range m.observations {
		if observation.name == name && observation.result == result {
			count++
		}
	}

	return count
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
		if label.Name == metricLabelResult || label.Name == metricLabelState {
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

// sawSpan reports whether a recorded span contains an attribute value.
func (t *recordingTracer) sawSpan(name string, attr string, value any) bool {
	for _, span := range t.spans {
		if span.name == name && span.attrs[attr] == value {
			return true
		}
	}

	return false
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

type fakeASNRegistryFetcher struct {
	data map[string][]byte
}

// Fetch returns configured fixture data for one registry URL.
func (f fakeASNRegistryFetcher) Fetch(_ context.Context, sourceURL string) ([]byte, error) {
	raw, ok := f.data[sourceURL]
	if !ok {
		return nil, errors.New("registry fixture missing")
	}

	return raw, nil
}

type fakeASNRouteFetcher struct {
	data map[string][]byte
}

// Fetch returns configured fixture data for one routing URL.
func (f fakeASNRouteFetcher) Fetch(_ context.Context, sourceURL string) ([]byte, error) {
	raw, ok := f.data[sourceURL]
	if !ok {
		return nil, errors.New("ASN routing fixture missing")
	}

	return raw, nil
}

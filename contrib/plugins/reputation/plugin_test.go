package main

import (
	"context"
	"encoding/json"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"sort"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
)

// testAdmissionMap builds a credential-free host admission snapshot with exact target grants.
func testAdmissionMap() map[string]any {
	return map[string]any{"host_context": map[string]any{"module_name": "reputation"}, "policy_admission": map[string]any{
		"enabled": true, "clients": []any{map[string]any{"principal": "ScanWriter", "targets": []any{"reputation/observe"}, "schemas": []any{"reputation/observe/v1"}, "max_concurrency": 2, "requests_per_second": 10, "diagnostics": false}},
	}}
}

// TestPluginStartCrossChecksExactPrincipalGrant prevents ready state under missing or wider caller authority.
func TestPluginStartCrossChecksExactPrincipalGrant(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{"exact", func(map[string]any) {}, true},
		{"missing", func(v map[string]any) { delete(v, "policy_admission") }, false},
		{"disabled", func(v map[string]any) { v["policy_admission"].(map[string]any)["enabled"] = false }, false},
		{"case mismatch", func(v map[string]any) { admissionClient(v)["principal"] = "scanwriter" }, false},
		{"wrong target", func(v map[string]any) { admissionClient(v)["targets"] = []any{"reputation/read"} }, false},
		{"wrong schema", func(v map[string]any) { admissionClient(v)["schemas"] = []any{"reputation/read/v1"} }, false},
		{"excess rate", func(v map[string]any) { admissionClient(v)["requests_per_second"] = 11 }, false},
		{"excess concurrency", func(v map[string]any) { admissionClient(v)["max_concurrency"] = 3 }, false},
		{"diagnostics", func(v map[string]any) { admissionClient(v)["diagnostics"] = true }, false},
		{"ambiguous", func(v map[string]any) {
			v["policy_admission"].(map[string]any)["clients"] = []any{admissionClient(v), admissionClient(v)}
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := pluginregistry.NewRegistry()
			registrar := registry.NewRegistrar(config.PluginModule{Name: "reputation", Type: config.PluginModuleTypeGo, Path: "/plugins/reputation.so", Config: testConfigMap(t)})
			plugin := NewPlugin()
			requireNoError(t, plugin.Register(registrar))
			requireNoError(t, registrar.Commit())

			if len(registry.DecisionFactProviders()) != 1 || len(registry.DecisionEffectProviders()) != 0 {
				t.Fatal("unexpected provider or premature effect registration")
			}

			raw := testAdmissionMap()
			tt.mutate(raw)

			tagger := manifestTestTagger(t, false)

			options := []pluginruntime.HostOption{pluginruntime.WithConfig(pluginregistry.NewConfigView(raw)), pluginruntime.WithOpaqueIdentifierTagger(tagger)}
			if tt.valid {
				options = append(options, pluginruntime.WithRedis(testStartupRedis(t, plugin.config, tagger)))
			}

			host := pluginruntime.NewHost(options...)

			err := plugin.Start(context.Background(), host)
			if (err == nil) != tt.valid {
				t.Fatalf("start valid=%t want=%t", err == nil, tt.valid)
			}
		})
	}
}

// admissionClient selects only the disposable fixture principal entry.
func admissionClient(raw map[string]any) map[string]any {
	return raw["policy_admission"].(map[string]any)["clients"].([]any)[0].(map[string]any)
}

// TestPluginStartRequiresReputationRedis prevents a fact-only ready state when the durable model owner is unavailable.
func TestPluginStartRequiresReputationRedis(t *testing.T) {
	plugin := NewPlugin()
	plugin.config = testConfig(t)
	host := pluginruntime.NewHost(pluginruntime.WithConfig(pluginregistry.NewConfigView(testAdmissionMap())), pluginruntime.WithOpaqueIdentifierTagger(manifestTestTagger(t, false)))
	requireError(t, plugin.Start(context.Background(), host))
}

// testStartupRedis expects durable model activation and every fenced shard before a successful module start.
func testStartupRedis(t *testing.T, cfg *configuration, tagger pluginapi.OpaqueIdentifierTagger) pluginapi.Redis {
	t.Helper()

	client, mock := redismock.NewClientMock()

	t.Cleanup(func() { requireNoError(t, mock.ExpectationsWereMet()); _ = client.Close() })

	facade := pluginruntime.NewRedisFacade(rediscli.NewTestClient(client))
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)

	sources := reputationScripts()

	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		mock.ExpectScriptLoad(sources[name]).SetVal(name)
	}

	metadata, err := json.Marshal(owner.metadataRequest("activate"))
	requireNoError(t, err)
	mock.ExpectEvalSha(scriptMetadata, owner.keys.metadata(), string(metadata)).SetVal([]any{"active", ""})
	control, err := json.Marshal(controlRequest{Operation: "activate", Schema: manifestSchema, Identity: owner.identity})
	requireNoError(t, err)

	for shard := range manifestShardCount {
		mock.ExpectEvalSha(scriptControl, []string{owner.keys.control(shard)}, string(control)).SetVal([]any{"active"})
	}

	return facade
}

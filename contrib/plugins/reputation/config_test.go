package main

import (
	"os"
	"testing"

	"github.com/croessner/nauthilus/v4/server/pluginregistry"

	"go.yaml.in/yaml/v3"
)

// testConfigMap returns a fresh explicit operator configuration for each negative vector.
func testConfigMap(t *testing.T) map[string]any {
	t.Helper()

	raw := testYAMLMap(t, "../../../server/docs/examples/go_plugin_reputation.yml")

	return raw["plugins"].(map[string]any)["modules"].([]any)[0].(map[string]any)["config"].(map[string]any)
}

// testConfig compiles the bounded fixture without assigning production defaults.
func testConfig(t *testing.T) *configuration {
	t.Helper()
	cfg, err := decodeConfig(pluginregistry.NewConfigView(testConfigMap(t)))
	requireNoError(t, err)

	return cfg
}

// TestConfigAdmissionRejectsMalformedCatalogs preserves explicit source and signal semantics.
func TestConfigAdmissionRejectsMalformedCatalogs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unknown field", func(c map[string]any) { c["secret_key"] = "forbidden" }},
		{"empty catalog", func(c map[string]any) { c["signals"] = map[string]any{} }},
		{"invalid model", func(c map[string]any) { c["model_id"] = "../unsafe" }},
		{"invalid retention", func(c map[string]any) { c["retention"] = "8761h" }},
		{"short manifest", func(c map[string]any) { c["event_manifest_ttl"] = "24h" }},
		{"missing limits", func(c map[string]any) {
			delete(c["sources"].(map[string]any)["scan"].(map[string]any), "requests_per_second")
		}},
		{"unknown kind", func(c map[string]any) {
			c["sources"].(map[string]any)["scan"].(map[string]any)["allowed_subjects"] = map[string]any{"smtp_peer": []any{"country"}}
		}},
		{"wrong origin", func(c map[string]any) {
			c["signals"].(map[string]any)["scan.clean"].(map[string]any)["evidence_origin"] = "host_backend_outcome"
		}},
		{"caller internal fields", func(c map[string]any) {
			c["sources"].(map[string]any)["scan"].(map[string]any)["binding"].(map[string]any)["module"] = "reputation"
		}},
		{"duplicate signal reference", func(c map[string]any) {
			c["sources"].(map[string]any)["scan"].(map[string]any)["allowed_signals"] = []any{"scan.clean", "scan.clean"}
		}},
		{"direct ASN nonauthority", func(c map[string]any) {
			c["sources"].(map[string]any)["scan"].(map[string]any)["allowed_subjects"] = map[string]any{"smtp_peer": []any{"asn"}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := testConfigMap(t)
			tt.mutate(raw)
			_, err := decodeConfig(pluginregistry.NewConfigView(raw))
			requireError(t, err)
		})
	}

	_ = testConfig(t)
}

// TestSourceIdentityUniqueness prevents aliases from bypassing source-scoped idempotency and limits.
func TestSourceIdentityUniqueness(t *testing.T) {
	for _, field := range []string{"source_policy_id", "caller_principal"} {
		t.Run(field, func(t *testing.T) {
			raw := testConfigMap(t)

			other := testConfigMap(t)["sources"].(map[string]any)["scan"].(map[string]any)
			if field == "source_policy_id" {
				other["binding"].(map[string]any)["caller_principal"] = "OtherWriter"
			} else {
				other["source_policy_id"] = "other-id"
			}

			raw["sources"].(map[string]any)["other"] = other
			_, err := decodeConfig(pluginregistry.NewConfigView(raw))
			requireError(t, err)
		})
	}
}

// requireNoError reports a failed positive contract case.
func requireNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

// requireError reports a negative contract case that was unexpectedly admitted.
func requireError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("expected rejection")
	}
}

// internalConfigMap configures one exact backend-outcome source without an external principal.
func internalConfigMap(t *testing.T) map[string]any {
	t.Helper()
	raw := testConfigMap(t)
	source := raw["sources"].(map[string]any)["scan"].(map[string]any)
	source["binding"] = map[string]any{"kind": "host_execution", "module": "reputation", "component": "learn_outcome", "extension_point": "post_action", "operation": "enqueue", "targets": []any{"authn/authenticate"}}
	raw["signals"].(map[string]any)["scan.clean"].(map[string]any)["evidence_origin"] = "host_backend_outcome"

	return raw
}

// TestSourceInternalIdentityRequiresExactRegistration verifies internal tuple isolation and startup rejection.
func TestSourceInternalIdentityRequiresExactRegistration(t *testing.T) {
	raw := internalConfigMap(t)
	cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)

	var key executionKey
	for identity := range cfg.internalSources {
		key = identity
	}

	view := pluginregistry.NewConfigView(map[string]any{"host_context": map[string]any{"module_name": "reputation"}})
	requireError(t, cfg.validateStartup(view, nil))
	requireNoError(t, cfg.validateStartup(view, map[executionKey]struct{}{key: {}}))
	wrong := key
	wrong.target.Action = "authorize"
	requireError(t, cfg.validateStartup(view, map[executionKey]struct{}{wrong: {}}))
	requireError(t, cfg.validateStartup(pluginregistry.NewConfigView(map[string]any{"host_context": map[string]any{"module_name": "other"}}), map[executionKey]struct{}{key: {}}))

	for _, change := range []string{"principal", "overlap", "operation"} {
		t.Run(change, func(t *testing.T) {
			raw := internalConfigMap(t)
			source := raw["sources"].(map[string]any)["scan"].(map[string]any)

			switch change {
			case "principal":
				source["binding"].(map[string]any)["caller_principal"] = "ScanWriter"
			case "operation":
				source["binding"].(map[string]any)["operation"] = ""
			case "overlap":
				other := internalConfigMap(t)["sources"].(map[string]any)["scan"].(map[string]any)
				other["source_policy_id"] = "other-id"
				raw["sources"].(map[string]any)["other"] = other
			}

			_, err := decodeConfig(pluginregistry.NewConfigView(raw))
			requireError(t, err)
		})
	}
}

// TestSourceDirectASNRequiresAuthoritativeExternalFeed rejects inferred authority from an internal callback.
func TestSourceDirectASNRequiresAuthoritativeExternalFeed(t *testing.T) {
	raw := internalConfigMap(t)
	source := raw["sources"].(map[string]any)["scan"].(map[string]any)
	source["allowed_subjects"] = map[string]any{"smtp_peer": []any{"asn"}}
	source["derived_subjects"] = map[string]any{}
	raw["signals"].(map[string]any)["scan.clean"].(map[string]any)["subject_roles"] = map[string]any{"smtp_peer": map[string]any{"asn": 0.1}}
	_, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireError(t, err)
}

// TestConfigStateCardinalityRequiresExplicitBounds prevents admitted producers from allocating unbounded history.
func TestConfigStateCardinalityRequiresExplicitBounds(t *testing.T) {
	for _, field := range []string{"maximum_event_manifests_per_source", "maximum_seen_events_per_subject"} {
		t.Run(field, func(t *testing.T) {
			raw := testConfigMap(t)
			delete(raw, field)
			_, err := decodeConfig(pluginregistry.NewConfigView(raw))
			requireError(t, err)
		})
	}
}

// TestConfigSeenRetentionCoversManifestRetries prevents a valid manifest from outliving its deduplication contract.
func TestConfigSeenRetentionCoversManifestRetries(t *testing.T) {
	raw := testConfigMap(t)
	raw["subject_seen_ttl"] = "48h30m"
	_, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireError(t, err)
}

// testYAMLMap reads shared operator examples as the authoritative test catalog.
func testYAMLMap(t *testing.T, path string) map[string]any {
	t.Helper()

	content, err := os.ReadFile(path)
	requireNoError(t, err)

	var raw map[string]any
	requireNoError(t, yaml.Unmarshal(content, &raw))

	return raw
}

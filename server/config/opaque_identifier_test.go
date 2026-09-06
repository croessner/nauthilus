package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpaqueIdentifierConfigCapturesTypedSecretReferences keeps key bytes outside configuration dumps.
func TestOpaqueIdentifierConfigCapturesTypedSecretReferences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opaque-key")

	material := strings.Repeat("k", 32)
	if err := os.WriteFile(path, []byte(material), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadPluginTestConfig(t, map[string]any{
		"opaque_identifier_tagger": map[string]any{"scopes": []map[string]any{{
			"scope": "workflow", "active": map[string]any{"version": "current", "secret_ref": map[string]any{"file": path}},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.GetPlugins().OpaqueIdentifierTagger == nil {
		t.Fatal("tagger configuration was omitted")
	}

	dump, err := cfg.GetConfigFileAsJSON()
	if err != nil || strings.Contains(string(dump), material) {
		t.Fatal("key material appeared in configuration dump")
	}

	snapshot, err := ArtifactSnapshotFor(cfg)
	if err != nil {
		t.Fatal(err)
	}

	content, err := snapshot.ReadFile(path)
	if err != nil || len(content) != 32 {
		t.Fatal("typed secret reference was not sealed")
	}

	clear(content)
}

// TestOpaqueIdentifierConfigRejectsInvalidReferences fails closed on missing or ambiguous rotation declarations.
func TestOpaqueIdentifierConfigRejectsInvalidReferences(t *testing.T) {
	for _, test := range []struct{ name, scope, version, path string }{
		{"empty scope", "", "current", "/run/secret"},
		{"empty version", "workflow", "", "/run/secret"},
		{"relative path", "workflow", "current", "secret"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &OpaqueIdentifierTaggerConfig{Scopes: []OpaqueIdentifierScopeConfig{{Scope: test.scope, Active: OpaqueIdentifierKeyReference{Version: test.version, SecretRef: SecretFileReference{File: test.path}}}}}
			if err := ValidateOpaqueIdentifierTaggerConfig(cfg); err == nil {
				t.Fatal("invalid typed key reference accepted")
			}
		})
	}
}

// TestOpaqueIdentifierConfigRejectsRawKeys requires mounted references instead of inline key material.
func TestOpaqueIdentifierConfigRejectsRawKeys(t *testing.T) {
	_, err := loadPluginTestConfig(t, map[string]any{
		"opaque_identifier_tagger": map[string]any{"scopes": []map[string]any{{
			"scope": "workflow", "active": map[string]any{"version": "current", "secret_ref": map[string]any{"value": "forbidden-inline-key"}},
		}}},
	})
	if err == nil || strings.Contains(err.Error(), "forbidden-inline-key") {
		t.Fatal("inline key was accepted or exposed")
	}
}

// TestOpaqueIdentifierConfigRejectsInvalidKeyMaterial validates mounted keys before runtime startup.
func TestOpaqueIdentifierConfigRejectsInvalidKeyMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short-key")
	if err := os.WriteFile(path, []byte("short-key-material"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := loadPluginTestConfig(t, map[string]any{
		"opaque_identifier_tagger": map[string]any{"scopes": []map[string]any{{
			"scope": "workflow", "active": map[string]any{"version": "current", "secret_ref": map[string]any{"file": path}},
		}}},
	})
	if err == nil || strings.Contains(err.Error(), "short-key-material") {
		t.Fatal("invalid mounted key was accepted or exposed")
	}
}

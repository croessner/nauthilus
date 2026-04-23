package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestConfigLoader_LoadFromFile_MergesIncludesAndPatches(t *testing.T) {
	root := t.TempDir()

	writeConfigFile(t, root, "base.yaml", `auth:
  backends:
    ldap:
      default:
        lookup_pool_size: 5
`)

	writeConfigFile(t, root, "dev.yaml", `patch:
  - op: add
    path: auth.backends.ldap.search
    value:
      protocol: imap
      cache_name: imap
`)

	mainPath := writeConfigFile(t, root, "main.yaml", `env: dev
includes:
  required:
    - base.yaml
  env:
    dev:
      optional:
        - dev.yaml
auth:
  backends:
    ldap:
      default:
        lookup_pool_size: 10
`)

	loader := NewConfigLoader("yaml")

	settings, err := loader.LoadFromFile(mainPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	auth, ok := settings["auth"].(map[string]any)
	if !ok {
		t.Fatalf("expected auth map, got %T", settings["auth"])
	}

	backends, ok := auth["backends"].(map[string]any)
	if !ok {
		t.Fatalf("expected auth.backends map, got %T", auth["backends"])
	}

	ldap, ok := backends["ldap"].(map[string]any)
	if !ok {
		t.Fatalf("expected auth.backends.ldap map, got %T", backends["ldap"])
	}

	defaultConfig, ok := ldap["default"].(map[string]any)
	if !ok {
		t.Fatalf("expected auth.backends.ldap.default map, got %T", ldap["default"])
	}

	if got := requireInt(t, defaultConfig["lookup_pool_size"]); got != 10 {
		t.Fatalf("expected lookup_pool_size 10, got %d", got)
	}

	search, ok := ldap["search"].([]any)
	if !ok {
		t.Fatalf("expected ldap.search slice, got %T", ldap["search"])
	}

	if len(search) != 1 {
		t.Fatalf("expected 1 ldap.search entry, got %d", len(search))
	}

	entry, ok := search[0].(map[string]any)
	if !ok {
		t.Fatalf("expected ldap.search entry map, got %T", search[0])
	}

	if entry["protocol"] != "imap" {
		t.Fatalf("expected protocol imap, got %v", entry["protocol"])
	}

	if _, ok := settings[includeKey]; ok {
		t.Fatal("includes should be stripped from merged settings")
	}

	if _, ok := settings[patchKey]; ok {
		t.Fatal("patch should be stripped from merged settings")
	}

	if _, ok := settings[envKey]; ok {
		t.Fatal("env should be stripped from merged settings")
	}
}

func TestConfigLoader_LoadFromFile_OptionalMissing(t *testing.T) {
	root := t.TempDir()

	mainPath := writeConfigFile(t, root, "main.yaml", `includes:
  optional:
    - missing.yaml
runtime:
  instance_name: optional
`)

	loader := NewConfigLoader("yaml")

	settings, err := loader.LoadFromFile(mainPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if _, ok := settings["runtime"]; !ok {
		t.Fatal("expected runtime settings in merged config")
	}
}

func TestConfigLoader_LoadFromFile_EnvFromViper(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setDefaultEnvVars()

	t.Setenv("NAUTHILUS_ENV", "dev")

	root := t.TempDir()

	writeConfigFile(t, root, "dev.yaml", `runtime:
  instance_name: from-env
`)

	mainPath := writeConfigFile(t, root, "main.yaml", `includes:
  env:
    dev:
      optional:
        - dev.yaml
`)

	loader := NewConfigLoader("yaml")

	settings, err := loader.LoadFromFile(mainPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	runtimeSettings, ok := settings["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("expected runtime map, got %T", settings["runtime"])
	}

	if runtimeSettings["instance_name"] != "from-env" {
		t.Fatalf("expected instance_name from-env, got %v", runtimeSettings["instance_name"])
	}
}

func TestConfigLoader_LoadFromFile_RequiredMissing(t *testing.T) {
	root := t.TempDir()

	mainPath := writeConfigFile(t, root, "main.yaml", `includes:
  required:
    - missing.yaml
runtime:
  instance_name: required
`)

	loader := NewConfigLoader("yaml")

	if _, err := loader.LoadFromFile(mainPath); err == nil {
		t.Fatal("expected error for missing required include")
	}
}

func TestConfigLoader_LoadFromFile_IncludeSupportsRootExtensionsWithAnchors(t *testing.T) {
	root := t.TempDir()

	writeConfigFile(t, root, "aliases.yaml", `x-claim-email: &x-claim-email
  claim: "email"
  attribute: "mail;x-hidden"
  type: "string"
x-oc-mappings:
  mappings:
    - *x-claim-email
`)

	mainPath := writeConfigFile(t, root, "main.yaml", `includes:
  required:
    - aliases.yaml
runtime:
  instance_name: include-anchors
`)

	loader := NewConfigLoader("yaml")

	settings, err := loader.LoadFromFile(mainPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	claimEmail, ok := settings["x-claim-email"].(map[string]any)
	if !ok {
		t.Fatalf("expected x-claim-email map, got %T", settings["x-claim-email"])
	}

	if claimEmail["claim"] != "email" {
		t.Fatalf("expected x-claim-email.claim email, got %v", claimEmail["claim"])
	}

	mappingsRoot, ok := settings["x-oc-mappings"].(map[string]any)
	if !ok {
		t.Fatalf("expected x-oc-mappings map, got %T", settings["x-oc-mappings"])
	}

	mappings, ok := mappingsRoot["mappings"].([]any)
	if !ok {
		t.Fatalf("expected x-oc-mappings.mappings slice, got %T", mappingsRoot["mappings"])
	}

	if len(mappings) != 1 {
		t.Fatalf("expected one mapping entry, got %d", len(mappings))
	}

	firstMapping, ok := mappings[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first mapping as map, got %T", mappings[0])
	}

	if firstMapping["claim"] != "email" {
		t.Fatalf("expected first mapping claim email, got %v", firstMapping["claim"])
	}
}

func writeConfigFile(t *testing.T, root string, name string, content string) string {
	t.Helper()

	path := filepath.Join(root, name)

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config %s: %v", name, err)
	}

	return path
}

func requireInt(t *testing.T, value any) int {
	t.Helper()

	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		t.Fatalf("expected numeric value, got %T", value)
	}

	return 0
}

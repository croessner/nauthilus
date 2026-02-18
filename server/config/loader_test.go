package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestConfigLoader_LoadFromFile_MergesIncludesAndPatches(t *testing.T) {
	root := t.TempDir()

	writeConfigFile(t, root, "base.yaml", `ldap:
  config:
    lookup_pool_size: 5
`)

	writeConfigFile(t, root, "dev.yaml", `patch:
  - op: add
    path: ldap.search
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
ldap:
  config:
    lookup_pool_size: 10
`)

	loader := NewConfigLoader("yaml")

	settings, err := loader.LoadFromFile(mainPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	ldap, ok := settings["ldap"].(map[string]any)
	if !ok {
		t.Fatalf("expected ldap map, got %T", settings["ldap"])
	}

	config, ok := ldap["config"].(map[string]any)
	if !ok {
		t.Fatalf("expected ldap.config map, got %T", ldap["config"])
	}

	if got := requireInt(t, config["lookup_pool_size"]); got != 10 {
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
server:
  instance_name: optional
`)

	loader := NewConfigLoader("yaml")

	settings, err := loader.LoadFromFile(mainPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if _, ok := settings["server"]; !ok {
		t.Fatal("expected server settings in merged config")
	}
}

func TestConfigLoader_LoadFromFile_EnvFromViper(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setDefaultEnvVars()

	t.Setenv("NAUTHILUS_ENV", "dev")

	root := t.TempDir()

	writeConfigFile(t, root, "dev.yaml", `server:
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

	server, ok := settings["server"].(map[string]any)
	if !ok {
		t.Fatalf("expected server map, got %T", settings["server"])
	}

	if server["instance_name"] != "from-env" {
		t.Fatalf("expected instance_name from-env, got %v", server["instance_name"])
	}
}

func TestConfigLoader_LoadFromFile_RequiredMissing(t *testing.T) {
	root := t.TempDir()

	mainPath := writeConfigFile(t, root, "main.yaml", `includes:
  required:
    - missing.yaml
server:
  instance_name: required
`)

	loader := NewConfigLoader("yaml")

	if _, err := loader.LoadFromFile(mainPath); err == nil {
		t.Fatal("expected error for missing required include")
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

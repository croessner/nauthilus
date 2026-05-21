package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

const (
	envExpansionRuntimeKey             = "runtime"
	envExpansionConfigPathKey          = "config_path"
	envExpansionPluginPathKey          = "plugin_path"
	envExpansionSecretValueKey         = "secret_value"
	envExpansionLiteralKey             = "literal"
	envExpansionNestedCaseName         = "nested"
	envExpansionBuiltinConfigPath      = "${NAUTHILUS_CONF_DIR}/nauthilus.yml"
	envExpansionBuiltinPluginPath      = "${NAUTHILUS_PLUGINS_DIR}/environment/login_context.lua"
	envExpansionDecodedRedisAddress    = "redis.example.test:6379"
	envExpansionOverrideRedisAddress   = "override.example.test:6379"
	envExpansionPositiveCacheTTL       = 30 * time.Second
	envExpansionPositiveCacheTTLString = "30s"
	envExpansionInvalidSyntaxError     = "invalid environment placeholder syntax"
	envExpansionOrdinaryDollarLiteral  = "cost is $5"
)

func TestConfigLoader_LoadFromFile_ExpandsEnvValuesAfterMerge(t *testing.T) {
	t.Setenv("CONFIG_ENV_ROOT_VALUE", "root-expanded")
	t.Setenv("CONFIG_ENV_INCLUDE_VALUE", "include-expanded")
	t.Setenv("CONFIG_ENV_PATCH_VALUE", "patch-expanded")

	root := t.TempDir()

	writeConfigFile(t, root, "include.yaml", `runtime:
  include_value: "include-${CONFIG_ENV_INCLUDE_VALUE}"
  nested_values:
    - "slice-${CONFIG_ENV_INCLUDE_VALUE}"
`)

	mainPath := writeConfigFile(t, root, "main.yaml", `includes:
  required:
    - include.yaml
patch:
  - op: replace
    path: runtime.patch_value
    value: "patched-${CONFIG_ENV_PATCH_VALUE}"
runtime:
  root_value: "root-${CONFIG_ENV_ROOT_VALUE}"
`)

	settings, err := NewConfigLoader(string(DumpFormatYAML)).LoadFromFile(mainPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	runtimeSettings := requireMapValue(t, settings, envExpansionRuntimeKey)
	if got := runtimeSettings["root_value"]; got != "root-root-expanded" {
		t.Fatalf("root value = %v, want root-root-expanded", got)
	}

	if got := runtimeSettings["include_value"]; got != "include-include-expanded" {
		t.Fatalf("include value = %v, want include-include-expanded", got)
	}

	if got := runtimeSettings["patch_value"]; got != "patched-patch-expanded" {
		t.Fatalf("patch value = %v, want patched-patch-expanded", got)
	}

	nestedValues, ok := runtimeSettings["nested_values"].([]any)
	if !ok {
		t.Fatalf("nested_values = %T, want []any", runtimeSettings["nested_values"])
	}

	if len(nestedValues) != 1 || nestedValues[0] != "slice-include-expanded" {
		t.Fatalf("nested_values = %v, want [slice-include-expanded]", nestedValues)
	}
}

func TestConfigLoader_LoadFromFile_KeepsEnvMapKeysLiteral(t *testing.T) {
	t.Setenv("CONFIG_ENV_DYNAMIC_KEY", "expanded_key")
	t.Setenv("CONFIG_ENV_DYNAMIC_VALUE", "expanded_value")

	settings := map[string]any{
		envExpansionRuntimeKey: map[string]any{
			"${CONFIG_ENV_DYNAMIC_KEY}": "${CONFIG_ENV_DYNAMIC_VALUE}",
		},
	}

	expanded, err := NewConfigLoader(string(DumpFormatYAML)).Load("inline.yaml", settings)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	runtimeSettings := requireMapValue(t, expanded, envExpansionRuntimeKey)
	if _, ok := runtimeSettings["expanded_key"]; ok {
		t.Fatal("map key was expanded")
	}

	if got := runtimeSettings["${CONFIG_ENV_DYNAMIC_KEY}"]; got != "expanded_value" {
		t.Fatalf("literal key value = %v, want expanded_value", got)
	}
}

func TestConfigLoader_LoadFromFile_ReportsMissingEnvWithPath(t *testing.T) {
	t.Setenv("CONFIG_ENV_PRESENT_SECRET", "do-not-leak-expanded-secret")

	settings := map[string]any{
		envExpansionRuntimeKey: map[string]any{
			envExpansionSecretValueKey: "prefix-${CONFIG_ENV_PRESENT_SECRET}-${CONFIG_ENV_MISSING_SECRET}",
		},
	}

	_, err := NewConfigLoader(string(DumpFormatYAML)).Load("inline.yaml", settings)
	if err == nil {
		t.Fatal("load config error = nil, want missing environment variable error")
	}

	errText := err.Error()
	if !strings.Contains(errText, "runtime.secret_value") {
		t.Fatalf("error = %q, want path runtime.secret_value", errText)
	}

	if !strings.Contains(errText, "CONFIG_ENV_MISSING_SECRET") {
		t.Fatalf("error = %q, want missing variable name", errText)
	}

	if strings.Contains(errText, "do-not-leak-expanded-secret") || strings.Contains(errText, "prefix-") {
		t.Fatalf("error leaked expanded or raw config value: %q", errText)
	}
}

func TestConfigLoader_LoadFromFile_ReportsInvalidEnvSyntaxWithPath(t *testing.T) {
	t.Setenv("CONFIG_ENV_PRESENT_SECRET", "do-not-leak-expanded-secret")
	t.Setenv("SOMETHING_EMBEDDED", "expanded")

	testCases := []struct {
		name  string
		value string
	}{
		{
			name:  envExpansionNestedCaseName,
			value: "prefix-${SOME_VAR_${SOMETHING_EMBEDDED}}",
		},
		{
			name:  "dash",
			value: "prefix-${BAD-NAME}",
		},
		{
			name:  "empty",
			value: "prefix-${}",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			settings := map[string]any{
				envExpansionRuntimeKey: map[string]any{
					envExpansionSecretValueKey: testCase.value,
				},
			}

			_, err := NewConfigLoader(string(DumpFormatYAML)).Load("inline.yaml", settings)
			if err == nil {
				t.Fatal("load config error = nil, want invalid environment placeholder syntax error")
			}

			errText := err.Error()
			if !strings.Contains(errText, "runtime.secret_value") {
				t.Fatalf("error = %q, want path runtime.secret_value", errText)
			}

			if !strings.Contains(errText, envExpansionInvalidSyntaxError) {
				t.Fatalf("error = %q, want invalid syntax marker", errText)
			}

			if strings.Contains(errText, "do-not-leak-expanded-secret") ||
				strings.Contains(errText, testCase.value) ||
				strings.Contains(errText, "prefix-") {
				t.Fatalf("error leaked config value: %q", errText)
			}
		})
	}
}

func TestConfigLoader_LoadFromFile_EnvExpansionKeepsOrdinaryDollarLiteral(t *testing.T) {
	settings := map[string]any{
		envExpansionRuntimeKey: map[string]any{
			envExpansionLiteralKey: envExpansionOrdinaryDollarLiteral,
		},
	}

	expanded, err := NewConfigLoader(string(DumpFormatYAML)).Load("inline.yaml", settings)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	runtimeSettings := requireMapValue(t, expanded, envExpansionRuntimeKey)
	if got := runtimeSettings[envExpansionLiteralKey]; got != envExpansionOrdinaryDollarLiteral {
		t.Fatalf("literal = %v, want %s", got, envExpansionOrdinaryDollarLiteral)
	}
}

func TestConfigLoader_LoadFromFile_ExpandsBuiltinEnvDefaults(t *testing.T) {
	unsetEnvForTest(t, "NAUTHILUS_CONF_DIR")
	unsetEnvForTest(t, "NAUTHILUS_PLUGINS_DIR")

	settings := map[string]any{
		envExpansionRuntimeKey: map[string]any{
			envExpansionConfigPathKey: envExpansionBuiltinConfigPath,
			envExpansionPluginPathKey: envExpansionBuiltinPluginPath,
		},
	}

	expanded, err := NewConfigLoader(string(DumpFormatYAML)).Load("inline.yaml", settings)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	runtimeSettings := requireMapValue(t, expanded, envExpansionRuntimeKey)
	if got := runtimeSettings[envExpansionConfigPathKey]; got != "/etc/nauthilus/nauthilus.yml" {
		t.Fatalf("config_path = %v, want /etc/nauthilus/nauthilus.yml", got)
	}

	wantPluginPath := "/usr/local/share/nauthilus/lua-plugins.d/environment/login_context.lua"
	if got := runtimeSettings[envExpansionPluginPathKey]; got != wantPluginPath {
		t.Fatalf("plugin_path = %v, want %s", got, wantPluginPath)
	}
}

func TestConfigLoader_LoadFromFile_EnvOverridesBuiltinDefaults(t *testing.T) {
	t.Setenv("NAUTHILUS_CONF_DIR", "/srv/nauthilus")
	t.Setenv("NAUTHILUS_PLUGINS_DIR", "/opt/nauthilus/plugins")

	settings := map[string]any{
		envExpansionRuntimeKey: map[string]any{
			envExpansionConfigPathKey: envExpansionBuiltinConfigPath,
			envExpansionPluginPathKey: envExpansionBuiltinPluginPath,
		},
	}

	expanded, err := NewConfigLoader(string(DumpFormatYAML)).Load("inline.yaml", settings)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	runtimeSettings := requireMapValue(t, expanded, envExpansionRuntimeKey)
	if got := runtimeSettings[envExpansionConfigPathKey]; got != "/srv/nauthilus/nauthilus.yml" {
		t.Fatalf("config_path = %v, want /srv/nauthilus/nauthilus.yml", got)
	}

	wantPluginPath := "/opt/nauthilus/plugins/environment/login_context.lua"
	if got := runtimeSettings[envExpansionPluginPathKey]; got != wantPluginPath {
		t.Fatalf("plugin_path = %v, want %s", got, wantPluginPath)
	}
}

func TestConfigLoader_LoadFromFile_EscapedEnvPlaceholderRemainsLiteral(t *testing.T) {
	t.Setenv("CONFIG_ENV_LITERAL", "expanded")

	settings := map[string]any{
		envExpansionRuntimeKey: map[string]any{
			"literal": "literal-$${CONFIG_ENV_LITERAL}",
		},
	}

	expanded, err := NewConfigLoader(string(DumpFormatYAML)).Load("inline.yaml", settings)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	runtimeSettings := requireMapValue(t, expanded, envExpansionRuntimeKey)
	if got := runtimeSettings["literal"]; got != "literal-${CONFIG_ENV_LITERAL}" {
		t.Fatalf("literal = %v, want literal-${CONFIG_ENV_LITERAL}", got)
	}
}

func TestFileSettings_HandleFile_DecodesTypedEnvExpansion(t *testing.T) {
	t.Setenv("CONFIG_ENV_REDIS_ADDRESS", envExpansionDecodedRedisAddress)
	t.Setenv("CONFIG_ENV_POSITIVE_CACHE_TTL", envExpansionPositiveCacheTTLString)

	cfg := loadFileSettingsFromContent(t, `storage:
  redis:
    primary:
      address: ${CONFIG_ENV_REDIS_ADDRESS}
    password_nonce: nonce-secret-1234
    encryption_secret: redis-secret-1234
    positive_cache_ttl: ${CONFIG_ENV_POSITIVE_CACHE_TTL}
`)

	if got := cfg.GetServer().GetRedis().GetStandaloneMaster().GetAddress(); got != envExpansionDecodedRedisAddress {
		t.Fatalf("redis primary address = %q, want %s", got, envExpansionDecodedRedisAddress)
	}

	if got := cfg.GetServer().GetRedis().GetPosCacheTTL(); got != envExpansionPositiveCacheTTL {
		t.Fatalf("positive cache ttl = %s, want 30s", got)
	}
}

func TestFileSettings_HandleFile_NauthilusEnvOverrideWinsAfterExpansion(t *testing.T) {
	t.Setenv("CONFIG_ENV_REDIS_ADDRESS", "file.example.test:6379")
	t.Setenv("NAUTHILUS_STORAGE_REDIS_PRIMARY_ADDRESS", envExpansionOverrideRedisAddress)

	cfg := loadFileSettingsFromContent(t, `storage:
  redis:
    primary:
      address: ${CONFIG_ENV_REDIS_ADDRESS}
    password_nonce: nonce-secret-1234
    encryption_secret: redis-secret-1234
`)

	if got := cfg.GetServer().GetRedis().GetStandaloneMaster().GetAddress(); got != envExpansionOverrideRedisAddress {
		t.Fatalf("redis primary address = %q, want %s", got, envExpansionOverrideRedisAddress)
	}
}

func loadFileSettingsFromContent(t *testing.T, content string) *FileSettings {
	t.Helper()

	root := t.TempDir()
	path := writeConfigFile(t, root, "nauthilus.yml", content)

	viper.Reset()
	t.Cleanup(viper.Reset)

	previousPath := ConfigFilePath
	previousType := ConfigFileType
	ConfigFilePath = path
	ConfigFileType = string(DumpFormatYAML)

	t.Cleanup(func() {
		ConfigFilePath = previousPath
		ConfigFileType = previousType

		SetTestFile(nil)
	})

	setDefaultEnvVars()

	mergedSettings, rootPath, err := loadMergedConfigSettings(ConfigFileType)
	if err != nil {
		t.Fatalf("load merged config: %v", err)
	}

	if err := applyMergedConfigSettings(mergedSettings, ConfigFileType, rootPath); err != nil {
		t.Fatalf("apply merged config: %v", err)
	}

	if err := bindEnvs(&FileSettings{}); err != nil {
		t.Fatalf("bind envs: %v", err)
	}

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("handle file: %v", err)
	}

	return cfg
}

func requireMapValue(t *testing.T, settings map[string]any, key string) map[string]any {
	t.Helper()

	value, ok := settings[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %T, want map[string]any", key, settings[key])
	}

	return value
}

func unsetEnvForTest(t *testing.T, name string) {
	t.Helper()

	value, ok := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("unset %s: %v", name, err)
	}

	t.Cleanup(func() {
		if ok {
			if err := os.Setenv(name, value); err != nil {
				t.Fatalf("restore %s: %v", name, err)
			}

			return
		}

		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("restore unset %s: %v", name, err)
		}
	})
}

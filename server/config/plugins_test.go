package config

import (
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/spf13/viper"
)

const (
	pluginConfigKeyAllowCapabilities  = "allow_capabilities"
	pluginConfigKeyAllowedDirs        = "allowed_dirs"
	pluginConfigKeyAPIKey             = "api_key"
	pluginConfigKeyConfig             = "config"
	pluginConfigKeyModules            = "modules"
	pluginConfigKeyName               = "name"
	pluginConfigKeyNested             = "nested"
	pluginConfigKeyPath               = "path"
	pluginConfigKeySignature          = "signature"
	pluginConfigKeySigner             = "signer"
	pluginConfigKeySigners            = "signers"
	pluginConfigKeyTrust              = "trust"
	pluginConfigKeyType               = "type"
	pluginConfigKeyVerificationPolicy = "verification_policy"
	pluginConfigModuleName            = "geoip"
	pluginConfigOpaqueValue           = "opaque-to-host"
	pluginConfigSignerID              = "build_key"
)

func TestPluginConfig_ValidMinimalModuleDefaultsTypeAndPreservesOpaqueConfig(t *testing.T) {
	pluginDir := t.TempDir()
	modulePath := pluginConfigArtifactPath(pluginDir)

	cfg, err := loadPluginTestConfig(t, map[string]any{
		pluginConfigKeyAllowedDirs: []string{pluginDir},
		pluginConfigKeyModules: []map[string]any{
			{
				pluginConfigKeyName: pluginConfigModuleName,
				pluginConfigKeyPath: modulePath,
				pluginConfigKeyConfig: map[string]any{
					"database_path":   "/var/lib/GeoIP/GeoLite2-City.mmdb",
					"reload_interval": "1h",
					pluginConfigKeyNested: map[string]any{
						pluginConfigKeyAPIKey: pluginConfigOpaqueValue,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("HandleFile() error = %v", err)
	}

	plugins := cfg.GetPlugins()
	if plugins == nil || len(plugins.Modules) != 1 {
		t.Fatalf("expected one plugin module, got %#v", plugins)
	}

	module := plugins.Modules[0]
	if module.Type != PluginModuleTypeGo {
		t.Fatalf("expected default module type %q, got %q", PluginModuleTypeGo, module.Type)
	}

	nested, ok := module.Config[pluginConfigKeyNested].(map[string]any)
	if !ok {
		t.Fatalf("expected opaque nested config map, got %T", module.Config[pluginConfigKeyNested])
	}

	if nested[pluginConfigKeyAPIKey] != pluginConfigOpaqueValue {
		t.Fatalf("expected opaque config to survive loading, got %#v", nested)
	}
}

func TestPluginConfig_RejectsInvalidModuleName(t *testing.T) {
	pluginDir := t.TempDir()

	err := loadPluginTestConfigError(t, map[string]any{
		pluginConfigKeyAllowedDirs: []string{pluginDir},
		pluginConfigKeyModules: []map[string]any{
			{
				pluginConfigKeyName: "GeoIP",
				pluginConfigKeyPath: pluginConfigArtifactPath(pluginDir),
			},
		},
	})

	assertPluginConfigError(t, err, "plugins.modules[0].name")
}

func TestPluginConfig_RejectsUnsupportedModuleType(t *testing.T) {
	pluginDir := t.TempDir()

	err := loadPluginTestConfigError(t, map[string]any{
		pluginConfigKeyAllowedDirs: []string{pluginDir},
		pluginConfigKeyModules: []map[string]any{
			{
				pluginConfigKeyName: pluginConfigModuleName,
				pluginConfigKeyType: "rust",
				pluginConfigKeyPath: pluginConfigArtifactPath(pluginDir),
			},
		},
	})

	assertPluginConfigError(t, err, "plugins.modules[0].type")
}

func TestPluginConfig_RejectsRelativeModulePath(t *testing.T) {
	err := loadPluginTestConfigError(t, map[string]any{
		pluginConfigKeyAllowedDirs: []string{t.TempDir()},
		pluginConfigKeyModules: []map[string]any{
			{
				pluginConfigKeyName: pluginConfigModuleName,
				pluginConfigKeyPath: "geoip.so",
			},
		},
	})

	assertPluginConfigError(t, err, "plugins.modules[0].path")
}

func TestPluginConfig_RejectsArtifactOutsideAllowedDirs(t *testing.T) {
	pluginDir := t.TempDir()
	otherDir := t.TempDir()

	err := loadPluginTestConfigError(t, map[string]any{
		pluginConfigKeyAllowedDirs: []string{pluginDir},
		pluginConfigKeyModules: []map[string]any{
			{
				pluginConfigKeyName: pluginConfigModuleName,
				pluginConfigKeyPath: pluginConfigArtifactPath(otherDir),
			},
		},
	})

	assertPluginConfigError(t, err, "plugins.modules[0].path")
}

func TestPluginConfig_RejectsMissingSignerReference(t *testing.T) {
	pluginDir := t.TempDir()

	err := loadPluginTestConfigError(t, map[string]any{
		pluginConfigKeyAllowedDirs: []string{pluginDir},
		pluginConfigKeyModules: []map[string]any{
			{
				pluginConfigKeyName:      pluginConfigModuleName,
				pluginConfigKeyPath:      pluginConfigArtifactPath(pluginDir),
				pluginConfigKeySignature: "minisign:" + pluginDir + "/geoip.so.minisig",
			},
		},
	})

	assertPluginConfigError(t, err, "plugins.modules[0].signer")
}

func TestPluginConfig_RejectsSignerWithInlineKeyAndKeyFile(t *testing.T) {
	pluginDir := t.TempDir()

	err := loadPluginTestConfigError(t, map[string]any{
		pluginConfigKeyAllowedDirs: []string{pluginDir},
		pluginConfigKeyTrust: map[string]any{
			pluginConfigKeySigners: []map[string]any{
				{
					"id":              pluginConfigSignerID,
					"format":          "minisign",
					"public_key":      "RWQ...",
					"public_key_file": pluginDir + "/build.pub",
				},
			},
		},
		pluginConfigKeyModules: []map[string]any{
			{
				pluginConfigKeyName:   pluginConfigModuleName,
				pluginConfigKeyPath:   pluginConfigArtifactPath(pluginDir),
				pluginConfigKeySigner: pluginConfigSignerID,
			},
		},
	})

	assertPluginConfigError(t, err, "plugins.trust.signers[0]")
}

func TestPluginConfig_RejectsMissingRequiredChecksum(t *testing.T) {
	pluginDir := t.TempDir()

	err := loadPluginTestConfigError(t, map[string]any{
		pluginConfigKeyVerificationPolicy: PluginVerificationPolicyChecksumRequired,
		pluginConfigKeyAllowedDirs:        []string{pluginDir},
		pluginConfigKeyModules: []map[string]any{
			{
				pluginConfigKeyName: pluginConfigModuleName,
				pluginConfigKeyPath: pluginConfigArtifactPath(pluginDir),
			},
		},
	})

	assertPluginConfigError(t, err, "plugins.modules[0].checksum")
}

func TestPluginConfig_RejectsMissingRequiredSignature(t *testing.T) {
	pluginDir := t.TempDir()

	err := loadPluginTestConfigError(t, map[string]any{
		pluginConfigKeyVerificationPolicy: PluginVerificationPolicySignatureRequired,
		pluginConfigKeyAllowedDirs:        []string{pluginDir},
		pluginConfigKeyModules: []map[string]any{
			{
				pluginConfigKeyName: pluginConfigModuleName,
				pluginConfigKeyPath: pluginConfigArtifactPath(pluginDir),
			},
		},
	})

	assertPluginConfigError(t, err, "plugins.modules[0].signature")
}

func TestPluginConfig_RejectsInvalidLifecycleTimeout(t *testing.T) {
	pluginDir := t.TempDir()

	err := loadPluginTestConfigError(t, map[string]any{
		pluginConfigKeyAllowedDirs: []string{pluginDir},
		pluginConfigKeyModules: []map[string]any{
			{
				pluginConfigKeyName: pluginConfigModuleName,
				pluginConfigKeyPath: pluginConfigArtifactPath(pluginDir),
				"stop_timeout":      -1 * time.Second,
			},
		},
	})

	assertPluginConfigError(t, err, "plugins.modules[0].stop_timeout")
}

func TestPluginConfig_AcceptsMailCapabilityAllowlist(t *testing.T) {
	pluginDir := t.TempDir()

	cfg, err := loadPluginTestConfig(t, map[string]any{
		pluginConfigKeyAllowedDirs: []string{pluginDir},
		pluginConfigKeyModules: []map[string]any{
			{
				pluginConfigKeyName: pluginConfigModuleName,
				pluginConfigKeyPath: pluginConfigArtifactPath(pluginDir),
				pluginConfigKeyAllowCapabilities: []string{
					string(pluginapi.CapabilityCredentials),
					string(pluginapi.CapabilityMail),
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("HandleFile() error = %v", err)
	}

	capabilities := cfg.GetPlugins().Modules[0].AllowCapabilities
	if len(capabilities) != 2 ||
		capabilities[0] != pluginapi.CapabilityCredentials ||
		capabilities[1] != pluginapi.CapabilityMail {
		t.Fatalf("AllowCapabilities = %#v, want credentials and mail", capabilities)
	}
}

func TestPluginConfigDump_OmitsOpaqueModuleConfig(t *testing.T) {
	settings := map[string]any{
		"plugins": map[string]any{
			pluginConfigKeyAllowedDirs: []any{"/usr/lib/nauthilus/plugins"},
			pluginConfigKeyModules: []any{
				map[string]any{
					pluginConfigKeyName: pluginConfigModuleName,
					pluginConfigKeyPath: "/usr/lib/nauthilus/plugins/geoip.so",
					pluginConfigKeyConfig: map[string]any{
						pluginConfigKeyAPIKey: "must-not-render",
					},
				},
			},
		},
	}

	output, err := RenderNonDefaultConfigDump(settings)
	if err != nil {
		t.Fatalf("RenderNonDefaultConfigDump() error = %v", err)
	}

	if strings.Contains(output, pluginConfigKeyAPIKey) || strings.Contains(output, "must-not-render") {
		t.Fatalf("RenderNonDefaultConfigDump() exposed opaque plugin config: %q", output)
	}

	if !strings.Contains(output, `plugins.modules[0].name = "geoip"`) {
		t.Fatalf("RenderNonDefaultConfigDump() omitted module loader fields: %q", output)
	}
}

func loadPluginTestConfig(t *testing.T, plugins map[string]any) (*FileSettings, error) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("plugins", plugins)

	cfg := &FileSettings{}

	return cfg, cfg.HandleFile()
}

func loadPluginTestConfigError(t *testing.T, plugins map[string]any) error {
	t.Helper()

	_, err := loadPluginTestConfig(t, plugins)
	if err == nil {
		t.Fatal("HandleFile() error = nil, want plugin config validation error")
	}

	return err
}

func assertPluginConfigError(t *testing.T, err error, want string) {
	t.Helper()

	if err == nil {
		t.Fatal("plugin config error = nil")
	}

	if !strings.Contains(err.Error(), want) {
		t.Fatalf("plugin config error = %q, want substring %q", err, want)
	}
}

func pluginConfigArtifactPath(root string) string {
	return root + "/geoip.so"
}

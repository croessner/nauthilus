package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/spf13/viper"
)

const (
	testRedisPasswordNonce    = "nonce-secret-1234"
	testRedisEncryptionSecret = "redis-secret-1234"
)

func TestHandleFile_ServerPrefiltersAlias(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("server", map[string]any{
		"prefilters": []any{"rbl"},
		"redis": map[string]any{
			"master": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("handle file failed: %v", err)
	}

	if !cfg.HasFeature(definitions.FeatureRBL) {
		t.Fatal("expected server.prefilters to enable rbl")
	}
}

func TestHandleFile_ServerCapabilitiesEnableLegacyFeatureChecks(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("server", map[string]any{
		"prefilters":   []any{"rbl"},
		"capabilities": []any{"brute_force", "backend_server_monitoring"},
		"redis": map[string]any{
			"master": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("handle file failed: %v", err)
	}

	if !cfg.HasFeature(definitions.FeatureRBL) {
		t.Fatal("expected server.prefilters to enable rbl")
	}

	if !cfg.HasFeature(definitions.FeatureBruteForce) {
		t.Fatal("expected server.capabilities to enable brute_force")
	}

	if !cfg.HasFeature(definitions.FeatureBackendServersMonitoring) {
		t.Fatal("expected server.capabilities to enable backend_server_monitoring")
	}
}

func TestHandleFile_LuaPrefiltersAlias(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("server", map[string]any{
		"redis": map[string]any{
			"master": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})
	viper.Set("lua", map[string]any{
		"prefilters": []any{
			map[string]any{
				"name":         "test_context_chain",
				"script_path":  testLuaPrefilterScriptPath(t),
				"when_no_auth": true,
			},
		},
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("handle file failed: %v", err)
	}

	if !cfg.HaveLuaFeatures() {
		t.Fatal("expected lua.prefilters to populate Lua features")
	}

	luaCfg := cfg.GetLua()
	if len(luaCfg.GetFeatures()) != 1 {
		t.Fatalf("expected one Lua prefilter, got %d", len(luaCfg.GetFeatures()))
	}

	if luaCfg.GetFeatures()[0].Name != "test_context_chain" {
		t.Fatalf("expected Lua prefilter %q, got %q", "test_context_chain", luaCfg.GetFeatures()[0].Name)
	}

	if !luaCfg.GetFeatures()[0].WhenNoAuth {
		t.Fatal("expected when_no_auth from lua.prefilters to be preserved")
	}
}

func TestHandleFile_ServerPrefiltersRejectCapabilities(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("server", map[string]any{
		"prefilters": []any{"brute_force"},
		"redis": map[string]any{
			"master": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})
	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err == nil {
		t.Fatal("expected handle file to reject brute_force in server.prefilters")
	}
}

func TestHandleFile_ServerFeaturesCannotBeMixedWithPrefilters(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("server", map[string]any{
		"features":   []any{"brute_force"},
		"prefilters": []any{"rbl"},
		"redis": map[string]any{
			"master": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err == nil {
		t.Fatal("expected handle file to reject mixed server.features and server.prefilters")
	}
}

func TestHandleFile_ServerFeaturesCannotBeMixedWithCapabilities(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("server", map[string]any{
		"features":     []any{"rbl"},
		"capabilities": []any{"brute_force"},
		"redis": map[string]any{
			"master": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err == nil {
		t.Fatal("expected handle file to reject mixed server.features and server.capabilities")
	}
}

func testLuaPrefilterScriptPath(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	return filepath.Join(wd, "..", "lua-plugins.d", "features", "test_context_chain.lua")
}

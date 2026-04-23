package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestLuaConfigCacheFlushScriptPath_ReadsFromLuaConfig(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setDefaultEnvVars()

	const cacheFlushScriptPath = "/tmp/cache_flush.lua"

	viper.Set("auth", map[string]any{
		"backends": map[string]any{
			"lua": map[string]any{
				"backend": map[string]any{
					"default": map[string]any{
						"cache_flush_script_path": cacheFlushScriptPath,
					},
				},
			},
		},
	})

	cfg := &FileSettings{}
	if err := viper.UnmarshalExact(cfg, createDecoderOption()); err != nil {
		t.Fatalf("unmarshal config failed: %v", err)
	}

	cfg.materializeLegacySections()

	if got := cfg.GetLuaCacheFlushScriptPath(); got != cacheFlushScriptPath {
		t.Fatalf("expected cache flush script path %q, got %q", cacheFlushScriptPath, got)
	}
}

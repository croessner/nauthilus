package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestHandleFile_RedisPrimaryAlias(t *testing.T) {
	t.Run("primary populates standalone master", func(t *testing.T) {
		cfg := handleRedisAliasConfig(t, map[string]any{
			"primary": map[string]any{
				"address": "primary.example.test:6379",
			},
		})

		if got := cfg.GetServer().GetRedis().GetStandaloneMaster().GetAddress(); got != "primary.example.test:6379" {
			t.Fatalf("expected primary alias address, got %q", got)
		}
	})

	t.Run("master remains supported", func(t *testing.T) {
		cfg := handleRedisAliasConfig(t, map[string]any{
			"master": map[string]any{
				"address": "master.example.test:6379",
			},
		})

		if got := cfg.GetServer().GetRedis().GetStandaloneMaster().GetAddress(); got != "master.example.test:6379" {
			t.Fatalf("expected legacy master address, got %q", got)
		}
	})

	t.Run("primary overrides master", func(t *testing.T) {
		cfg := handleRedisAliasConfig(t, map[string]any{
			"primary": map[string]any{
				"address": "primary.example.test:6379",
			},
			"master": map[string]any{
				"address": "master.example.test:6379",
			},
		})

		if got := cfg.GetServer().GetRedis().GetStandaloneMaster().GetAddress(); got != "primary.example.test:6379" {
			t.Fatalf("expected primary alias to win, got %q", got)
		}
	})
}

func handleRedisAliasConfig(t *testing.T, redis map[string]any) *FileSettings {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	redis["password_nonce"] = testRedisPasswordNonce
	redis["encryption_secret"] = testRedisEncryptionSecret

	viper.Set("server", map[string]any{
		"redis": redis,
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("handle file failed: %v", err)
	}

	return cfg
}

package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestHandleFile_RedisPrimarySchema(t *testing.T) {
	cfg := handleRedisConfig(t, map[string]any{
		"primary": map[string]any{
			"address": "primary.example.test:6379",
		},
	})

	if got := cfg.GetServer().GetRedis().GetStandaloneMaster().GetAddress(); got != "primary.example.test:6379" {
		t.Fatalf("expected primary address, got %q", got)
	}
}

func TestHandleFile_RedisMasterIsRejected(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("storage", map[string]any{
		"redis": map[string]any{
			"master": map[string]any{
				"address": "legacy.example.test:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})

	cfg := &FileSettings{}
	err := cfg.HandleFile()
	if err == nil {
		t.Fatal("expected legacy storage.redis.master to be rejected")
	}

	if !strings.Contains(err.Error(), "storage.redis") || !strings.Contains(err.Error(), "master") {
		t.Fatalf("expected error to mention storage.redis.master, got %v", err)
	}
}

func handleRedisConfig(t *testing.T, redis map[string]any) *FileSettings {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	redis["password_nonce"] = testRedisPasswordNonce
	redis["encryption_secret"] = testRedisEncryptionSecret

	viper.Set("storage", map[string]any{
		"redis": redis,
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("handle file failed: %v", err)
	}

	return cfg
}

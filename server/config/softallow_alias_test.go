package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestHandleFile_BruteForceSoftAllowlistAlias(t *testing.T) {
	t.Run("soft_allowlist populates legacy field", func(t *testing.T) {
		cfg := handleSoftAllowAliasConfig(t, "brute_force", map[string]any{
			"buckets": []any{
				map[string]any{
					"name":            "test",
					"period":          60,
					"cidr":            32,
					"ipv4":            true,
					"failed_requests": 1,
				},
			},
			"soft_allowlist": map[string]any{
				"user1": []any{"192.168.0.0/24"},
			},
		})

		assertSoftWhitelistEntry(t, cfg.GetBruteForce().GetSoftWhitelist(), "user1", "192.168.0.0/24")
	})

	t.Run("soft_allowlist overrides soft_whitelist", func(t *testing.T) {
		cfg := handleSoftAllowAliasConfig(t, "brute_force", map[string]any{
			"buckets": []any{
				map[string]any{
					"name":            "test",
					"period":          60,
					"cidr":            32,
					"ipv4":            true,
					"failed_requests": 1,
				},
			},
			"soft_allowlist": map[string]any{
				"user1": []any{"192.168.0.0/24"},
			},
			"soft_whitelist": map[string]any{
				"user1": []any{"10.0.0.0/8"},
			},
		})

		assertSoftWhitelistEntry(t, cfg.GetBruteForce().GetSoftWhitelist(), "user1", "192.168.0.0/24")
	})
}

func TestHandleFile_RelayDomainsSoftAllowlistAlias(t *testing.T) {
	cfg := handleSoftAllowAliasConfig(t, "relay_domains", map[string]any{
		"static": []any{"example.test"},
		"soft_allowlist": map[string]any{
			"user1": []any{"192.168.0.0/24"},
		},
	})

	assertSoftWhitelistEntry(t, cfg.GetRelayDomains().GetSoftWhitelist(), "user1", "192.168.0.0/24")
}

func TestHandleFile_RBLSoftAllowlistAlias(t *testing.T) {
	cfg := handleSoftAllowAliasConfig(t, "realtime_blackhole_lists", map[string]any{
		"lists": []any{
			map[string]any{
				"name":         "test-rbl",
				"rbl":          "rbl.example.test",
				"return_codes": []any{"127.0.0.2"},
			},
		},
		"soft_allowlist": map[string]any{
			"user1": []any{"192.168.0.0/24"},
		},
	})

	assertSoftWhitelistEntry(t, cfg.GetRBLs().GetSoftWhitelist(), "user1", "192.168.0.0/24")
}

func handleSoftAllowAliasConfig(t *testing.T, key string, section map[string]any) *FileSettings {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("server", map[string]any{
		"redis": map[string]any{
			"primary": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})
	viper.Set(key, section)

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("handle file failed: %v", err)
	}

	return cfg
}

func assertSoftWhitelistEntry(t *testing.T, whitelist SoftWhitelist, username string, want string) {
	t.Helper()

	networks := whitelist.Get(username)
	if len(networks) != 1 || networks[0] != want {
		t.Fatalf("expected %q to contain %q, got %v", username, want, networks)
	}
}

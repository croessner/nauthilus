// Package config tests the public configuration schema.
package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestHandleFile_BruteForceAllowlistSchema(t *testing.T) {
	cfg := handleAllowlistConfig(t, map[string]any{
		"auth": map[string]any{
			"controls": map[string]any{
				"brute_force": map[string]any{
					"buckets": []any{
						map[string]any{
							"name":            "test",
							"period":          60,
							"cidr":            32,
							"ipv4":            true,
							"failed_requests": 1,
						},
					},
					"allowlist": map[string]any{
						"user1": []any{"192.168.0.0/24"},
					},
				},
			},
		},
	})

	assertSoftWhitelistEntry(t, cfg.GetBruteForce().GetSoftWhitelist(), "user1", "192.168.0.0/24")
}

func TestHandleFile_RelayDomainsAllowlistSchema(t *testing.T) {
	cfg := handleAllowlistConfig(t, map[string]any{
		"auth": map[string]any{
			"controls": map[string]any{
				"relay_domains": map[string]any{
					"static": []any{"example.test"},
					"allowlist": map[string]any{
						"user1": []any{"192.168.0.0/24"},
					},
				},
			},
		},
	})

	assertSoftWhitelistEntry(t, cfg.GetRelayDomains().GetSoftWhitelist(), "user1", "192.168.0.0/24")
}

func TestHandleFile_RBLAllowlistSchema(t *testing.T) {
	cfg := handleAllowlistConfig(t, map[string]any{
		"auth": map[string]any{
			"controls": map[string]any{
				"rbl": map[string]any{
					"lists": []any{
						map[string]any{
							"name":         "test-rbl",
							"rbl":          "rbl.example.test",
							"return_codes": []any{"127.0.0.2"},
						},
					},
					"ip_allowlist": []any{"192.168.0.0/24"},
				},
			},
		},
	})

	allowlist := cfg.GetRBLs().GetIPWhiteList()
	if len(allowlist) != 1 || allowlist[0] != "192.168.0.0/24" {
		t.Fatalf("expected RBL allowlist to contain 192.168.0.0/24, got %v", allowlist)
	}
}

func TestHandleFile_LegacyAllowlistNamesAreRejected(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("storage", map[string]any{
		"redis": map[string]any{
			"primary": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})
	viper.Set("auth", map[string]any{
		"controls": map[string]any{
			"brute_force": map[string]any{
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
			},
		},
	})

	cfg := &FileSettings{}
	err := cfg.HandleFile()
	if err == nil {
		t.Fatal("expected legacy soft_allowlist to be rejected")
	}

	if !strings.Contains(err.Error(), "auth.controls.brute_force") || !strings.Contains(err.Error(), "soft_allowlist") {
		t.Fatalf("expected error to mention auth.controls.brute_force.soft_allowlist, got %v", err)
	}
}

func handleAllowlistConfig(t *testing.T, root map[string]any) *FileSettings {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("storage", map[string]any{
		"redis": map[string]any{
			"primary": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})

	for key, value := range root {
		viper.Set(key, value)
	}

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

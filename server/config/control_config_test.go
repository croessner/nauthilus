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

func TestHandleFile_ServerControlsAndServicesEnableRuntimeFeatures(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("auth", map[string]any{
		"controls": map[string]any{
			"enabled": []any{"rbl", "brute_force"},
		},
		"services": map[string]any{
			"enabled": []any{"backend_health_checks"},
		},
	})
	viper.Set("storage", map[string]any{
		"redis": map[string]any{
			"primary": map[string]any{
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
		t.Fatal("expected auth.controls to enable rbl")
	}

	if !cfg.HasFeature(definitions.FeatureBruteForce) {
		t.Fatal("expected auth.controls to enable brute_force")
	}

	if !cfg.HasFeature(definitions.FeatureBackendServersMonitoring) {
		t.Fatal("expected auth.services to enable backend_health_checks")
	}
}

func TestHandleFile_LuaControlsPopulateLuaFeatures(t *testing.T) {
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
			"lua": map[string]any{
				"controls": []any{
					map[string]any{
						"name":         "test_context_chain",
						"script_path":  testLuaControlScriptPath(t),
						"when_no_auth": true,
					},
				},
			},
		},
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("handle file failed: %v", err)
	}

	if !cfg.HaveLuaFeatures() {
		t.Fatal("expected lua.controls to populate Lua features")
	}

	luaCfg := cfg.GetLua()
	if len(luaCfg.GetFeatures()) != 1 {
		t.Fatalf("expected one Lua control, got %d", len(luaCfg.GetFeatures()))
	}

	if luaCfg.GetFeatures()[0].Name != "test_context_chain" {
		t.Fatalf("expected Lua control %q, got %q", "test_context_chain", luaCfg.GetFeatures()[0].Name)
	}

	if !luaCfg.GetFeatures()[0].WhenNoAuth {
		t.Fatal("expected when_no_auth from lua.controls to be preserved")
	}
}

func TestHandleFile_ServerControlsRejectServices(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("auth", map[string]any{
		"controls": map[string]any{
			"enabled": []any{"backend_health_checks"},
		},
	})
	viper.Set("storage", map[string]any{
		"redis": map[string]any{
			"primary": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err == nil {
		t.Fatal("expected handle file to reject backend_health_checks in auth.controls")
	}
}

func TestHandleFile_ServerServicesRejectControls(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("auth", map[string]any{
		"services": map[string]any{
			"enabled": []any{"brute_force"},
		},
	})
	viper.Set("storage", map[string]any{
		"redis": map[string]any{
			"primary": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err == nil {
		t.Fatal("expected handle file to reject brute_force in auth.services")
	}
}

func TestHandleFile_BruteForceLearningAcceptsFeatureNames(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

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
				"learning": []any{"lua", "relay_domains", "rbl", "brute_force"},
			},
		},
	})
	viper.Set("storage", map[string]any{
		"redis": map[string]any{
			"primary": map[string]any{
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

	for _, feature := range []string{"lua", "relay_domains", "rbl", "brute_force"} {
		if !cfg.GetBruteForce().LearnFromFeature(feature) {
			t.Fatalf("expected brute force learning to include %q", feature)
		}
	}
}

func TestHandleFile_OptionalLDAPAndLuaBackendsInV2(t *testing.T) {
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
		"backends": map[string]any{
			"ldap": map[string]any{
				"default": map[string]any{
					"server_uri":            []any{"ldap://ldap:389"},
					"auth_pool_size":        4,
					"lookup_pool_size":      4,
					"lookup_idle_pool_size": 1,
				},
				"pools": map[string]any{
					"list-account": map[string]any{
						"server_uri":       []any{"ldap://ldap-list:389"},
						"auth_pool_size":   2,
						"lookup_pool_size": 2,
					},
				},
			},
			"lua": map[string]any{
				"backend": map[string]any{
					"default": map[string]any{
						"backend_script_path": testLuaBackendScriptPath(t),
						"package_path":        "server/lua-plugins.d/?.lua",
					},
					"named_backends": map[string]any{
						"reporting": map[string]any{
							"backend_script_path": testLuaBackendScriptPath(t),
							"package_path":        "server/lua-plugins.d/?.lua",
						},
					},
				},
			},
		},
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("handle file failed: %v", err)
	}

	if len(cfg.GetLDAP().GetOptionalLDAPPools()) != 1 {
		t.Fatalf("expected one optional LDAP pool, got %d", len(cfg.GetLDAP().GetOptionalLDAPPools()))
	}

	if len(cfg.GetLua().GetOptionalLuaBackends()) != 1 {
		t.Fatalf("expected one optional Lua backend, got %d", len(cfg.GetLua().GetOptionalLuaBackends()))
	}
}

func testLuaControlScriptPath(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	return filepath.Join(wd, "..", "lua-plugins.d", "features", "test_context_chain.lua")
}

func testLuaBackendScriptPath(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	return filepath.Join(wd, "..", "lua-plugins.d", "backend", "backend.lua")
}

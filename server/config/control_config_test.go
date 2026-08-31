//nolint:goconst
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/spf13/viper"
)

const (
	testRedisPasswordNonce    = "nonce-secret-1234"
	testRedisEncryptionSecret = "redis-secret-1234"
)

func TestHandleFile_ServerControlsAndServicesEnableRuntimeModules(t *testing.T) {
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

	if !cfg.HasRuntimeModule(definitions.ControlRBL) {
		t.Fatal("expected auth.controls to enable rbl")
	}

	if !cfg.HasRuntimeModule(definitions.ControlBruteForce) {
		t.Fatal("expected auth.controls to enable brute_force")
	}

	if !cfg.HasRuntimeModule(definitions.ServiceBackendHealthChecks) {
		t.Fatal("expected auth.services to enable backend_health_checks")
	}
}

func TestHandleFile_BackendHealthChecksExposeTimeoutsIntervalsAndThresholds(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setBackendHealthChecksTestConfig()

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("handle file failed: %v", err)
	}

	monitoring := cfg.GetBackendServerMonitoring()
	assertBackendHealthCheckTimings(t, monitoring)
	assertBackendHealthCheckThresholds(t, monitoring)
	assertBackendHealthCheckTargetOverrides(t, monitoring)
}

func TestMaterializeLegacySectionsDoesNotClearFrontendTemplateDefaultWhenHealthChecksMissing(t *testing.T) {
	cfg := &FileSettings{
		Identity: &IdentitySection{
			Frontend: IdentityFrontendSection{
				Enabled: true,
			},
		},
	}

	cfg.materializeLegacySections()

	if err := cfg.setDefaultHTMLStaticContentPath(); err != nil {
		t.Fatalf("set default HTML path failed: %v", err)
	}

	if got := cfg.GetServer().Frontend.GetHTMLStaticContentPath(); got != definitions.HTMLStaticContentPath {
		t.Fatalf("expected frontend HTML path default %q after load, got %q", definitions.HTMLStaticContentPath, got)
	}

	_ = cfg.GetBackendServerMonitoring()

	if got := cfg.GetServer().Frontend.GetHTMLStaticContentPath(); got != definitions.HTMLStaticContentPath {
		t.Fatalf("expected backend monitoring lookup to preserve frontend HTML path default %q, got %q", definitions.HTMLStaticContentPath, got)
	}
}

func setBackendHealthChecksTestConfig() {
	viper.Set("auth", map[string]any{
		"services": map[string]any{
			"enabled": []any{"backend_health_checks"},
			"backend_health_checks": map[string]any{
				"connect_timeout":    "150ms",
				"tls_timeout":        "250ms",
				"deep_timeout":       "750ms",
				"connect_interval":   "5s",
				"deep_interval":      "1m",
				"failure_threshold":  3,
				"recovery_threshold": 2,
				"targets": []any{
					map[string]any{
						"protocol":        "imap",
						"host":            "127.0.0.1",
						"port":            993,
						"deep_check":      true,
						"connect_timeout": "50ms",
						"deep_timeout":    "500ms",
					},
				},
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
}

func assertBackendHealthCheckTimings(t *testing.T, monitoring *BackendServerMonitoring) {
	t.Helper()

	if monitoring.GetConnectTimeout() != 150*time.Millisecond {
		t.Fatalf("expected connect timeout 150ms, got %s", monitoring.GetConnectTimeout())
	}

	if monitoring.GetTLSTimeout() != 250*time.Millisecond {
		t.Fatalf("expected TLS timeout 250ms, got %s", monitoring.GetTLSTimeout())
	}

	if monitoring.GetDeepTimeout() != 750*time.Millisecond {
		t.Fatalf("expected deep timeout 750ms, got %s", monitoring.GetDeepTimeout())
	}

	if monitoring.GetConnectInterval(0) != 5*time.Second {
		t.Fatalf("expected connect interval 5s, got %s", monitoring.GetConnectInterval(0))
	}

	if monitoring.GetDeepInterval(monitoring.GetConnectInterval(0)) != time.Minute {
		t.Fatalf("expected deep interval 1m, got %s", monitoring.GetDeepInterval(0))
	}
}

func assertBackendHealthCheckThresholds(t *testing.T, monitoring *BackendServerMonitoring) {
	t.Helper()

	if monitoring.GetFailureThreshold() != 3 {
		t.Fatalf("expected failure threshold 3, got %d", monitoring.GetFailureThreshold())
	}

	if monitoring.GetRecoveryThreshold() != 2 {
		t.Fatalf("expected recovery threshold 2, got %d", monitoring.GetRecoveryThreshold())
	}
}

func assertBackendHealthCheckTargetOverrides(t *testing.T, monitoring *BackendServerMonitoring) {
	t.Helper()

	targets := monitoring.GetBackendServers()
	if len(targets) != 1 {
		t.Fatalf("expected one target, got %d", len(targets))
	}

	if got := monitoring.GetServerConnectTimeout(targets[0]); got != 50*time.Millisecond {
		t.Fatalf("expected target connect timeout 50ms, got %s", got)
	}

	if got := monitoring.GetServerDeepTimeout(targets[0]); got != 500*time.Millisecond {
		t.Fatalf("expected target deep timeout 500ms, got %s", got)
	}
}

func TestHandleFile_ServerControlsRejectRemovedWhenNoAuthShape(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("auth", map[string]any{
		"controls": map[string]any{
			"enabled": []any{
				map[string]any{
					"name":         "tls_encryption",
					"when_no_auth": true,
				},
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
	if err := cfg.HandleFile(); err == nil {
		t.Fatal("HandleFile() error = nil, want removed when_no_auth shape rejection")
	}
}

func TestHandleFile_RuntimeModuleListsRejectWrongModuleType(t *testing.T) {
	for _, testCase := range runtimeModuleListRejectionCases() {
		t.Run(testCase.name, func(t *testing.T) {
			assertRuntimeModuleListRejected(t, testCase)
		})
	}
}

type runtimeModuleListRejectionCase struct {
	name    string
	section string
	module  string
	message string
}

// runtimeModuleListRejectionCases lists controls and services placed in the wrong config section.
func runtimeModuleListRejectionCases() []runtimeModuleListRejectionCase {
	return []runtimeModuleListRejectionCase{
		{
			name:    "service in controls",
			section: "controls",
			module:  "backend_health_checks",
			message: "expected handle file to reject backend_health_checks in auth.controls",
		},
		{
			name:    "control in services",
			section: "services",
			module:  "brute_force",
			message: "expected handle file to reject brute_force in auth.services",
		},
	}
}

// assertRuntimeModuleListRejected verifies that controls and services cannot be mixed.
func assertRuntimeModuleListRejected(t *testing.T, testCase runtimeModuleListRejectionCase) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("auth", map[string]any{
		testCase.section: map[string]any{
			"enabled": []any{testCase.module},
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
		t.Fatal(testCase.message)
	}
}

func TestHandleFile_BruteForceLearningAcceptsControlNames(t *testing.T) {
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

	for _, runtimeModule := range []string{"lua", "relay_domains", "rbl", "brute_force"} {
		if !cfg.GetBruteForce().LearnFromControl(runtimeModule) {
			t.Fatalf("expected brute force learning to include %q", runtimeModule)
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

func testLuaBackendScriptPath(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	return filepath.Join(wd, "..", "lua-plugins.d", "backend", "backend.lua")
}

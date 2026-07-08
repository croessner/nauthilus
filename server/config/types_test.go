package config

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
)

func TestRuntimeModuleSet_BackendMonitoringAliasIsRejected(t *testing.T) {
	f := &RuntimeModule{}
	if err := f.Set("backend_monitoring"); err == nil {
		t.Fatalf("expected alias to be rejected, got nil error")
	}
}

func TestDbgModuleSetAcceptsPluginDebugSelectors(t *testing.T) {
	tests := []string{
		"plugin",
		"plugin.clickhouse",
		"plugin.clickhouse.batch",
	}

	for _, selector := range tests {
		t.Run(selector, func(t *testing.T) {
			module := &DbgModule{}
			if err := module.Set(selector); err != nil {
				t.Fatalf("Set(%q) error = %v", selector, err)
			}

			if module.Get() != selector {
				t.Fatalf("Get() = %q, want %q", module.Get(), selector)
			}
		})
	}
}

func TestDbgModuleSetRejectsInvalidPluginDebugSelectors(t *testing.T) {
	tests := []string{
		"plugin.",
		"plugin.clickhouse.batch.extra",
		"plugin.clickhouse.all",
		"debug.clickhouse",
	}

	for _, selector := range tests {
		t.Run(selector, func(t *testing.T) {
			module := &DbgModule{}
			if err := module.Set(selector); err == nil {
				t.Fatalf("Set(%q) error = nil, want invalid debug module", selector)
			}
		})
	}
}

func TestResolveLDAPSearchPoolName(t *testing.T) {
	cfg := &FileSettings{
		LDAP: &LDAPSection{
			Search: []LDAPSearchProtocol{
				{
					PoolName:  definitions.DefaultBackendName,
					Protocols: []string{"idp", "oidc"},
				},
				{
					PoolName:  "mail",
					Protocols: []string{"smtp"},
				},
			},
		},
	}

	poolName, ok := ResolveLDAPSearchPoolName(cfg, "oidc")
	if !ok {
		t.Fatalf("expected pool to resolve")
	}

	if poolName != definitions.DefaultBackendName {
		t.Fatalf("expected default pool, got %s", poolName)
	}

	poolName, ok = ResolveLDAPSearchPoolName(cfg, "unknown")
	if ok || poolName != "" {
		t.Fatalf("expected no match for unknown protocol")
	}
}

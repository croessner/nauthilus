package config

import (
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
)

func TestFeatureSet_BackendMonitoringAliasIsRejected(t *testing.T) {
	f := &Feature{}
	if err := f.Set("backend_monitoring"); err == nil {
		t.Fatalf("expected alias to be rejected, got nil error")
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

package core

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
)

const backendPlanAccountField = "uid"

func TestBuildAuthnTypedBackendExecutionPlanSelectsOnlyExactProvider(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Backends = []*config.Backend{
		mustBackendPlanConfig(t, definitions.BackendCacheName),
		mustBackendPlanConfig(t, definitions.BackendLDAPName),
		mustBackendPlanConfig(t, definitions.BackendLuaName),
		mustBackendPlanConfig(t, "plugin(example.identity)"),
	}
	auth, _, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.deps.PluginBackendFactory = func(string, AuthDeps) BackendManager {
		return &testBackendManagerImpl{}
	}

	tests := []struct {
		name       string
		providerID string
		backend    definitions.Backend
	}{
		{name: "LDAP", providerID: policy.AuthnProviderLDAPBackend, backend: definitions.BackendLDAP},
		{name: "Lua", providerID: policy.AuthnProviderLuaBackend, backend: definitions.BackendLua},
		{name: "plugin", providerID: policy.AuthnProviderPluginBackendOrder, backend: definitions.BackendPlugin},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := auth.buildAuthnTypedBackendExecutionPlan(test.providerID)
			if err != nil {
				t.Fatalf("buildAuthnTypedBackendExecutionPlan(%q) error = %v", test.providerID, err)
			}

			if len(plan.passDBs) != 1 || plan.passDBs[0].backend != test.backend {
				t.Fatalf("typed plan %q backends = %#v, want only %s", test.providerID, plan.passDBs, test.backend)
			}

			if plan.hasPositivePasswordCache {
				t.Fatalf("typed plan %q retained ambient positive-cache authority", test.providerID)
			}
		})
	}

	if _, err := auth.buildAuthnTypedBackendExecutionPlan(policy.AuthnProviderBackend); err == nil {
		t.Fatal("typed backend plan accepted the aggregate backend provider")
	}
}

// mustBackendPlanConfig constructs one exact backend-order entry.
func mustBackendPlanConfig(t *testing.T, value string) *config.Backend {
	t.Helper()

	backend := &config.Backend{}
	if err := backend.Set(value); err != nil {
		t.Fatalf("Backend.Set(%q) error = %v", value, err)
	}

	return backend
}

func TestBackendExecutionPlanPositivePasswordCache(t *testing.T) {
	for _, tt := range backendExecutionPlanPositivePasswordCacheCases() {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.plan.positivePasswordCacheEnabled(tt.usedBackend); got != tt.wantEnabled {
				t.Fatalf("positivePasswordCacheEnabled(%v) = %v, want %v", tt.usedBackend, got, tt.wantEnabled)
			}
		})
	}
}

type backendExecutionPlanPositivePasswordCacheCase struct {
	name        string
	plan        backendExecutionPlan
	usedBackend definitions.Backend
	wantEnabled bool
}

func backendExecutionPlanPositivePasswordCacheCases() []backendExecutionPlanPositivePasswordCacheCase {
	testCases := backendExecutionPlanPositivePasswordCacheEnabledCases()

	return append(testCases, backendExecutionPlanPositivePasswordCacheDisabledCases()...)
}

// backendExecutionPlanPositivePasswordCacheEnabledCases returns positive cache cases.
func backendExecutionPlanPositivePasswordCacheEnabledCases() []backendExecutionPlanPositivePasswordCacheCase {
	return []backendExecutionPlanPositivePasswordCacheCase{
		{
			name: "enabled when cache precedes non-remote backend",
			plan: backendExecutionPlan{
				positions: map[definitions.Backend]int{
					definitions.BackendCache: 0,
					definitions.BackendLDAP:  1,
				},
				hasPositivePasswordCache: true,
			},
			usedBackend: definitions.BackendLDAP,
			wantEnabled: true,
		},
	}
}

// backendExecutionPlanPositivePasswordCacheDisabledCases returns negative cache cases.
func backendExecutionPlanPositivePasswordCacheDisabledCases() []backendExecutionPlanPositivePasswordCacheCase {
	return []backendExecutionPlanPositivePasswordCacheCase{
		{
			name: "disabled without configured cache backend",
			plan: backendExecutionPlan{
				positions: map[definitions.Backend]int{
					definitions.BackendLDAP: 0,
					definitions.BackendLua:  1,
				},
			},
			usedBackend: definitions.BackendLua,
		},
		{
			name: "disabled when cache follows used backend",
			plan: backendExecutionPlan{
				positions: map[definitions.Backend]int{
					definitions.BackendLDAP:  0,
					definitions.BackendCache: 1,
				},
				hasPositivePasswordCache: true,
			},
			usedBackend: definitions.BackendLDAP,
		},
		{
			name: "disabled for remote backend",
			plan: backendExecutionPlan{
				positions: map[definitions.Backend]int{
					definitions.BackendCache:  0,
					definitions.BackendRemote: 1,
				},
				hasPositivePasswordCache: true,
			},
			usedBackend: definitions.BackendRemote,
		},
		{
			name: "disabled for plugin backend",
			plan: backendExecutionPlan{
				positions: map[definitions.Backend]int{
					definitions.BackendCache:  0,
					definitions.BackendPlugin: 1,
				},
				hasPositivePasswordCache: true,
			},
			usedBackend: definitions.BackendPlugin,
		},
		{
			name: "disabled for backend missing from plan",
			plan: backendExecutionPlan{
				positions: map[definitions.Backend]int{
					definitions.BackendCache: 0,
				},
				hasPositivePasswordCache: true,
			},
			usedBackend: definitions.BackendLDAP,
		},
	}
}

package pluginregistry

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
)

// cacheSafeRegistryBackend declares whether its successful results may be cached.
type cacheSafeRegistryBackend struct {
	fakeBackend
	safe bool
}

// PositivePasswordCacheable exposes the explicit declaration under test.
func (b cacheSafeRegistryBackend) PositivePasswordCacheable() bool { return b.safe }

func TestBackendPositiveCacheRequiresJointOptIn(t *testing.T) {
	for _, operator := range []bool{false, true} {
		for _, plugin := range []bool{false, true} {
			registry := NewRegistry()
			registrar := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP, PositivePasswordCache: operator})

			err := registrar.RegisterBackend(cacheSafeRegistryBackend{fakeBackend: fakeBackend{name: testRegistryBackendName}, safe: plugin})
			if operator && !plugin {
				if err == nil {
					t.Fatal("operator opt-in accepted without plugin declaration")
				}

				continue
			}

			if err != nil {
				t.Fatal(err)
			}

			if err := registrar.Commit(); err != nil {
				t.Fatal(err)
			}

			component, ok := registry.Lookup(testRegistryModuleGeoIP + "." + testRegistryBackendName)
			if !ok || component.PositivePasswordCache != (operator && plugin) {
				t.Fatal("cache admission did not require both opt-ins")
			}
		}
	}

	registrar := NewRegistry().NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP, PositivePasswordCache: true})
	if registrar.RegisterBackend(fakeBackend{name: testRegistryBackendName}) == nil {
		t.Fatal("legacy backend accepted explicit cache opt-in")
	}
}

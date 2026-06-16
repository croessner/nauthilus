package pluginloader

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/config"
)

const (
	discoveryMetadataName     = "geoip-plugin"
	discoveryEnvironmentName  = "environment"
	discoverySecretConfigKey  = "api_token"
	discoverySecretConfigText = "secret-token"
)

func TestStateDiscoveryUsesDescriptorsMetadataAndOmitsPluginConfig(t *testing.T) {
	artifact := writeLoaderArtifact(t)
	opener := fakeFactoryOpener(artifact, func() (pluginapi.Plugin, error) {
		return fakePlugin{
			metadata: pluginapi.Metadata{
				Name:        discoveryMetadataName,
				Version:     testLoaderPluginVersion,
				APIVersion:  pluginapi.APIVersion,
				Description: "GeoIP enrichment",
				DocsURL:     "https://example.test/geoip",
				Features:    []pluginapi.Feature{discoveryEnvironmentName},
				Capabilities: []pluginapi.Capability{
					pluginapi.CapabilityCredentials,
				},
				Build: pluginapi.BuildInfo{
					GoVersion: "go1.26",
					GitCommit: "abc123",
					BuildTime: "2026-06-16T00:00:00Z",
					BuildTags: []string{"netgo"},
				},
			},
			register: func(registrar pluginapi.Registrar) error {
				if err := registrar.RegisterEnvironmentSource(discoveryEnvironmentSource{}); err != nil {
					return err
				}

				return registrar.RegisterHook(discoveryHook{})
			},
		}, nil
	})

	state, err := NewLoader(WithOpener(opener)).Load([]VerifiedModule{
		verifiedLoaderModule(testPluginModuleName, artifact, func(module *config.PluginModule) {
			module.Config = map[string]any{
				discoverySecretConfigKey: discoverySecretConfigText,
			}
		}),
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	discovery := state.Discovery()
	module := assertDiscoveryModule(t, discovery)
	assertDiscoveryComponents(t, module)
	assertDiscoveryOmitsConfig(t, discovery)
}

// assertDiscoveryModule verifies module-level discovery metadata.
func assertDiscoveryModule(t *testing.T, discovery DiscoveryDocument) DiscoveryModule {
	t.Helper()

	if len(discovery.Modules) != 1 {
		t.Fatalf("Discovery modules len = %d, want 1", len(discovery.Modules))
	}

	module := discovery.Modules[0]
	if module.Name != testPluginModuleName || module.Metadata.Name != discoveryMetadataName {
		t.Fatalf("discovery module = %#v", module)
	}

	if got := module.Metadata.Features; len(got) != 1 || got[0] != pluginapi.Feature(discoveryEnvironmentName) {
		t.Fatalf("metadata features = %#v", got)
	}

	return module
}

// assertDiscoveryComponents verifies descriptor-derived component output.
func assertDiscoveryComponents(t *testing.T, module DiscoveryModule) {
	t.Helper()

	if len(module.Components) != 2 {
		t.Fatalf("components len = %d, want 2", len(module.Components))
	}

	source := module.Components[0]
	if source.QualifiedName != testPluginModuleName+"."+discoveryEnvironmentName || source.Source == nil {
		t.Fatalf("source discovery = %#v", source)
	}

	if got := source.Source.Requires; len(got) != 1 || got[0] != testPluginModuleName+".warmup" {
		t.Fatalf("source requires = %#v", got)
	}

	hook := module.Components[1]
	if hook.QualifiedName != testPluginModuleName+".status" || hook.Hook == nil {
		t.Fatalf("hook discovery = %#v", hook)
	}
}

// assertDiscoveryOmitsConfig verifies plugin-owned config is not serialized.
func assertDiscoveryOmitsConfig(t *testing.T, discovery DiscoveryDocument) {
	t.Helper()

	payload, err := json.Marshal(discovery)
	if err != nil {
		t.Fatalf("marshal discovery: %v", err)
	}

	if strings.Contains(string(payload), discoverySecretConfigText) || strings.Contains(string(payload), discoverySecretConfigKey) {
		t.Fatalf("discovery leaked plugin-owned config: %s", payload)
	}
}

type discoveryEnvironmentSource struct{}

func (discoveryEnvironmentSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{
		Name:     discoveryEnvironmentName,
		Requires: []string{"warmup"},
		After:    []string{"other.source"},
		Timeout:  250 * time.Millisecond,
		Priority: 10,
	}
}

func (discoveryEnvironmentSource) Evaluate(
	_ context.Context,
	_ pluginapi.EnvironmentRequest,
) (pluginapi.EnvironmentResult, error) {
	return pluginapi.EnvironmentResult{}, nil
}

type discoveryHook struct{}

func (discoveryHook) Descriptor() pluginapi.HookDescriptor {
	return pluginapi.HookDescriptor{
		Name:         "status",
		Method:       "GET",
		Path:         "/plugins/geoip/status",
		Alias:        "/plugins/geoip",
		Scope:        pluginapi.HookScopeAdmin,
		Auth:         pluginapi.HookAuthAdmin,
		Timeout:      time.Second,
		MaxBodyBytes: 1024,
	}
}

func (discoveryHook) Serve(
	_ context.Context,
	_ pluginapi.HookRequest,
) (pluginapi.HookResponse, error) {
	return pluginapi.HookResponse{}, nil
}

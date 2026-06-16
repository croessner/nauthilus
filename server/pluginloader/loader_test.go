package pluginloader

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/pluginregistry"
)

const (
	testLoaderAPIVersionUnsupported = "nauthilus.plugin.v2"
	testLoaderBackendName           = "passdb"
	testLoaderPluginVersion         = "1.0.0"
	testLoaderModuleCustomerA       = "customer_a"
	testLoaderModuleCustomerB       = "customer_b"
)

func TestLoader_RejectsMissingArtifactAfterValidationHandoff(t *testing.T) {
	artifact := writeLoaderArtifact(t)
	if err := os.Remove(artifact); err != nil {
		t.Fatalf("remove verified artifact: %v", err)
	}

	_, err := NewLoader(WithOpener(fakeOpener{})).Load([]VerifiedModule{
		verifiedLoaderModule(testPluginModuleName, artifact, nil),
	})
	if !errors.Is(err, ErrArtifactUnavailable) {
		t.Fatalf("Load() error = %v, want ErrArtifactUnavailable", err)
	}
}

func TestLoader_RejectsMissingFactorySymbol(t *testing.T) {
	artifact := writeLoaderArtifact(t)
	opener := fakeOpener{
		artifact: fakeHandle{lookupErr: errors.New("missing symbol")},
	}

	_, err := NewLoader(WithOpener(opener)).Load([]VerifiedModule{
		verifiedLoaderModule(testPluginModuleName, artifact, nil),
	})
	if !errors.Is(err, ErrFactorySymbolMissing) {
		t.Fatalf("Load() error = %v, want ErrFactorySymbolMissing", err)
	}
}

func TestLoader_RejectsWrongFactorySymbolType(t *testing.T) {
	artifact := writeLoaderArtifact(t)
	opener := fakeOpener{
		artifact: fakeHandle{symbol: func() error { return nil }},
	}

	_, err := NewLoader(WithOpener(opener)).Load([]VerifiedModule{
		verifiedLoaderModule(testPluginModuleName, artifact, nil),
	})
	if !errors.Is(err, ErrFactorySymbolInvalid) {
		t.Fatalf("Load() error = %v, want ErrFactorySymbolInvalid", err)
	}
}

func TestLoader_RejectsFactoryError(t *testing.T) {
	artifact := writeLoaderArtifact(t)
	opener := fakeFactoryOpener(artifact, func() (pluginapi.Plugin, error) {
		return nil, errors.New("factory failed")
	})

	_, err := NewLoader(WithOpener(opener)).Load([]VerifiedModule{
		verifiedLoaderModule(testPluginModuleName, artifact, nil),
	})
	if !errors.Is(err, ErrFactoryFailed) {
		t.Fatalf("Load() error = %v, want ErrFactoryFailed", err)
	}
}

func TestLoader_RejectsNilPluginFactoryResult(t *testing.T) {
	artifact := writeLoaderArtifact(t)
	opener := fakeFactoryOpener(artifact, func() (pluginapi.Plugin, error) {
		return nil, nil
	})

	_, err := NewLoader(WithOpener(opener)).Load([]VerifiedModule{
		verifiedLoaderModule(testPluginModuleName, artifact, nil),
	})
	if !errors.Is(err, ErrNilPlugin) {
		t.Fatalf("Load() error = %v, want ErrNilPlugin", err)
	}
}

func TestLoader_RejectsUnsupportedAPIVersion(t *testing.T) {
	artifact := writeLoaderArtifact(t)
	opener := fakeFactoryOpener(artifact, func() (pluginapi.Plugin, error) {
		return fakePlugin{metadata: pluginapi.Metadata{
			Name:       testPluginModuleName,
			Version:    testLoaderPluginVersion,
			APIVersion: testLoaderAPIVersionUnsupported,
		}}, nil
	})

	_, err := NewLoader(WithOpener(opener)).Load([]VerifiedModule{
		verifiedLoaderModule(testPluginModuleName, artifact, nil),
	})
	if !errors.Is(err, pluginapi.ErrUnsupportedAPIVersion) {
		t.Fatalf("Load() error = %v, want ErrUnsupportedAPIVersion", err)
	}
}

func TestLoader_RejectsDuplicateComponentRegistration(t *testing.T) {
	artifact := writeLoaderArtifact(t)
	opener := fakeFactoryOpener(artifact, func() (pluginapi.Plugin, error) {
		return fakePlugin{
			metadata: validLoaderMetadata(),
			register: func(registrar pluginapi.Registrar) error {
				if err := registrar.RegisterBackend(fakeLoaderBackend{name: testLoaderBackendName}); err != nil {
					return err
				}

				return registrar.RegisterBackend(fakeLoaderBackend{name: testLoaderBackendName})
			},
		}, nil
	})

	_, err := NewLoader(WithOpener(opener)).Load([]VerifiedModule{
		verifiedLoaderModule(testPluginModuleName, artifact, nil),
	})
	if !errors.Is(err, pluginregistry.ErrDuplicateComponent) {
		t.Fatalf("Load() error = %v, want ErrDuplicateComponent", err)
	}
}

func TestLoader_ReturnsErrorForRequiredModuleFailure(t *testing.T) {
	artifact := writeLoaderArtifact(t)
	opener := fakeFactoryOpener(artifact, func() (pluginapi.Plugin, error) {
		return nil, errors.New("factory failed")
	})

	_, err := NewLoader(WithOpener(opener)).Load([]VerifiedModule{
		verifiedLoaderModule(testPluginModuleName, artifact, nil),
	})
	if !errors.Is(err, ErrRequiredModuleFailed) {
		t.Fatalf("Load() error = %v, want ErrRequiredModuleFailed", err)
	}
}

func TestLoader_RecordsOptionalModuleFailure(t *testing.T) {
	artifact := writeLoaderArtifact(t)
	opener := fakeFactoryOpener(artifact, func() (pluginapi.Plugin, error) {
		return nil, errors.New("factory failed")
	})

	state, err := NewLoader(WithOpener(opener)).Load([]VerifiedModule{
		verifiedLoaderModule(testPluginModuleName, artifact, func(module *config.PluginModule) {
			module.Optional = true
		}),
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	instances := state.Instances()
	if len(instances) != 1 {
		t.Fatalf("Instances() len = %d, want 1", len(instances))
	}

	if instances[0].Status != ModuleStatusFailed || instances[0].RegistrationError == nil {
		t.Fatalf("optional instance = %#v, want failed state with error", instances[0])
	}
}

func TestLoader_DoesNotCommitOptionalPartialRegistrationFailure(t *testing.T) {
	artifact := writeLoaderArtifact(t)
	opener := fakeFactoryOpener(artifact, func() (pluginapi.Plugin, error) {
		return fakePlugin{
			metadata: validLoaderMetadata(),
			register: func(registrar pluginapi.Registrar) error {
				if err := registrar.RegisterBackend(fakeLoaderBackend{name: testLoaderBackendName}); err != nil {
					return err
				}

				return errors.New("registration failed")
			},
		}, nil
	})

	state, err := NewLoader(WithOpener(opener)).Load([]VerifiedModule{
		verifiedLoaderModule(testPluginModuleName, artifact, func(module *config.PluginModule) {
			module.Optional = true
		}),
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if _, ok := state.Registry().Lookup(testPluginModuleName + "." + testLoaderBackendName); ok {
		t.Fatal("optional failed module leaked a registered backend")
	}
}

func TestLoader_SameArtifactPathCreatesSeparateModuleInstances(t *testing.T) {
	artifact := writeLoaderArtifact(t)

	var factoryCalls int

	opener := fakeFactoryOpener(artifact, func() (pluginapi.Plugin, error) {
		factoryCalls++

		return fakePlugin{
			metadata: validLoaderMetadata(),
			register: func(registrar pluginapi.Registrar) error {
				return registrar.RegisterBackend(fakeLoaderBackend{name: testLoaderBackendName})
			},
			id: factoryCalls,
		}, nil
	})

	state, err := NewLoader(WithOpener(opener)).Load([]VerifiedModule{
		verifiedLoaderModule(testLoaderModuleCustomerA, artifact, nil),
		verifiedLoaderModule(testLoaderModuleCustomerB, artifact, nil),
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if factoryCalls != 2 {
		t.Fatalf("factory calls = %d, want 2", factoryCalls)
	}

	instances := state.Instances()
	if len(instances) != 2 {
		t.Fatalf("Instances() len = %d, want 2", len(instances))
	}

	first := instances[0].Plugin.(fakePlugin)

	second := instances[1].Plugin.(fakePlugin)
	if first.id == second.id {
		t.Fatalf("plugin instances share id %d, want separate factory results", first.id)
	}

	if _, ok := state.Registry().Lookup(testLoaderModuleCustomerA + "." + testLoaderBackendName); !ok {
		t.Fatal("missing customer_a backend descriptor")
	}

	if _, ok := state.Registry().Lookup(testLoaderModuleCustomerB + "." + testLoaderBackendName); !ok {
		t.Fatal("missing customer_b backend descriptor")
	}
}

func TestValidateOrderedPluginBackends_AcceptsRegisteredBackend(t *testing.T) {
	state := loadBackendPluginState(t, testLoaderModuleCustomerA, testLoaderBackendName, false)
	cfg := fileWithPluginBackendOrder(t, testLoaderModuleCustomerA+"."+testLoaderBackendName)

	if err := ValidateOrderedPluginBackends(cfg, state); err != nil {
		t.Fatalf("ValidateOrderedPluginBackends() error = %v", err)
	}
}

func TestValidateOrderedPluginBackends_RejectsMissingModuleReference(t *testing.T) {
	state := loadBackendPluginState(t, testLoaderModuleCustomerA, testLoaderBackendName, false)
	cfg := fileWithPluginBackendOrder(t, "missing."+testLoaderBackendName)

	err := ValidateOrderedPluginBackends(cfg, state)
	if !errors.Is(err, ErrOrderedPluginBackendMissing) {
		t.Fatalf("ValidateOrderedPluginBackends() error = %v, want ErrOrderedPluginBackendMissing", err)
	}
}

func TestValidateOrderedPluginBackends_RejectsMissingBackendReference(t *testing.T) {
	state := loadBackendPluginState(t, testLoaderModuleCustomerA, "other", false)
	cfg := fileWithPluginBackendOrder(t, testLoaderModuleCustomerA+"."+testLoaderBackendName)

	err := ValidateOrderedPluginBackends(cfg, state)
	if !errors.Is(err, ErrOrderedPluginBackendMissing) {
		t.Fatalf("ValidateOrderedPluginBackends() error = %v, want ErrOrderedPluginBackendMissing", err)
	}
}

func TestValidateOrderedPluginBackends_RejectsReferencedOptionalModuleFailure(t *testing.T) {
	state := loadBackendPluginState(t, testLoaderModuleCustomerA, testLoaderBackendName, true)
	cfg := fileWithPluginBackendOrder(t, testLoaderModuleCustomerA+"."+testLoaderBackendName)

	err := ValidateOrderedPluginBackends(cfg, state)
	if !errors.Is(err, ErrOrderedPluginBackendMissing) {
		t.Fatalf("ValidateOrderedPluginBackends() error = %v, want ErrOrderedPluginBackendMissing", err)
	}
}

func writeLoaderArtifact(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "plugin.so")
	if err := os.WriteFile(path, []byte("fake plugin"), 0o600); err != nil {
		t.Fatalf("write fake plugin artifact: %v", err)
	}

	return path
}

func verifiedLoaderModule(name string, artifact string, mutate func(*config.PluginModule)) VerifiedModule {
	module := config.PluginModule{
		Name: name,
		Type: config.PluginModuleTypeGo,
		Path: artifact,
	}
	if mutate != nil {
		mutate(&module)
	}

	return VerifiedModule{
		Module:       module,
		ArtifactPath: artifact,
	}
}

func validLoaderMetadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:       testPluginModuleName,
		Version:    testLoaderPluginVersion,
		APIVersion: pluginapi.APIVersion,
	}
}

func loadBackendPluginState(t *testing.T, moduleName string, backendName string, failOptional bool) *State {
	t.Helper()

	artifact := writeLoaderArtifact(t)
	opener := fakeFactoryOpener(artifact, func() (pluginapi.Plugin, error) {
		if failOptional {
			return nil, errors.New("optional plugin unavailable")
		}

		return fakePlugin{
			metadata: validLoaderMetadata(),
			register: func(registrar pluginapi.Registrar) error {
				return registrar.RegisterBackend(fakeLoaderBackend{name: backendName})
			},
		}, nil
	})

	state, err := NewLoader(WithOpener(opener)).Load([]VerifiedModule{
		verifiedLoaderModule(moduleName, artifact, func(module *config.PluginModule) {
			module.Optional = failOptional
		}),
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	return state
}

func fileWithPluginBackendOrder(t *testing.T, qualifiedName string) *config.FileSettings {
	t.Helper()

	backend := &config.Backend{}
	if err := backend.Set(definitions.BackendPluginName + "(" + qualifiedName + ")"); err != nil {
		t.Fatalf("Backend.Set() error = %v", err)
	}

	return &config.FileSettings{
		Server: &config.ServerSection{Backends: []*config.Backend{backend}},
	}
}

type fakeOpener map[string]fakeHandle

func (o fakeOpener) Open(path string) (PluginHandle, error) {
	handle, ok := o[path]
	if !ok {
		return nil, fmt.Errorf("unexpected plugin path %s", path)
	}

	return handle, nil
}

func fakeFactoryOpener(path string, factory func() (pluginapi.Plugin, error)) fakeOpener {
	return fakeOpener{
		path: fakeHandle{symbol: factory},
	}
}

type fakeHandle struct {
	symbol    any
	lookupErr error
}

func (h fakeHandle) Lookup(string) (any, error) {
	if h.lookupErr != nil {
		return nil, h.lookupErr
	}

	return h.symbol, nil
}

type fakePlugin struct {
	register func(pluginapi.Registrar) error
	metadata pluginapi.Metadata
	id       int
}

func (p fakePlugin) Metadata() pluginapi.Metadata {
	return p.metadata
}

func (p fakePlugin) Register(registrar pluginapi.Registrar) error {
	if p.register == nil {
		return nil
	}

	return p.register(registrar)
}

type fakeLoaderBackend struct {
	name string
}

func (b fakeLoaderBackend) Name() string {
	return b.name
}

func (b fakeLoaderBackend) VerifyPassword(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
	return pluginapi.BackendResult{}, nil
}

func (b fakeLoaderBackend) ListAccounts(context.Context, pluginapi.AccountListRequest) (pluginapi.AccountListResult, error) {
	return pluginapi.AccountListResult{}, nil
}

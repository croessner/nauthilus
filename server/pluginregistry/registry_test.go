package pluginregistry

import (
	"context"
	"errors"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
)

const (
	testRegistryBackendName     = "passdb"
	testRegistryConfigPath      = "/var/lib/geoip.mmdb"
	testRegistryEnvironmentName = "environment"
	testRegistryHookName        = "hook"
	testRegistryModuleCustomerA = "customer_a"
	testRegistryModuleCustomerB = "customer_b"
	testRegistryModuleGeoIP     = "geoip"
	testRegistryPolicyAttribute = "plugin.geoip.country"
	testRegistryRemoteSource    = "customer_a.remote_source"
)

func TestRegistrar_RejectsDuplicateQualifiedComponentName(t *testing.T) {
	registry := NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})
	backend := fakeBackend{name: testRegistryBackendName}

	if err := registrar.RegisterBackend(backend); err != nil {
		t.Fatalf("RegisterBackend() error = %v", err)
	}

	err := registrar.RegisterBackend(backend)
	if !errors.Is(err, ErrDuplicateComponent) {
		t.Fatalf("RegisterBackend() error = %v, want ErrDuplicateComponent", err)
	}
}

func TestRegistrar_AllowsSameLocalNameAcrossModuleNamespaces(t *testing.T) {
	registry := NewRegistry()

	first := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleCustomerA})
	if err := first.RegisterBackend(fakeBackend{name: testRegistryBackendName}); err != nil {
		t.Fatalf("first RegisterBackend() error = %v", err)
	}

	if err := first.Commit(); err != nil {
		t.Fatalf("first Commit() error = %v", err)
	}

	second := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleCustomerB})
	if err := second.RegisterBackend(fakeBackend{name: testRegistryBackendName}); err != nil {
		t.Fatalf("second RegisterBackend() error = %v", err)
	}

	if err := second.Commit(); err != nil {
		t.Fatalf("second Commit() error = %v", err)
	}

	if _, ok := registry.Lookup(testRegistryModuleCustomerA + "." + testRegistryBackendName); !ok {
		t.Fatal("missing customer_a.passdb component")
	}

	if _, ok := registry.Lookup(testRegistryModuleCustomerB + "." + testRegistryBackendName); !ok {
		t.Fatal("missing customer_b.passdb component")
	}
}

func TestRegistrar_StagesComponentsUntilCommit(t *testing.T) {
	registry := NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})

	if err := registrar.RegisterBackend(fakeBackend{name: testRegistryBackendName}); err != nil {
		t.Fatalf("RegisterBackend() error = %v", err)
	}

	if _, ok := registry.Lookup(testRegistryModuleGeoIP + "." + testRegistryBackendName); ok {
		t.Fatal("component is globally visible before Commit()")
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	if _, ok := registry.Lookup(testRegistryModuleGeoIP + "." + testRegistryBackendName); !ok {
		t.Fatal("component is not globally visible after Commit()")
	}
}

func TestRegistrar_RejectsDisallowedCapability(t *testing.T) {
	registrar := NewRegistry().NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})

	err := registrar.RequireCapability(pluginapi.CapabilityCredentials)
	if !errors.Is(err, ErrCapabilityNotAllowed) {
		t.Fatalf("RequireCapability() error = %v, want ErrCapabilityNotAllowed", err)
	}
}

func TestRegistrar_RecordsAllowedCapability(t *testing.T) {
	registrar := NewRegistry().NewRegistrar(config.PluginModule{
		Name:              testRegistryModuleGeoIP,
		AllowCapabilities: []pluginapi.Capability{pluginapi.CapabilityCredentials},
	})

	if err := registrar.RequireCapability(pluginapi.CapabilityCredentials); err != nil {
		t.Fatalf("RequireCapability() error = %v", err)
	}

	capabilities := registrar.Capabilities()
	if len(capabilities) != 1 || capabilities[0] != pluginapi.CapabilityCredentials {
		t.Fatalf("Capabilities() = %#v, want credentials", capabilities)
	}
}

func TestRegistrar_RejectsCapabilityOutsideAllowlist(t *testing.T) {
	registrar := NewRegistry().NewRegistrar(config.PluginModule{
		Name:              testRegistryModuleGeoIP,
		AllowCapabilities: []pluginapi.Capability{pluginapi.CapabilityCredentials},
	})

	err := registrar.RequireCapability(pluginapi.Capability("network"))
	if !errors.Is(err, ErrCapabilityNotAllowed) {
		t.Fatalf("RequireCapability() error = %v, want ErrCapabilityNotAllowed", err)
	}
}

func TestRegistrar_AcceptsOrdinaryCapabilityWithoutAllowlist(t *testing.T) {
	registrar := NewRegistry().NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})

	if err := registrar.RequireCapability(pluginapi.Capability("metrics")); err != nil {
		t.Fatalf("RequireCapability() error = %v", err)
	}
}

func TestRegistrar_RegistersAllComponentSlots(t *testing.T) {
	registry := NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})

	registrations := []func() error{
		func() error { return registrar.RegisterInitTask(fakeInitTask{name: "init"}) },
		func() error {
			return registrar.RegisterEnvironmentSource(fakeEnvironmentSource{name: testRegistryEnvironmentName})
		},
		func() error { return registrar.RegisterSubjectSource(fakeSubjectSource{name: "subject"}) },
		func() error { return registrar.RegisterBackend(fakeBackend{name: testRegistryBackendName}) },
		func() error { return registrar.RegisterObligationTarget(fakeObligationTarget{name: "obligation"}) },
		func() error { return registrar.RegisterPostActionTarget(fakePostActionTarget{name: "post_action"}) },
		func() error { return registrar.RegisterHook(fakeHook{name: testRegistryHookName}) },
	}
	for index, register := range registrations {
		if err := register(); err != nil {
			t.Fatalf("registration %d error = %v", index, err)
		}
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	assertComponentSlot(t, registry.InitTasks(), ComponentKindInitTask)
	assertComponentSlot(t, registry.EnvironmentSources(), ComponentKindEnvironmentSource)
	assertComponentSlot(t, registry.SubjectSources(), ComponentKindSubjectSource)
	assertComponentSlot(t, registry.Backends(), ComponentKindBackend)
	assertComponentSlot(t, registry.ObligationTargets(), ComponentKindObligationTarget)
	assertComponentSlot(t, registry.PostActionTargets(), ComponentKindPostActionTarget)
	assertComponentSlot(t, registry.Hooks(), ComponentKindHook)
}

func TestRegistrar_QualifiesSourceDependencies(t *testing.T) {
	registry := NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})

	source := fakeEnvironmentSource{
		name:     testRegistryEnvironmentName,
		requires: []string{"local_cache", testRegistryRemoteSource},
		after:    []string{"warmup"},
	}
	if err := registrar.RegisterEnvironmentSource(source); err != nil {
		t.Fatalf("RegisterEnvironmentSource() error = %v", err)
	}

	component := registrar.Components()[0]
	if got := component.SourceDescriptor.Requires; !slicesEqual(got, []string{"geoip.local_cache", testRegistryRemoteSource}) {
		t.Fatalf("Requires = %#v", got)
	}

	if got := component.SourceDescriptor.After; !slicesEqual(got, []string{"geoip.warmup"}) {
		t.Fatalf("After = %#v", got)
	}
}

func TestRegistrar_RejectsInvalidDescriptor(t *testing.T) {
	registrar := NewRegistry().NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})

	err := registrar.RegisterHook(fakeHook{name: testRegistryHookName, path: "relative"})
	if !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("RegisterHook() error = %v, want ErrInvalidDescriptor", err)
	}
}

func TestRegistrar_RegistersPolicyAttributeHandoff(t *testing.T) {
	policyAttributes := policyregistry.NewAttributeRegistry()
	registry := NewRegistry(WithPolicyAttributeRegistrar(policyAttributes))
	registrar := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})

	if err := registrar.RegisterPolicyAttribute(validPluginPolicyAttribute()); err != nil {
		t.Fatalf("RegisterPolicyAttribute() error = %v", err)
	}

	if _, ok := policyAttributes.Lookup(testRegistryPolicyAttribute); ok {
		t.Fatal("policy attribute was handed off before Commit()")
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	definition, ok := policyAttributes.Lookup(testRegistryPolicyAttribute)
	if !ok {
		t.Fatal("policy attribute was not handed off")
	}

	if definition.Source != policyregistry.SourcePlugin {
		t.Fatalf("Source = %q, want plugin", definition.Source)
	}

	if definition.Stage != policy.StagePreAuth {
		t.Fatalf("Stage = %q, want pre_auth", definition.Stage)
	}
}

func TestConfigView_GetSubAndStrictDecode(t *testing.T) {
	view := NewConfigView(map[string]any{
		"database": map[string]any{
			"path": testRegistryConfigPath,
		},
	})

	value, ok := view.Get("database.path")
	if !ok || value != testRegistryConfigPath {
		t.Fatalf("Get() = %#v, %v; want path", value, ok)
	}

	var decoded struct {
		Path string `mapstructure:"path"`
	}
	if err := view.Sub("database").Decode(&decoded); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if decoded.Path != testRegistryConfigPath {
		t.Fatalf("Decode() path = %q", decoded.Path)
	}

	err := view.Decode(&decoded)
	if err == nil {
		t.Fatal("Decode() error = nil, want strict unused-field error")
	}
}

func assertComponentSlot(t *testing.T, components []Component, kind ComponentKind) {
	t.Helper()

	if len(components) != 1 {
		t.Fatalf("%s components len = %d, want 1", kind, len(components))
	}

	if components[0].Kind != kind {
		t.Fatalf("component kind = %q, want %q", components[0].Kind, kind)
	}
}

func slicesEqual(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}

	return true
}

func validPluginPolicyAttribute() pluginapi.AttributeDefinition {
	return pluginapi.AttributeDefinition{
		ID:          testRegistryPolicyAttribute,
		Description: "GeoIP country code emitted by a native plugin.",
		Stage:       pluginapi.PolicyStagePreAuth,
		Operations:  []pluginapi.PolicyOperation{pluginapi.PolicyOperationAuthenticate},
		Category:    pluginapi.AttributeCategoryEnvironment,
		Type:        pluginapi.AttributeTypeString,
		Details: map[string]pluginapi.DetailDefinition{
			"country": {
				Type:        pluginapi.AttributeTypeString,
				Sensitivity: pluginapi.DetailSensitivityInternal,
			},
		},
	}
}

type fakeInitTask struct {
	name string
}

func (t fakeInitTask) Name() string {
	return t.name
}

func (t fakeInitTask) Start(context.Context, pluginapi.InitContext) error {
	return nil
}

func (t fakeInitTask) Stop(context.Context) error {
	return nil
}

type fakeEnvironmentSource struct {
	requires []string
	after    []string
	name     string
}

func (s fakeEnvironmentSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{
		Timeout:     time.Second,
		Name:        s.name,
		Requires:    s.requires,
		After:       s.after,
		AbortPolicy: pluginapi.AbortPolicyNone,
	}
}

func (s fakeEnvironmentSource) Evaluate(context.Context, pluginapi.EnvironmentRequest) (pluginapi.EnvironmentResult, error) {
	return pluginapi.EnvironmentResult{}, nil
}

type fakeSubjectSource struct {
	name string
}

func (s fakeSubjectSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{
		Timeout:     time.Second,
		Name:        s.name,
		AbortPolicy: pluginapi.AbortPolicyNone,
	}
}

func (s fakeSubjectSource) Evaluate(context.Context, pluginapi.SubjectRequest) (pluginapi.SubjectResult, error) {
	return pluginapi.SubjectResult{}, nil
}

type fakeBackend struct {
	name string
}

func (b fakeBackend) Name() string {
	return b.name
}

func (b fakeBackend) VerifyPassword(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
	return pluginapi.BackendResult{}, nil
}

func (b fakeBackend) ListAccounts(context.Context, pluginapi.AccountListRequest) (pluginapi.AccountListResult, error) {
	return pluginapi.AccountListResult{}, nil
}

type fakeObligationTarget struct {
	name string
}

func (t fakeObligationTarget) Name() string {
	return t.name
}

func (t fakeObligationTarget) Execute(context.Context, pluginapi.ObligationRequest) (pluginapi.ObligationResult, error) {
	return pluginapi.ObligationResult{}, nil
}

type fakePostActionTarget struct {
	name string
}

func (t fakePostActionTarget) Name() string {
	return t.name
}

func (t fakePostActionTarget) Enqueue(context.Context, pluginapi.PostActionRequest) (pluginapi.PostActionEnqueueResult, error) {
	return pluginapi.PostActionEnqueueResult{}, nil
}

type fakeHook struct {
	name string
	path string
}

func (h fakeHook) Descriptor() pluginapi.HookDescriptor {
	path := h.path
	if path == "" {
		path = "/hook"
	}

	return pluginapi.HookDescriptor{
		Timeout:      time.Second,
		Name:         h.name,
		Method:       "GET",
		Path:         path,
		Scope:        pluginapi.HookScopeInternal,
		Auth:         pluginapi.HookAuthToken,
		MaxBodyBytes: 1024,
	}
}

func (h fakeHook) Serve(context.Context, pluginapi.HookRequest) (pluginapi.HookResponse, error) {
	return pluginapi.HookResponse{}, nil
}

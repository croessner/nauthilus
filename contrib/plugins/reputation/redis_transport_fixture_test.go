//go:build reputation_integration

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/policy/admission"
	"github.com/croessner/nauthilus/v4/server/policy/callerauth"
	"github.com/croessner/nauthilus/v4/server/policy/catalogcompile"
	"github.com/croessner/nauthilus/v4/server/policy/configinput"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
	"go.yaml.in/yaml/v3"
)

const transportTestPassword = "isolated-reputation-test"

type transportTestThrottler struct{}

// BeforeAttempt leaves rate admission to the real configured admission authority in this isolated fixture.
func (transportTestThrottler) BeforeAttempt(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// RecordFailure has no external state in the isolated authentication fixture.
func (transportTestThrottler) RecordFailure(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// RecordSuccess has no external state in the isolated authentication fixture.
func (transportTestThrottler) RecordSuccess(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// transportPolicyInput loads the actual operator example with a disposable credential and both unary transports.
func transportPolicyInput(t *testing.T) configinput.UnifiedPolicyInput {
	t.Helper()

	content, err := os.ReadFile("../../../server/docs/examples/go_plugin_reputation.yml")
	requireNoError(t, err)

	var raw map[string]any
	requireNoError(t, yaml.Unmarshal(content, &raw))
	content, err = yaml.Marshal(map[string]any{"policy": raw["policy"]})
	requireNoError(t, err)

	content = []byte(strings.ReplaceAll(string(content), "${POLICY_REPUTATION_PASSWORD}", transportTestPassword))
	document, err := policyconfig.Decode("yaml", bytes.NewReader(content))
	requireNoError(t, err)

	document.Policy.API.GRPC.Enabled = true
	normalized, err := configinput.Normalize(t.Context(), document)
	requireNoError(t, err)

	return normalized
}

// transportNativeBindings registers actual providers and retains their immutable module generation.
func transportNativeBindings(t *testing.T, plugin *Plugin) *pluginruntime.GenerationBindings {
	t.Helper()

	registry := pluginregistry.NewRegistry()
	artifact := filepath.Join(t.TempDir(), "reputation-fixture.so")
	requireNoError(t, os.WriteFile(artifact, []byte("in-process-native-fixture"), 0600))
	module := config.PluginModule{Name: pluginName, Type: config.PluginModuleTypeGo, Path: artifact, Config: testConfigMap(t)}
	registrar := registry.NewRegistrar(module)
	requireNoError(t, plugin.Register(registrar))
	requireNoError(t, registrar.Commit())

	digest, err := pluginloader.DigestArtifact(artifact)
	requireNoError(t, err)
	bindings, err := pluginruntime.CaptureGenerationBindings([]pluginloader.ModuleInstance{{Module: module,
		Descriptors: registrar.Components(), ArtifactPath: artifact, ArtifactDigest: digest, ModuleName: pluginName, Status: pluginloader.ModuleStatusRegistered}})
	requireNoError(t, err)

	return bindings
}

// newReputationTransportService uses the real catalog, caller authentication, admission and selected native effects.
func newReputationTransportService(t *testing.T) (*decisionservice.DecisionService, *Plugin) {
	t.Helper()
	_, facade := localReputationRedis(t)
	plugin := NewPlugin()
	bindings := transportNativeBindings(t, plugin)
	host := pluginruntime.NewHost(pluginruntime.WithConfig(pluginregistry.NewConfigView(testAdmissionMap())), pluginruntime.WithRedis(facade), pluginruntime.WithOpaqueIdentifierTagger(manifestTestTagger(t, false)))
	requireNoError(t, plugin.Start(t.Context(), host))
	normalized := transportPolicyInput(t)
	supervisor, err := effectsupervisor.New(effectsupervisor.Config{Lifetime: t.Context(), Capacity: 4, Workers: 1})
	requireNoError(t, err)
	t.Cleanup(func() { requireNoError(t, supervisor.Shutdown(context.Background())) })
	preparation, err := configinput.PrepareConfiguredNativeGeneration(t.Context(), configinput.ConfiguredNativeGenerationInput{Policy: normalized.Policy, Bindings: bindings, PostActionAcceptance: supervisor})
	requireNoError(t, err)
	contributors, err := normalized.Contributors(t.Context(), supervisor)
	requireNoError(t, err)

	var activations []registry.TargetActivation

	for _, activation := range normalized.Activations {
		if activation.Target().String() == "reputation/observe" {
			activations = append(activations, activation)
		}
	}

	catalog, err := catalogcompile.NewTargetCatalogCompiler(contributors...).Compile(t.Context(), activations)
	requireNoError(t, err)
	requireNoError(t, preparation.Bindings.ValidateCatalog(catalog))

	store := policyruntime.NewGenerationStore()
	coordinator, err := policyruntime.NewCoordinator(policyruntime.CoordinatorConfig{Store: store, Slots: reputationTransportSlots(normalized, catalog, preparation)})
	requireNoError(t, err)
	_, err = coordinator.Apply(t.Context(), policyruntime.PrepareInput{Config: &config.FileSettings{Server: &config.ServerSection{}, Policy: normalized.Policy}, ID: 1})
	requireNoError(t, err)
	source, err := decisionservice.NewStoreGenerationSource(store)
	requireNoError(t, err)
	service, err := decisionservice.NewDecisionService(source)
	requireNoError(t, err)
	t.Cleanup(func() { requireNoError(t, store.Shutdown(context.Background())) })

	return service, plugin
}

// reputationTransportSlots binds one coherent generation to the example's actual authorities.
func reputationTransportSlots(normalized configinput.UnifiedPolicyInput, catalog *policyruntime.TargetCatalog, preparation policyruntime.ExtensionPreparation) policyruntime.PreparationSlots {
	return policyruntime.PreparationSlots{
		Policy: policyruntime.PolicyPreparationFunc(func(ctx context.Context, input policyruntime.PreparationInput) (policyruntime.PolicyPreparation, error) {
			prepared, err := configinput.PreparePolicy(ctx, input.ID(), policyconfig.PolicyConfig{})
			return policyruntime.PolicyPreparation{Policy: prepared}, err
		}),
		Extensions: policyruntime.ExtensionPreparationFunc(func(context.Context, policyruntime.PreparationInput) (policyruntime.ExtensionPreparation, error) {
			return preparation, nil
		}),
		Catalog: policyruntime.CatalogPreparationFunc(func(context.Context, policyruntime.CatalogPreparationInput) (policyruntime.CatalogPreparation, error) {
			return policyruntime.CatalogPreparation{Catalog: catalog}, nil
		}),
		CallerAuthentication: policyruntime.CallerAuthenticationPreparationFunc(func(context.Context, policyruntime.AuthorityPreparationInput) (policyruntime.CallerAuthenticationPreparation, error) {
			authentication := normalized.CallerAuthentication()
			authentication.Throttler = transportTestThrottler{}
			authentication.TransportCapabilities = callerauth.TransportCapabilities{HTTPProtected: true, GRPCProtected: true}

			return callerauth.Prepare(authentication)
		}),
		Admission: policyruntime.AdmissionPreparationFunc(func(_ context.Context, input policyruntime.AdmissionPreparationInput) (policyruntime.AdmissionPreparation, error) {
			return admission.Prepare(normalized.CallerAdmission(), input.TargetCatalog(), input.CredentialProfiles())
		}),
		Settings: policyruntime.SettingsPreparationFunc(func(context.Context, policyruntime.SettingsPreparationInput) (policyruntime.SettingsPreparation, error) {
			return policyruntime.SettingsPreparation{MessageResolver: localization.NewResolver(localization.NewMapCatalog(nil), "en"), Settings: policyruntime.GenerationSettings{Limits: policyruntime.DecisionLimits{EvaluationTimeout: 2 * time.Second, PostActionBudget: time.Second, MaxDiagnosticsEntries: 8}, Reports: policyruntime.DecisionReportSettings{MaxEntries: 8}}}, nil
		}),
		Application: decisionservice.NewRuntimeApplicationPreparationSlot(),
	}
}

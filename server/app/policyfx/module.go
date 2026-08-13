// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Package policyfx wires the sole atomic policy runtime generation coordinator.
package policyfx

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/app/reloadfx"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginruntime"
	"github.com/croessner/nauthilus/v3/server/policy/compiler"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"

	"go.uber.org/fx"
)

const (
	defaultEvaluationTimeout     = 5 * time.Second
	defaultPostActionBudget      = 30 * time.Second
	defaultDiagnosticEntryLimit  = 128
	defaultInternalReportEntries = 256
)

var errPolicyDecisionUnavailable = errors.New("policy decision authority is not active")

var errPolicyBindingsRestartRequired = errors.New("policy extension binding changes require restart")

var bindDefaultGenerationViewsOnce sync.Once
var bindDefaultGenerationViewsErr error

type snapshotPreparationSlot struct {
	compiler compiler.Compiler
}

type builtinExtensionPreparationSlot struct {
	acceptor effectsupervisor.Acceptor
	native   *pluginruntime.GenerationBindings
}

type targetCatalogPreparationSlot struct{}

type closedCallerAuthenticationSlot struct{}

type closedAdmissionSlot struct{}

type defaultSettingsPreparationSlot struct{}

type closedCallerAuthenticator struct{}

type closedAdmissionAuthority struct{}

type closedPostActionAcceptor struct{}

type preparedDefinitionContributor struct {
	contribution registry.DefinitionContribution
}

// Coordinator adapts config snapshots to the sole runtime generation protocol.
type Coordinator struct {
	runtime *policyruntime.Coordinator
}

// Module registers the atomic generation coordinator as the reload authority.
func Module() fx.Option {
	return fx.Options(
		fx.Provide(
			fx.Annotate(
				NewCoordinator,
				fx.As(new(reloadfx.GenerationCoordinator)),
			),
		),
	)
}

// NewCoordinator constructs the process-wide generation coordinator.
func NewCoordinator(logger *slog.Logger) (*Coordinator, error) {
	store := policyruntime.DefaultGenerationStore()

	bindDefaultGenerationViewsOnce.Do(func() {
		bindDefaultGenerationViewsErr = bindDefaultGenerationViews(store)
	})

	if bindDefaultGenerationViewsErr != nil {
		return nil, bindDefaultGenerationViewsErr
	}

	native, err := captureLoadedNativeBindings()
	if err != nil {
		return nil, err
	}

	return newCoordinatorWithNativeBindings(store, compiler.NewCompiler(), logger, native)
}

// bindDefaultGenerationViews installs read-only legacy projections exactly once.
func bindDefaultGenerationViews(store *policyruntime.GenerationStore) error {
	if err := policyruntime.BindDefaultStoreToGeneration(store); err != nil {
		return err
	}

	return config.BindActiveFileSource(func() config.File {
		generation := store.Active()
		if generation == nil {
			return nil
		}

		return generation.Config()
	})
}

// Apply prepares, validates, and commits one complete config-derived generation.
func (c *Coordinator) Apply(ctx context.Context, snapshot configfx.Snapshot) error {
	if c == nil || c.runtime == nil {
		return policyruntime.ErrInvalidGeneration
	}

	_, err := c.runtime.Apply(ctx, policyruntime.PrepareInput{
		Config: snapshot.File,
		ID:     snapshot.Version,
	})

	return err
}

// newCoordinator assembles explicit fail-closed preparation slots over one store.
func newCoordinator(
	store *policyruntime.GenerationStore,
	policyCompiler compiler.Compiler,
	logger *slog.Logger,
) (*Coordinator, error) {
	native, err := pluginruntime.CaptureGenerationBindings(nil)
	if err != nil {
		return nil, err
	}

	return newCoordinatorWithNativeBindings(store, policyCompiler, logger, native)
}

// newCoordinatorWithNativeBindings assembles one coordinator from the startup-loaded native snapshot.
func newCoordinatorWithNativeBindings(
	store *policyruntime.GenerationStore,
	policyCompiler compiler.Compiler,
	logger *slog.Logger,
	native *pluginruntime.GenerationBindings,
) (*Coordinator, error) {
	acceptor := &closedPostActionAcceptor{}

	coordinator, err := policyruntime.NewCoordinator(policyruntime.CoordinatorConfig{
		Store:  store,
		Logger: logger,
		Slots: policyruntime.PreparationSlots{
			Policy:               snapshotPreparationSlot{compiler: policyCompiler},
			Extensions:           builtinExtensionPreparationSlot{acceptor: acceptor, native: native},
			Catalog:              targetCatalogPreparationSlot{},
			CallerAuthentication: closedCallerAuthenticationSlot{},
			Admission:            closedAdmissionSlot{},
			Settings:             defaultSettingsPreparationSlot{},
			Application:          service.NewRuntimeApplicationPreparationSlot(),
		},
	})
	if err != nil {
		return nil, err
	}

	return &Coordinator{runtime: coordinator}, nil
}

// captureLoadedNativeBindings detaches the startup loader state before generation publication.
func captureLoadedNativeBindings() (*pluginruntime.GenerationBindings, error) {
	state, ok := pluginloader.DefaultState()
	if !ok {
		return pluginruntime.CaptureGenerationBindings(nil)
	}

	return pluginruntime.CaptureGenerationBindings(state.Instances())
}

// Prepare compiles the exact legacy policy view without publishing it.
func (s snapshotPreparationSlot) Prepare(
	ctx context.Context,
	input policyruntime.PreparationInput,
) (policyruntime.PolicyPreparation, error) {
	policyCompiler := s.compiler
	if policyCompiler == nil {
		policyCompiler = compiler.NewCompiler()
	}

	snapshot, err := policyCompiler.Compile(ctx, compiler.Input{
		Config: input.Config(), Generation: input.ID(),
	})
	if err != nil {
		return policyruntime.PolicyPreparation{}, err
	}

	return policyruntime.PolicyPreparation{Snapshot: snapshot}, nil
}

// Prepare captures immutable builtin definitions and closed extension bindings.
func (s builtinExtensionPreparationSlot) Prepare(
	ctx context.Context,
	input policyruntime.PreparationInput,
) (policyruntime.ExtensionPreparation, error) {
	if err := validateRestartBoundBindings(input.PreviousConfig(), input.Config(), s.native); err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	contribution, err := registry.NewBuiltinTargetContributor(s.acceptor).Contribute(ctx)
	if err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	bindings, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		NativeModules:        nativeModuleBindingInputs(s.native),
		PostActionAcceptance: s.acceptor,
	})
	if err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	return policyruntime.ExtensionPreparation{
		Definitions: []registry.DefinitionContribution{contribution},
		Bindings:    bindings,
	}, nil
}

// validateRestartBoundBindings rejects config changes without immutable adapter preparation.
func validateRestartBoundBindings(
	previous config.File,
	candidate config.File,
	native *pluginruntime.GenerationBindings,
) error {
	if previous != nil && candidate != nil {
		if !reflect.DeepEqual(previous.GetLua(), candidate.GetLua()) {
			return fmt.Errorf("%w: Lua configuration changed", errPolicyBindingsRestartRequired)
		}

		if !reflect.DeepEqual(previous.GetPlugins(), candidate.GetPlugins()) {
			return fmt.Errorf(
				"%w: %w: native plugin configuration changed",
				errPolicyBindingsRestartRequired,
				pluginruntime.ErrRestartRequired,
			)
		}
	}

	if err := native.ValidateArtifacts(); err != nil {
		return fmt.Errorf("%w: %w", errPolicyBindingsRestartRequired, err)
	}

	return nil
}

// nativeModuleBindingInputs maps loaded capabilities into generation-owned generic bindings.
func nativeModuleBindingInputs(
	bindings *pluginruntime.GenerationBindings,
) []policyruntime.NativeModuleBindingInput {
	modules := bindings.Modules()
	result := make([]policyruntime.NativeModuleBindingInput, 0, len(modules))

	for _, module := range modules {
		components := module.Components()
		componentInputs := make([]policyruntime.NativeComponentBindingInput, 0, len(components))

		for _, component := range components {
			componentInputs = append(componentInputs, policyruntime.NativeComponentBindingInput{
				Value:         component.Value,
				QualifiedName: component.QualifiedName,
				Kind:          string(component.Kind),
			})
		}

		capabilities := module.Capabilities()
		capabilityNames := make([]string, 0, len(capabilities))

		for _, capability := range capabilities {
			capabilityNames = append(capabilityNames, string(capability))
		}

		digest := module.ArtifactDigest()
		result = append(result, policyruntime.NativeModuleBindingInput{
			Components:     componentInputs,
			Capabilities:   capabilityNames,
			ModuleName:     module.ModuleName(),
			ArtifactPath:   module.ArtifactPath(),
			ArtifactDigest: hex.EncodeToString(digest[:]),
		})
	}

	return result
}

// Prepare compiles contributed definitions with no new production target activation.
func (targetCatalogPreparationSlot) Prepare(
	ctx context.Context,
	input policyruntime.CatalogPreparationInput,
) (policyruntime.CatalogPreparation, error) {
	definitions := input.Definitions()

	contributors := make([]registry.Contributor, 0, len(definitions))
	for _, definition := range definitions {
		contributors = append(contributors, preparedDefinitionContributor{contribution: definition})
	}

	catalog, err := compiler.NewTargetCatalogCompiler(contributors...).Compile(ctx, nil)
	if err != nil {
		return policyruntime.CatalogPreparation{}, err
	}

	return policyruntime.CatalogPreparation{Catalog: catalog}, nil
}

// Prepare installs an explicit rejecting caller authenticator until its owner slice lands.
func (closedCallerAuthenticationSlot) Prepare(
	context.Context,
	policyruntime.AuthorityPreparationInput,
) (policyruntime.CallerAuthenticationPreparation, error) {
	profiles, err := policyruntime.NewCredentialProfiles(nil)
	if err != nil {
		return policyruntime.CallerAuthenticationPreparation{}, err
	}

	return policyruntime.CallerAuthenticationPreparation{
		Authenticator: &closedCallerAuthenticator{},
		Credentials:   profiles,
	}, nil
}

// Prepare installs explicit rejecting admission until production client profiles land.
func (closedAdmissionSlot) Prepare(
	context.Context,
	policyruntime.AdmissionPreparationInput,
) (policyruntime.AdmissionPreparation, error) {
	profiles, err := policyruntime.NewAdmissionProfiles(nil)
	if err != nil {
		return policyruntime.AdmissionPreparation{}, err
	}

	return policyruntime.AdmissionPreparation{
		Authority: &closedAdmissionAuthority{},
		Profiles:  profiles,
	}, nil
}

// Prepare supplies bounded settings without introducing a production policy config root.
func (defaultSettingsPreparationSlot) Prepare(
	context.Context,
	policyruntime.SettingsPreparationInput,
) (policyruntime.SettingsPreparation, error) {
	return policyruntime.SettingsPreparation{Settings: policyruntime.GenerationSettings{
		Limits: policyruntime.DecisionLimits{
			EvaluationTimeout:     defaultEvaluationTimeout,
			PostActionBudget:      defaultPostActionBudget,
			MaxDiagnosticsEntries: defaultDiagnosticEntryLimit,
		},
		Reports: policyruntime.DecisionReportSettings{
			MaxEntries: defaultInternalReportEntries,
		},
	}}, nil
}

// Authenticate rejects all Policy callers before production credential profiles exist.
func (*closedCallerAuthenticator) Authenticate(
	context.Context,
	decision.AuthenticationInput,
) (decision.CallerContext, error) {
	return decision.CallerContext{}, errPolicyDecisionUnavailable
}

// Admit rejects all Policy requests before production admission profiles exist.
func (*closedAdmissionAuthority) Admit(
	context.Context,
	decision.CallerContext,
	decision.DecisionRequest,
) error {
	return errPolicyDecisionUnavailable
}

// Accept rejects detached work because no generic post-action adapter is active yet.
func (*closedPostActionAcceptor) Accept(
	context.Context,
	effectsupervisor.Plan,
) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, errPolicyDecisionUnavailable
}

// Contribute returns a detached immutable definition batch captured during preparation.
func (c preparedDefinitionContributor) Contribute(
	ctx context.Context,
) (registry.DefinitionContribution, error) {
	if err := ctx.Err(); err != nil {
		return registry.DefinitionContribution{}, err
	}

	return registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
		Ownership:  c.contribution.Ownership(),
		Targets:    c.contribution.Targets(),
		Schemas:    c.contribution.Schemas(),
		PolicySets: c.contribution.PolicySets(),
		Plans:      c.contribution.Plans(),
		Providers:  c.contribution.Providers(),
		Effects:    c.contribution.Effects(),
	})
}

var _ reloadfx.GenerationCoordinator = (*Coordinator)(nil)

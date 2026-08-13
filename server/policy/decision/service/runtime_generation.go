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

package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

type runtimeApplicationPreparationSlot struct{}

type storeGenerationSource struct {
	store *policyruntime.GenerationStore
}

type capturedFactProvider struct {
	provider policyruntime.FactProvider
}

type capturedSyncEffectProvider struct {
	provider policyruntime.SyncEffectProvider
}

type capturedPostActionProvider struct {
	provider policyruntime.PostActionProvider
}

type runtimeFactProviderCallCapturer interface {
	CaptureFactProviderCall() (policyruntime.FactProvider, error)
}

type runtimeSyncEffectCallCapturer interface {
	CaptureSyncEffectCall() (policyruntime.SyncEffectProvider, error)
}

type runtimePostActionCallCapturer interface {
	CapturePostActionCall() (policyruntime.PostActionProvider, error)
}

// NewRuntimeApplicationPreparationSlot returns the stable Decision Service assembly slot.
func NewRuntimeApplicationPreparationSlot() policyruntime.ApplicationPreparationSlot {
	return runtimeApplicationPreparationSlot{}
}

// NewStoreGenerationSource returns the sole Decision Service capture seam over server state.
func NewStoreGenerationSource(store *policyruntime.GenerationStore) (GenerationSource, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: generation store is required", ErrDecisionServiceDependencyMissing)
	}

	return &storeGenerationSource{store: store}, nil
}

// Prepare assembles the private evaluator and sealed application generation off-side.
func (runtimeApplicationPreparationSlot) Prepare(
	_ context.Context,
	input policyruntime.ApplicationPreparationInput,
) (policyruntime.ApplicationPreparation, error) {
	bindings := input.Bindings()
	if bindings == nil {
		return policyruntime.ApplicationPreparation{}, fmt.Errorf(
			"%w: prepared bindings are required",
			ErrDecisionServiceDependencyMissing,
		)
	}

	settings := input.Settings()

	evaluator, err := newCheckpointRuntime(checkpointRuntimeConfig{
		catalog:           input.TargetCatalog(),
		factProviders:     capturedFactProviderBindings(bindings),
		syncEffects:       capturedSyncEffectBindings(bindings),
		postActions:       capturedPostActionBindings(bindings),
		evaluationTimeout: settings.Limits.EvaluationTimeout,
		postActionBudget:  settings.Limits.PostActionBudget,
	})
	if err != nil {
		return policyruntime.ApplicationPreparation{}, err
	}

	generation, err := newRuntimeGeneration(input.ID(), runtimeGenerationDependencies{
		authenticator: input.CallerAuthenticator(),
		admission:     input.AdmissionAuthority(),
		evaluator:     evaluator,
		supervisor:    bindings.PostActionAcceptance(),
	})
	if err != nil {
		return policyruntime.ApplicationPreparation{}, err
	}

	application, ok := generation.(policyruntime.Application)
	if !ok {
		return policyruntime.ApplicationPreparation{}, fmt.Errorf(
			"%w: application generation does not expose runtime identity",
			ErrDecisionServiceDependencyMissing,
		)
	}

	return policyruntime.ApplicationPreparation{Application: application}, nil
}

// WithGeneration unwraps one application authority under the store's complete lease scope.
func (s *storeGenerationSource) WithGeneration(
	ctx context.Context,
	use func(Generation) error,
) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("%w: generation store is required", ErrDecisionGenerationUnavailable)
	}

	err := s.store.WithActive(ctx, func(generation *policyruntime.Generation) error {
		application := generation.Application()

		captured, ok := application.(Generation)
		if !ok || nilDependency(captured) || application.GenerationID() != generation.ID() {
			return fmt.Errorf("%w: generation application authority is incomplete", ErrDecisionGenerationUnavailable)
		}

		return use(captured)
	})
	if errors.Is(err, policyruntime.ErrGenerationUnavailable) ||
		errors.Is(err, policyruntime.ErrGenerationStoreClosed) {
		return fmt.Errorf("%w: %v", ErrDecisionGenerationUnavailable, err)
	}

	return err
}

// Collect adapts the stable generation binding contract to the private evaluator contract.
func (p capturedFactProvider) Collect(
	ctx context.Context,
	input factProviderInput,
) ([]providedFact, error) {
	capturedInput, err := policyruntime.NewFactProviderInput(input.facts, input.target, input.checkpoint)
	if err != nil {
		return nil, err
	}

	provided, err := p.provider.Collect(ctx, capturedInput)
	if err != nil {
		return nil, err
	}

	result := make([]providedFact, 0, len(provided))
	for _, fact := range provided {
		result = append(result, providedFact{
			id: fact.ID(), value: fact.Value(), category: fact.Category(),
		})
	}

	return result, nil
}

// captureFactProviderCall adapts one pre-retained runtime provider call.
func (p capturedFactProvider) captureFactProviderCall() (factProvider, error) {
	capturer, ok := p.provider.(runtimeFactProviderCallCapturer)
	if !ok {
		return p, nil
	}

	provider, err := capturer.CaptureFactProviderCall()
	if err != nil {
		return nil, err
	}

	return capturedFactProvider{provider: provider}, nil
}

// Execute adapts one private selected effect to the stable generation binding contract.
func (p capturedSyncEffectProvider) Execute(
	ctx context.Context,
	input effectExecution,
) effectsupervisor.Result {
	captured, err := capturedEffectExecution(input)
	if err != nil {
		return effectsupervisor.Failed("invalid_generation_binding")
	}

	return p.provider.Execute(ctx, captured)
}

// captureSyncEffectCall adapts one pre-retained runtime effect call.
func (p capturedSyncEffectProvider) captureSyncEffectCall() (syncEffectProvider, error) {
	capturer, ok := p.provider.(runtimeSyncEffectCallCapturer)
	if !ok {
		return p, nil
	}

	provider, err := capturer.CaptureSyncEffectCall()
	if err != nil {
		return nil, err
	}

	return capturedSyncEffectProvider{provider: provider}, nil
}

// Prepare adapts one private post action to the stable generation binding contract.
func (p capturedPostActionProvider) Prepare(
	ctx context.Context,
	input effectExecution,
) (effectsupervisor.Work, error) {
	captured, err := capturedEffectExecution(input)
	if err != nil {
		return nil, err
	}

	return p.provider.Prepare(ctx, captured)
}

// capturePostActionCall adapts one pre-retained runtime preparation call.
func (p capturedPostActionProvider) capturePostActionCall() (postActionProvider, error) {
	capturer, ok := p.provider.(runtimePostActionCallCapturer)
	if !ok {
		return p, nil
	}

	provider, err := capturer.CapturePostActionCall()
	if err != nil {
		return nil, err
	}

	return capturedPostActionProvider{provider: provider}, nil
}

// capturedFactProviderBindings converts detached prepared bindings for evaluator ownership.
func capturedFactProviderBindings(bindings *policyruntime.BindingSet) map[string]factProviderBinding {
	result := make(map[string]factProviderBinding)
	for id, binding := range bindings.FactProviders() {
		result[id] = factProviderBinding{
			provider: capturedFactProvider{provider: binding.Provider},
			source:   binding.Source, authority: binding.Authority, component: binding.Component,
		}
	}

	return result
}

// capturedSyncEffectBindings converts detached synchronous effect bindings.
func capturedSyncEffectBindings(bindings *policyruntime.BindingSet) map[string]syncEffectBinding {
	result := make(map[string]syncEffectBinding)
	for id, provider := range bindings.SyncEffects() {
		result[id] = syncEffectBinding{provider: capturedSyncEffectProvider{provider: provider}}
	}

	return result
}

// capturedPostActionBindings converts detached post-action bindings.
func capturedPostActionBindings(bindings *policyruntime.BindingSet) map[string]postActionBinding {
	result := make(map[string]postActionBinding)
	for id, provider := range bindings.PostActions() {
		result[id] = postActionBinding{provider: capturedPostActionProvider{provider: provider}}
	}

	return result
}

// capturedEffectExecution validates and owns one effect adapter invocation.
func capturedEffectExecution(input effectExecution) (policyruntime.EffectExecution, error) {
	return policyruntime.NewEffectExecution(policyruntime.EffectExecutionInput{
		Parameters: input.parameters,
		Target:     input.target,
		EffectID:   input.effectID,
		DecisionID: input.decisionID,
		Provider:   input.provider,
		Generation: input.generation,
		Ordinal:    input.ordinal,
	})
}

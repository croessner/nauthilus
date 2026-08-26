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
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

type serviceGenerationResource struct {
	disposals atomic.Int64
}

type servicePolicyModel struct {
	id uint64
}

// ClonePolicyModel returns a detached service-test model.
func (m *servicePolicyModel) ClonePolicyModel() policyruntime.PolicyModel {
	if m == nil {
		return (*servicePolicyModel)(nil)
	}

	clone := *m

	return &clone
}

// ValidatePolicyModel validates the service-test generation identity.
func (m *servicePolicyModel) ValidatePolicyModel() error {
	if m == nil || m.id == 0 {
		return policyruntime.ErrInvalidGeneration
	}

	return nil
}

// GenerationID returns the service-test generation identity.
func (m *servicePolicyModel) GenerationID() uint64 {
	if m == nil {
		return 0
	}

	return m.id
}

// Dispose records final generation retirement.
func (r *serviceGenerationResource) Dispose(context.Context) error {
	r.disposals.Add(1)

	return nil
}

// TestGenerationSourceCapturesCommittedDecisionApplication proves one application capture seam.
func TestGenerationSourceCapturesCommittedDecisionApplication(t *testing.T) {
	store := policyruntime.NewGenerationStore()
	coordinator := newServiceGenerationCoordinator(t, store)

	first, err := coordinator.Apply(context.Background(), policyruntime.PrepareInput{
		Config: &config.FileSettings{},
		ID:     1,
	})
	if err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}

	source, err := NewStoreGenerationSource(store)
	if err != nil {
		t.Fatalf("NewStoreGenerationSource() error = %v", err)
	}

	var capturedFirst Generation

	err = source.WithGeneration(context.Background(), func(generation Generation) error {
		capturedFirst = generation

		return nil
	})
	if err != nil {
		t.Fatalf("first WithGeneration() error = %v", err)
	}

	if capturedFirst.decisionGeneration().id != first.ID() {
		t.Fatalf("first captured generation = %d, want %d", capturedFirst.decisionGeneration().id, first.ID())
	}

	second, err := coordinator.Apply(context.Background(), policyruntime.PrepareInput{
		Config: &config.FileSettings{},
		ID:     2,
	})
	if err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}

	var capturedSecond Generation

	err = source.WithGeneration(context.Background(), func(generation Generation) error {
		capturedSecond = generation

		return nil
	})
	if err != nil {
		t.Fatalf("second WithGeneration() error = %v", err)
	}

	if capturedSecond.decisionGeneration().id != second.ID() {
		t.Fatalf("second captured generation = %d, want %d", capturedSecond.decisionGeneration().id, second.ID())
	}

	if capturedFirst.decisionGeneration().id != 1 {
		t.Fatal("previous capture changed after the next generation committed")
	}
}

// TestGenerationSessionRetainsOneApplicationAcrossConcurrentReload proves checkpoint consistency and release.
func TestGenerationSessionRetainsOneApplicationAcrossConcurrentReload(t *testing.T) {
	store := policyruntime.NewGenerationStore()
	firstResource := &serviceGenerationResource{}
	secondResource := &serviceGenerationResource{}
	firstEvaluator := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 1, "generation-one")}
	secondEvaluator := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 2, "generation-two")}
	coordinator := newTrackedServiceGenerationCoordinator(t, store, map[uint64]trackedServiceGeneration{
		1: {evaluator: firstEvaluator, resource: firstResource},
		2: {evaluator: secondEvaluator, resource: secondResource},
	})

	if err := applyTrackedServiceGeneration(coordinator, 1); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}

	source, err := NewStoreGenerationSource(store)
	if err != nil {
		t.Fatalf("NewStoreGenerationSource() error = %v", err)
	}

	service := mustDecisionService(t, source)

	err = service.WithSession(
		context.Background(),
		mustAuthorityInvocation(t, true),
		func(session DecisionSession) error {
			return exerciseSessionAcrossReload(t, session, coordinator, firstResource)
		},
	)
	if err != nil {
		t.Fatalf("DecisionService.WithSession() error = %v", err)
	}

	if got := firstResource.disposals.Load(); got != 1 {
		t.Fatalf("first resource disposals after session = %d, want 1", got)
	}

	if firstEvaluator.callCount() != 2 || secondEvaluator.callCount() != 0 {
		t.Fatalf(
			"checkpoint calls = first:%d second:%d, want first:2 second:0",
			firstEvaluator.callCount(),
			secondEvaluator.callCount(),
		)
	}

	if err = store.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	if got := secondResource.disposals.Load(); got != 1 {
		t.Fatalf("second resource disposals after shutdown = %d, want 1", got)
	}
}

// exerciseSessionAcrossReload proves both checkpoints retain the first generation owner.
func exerciseSessionAcrossReload(
	t *testing.T,
	session DecisionSession,
	coordinator *policyruntime.Coordinator,
	firstResource *serviceGenerationResource,
) error {
	t.Helper()

	evaluateSessionCheckpoints(t, session, []string{"pre_auth"})

	reload := make(chan error, 1)

	go func() {
		reload <- applyTrackedServiceGeneration(coordinator, 2)
	}()

	if err := <-reload; err != nil {
		return err
	}

	if got := firstResource.disposals.Load(); got != 0 {
		t.Fatalf("first resource disposals during session = %d, want 0", got)
	}

	evaluateSessionCheckpoints(t, session, []string{"auth_decision"})

	return nil
}

// applyTrackedServiceGeneration publishes one tracked Decision Service generation.
func applyTrackedServiceGeneration(coordinator *policyruntime.Coordinator, id uint64) error {
	_, err := coordinator.Apply(context.Background(), policyruntime.PrepareInput{
		Config: &config.FileSettings{},
		ID:     id,
	})

	return err
}

type trackedServiceGeneration struct {
	evaluator checkpointEvaluator
	resource  policyruntime.CandidateResource
}

// newTrackedServiceGenerationCoordinator builds generation-specific evaluators and resources.
func newTrackedServiceGenerationCoordinator(
	t *testing.T,
	store *policyruntime.GenerationStore,
	tracked map[uint64]trackedServiceGeneration,
) *policyruntime.Coordinator {
	t.Helper()

	bindings, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		PostActionAcceptance: &recordingEffectAcceptor{},
	})
	if err != nil {
		t.Fatalf("NewBindingSet() error = %v", err)
	}

	slots := serviceGenerationSlots(t, bindings)
	slots.CallerAuthentication = policyruntime.CallerAuthenticationPreparationFunc(func(
		context.Context,
		policyruntime.AuthorityPreparationInput,
	) (policyruntime.CallerAuthenticationPreparation, error) {
		return policyruntime.CallerAuthenticationPreparation{
			Authenticator: &recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)},
		}, nil
	})
	slots.Application = policyruntime.ApplicationPreparationFunc(func(
		_ context.Context,
		input policyruntime.ApplicationPreparationInput,
	) (policyruntime.ApplicationPreparation, error) {
		entry := tracked[input.ID()]

		material, materialErr := input.DecisionServiceMaterial()
		if materialErr != nil {
			return policyruntime.ApplicationPreparation{}, materialErr
		}

		generation, generationErr := newRuntimeGeneration(input.ID(), runtimeGenerationDependencies{
			material:      material,
			authenticator: input.CallerAuthenticator(),
			admission:     input.AdmissionAuthority(),
			evaluator:     entry.evaluator,
			supervisor:    bindings.PostActionAcceptance(),
		})
		if generationErr != nil {
			return policyruntime.ApplicationPreparation{}, generationErr
		}

		application := generation.(policyruntime.Application)

		return policyruntime.ApplicationPreparation{
			Application: application,
			Resources:   []policyruntime.CandidateResource{entry.resource},
		}, nil
	})

	coordinator, err := policyruntime.NewCoordinator(policyruntime.CoordinatorConfig{
		Store: store,
		Slots: slots,
	})
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	return coordinator
}

// newServiceGenerationCoordinator assembles one explicit generation with the production application seam.
func newServiceGenerationCoordinator(
	t *testing.T,
	store *policyruntime.GenerationStore,
) *policyruntime.Coordinator {
	t.Helper()

	bindings, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		PostActionAcceptance: &recordingEffectAcceptor{},
	})
	if err != nil {
		t.Fatalf("NewBindingSet() error = %v", err)
	}

	coordinator, err := policyruntime.NewCoordinator(policyruntime.CoordinatorConfig{
		Store: store,
		Slots: serviceGenerationSlots(t, bindings),
	})
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	return coordinator
}

// serviceGenerationSlots returns the explicit test preparation graph.
func serviceGenerationSlots(
	t *testing.T,
	bindings *policyruntime.BindingSet,
) policyruntime.PreparationSlots {
	return policyruntime.PreparationSlots{
		Policy:     policyruntime.PolicyPreparationFunc(prepareServicePolicy),
		Extensions: serviceExtensionPreparation(bindings),
		Catalog:    policyruntime.CatalogPreparationFunc(prepareServiceCatalog),
		CallerAuthentication: policyruntime.CallerAuthenticationPreparationFunc(func(
			context.Context,
			policyruntime.AuthorityPreparationInput,
		) (policyruntime.CallerAuthenticationPreparation, error) {
			return policyruntime.CallerAuthenticationPreparation{
				Authenticator: &recordingCallerAuthenticator{caller: mustAuthorityCaller(t, false)},
			}, nil
		}),
		Admission:   policyruntime.AdmissionPreparationFunc(prepareServiceAdmission),
		Settings:    policyruntime.SettingsPreparationFunc(prepareServiceSettings),
		Application: NewRuntimeApplicationPreparationSlot(),
	}
}

// prepareServicePolicy builds one empty identity-matched policy view.
func prepareServicePolicy(
	_ context.Context,
	input policyruntime.PreparationInput,
) (policyruntime.PolicyPreparation, error) {
	return policyruntime.PolicyPreparation{
		Policy: &servicePolicyModel{id: input.ID()},
	}, nil
}

// serviceExtensionPreparation captures the prepared binding set in one fake slot.
func serviceExtensionPreparation(
	bindings *policyruntime.BindingSet,
) policyruntime.ExtensionPreparationSlot {
	return policyruntime.ExtensionPreparationFunc(func(
		context.Context,
		policyruntime.PreparationInput,
	) (policyruntime.ExtensionPreparation, error) {
		return policyruntime.ExtensionPreparation{Bindings: bindings}, nil
	})
}

// prepareServiceCatalog builds an empty exact catalog for the capture seam test.
func prepareServiceCatalog(
	context.Context,
	policyruntime.CatalogPreparationInput,
) (policyruntime.CatalogPreparation, error) {
	catalog, err := policyruntime.NewTargetCatalog(nil)

	return policyruntime.CatalogPreparation{Catalog: catalog}, err
}

// prepareServiceAdmission installs an explicit fake admission authority.
func prepareServiceAdmission(
	context.Context,
	policyruntime.AdmissionPreparationInput,
) (policyruntime.AdmissionPreparation, error) {
	return policyruntime.AdmissionPreparation{Authority: &recordingAdmissionAuthority{}}, nil
}

// prepareServiceSettings returns valid bounded evaluation settings.
func prepareServiceSettings(
	context.Context,
	policyruntime.SettingsPreparationInput,
) (policyruntime.SettingsPreparation, error) {
	return policyruntime.SettingsPreparation{
		MessageResolver: localization.NewResolver(localization.NewMapCatalog(nil), "en"),
		Settings: policyruntime.GenerationSettings{
			Limits: policyruntime.DecisionLimits{
				EvaluationTimeout:     time.Second,
				PostActionBudget:      time.Second,
				MaxDiagnosticsEntries: 1,
			},
			Reports: policyruntime.DecisionReportSettings{MaxEntries: 1},
		},
	}, nil
}

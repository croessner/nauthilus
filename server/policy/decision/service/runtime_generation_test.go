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
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

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

	capturedFirst, err := source.Capture(context.Background())
	if err != nil {
		t.Fatalf("first Capture() error = %v", err)
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

	capturedSecond, err := source.Capture(context.Background())
	if err != nil {
		t.Fatalf("second Capture() error = %v", err)
	}

	if capturedSecond.decisionGeneration().id != second.ID() {
		t.Fatalf("second captured generation = %d, want %d", capturedSecond.decisionGeneration().id, second.ID())
	}

	if capturedFirst.decisionGeneration().id != 1 {
		t.Fatal("previous capture changed after the next generation committed")
	}
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
		Snapshot: &policyruntime.Snapshot{Generation: input.ID()},
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
	return policyruntime.SettingsPreparation{Settings: policyruntime.GenerationSettings{
		Limits: policyruntime.DecisionLimits{
			EvaluationTimeout:     time.Second,
			PostActionBudget:      time.Second,
			MaxDiagnosticsEntries: 1,
		},
		Reports: policyruntime.DecisionReportSettings{MaxEntries: 1},
	}}, nil
}

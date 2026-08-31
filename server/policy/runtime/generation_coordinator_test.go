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

package runtime

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

const (
	testOldMarker = "old"
	testNewMarker = "new"
)

type generationFixture struct {
	t            *testing.T
	failAt       string
	marker       string
	disposeErr   error
	omitBindings bool
	mismatchAuth bool
	resourcesMu  sync.Mutex
	resources    []*countingCandidateResource
}

type rejectingTestAuthenticator struct {
	marker string
}

type rejectingTestAdmission struct {
	marker string
}

type testGenerationApplication struct {
	id uint64
}

type testPolicyModel struct {
	marker string
	id     uint64
}

type testFactProvider struct{}

type testSyncEffectProvider struct{}

type testPostActionProvider struct{}

type rejectingTestAcceptor struct{}

type countingCandidateResource struct {
	err       error
	disposals atomic.Int64
}

// Authenticate rejects test evidence because only component identity matters here.
func (a *rejectingTestAuthenticator) Authenticate(
	context.Context,
	decision.AuthenticationInput,
) (decision.CallerContext, error) {
	return decision.CallerContext{}, fmt.Errorf("authenticator %s rejected evidence", a.marker)
}

// Admit rejects test requests because no route authority is active in this slice.
func (a *rejectingTestAdmission) Admit(
	context.Context,
	decision.CallerContext,
	decision.DecisionRequest,
) (AdmissionPermit, error) {
	return nil, fmt.Errorf("admission %s rejected request", a.marker)
}

// GenerationID returns the immutable test application generation identity.
func (a *testGenerationApplication) GenerationID() uint64 {
	return a.id
}

// ClonePolicyModel returns one detached coordinator-test policy model.
func (m *testPolicyModel) ClonePolicyModel() PolicyModel {
	if m == nil {
		return (*testPolicyModel)(nil)
	}

	cloned := *m

	return &cloned
}

// ValidatePolicyModel verifies the coordinator-test identity and marker.
func (m *testPolicyModel) ValidatePolicyModel() error {
	if m == nil || m.id == 0 || m.marker == "" {
		return ErrInvalidGeneration
	}

	return nil
}

// GenerationID returns the coordinator-test policy generation identity.
func (m *testPolicyModel) GenerationID() uint64 {
	if m == nil {
		return 0
	}

	return m.id
}

// Collect returns no facts for the coordinator-only binding fake.
func (*testFactProvider) Collect(context.Context, FactProviderInput) ([]ProvidedFact, error) {
	return nil, nil
}

// Execute reports success for the coordinator-only synchronous binding fake.
func (*testSyncEffectProvider) Execute(context.Context, EffectExecution) effectsupervisor.Result {
	return effectsupervisor.Succeeded()
}

// Prepare returns no work because the coordinator test never executes effects.
func (*testPostActionProvider) Prepare(context.Context, EffectExecution) (effectsupervisor.Work, error) {
	return nil, nil
}

// Accept rejects work because the fake proves only immutable binding capture.
func (*rejectingTestAcceptor) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, errors.New("test post action rejected")
}

// Dispose records exactly-once failed-candidate cleanup.
func (r *countingCandidateResource) Dispose(context.Context) error {
	r.disposals.Add(1)

	return r.err
}

// TestGenerationCoordinatorRetainsCompleteActiveGenerationForEveryFailure covers every slot and validator.
func TestGenerationCoordinatorRetainsCompleteActiveGenerationForEveryFailure(t *testing.T) {
	failurePoints := []string{
		"policy",
		"extensions",
		"catalog",
		"caller_authentication",
		"admission",
		"settings",
		"application",
		"validation",
	}

	for _, failurePoint := range failurePoints {
		t.Run(failurePoint, func(t *testing.T) {
			store := NewGenerationStore()
			fixture := newGenerationFixture(t, testOldMarker)
			coordinator := fixture.coordinator(store)

			oldFile := &config.FileSettings{}
			if _, err := coordinator.Apply(context.Background(), PrepareInput{Config: oldFile, ID: 1}); err != nil {
				t.Fatalf("initial Apply() error = %v", err)
			}

			activeBefore := store.Active()
			fixture.marker = testNewMarker
			fixture.failAt = failurePoint
			fixture.resetResources()

			_, err := coordinator.Apply(context.Background(), PrepareInput{
				Config: &config.FileSettings{},
				ID:     2,
			})
			if err == nil {
				t.Fatal("candidate Apply() error = nil, want failure")
			}

			activeAfter := store.Active()
			if activeAfter != activeBefore {
				t.Fatal("failed candidate replaced the active generation pointer")
			}

			assertGenerationMarker(t, activeAfter, testOldMarker, oldFile, 1, 0)
			fixture.assertCandidateResourcesDisposedOnce(t)
		})
	}
}

// TestGenerationCoordinatorCommitsEveryCandidateComponentTogether proves one complete publication.
func TestGenerationCoordinatorCommitsEveryCandidateComponentTogether(t *testing.T) {
	store := NewGenerationStore()
	fixture := newGenerationFixture(t, testOldMarker)
	coordinator := fixture.coordinator(store)

	oldFile := &config.FileSettings{}
	if _, err := coordinator.Apply(context.Background(), PrepareInput{Config: oldFile, ID: 1}); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	activeBefore := store.Active()
	fixture.marker = testNewMarker
	fixture.resetResources()

	newFile := &config.FileSettings{}

	committed, err := coordinator.Apply(context.Background(), PrepareInput{Config: newFile, ID: 2})
	if err != nil {
		t.Fatalf("candidate Apply() error = %v", err)
	}

	if committed == activeBefore || store.Active() != committed {
		t.Fatal("successful candidate was not published through one generation pointer")
	}

	assertGenerationMarker(t, committed, testNewMarker, newFile, 2, 1)
	fixture.assertCandidateResourcesNotDisposed(t)
}

// TestGenerationCommitDoesNotExposeMixedCandidateState exercises concurrent capture visibility.
func TestGenerationCommitDoesNotExposeMixedCandidateState(t *testing.T) {
	store := NewGenerationStore()
	fixture := newGenerationFixture(t, testOldMarker)
	coordinator := fixture.coordinator(store)

	oldFile := &config.FileSettings{}
	if _, err := coordinator.Apply(context.Background(), PrepareInput{Config: oldFile, ID: 1}); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	fixture.marker = testNewMarker
	fixture.resetResources()

	newFile := &config.FileSettings{}

	var (
		mixed atomic.Bool
		wait  sync.WaitGroup
	)

	start := make(chan struct{})

	for range 8 {
		wait.Add(1)

		go func() {
			defer wait.Done()

			<-start

			for range 2_000 {
				generation := store.Active()
				if generation == nil || !generationHasMarker(generation, testOldMarker, oldFile, 1, 0) &&
					!generationHasMarker(generation, testNewMarker, newFile, 2, 1) {
					mixed.Store(true)

					return
				}
			}
		}()
	}

	close(start)

	if _, err := coordinator.Apply(context.Background(), PrepareInput{Config: newFile, ID: 2}); err != nil {
		t.Fatalf("candidate Apply() error = %v", err)
	}

	wait.Wait()

	if mixed.Load() {
		t.Fatal("a reader observed a mixed runtime generation")
	}
}

// TestGenerationCoordinatorDisposesLateFailedCandidateResourcesExactlyOnce proves cleanup ownership.
func TestGenerationCoordinatorDisposesLateFailedCandidateResourcesExactlyOnce(t *testing.T) {
	store := NewGenerationStore()
	fixture := newGenerationFixture(t, testOldMarker)
	coordinator := fixture.coordinator(store)

	if _, err := coordinator.Apply(context.Background(), PrepareInput{Config: &config.FileSettings{}, ID: 1}); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	fixture.marker = testNewMarker
	fixture.failAt = "application"
	fixture.resetResources()

	if _, err := coordinator.Apply(context.Background(), PrepareInput{Config: &config.FileSettings{}, ID: 2}); err == nil {
		t.Fatal("candidate Apply() error = nil, want application preparation failure")
	}

	fixture.assertCandidateResourcesDisposedOnce(t)
}

// TestGenerationValidationRejectsCrossComponentMismatch proves binding and authority validation.
func TestGenerationValidationRejectsCrossComponentMismatch(t *testing.T) {
	tests := []struct {
		configure func(*generationFixture)
		want      error
		name      string
	}{
		{
			name: "catalog without prepared binding",
			configure: func(fixture *generationFixture) {
				fixture.omitBindings = true
			},
			want: ErrInvalidGenerationBinding,
		},
		{
			name: "admission without credential profile",
			configure: func(fixture *generationFixture) {
				fixture.mismatchAuth = true
			},
			want: ErrInvalidGeneration,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := NewGenerationStore()
			fixture := newGenerationFixture(t, testOldMarker)
			coordinator := fixture.coordinator(store)

			if _, err := coordinator.Apply(context.Background(), PrepareInput{
				Config: &config.FileSettings{}, ID: 1,
			}); err != nil {
				t.Fatalf("initial Apply() error = %v", err)
			}

			active := store.Active()
			fixture.marker = testNewMarker
			test.configure(fixture)
			fixture.resetResources()

			_, err := coordinator.Apply(context.Background(), PrepareInput{
				Config: &config.FileSettings{}, ID: 2,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("Apply() error = %v, want %v", err, test.want)
			}

			if store.Active() != active {
				t.Fatal("cross-validation failure replaced the active generation")
			}

			fixture.assertCandidateResourcesDisposedOnce(t)
		})
	}
}

// TestGenerationCoordinatorRejectsStaleCandidateCommit proves compare-and-swap ownership.
func TestGenerationCoordinatorRejectsStaleCandidateCommit(t *testing.T) {
	store := NewGenerationStore()
	fixture := newGenerationFixture(t, testOldMarker)
	coordinator := fixture.coordinator(store)

	if _, err := coordinator.Apply(context.Background(), PrepareInput{Config: &config.FileSettings{}, ID: 1}); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	fixture.marker = testNewMarker
	fixture.resetResources()

	stale, err := coordinator.Prepare(context.Background(), PrepareInput{Config: &config.FileSettings{}, ID: 2})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	if err = coordinator.Validate(context.Background(), stale); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	fixture.marker = "newer"

	if _, err = coordinator.Apply(context.Background(), PrepareInput{Config: &config.FileSettings{}, ID: 3}); err != nil {
		t.Fatalf("newer Apply() error = %v", err)
	}

	if _, err = coordinator.Commit(context.Background(), stale); !errors.Is(err, ErrGenerationChanged) {
		t.Fatalf("stale Commit() error = %v, want ErrGenerationChanged", err)
	}

	if got := store.Active().ID(); got != 3 {
		t.Fatalf("active generation = %d, want 3", got)
	}
}

// newGenerationFixture constructs the complete fake preparation graph.
func newGenerationFixture(t *testing.T, marker string) *generationFixture {
	t.Helper()

	return &generationFixture{t: t, marker: marker}
}

// coordinator builds one coordinator whose slots expose fixture-controlled failures.
func (f *generationFixture) coordinator(store *GenerationStore) *Coordinator {
	f.t.Helper()

	coordinator, err := NewCoordinator(CoordinatorConfig{
		Store: store,
		Slots: PreparationSlots{
			Policy:               PolicyPreparationFunc(f.preparePolicy),
			Extensions:           ExtensionPreparationFunc(f.prepareExtensions),
			Catalog:              CatalogPreparationFunc(f.prepareCatalog),
			CallerAuthentication: CallerAuthenticationPreparationFunc(f.prepareCallerAuthentication),
			Admission:            AdmissionPreparationFunc(f.prepareAdmission),
			Settings:             SettingsPreparationFunc(f.prepareSettings),
			Application:          ApplicationPreparationFunc(f.prepareApplication),
			Validators: []GenerationValidator{
				GenerationValidationFunc(f.validateGeneration),
			},
		},
	})
	if err != nil {
		f.t.Fatalf("NewCoordinator() error = %v", err)
	}

	return coordinator
}

// preparePolicy builds one marker-bearing normalized policy model.
func (f *generationFixture) preparePolicy(
	_ context.Context,
	input PreparationInput,
) (PolicyPreparation, error) {
	result := PolicyPreparation{
		Policy:    &testPolicyModel{id: input.ID(), marker: f.marker},
		Resources: f.newResources("policy"),
	}

	return result, f.failure("policy")
}

// prepareExtensions builds marker-bearing immutable provider bindings.
func (f *generationFixture) prepareExtensions(
	_ context.Context,
	_ PreparationInput,
) (ExtensionPreparation, error) {
	factProviders := map[string]FactProviderBinding{
		f.marker: {
			Provider:  &testFactProvider{},
			Source:    decision.FactSourcePlugin,
			Authority: f.marker,
			Component: f.marker,
		},
	}
	syncEffects := make(map[string]SyncEffectProvider)
	postActions := make(map[string]PostActionProvider)

	if f.marker != testOldMarker && !f.omitBindings {
		record := newGenerationTargetCatalogRecord(f.t)
		for _, provider := range record.Providers {
			factProviders[provider.ID()] = FactProviderBinding{
				Provider: &testFactProvider{}, Source: decision.FactSourcePlugin,
				Authority: f.marker, Component: provider.ID(),
			}
			syncEffects[provider.ID()] = &testSyncEffectProvider{}
			postActions[provider.ID()] = &testPostActionProvider{}
		}
	}

	bindings, err := NewBindingSet(BindingSetInput{
		FactProviders:        factProviders,
		SyncEffects:          syncEffects,
		PostActions:          postActions,
		PostActionAcceptance: &rejectingTestAcceptor{},
	})
	if err != nil {
		f.t.Fatalf("NewBindingSet() error = %v", err)
	}

	result := ExtensionPreparation{Bindings: bindings, Resources: f.newResources("extensions")}

	return result, f.failure("extensions")
}

// prepareCatalog builds an empty old catalog and one-target candidate catalog.
func (f *generationFixture) prepareCatalog(
	_ context.Context,
	_ CatalogPreparationInput,
) (CatalogPreparation, error) {
	var records []TargetCatalogRecord

	if f.marker != testOldMarker {
		record := newGenerationTargetCatalogRecord(f.t)
		records = []TargetCatalogRecord{record}
	}

	catalog, err := NewTargetCatalog(records)
	if err != nil {
		f.t.Fatalf("NewTargetCatalog() error = %v", err)
	}

	result := CatalogPreparation{Catalog: catalog, Resources: f.newResources("catalog")}

	return result, f.failure("catalog")
}

// newGenerationTargetCatalogRecord adds one scheduled provider for binding validation.
func newGenerationTargetCatalogRecord(t *testing.T) TargetCatalogRecord {
	t.Helper()

	record, _ := newTargetCatalogRecord(t)

	provider, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID:         "dkim2/test_provider",
		Targets:    []decision.Target{record.Target},
		Executions: []registry.ExecutionClass{registry.ExecutionHostSync},
	})
	if err != nil {
		t.Fatalf("registry.NewProviderDefinition() error = %v", err)
	}

	record.Providers = append(record.Providers, provider)

	effect, err := registry.NewEffectDefinition(registry.EffectDefinitionInput{
		ID:        "dkim2/test_effect",
		Provider:  provider.ID(),
		Targets:   []decision.Target{record.Target},
		Kind:      registry.EffectKindObligation,
		Execution: registry.ExecutionHostSync,
	})
	if err != nil {
		t.Fatalf("registry.NewEffectDefinition() error = %v", err)
	}

	record.Effects = append(record.Effects, effect)

	return record
}

// prepareCallerAuthentication builds an explicit rejecting authenticator and metadata.
func (f *generationFixture) prepareCallerAuthentication(
	_ context.Context,
	_ AuthorityPreparationInput,
) (CallerAuthenticationPreparation, error) {
	profiles, err := NewCredentialProfiles([]string{f.marker})
	if err != nil {
		f.t.Fatalf("NewCredentialProfiles() error = %v", err)
	}

	result := CallerAuthenticationPreparation{
		Authenticator: &rejectingTestAuthenticator{marker: f.marker},
		Credentials:   profiles,
		Resources:     f.newResources("caller_authentication"),
	}

	return result, f.failure("caller_authentication")
}

// prepareAdmission builds an explicit rejecting authority and matching profiles.
func (f *generationFixture) prepareAdmission(
	_ context.Context,
	_ AdmissionPreparationInput,
) (AdmissionPreparation, error) {
	profileMarker := f.marker
	if f.mismatchAuth {
		profileMarker = "unmatched"
	}

	profiles, err := NewAdmissionProfiles([]string{profileMarker})
	if err != nil {
		f.t.Fatalf("NewAdmissionProfiles() error = %v", err)
	}

	result := AdmissionPreparation{
		Authority: &rejectingTestAdmission{marker: f.marker},
		Profiles:  profiles,
		Resources: f.newResources("admission"),
	}

	return result, f.failure("admission")
}

// prepareSettings builds bounded marker-bearing runtime settings.
func (f *generationFixture) prepareSettings(
	_ context.Context,
	_ SettingsPreparationInput,
) (SettingsPreparation, error) {
	markerLimit := 1
	if f.marker != testOldMarker {
		markerLimit = 2
	}

	result := SettingsPreparation{
		Settings: GenerationSettings{
			Limits: DecisionLimits{
				EvaluationTimeout:     time.Second,
				PostActionBudget:      time.Second,
				MaxDiagnosticsEntries: markerLimit,
			},
			Reports: DecisionReportSettings{MaxEntries: markerLimit},
		},
		Resources: f.newResources("settings"),
	}

	return result, f.failure("settings")
}

// prepareApplication binds the final application authority to the candidate ID.
func (f *generationFixture) prepareApplication(
	_ context.Context,
	input ApplicationPreparationInput,
) (ApplicationPreparation, error) {
	result := ApplicationPreparation{
		Application: &testGenerationApplication{id: input.ID()},
		Resources:   f.newResources("application"),
	}

	return result, f.failure("application")
}

// validateGeneration injects the final cross-validation failure point.
func (f *generationFixture) validateGeneration(context.Context, *Generation) error {
	return f.failure("validation")
}

// failure returns a deterministic fixture error for one selected preparation point.
func (f *generationFixture) failure(point string) error {
	if f.failAt != point {
		return nil
	}

	return fmt.Errorf("injected %s failure", point)
}

// newResources records one owned candidate resource for a completed slot.
func (f *generationFixture) newResources(_ string) []CandidateResource {
	resource := &countingCandidateResource{err: f.disposeErr}

	f.resourcesMu.Lock()
	f.resources = append(f.resources, resource)
	f.resourcesMu.Unlock()

	return []CandidateResource{resource}
}

// resetResources starts a new candidate resource observation window.
func (f *generationFixture) resetResources() {
	f.resourcesMu.Lock()
	f.resources = nil
	f.resourcesMu.Unlock()
}

// assertCandidateResourcesDisposedOnce checks failed-candidate ownership cleanup.
func (f *generationFixture) assertCandidateResourcesDisposedOnce(t *testing.T) {
	t.Helper()

	f.resourcesMu.Lock()
	resources := append([]*countingCandidateResource(nil), f.resources...)
	f.resourcesMu.Unlock()

	if len(resources) == 0 {
		t.Fatal("candidate prepared no resources")
	}

	for index, resource := range resources {
		if got := resource.disposals.Load(); got != 1 {
			t.Fatalf("candidate resource %d disposal count = %d, want 1", index, got)
		}
	}
}

// assertCandidateResourcesNotDisposed checks ownership transfer after commit.
func (f *generationFixture) assertCandidateResourcesNotDisposed(t *testing.T) {
	t.Helper()

	f.resourcesMu.Lock()
	resources := append([]*countingCandidateResource(nil), f.resources...)
	f.resourcesMu.Unlock()

	for index, resource := range resources {
		if got := resource.disposals.Load(); got != 0 {
			t.Fatalf("committed resource %d disposal count = %d, want 0", index, got)
		}
	}
}

// assertGenerationMarker verifies every authority comes from one expected generation.
func assertGenerationMarker(
	t *testing.T,
	generation *Generation,
	marker string,
	file config.File,
	id uint64,
	catalogSize int,
) {
	t.Helper()

	if !generationHasMarker(generation, marker, file, id, catalogSize) {
		t.Fatalf("generation does not contain the complete %q candidate", marker)
	}
}

// generationHasMarker reports whether all observable components belong together.
func generationHasMarker(
	generation *Generation,
	marker string,
	file config.File,
	id uint64,
	catalogSize int,
) bool {
	if generation == nil {
		return false
	}

	policy, _ := generation.Policy().(*testPolicyModel)
	catalog := generation.TargetCatalog()
	credentials := generation.CredentialProfiles().IDs()
	admission := generation.AdmissionProfiles().IDs()
	factProviderIDs := generation.Bindings().FactProviderIDs()
	settings := generation.Settings()
	application := generation.Application()

	observed := generationMarkerObservation{
		policyMode:         policyMode(policy),
		credential:         soleProfileID(credentials),
		admission:          soleProfileID(admission),
		generationID:       generation.ID(),
		policyGenerationID: policyGenerationID(policy),
		applicationID:      applicationGenerationID(application),
		catalogSize:        targetCatalogSize(catalog),
		diagnosticLimit:    settings.Limits.MaxDiagnosticsEntries,
		configMatches:      generation.Config() == file,
		bindingMatches:     slices.Contains(factProviderIDs, marker),
	}
	expected := generationMarkerObservation{
		policyMode:         marker,
		credential:         marker,
		admission:          marker,
		generationID:       id,
		policyGenerationID: id,
		applicationID:      id,
		catalogSize:        catalogSize,
		diagnosticLimit:    int(id),
		configMatches:      true,
		bindingMatches:     true,
	}

	return observed == expected
}

type generationMarkerObservation struct {
	policyMode         string
	credential         string
	admission          string
	generationID       uint64
	policyGenerationID uint64
	applicationID      uint64
	catalogSize        int
	diagnosticLimit    int
	configMatches      bool
	bindingMatches     bool
}

// policyMode returns an empty marker for a missing policy view.
func policyMode(policy *testPolicyModel) string {
	if policy == nil {
		return ""
	}

	return policy.marker
}

// policyGenerationID returns zero for a missing policy view.
func policyGenerationID(policy *testPolicyModel) uint64 {
	if policy == nil {
		return 0
	}

	return policy.id
}

// applicationGenerationID returns zero for a missing application authority.
func applicationGenerationID(application Application) uint64 {
	if application == nil {
		return 0
	}

	return application.GenerationID()
}

// targetCatalogSize returns zero for a missing target catalog.
func targetCatalogSize(catalog *TargetCatalog) int {
	if catalog == nil {
		return 0
	}

	return catalog.Len()
}

// soleProfileID returns the identity only for an exact singleton profile set.
func soleProfileID(ids []string) string {
	if len(ids) != 1 {
		return ""
	}

	return ids[0]
}

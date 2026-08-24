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
	"sync"
	"testing"

	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/admission"
	"github.com/croessner/nauthilus/v3/server/policy/callerauth"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	callerAdmissionGenerationPrincipal = "generation-policy-client"
	callerAdmissionGenerationOldSecret = "generation-admission-old-secret"
	callerAdmissionGenerationNewSecret = "generation-admission-new-secret"
	callerAdmissionOldField            = "old_marker"
	callerAdmissionNewField            = "new_marker"
)

type callerAdmissionGenerationEvaluator struct {
	delegate *recordingCheckpointEvaluator
	started  chan struct{}
	release  <-chan struct{}
	once     sync.Once
}

type callerAdmissionGenerationAuthorities struct {
	authenticators map[uint64]policyruntime.CallerAuthenticator
	admissions     map[uint64]policyruntime.AdmissionAuthority
	mu             sync.Mutex
}

type callerAdmissionGenerationFixture struct {
	service         *DecisionService
	coordinator     *policyruntime.Coordinator
	authorities     *callerAdmissionGenerationAuthorities
	firstEvaluator  *recordingCheckpointEvaluator
	secondEvaluator *recordingCheckpointEvaluator
	authStarted     chan struct{}
	authRelease     chan struct{}
	evalStarted     chan struct{}
	evalRelease     chan struct{}
	authReleaseOnce sync.Once
	evalReleaseOnce sync.Once
}

// Checkpoints delegates the exact target plan to the synchronized recorder.
func (e *callerAdmissionGenerationEvaluator) Checkpoints(target decision.Target) ([]CheckpointPlan, error) {
	return e.delegate.Checkpoints(target)
}

// Evaluate optionally holds one admitted call while retaining its generation permit.
func (e *callerAdmissionGenerationEvaluator) Evaluate(
	ctx context.Context,
	input checkpointEvaluation,
) (runtimeEvaluation, error) {
	if e.started != nil {
		e.once.Do(func() {
			close(e.started)
		})
	}

	if e.release != nil {
		select {
		case <-e.release:
		case <-ctx.Done():
			return runtimeEvaluation{}, ctx.Err()
		}
	}

	return e.delegate.Evaluate(ctx, input)
}

// record stores generation-owned caller authorities for lifecycle assertions.
func (a *callerAdmissionGenerationAuthorities) record(
	id uint64,
	authenticator policyruntime.CallerAuthenticator,
	authority policyruntime.AdmissionAuthority,
) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.authenticators[id] = authenticator
	a.admissions[id] = authority
}

// generation returns authorities captured from one completed preparation.
func (a *callerAdmissionGenerationAuthorities) generation(
	id uint64,
) (policyruntime.CallerAuthenticator, policyruntime.AdmissionAuthority) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.authenticators[id], a.admissions[id]
}

// TestCallerAdmissionRetainsOneGenerationAcrossConcurrentReload proves the complete admission boundary is atomic.
func TestCallerAdmissionRetainsOneGenerationAcrossConcurrentReload(t *testing.T) {
	fixture := newCallerAdmissionGenerationFixture(t)
	oldInvocation := mustCallerAdmissionGenerationInvocation(
		t,
		callerAdmissionGenerationOldSecret,
		callerAdmissionOldField,
	)
	oldResult := startCallerAdmissionGenerationEvaluation(fixture.service, oldInvocation)

	waitPolicyCallerAuthSignal(t, fixture.authStarted, "old generation authentication")
	applyPolicyCallerAuthGeneration(t, fixture.coordinator, 2)
	fixture.releaseAuthentication()
	waitPolicyCallerAuthSignal(t, fixture.evalStarted, "old generation evaluation")

	assertCallerAdmissionReloadRejectsOldAuthority(t, fixture)
	assertCallerAdmissionOldLimitIsHeld(t, fixture, oldInvocation)
	assertCallerAdmissionNewGeneration(t, fixture)

	fixture.releaseEvaluation()

	result := waitPolicyCallerAuthEvaluation(t, oldResult)
	assertCallerAdmissionOldGeneration(t, fixture, result)
	assertCallerAdmissionOldLimitWasReleased(t, fixture, oldInvocation)
}

// newCallerAdmissionGenerationFixture publishes one blocked generation and prepares its replacement.
func newCallerAdmissionGenerationFixture(t *testing.T) *callerAdmissionGenerationFixture {
	t.Helper()

	store := policyruntime.NewGenerationStore()
	authStarted := make(chan struct{})
	authRelease := make(chan struct{})
	evalStarted := make(chan struct{})
	evalRelease := make(chan struct{})
	first := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 1, "admission-generation-one")}
	second := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 2, "admission-generation-two")}
	authorities := &callerAdmissionGenerationAuthorities{
		authenticators: make(map[uint64]policyruntime.CallerAuthenticator),
		admissions:     make(map[uint64]policyruntime.AdmissionAuthority),
	}
	coordinator := newCallerAdmissionGenerationCoordinator(t, store, callerAdmissionGenerationAssembly{
		authorities: authorities,
		authThrottler: &policyCallerAuthBlockingThrottler{
			started: authStarted,
			release: authRelease,
		},
		firstEvaluator: &callerAdmissionGenerationEvaluator{
			delegate: first,
			started:  evalStarted,
			release:  evalRelease,
		},
		secondEvaluator: &callerAdmissionGenerationEvaluator{delegate: second},
	})
	applyPolicyCallerAuthGeneration(t, coordinator, 1)

	source, err := NewStoreGenerationSource(store)
	if err != nil {
		t.Fatalf("NewStoreGenerationSource() error = %v", err)
	}

	shutdownPolicyCallerAuthStore(t, store)

	fixture := &callerAdmissionGenerationFixture{
		service:         mustDecisionService(t, source),
		coordinator:     coordinator,
		authorities:     authorities,
		firstEvaluator:  first,
		secondEvaluator: second,
		authStarted:     authStarted,
		authRelease:     authRelease,
		evalStarted:     evalStarted,
		evalRelease:     evalRelease,
	}
	t.Cleanup(fixture.releaseAuthentication)
	t.Cleanup(fixture.releaseEvaluation)

	return fixture
}

// releaseAuthentication unblocks the old credential check at most once.
func (f *callerAdmissionGenerationFixture) releaseAuthentication() {
	f.authReleaseOnce.Do(func() {
		close(f.authRelease)
	})
}

// releaseEvaluation unblocks the admitted old evaluator at most once.
func (f *callerAdmissionGenerationFixture) releaseEvaluation() {
	f.evalReleaseOnce.Do(func() {
		close(f.evalRelease)
	})
}

type callerAdmissionGenerationAssembly struct {
	authorities     *callerAdmissionGenerationAuthorities
	authThrottler   callerauth.BasicThrottler
	firstEvaluator  checkpointEvaluator
	secondEvaluator checkpointEvaluator
}

// newCallerAdmissionGenerationCoordinator assembles real auth and admission authorities per generation.
func newCallerAdmissionGenerationCoordinator(
	t *testing.T,
	store *policyruntime.GenerationStore,
	assembly callerAdmissionGenerationAssembly,
) *policyruntime.Coordinator {
	t.Helper()

	bindings, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		PostActionAcceptance: &recordingEffectAcceptor{},
	})
	if err != nil {
		t.Fatalf("NewBindingSet() error = %v", err)
	}

	catalogs, profiles := callerAdmissionGenerationCatalogs(t)
	slots := serviceGenerationSlots(t, bindings)
	slots.Catalog = callerAdmissionGenerationCatalogSlot(catalogs)
	slots.CallerAuthentication = callerAdmissionGenerationAuthenticationSlot(assembly)
	slots.Admission = callerAdmissionGenerationAdmissionSlot(profiles, assembly.authorities)
	slots.Application = callerAdmissionGenerationApplicationSlot(t, bindings, assembly)

	coordinator, err := policyruntime.NewCoordinator(policyruntime.CoordinatorConfig{Store: store, Slots: slots})
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	return coordinator
}

// callerAdmissionGenerationCatalogs constructs schema-incompatible old and new target views.
func callerAdmissionGenerationCatalogs(
	t *testing.T,
) (map[uint64]*policyruntime.TargetCatalog, map[uint64]admission.Configuration) {
	t.Helper()

	oldCatalog, oldReference := callerAdmissionGenerationCatalog(t, "v1", callerAdmissionOldField)
	newCatalog, newReference := callerAdmissionGenerationCatalog(t, "v2", callerAdmissionNewField)

	return map[uint64]*policyruntime.TargetCatalog{1: oldCatalog, 2: newCatalog},
		map[uint64]admission.Configuration{
			1: callerAdmissionGenerationProfile(oldReference, callerAdmissionOldField),
			2: callerAdmissionGenerationProfile(newReference, callerAdmissionNewField),
		}
}

// callerAdmissionGenerationCatalog creates one exact target/schema fact contract.
func callerAdmissionGenerationCatalog(
	t *testing.T,
	version string,
	field string,
) (*policyruntime.TargetCatalog, registry.ClientAdmissionReference) {
	t.Helper()

	target, err := decision.NewTarget("mail", "submit")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	identity, err := registry.NewSchemaIdentity("mail", "submit", version)
	if err != nil {
		t.Fatalf("NewSchemaIdentity() error = %v", err)
	}

	schema, err := registry.NewSchemaDefinition(identity, []registry.FactSchema{
		decisionRuntimeFactSchema(t, "input."+field, decision.FactSourceCaller, true),
	})
	if err != nil {
		t.Fatalf("NewSchemaDefinition() error = %v", err)
	}

	checkpoint, err := registry.NewCheckpointDefinition(decision.CheckpointFinalDecision, nil, nil)
	if err != nil {
		t.Fatalf("NewCheckpointDefinition() error = %v", err)
	}

	plan, err := registry.NewDomainPlanDefinition(target, []registry.CheckpointDefinition{checkpoint})
	if err != nil {
		t.Fatalf("NewDomainPlanDefinition() error = %v", err)
	}

	catalog, err := policyruntime.NewTargetCatalog([]policyruntime.TargetCatalogRecord{{
		Target:        target,
		Schema:        schema,
		SourcePlan:    plan,
		Checkpoints:   []policyruntime.CheckpointRecord{{Name: decision.CheckpointFinalDecision}},
		NoMatch:       registry.NoMatchDeny,
		AuthorityMode: registry.AuthorityModeEnforce,
	}}, nil)
	if err != nil {
		t.Fatalf("NewTargetCatalog() error = %v", err)
	}

	reference, err := registry.NewClientAdmissionReference(
		"test.caller-admission."+version,
		target.Namespace(),
		target.Action(),
		identity.String(),
	)
	if err != nil {
		t.Fatalf("NewClientAdmissionReference() error = %v", err)
	}

	return catalog, reference
}

// callerAdmissionGenerationProfile binds one principal to one exact schema and submitted field.
func callerAdmissionGenerationProfile(
	reference registry.ClientAdmissionReference,
	field string,
) admission.Configuration {
	return admission.Configuration{
		GlobalLimits: admission.Limits{
			MaxRequestBytes:   4096,
			MaxFacts:          8,
			MaxConcurrency:    4,
			RequestsPerSecond: 1000,
		},
		Profiles: []admission.Profile{{
			Principal:              callerAdmissionGenerationPrincipal,
			AuthenticationKinds:    []string{policy.CallerAuthenticationKindBasic},
			References:             []registry.ClientAdmissionReference{reference},
			AllowedInputAttributes: []string{field},
			Limits:                 admission.Limits{MaxConcurrency: 1},
		}},
	}
}

// callerAdmissionGenerationCatalogSlot selects the exact generation catalog.
func callerAdmissionGenerationCatalogSlot(
	catalogs map[uint64]*policyruntime.TargetCatalog,
) policyruntime.CatalogPreparationSlot {
	return policyruntime.CatalogPreparationFunc(func(
		_ context.Context,
		input policyruntime.CatalogPreparationInput,
	) (policyruntime.CatalogPreparation, error) {
		catalog := catalogs[input.ID()]
		if catalog == nil {
			return policyruntime.CatalogPreparation{}, fmt.Errorf("missing caller admission catalog %d", input.ID())
		}

		return policyruntime.CatalogPreparation{Catalog: catalog}, nil
	})
}

// callerAdmissionGenerationAuthenticationSlot compiles generation-specific Basic evidence.
func callerAdmissionGenerationAuthenticationSlot(
	assembly callerAdmissionGenerationAssembly,
) policyruntime.CallerAuthenticationPreparationSlot {
	return policyruntime.CallerAuthenticationPreparationFunc(func(
		_ context.Context,
		input policyruntime.AuthorityPreparationInput,
	) (policyruntime.CallerAuthenticationPreparation, error) {
		var (
			throttler callerauth.BasicThrottler
			password  = callerAdmissionGenerationNewSecret
		)

		if input.ID() == 1 {
			password = callerAdmissionGenerationOldSecret
			throttler = assembly.authThrottler
		}

		prepared, err := callerauth.Prepare(policyCallerAuthBasicConfiguration(password, throttler, true))
		if err == nil {
			assembly.authorities.record(input.ID(), prepared.Authenticator, nil)
		}

		return prepared, err
	})
}

// callerAdmissionGenerationAdmissionSlot compiles profiles against the same catalog and credentials.
func callerAdmissionGenerationAdmissionSlot(
	profiles map[uint64]admission.Configuration,
	authorities *callerAdmissionGenerationAuthorities,
) policyruntime.AdmissionPreparationSlot {
	return policyruntime.AdmissionPreparationFunc(func(
		_ context.Context,
		input policyruntime.AdmissionPreparationInput,
	) (policyruntime.AdmissionPreparation, error) {
		prepared, err := admission.Prepare(
			profiles[input.ID()],
			input.TargetCatalog(),
			input.CredentialProfiles(),
		)
		if err == nil {
			authenticator, _ := authorities.generation(input.ID())
			authorities.record(input.ID(), authenticator, prepared.Authority)
		}

		return prepared, err
	})
}

// callerAdmissionGenerationApplicationSlot binds each evaluator to its captured caller authorities.
func callerAdmissionGenerationApplicationSlot(
	t *testing.T,
	bindings *policyruntime.BindingSet,
	assembly callerAdmissionGenerationAssembly,
) policyruntime.ApplicationPreparationSlot {
	t.Helper()

	return policyruntime.ApplicationPreparationFunc(func(
		_ context.Context,
		input policyruntime.ApplicationPreparationInput,
	) (policyruntime.ApplicationPreparation, error) {
		evaluator := assembly.secondEvaluator
		if input.ID() == 1 {
			evaluator = assembly.firstEvaluator
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

		return policyruntime.ApplicationPreparation{Application: generation.(policyruntime.Application)}, nil
	})
}

// mustCallerAdmissionGenerationInvocation constructs one exact Basic request and submitted marker.
func mustCallerAdmissionGenerationInvocation(
	t *testing.T,
	password string,
	field string,
) decision.Invocation {
	t.Helper()

	target, err := decision.NewTarget("mail", "submit")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	authentication, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          policy.CallerAuthenticationKindBasic,
		Credential:    []byte(policyCallerAuthGenerationUsername + ":" + password),
		TransportKind: "http",
		Listener:      "policy-http",
		HTTPRoute:     "/api/v1/policy/evaluate",
		Peer:          "192.0.2.31:443",
		Protected:     true,
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	return decision.Invocation{
		Request: decision.DecisionRequestInput{
			Version:   decision.ContractVersion,
			RequestID: "caller-admission-" + field,
			Target:    target,
			Attributes: map[string]decision.Value{
				field: runtimeStringValue(t, field),
			},
		},
		Authentication: authentication,
	}
}

// startCallerAdmissionGenerationEvaluation starts one result-buffered old-generation call.
func startCallerAdmissionGenerationEvaluation(
	service *DecisionService,
	invocation decision.Invocation,
) <-chan evaluationResult {
	result := make(chan evaluationResult, 1)

	go func() {
		response, err := service.Evaluate(context.Background(), invocation)
		result <- evaluationResult{response: response, err: err}
	}()

	return result
}

// assertCallerAdmissionReloadRejectsOldAuthority proves post-reload calls use only new credentials and profiles.
func assertCallerAdmissionReloadRejectsOldAuthority(
	t *testing.T,
	fixture *callerAdmissionGenerationFixture,
) {
	t.Helper()

	oldCredential := mustCallerAdmissionGenerationInvocation(
		t,
		callerAdmissionGenerationOldSecret,
		callerAdmissionOldField,
	)
	if _, err := fixture.service.Evaluate(context.Background(), oldCredential); !errors.Is(err, ErrDecisionAuthentication) {
		t.Fatalf("old credential after reload error = %v, want ErrDecisionAuthentication", err)
	}

	oldProfile := mustCallerAdmissionGenerationInvocation(
		t,
		callerAdmissionGenerationNewSecret,
		callerAdmissionOldField,
	)
	if _, err := fixture.service.Evaluate(context.Background(), oldProfile); !errors.Is(err, ErrDecisionAdmission) {
		t.Fatalf("old profile after reload error = %v, want ErrDecisionAdmission", err)
	}

	if fixture.secondEvaluator.callCount() != 0 {
		t.Fatalf("new evaluator calls after rejected old authority = %d, want 0", fixture.secondEvaluator.callCount())
	}
}

// assertCallerAdmissionOldLimitIsHeld proves one old permit does not consume new-generation capacity.
func assertCallerAdmissionOldLimitIsHeld(
	t *testing.T,
	fixture *callerAdmissionGenerationFixture,
	invocation decision.Invocation,
) {
	t.Helper()

	authenticator, authority := fixture.authorities.generation(1)
	caller, request := mustCallerAdmissionGenerationRequest(t, authenticator, invocation)

	permit, err := authority.Admit(context.Background(), caller, request)

	if err == nil || permit != nil {
		if permit != nil {
			permit.Release()
		}

		t.Fatalf("second old-generation admission = permit:%v error:%v, want limit rejection", permit != nil, err)
	}
}

// assertCallerAdmissionNewGeneration proves replacement auth, schema, facts, limits, and evaluator agree.
func assertCallerAdmissionNewGeneration(
	t *testing.T,
	fixture *callerAdmissionGenerationFixture,
) {
	t.Helper()

	invocation := mustCallerAdmissionGenerationInvocation(
		t,
		callerAdmissionGenerationNewSecret,
		callerAdmissionNewField,
	)

	response, err := fixture.service.Evaluate(context.Background(), invocation)
	if err != nil {
		t.Fatalf("new generation Evaluate() error = %v", err)
	}

	if response.Policy().Generation() != 2 || response.DecisionID().String() != "admission-generation-two" {
		t.Fatalf(
			"new generation response = %d/%q, want 2/admission-generation-two",
			response.Policy().Generation(),
			response.DecisionID().String(),
		)
	}

	assertCallerAdmissionRecordedFact(t, fixture.secondEvaluator.recordedCalls(), 2, callerAdmissionNewField)
}

// assertCallerAdmissionOldGeneration proves the blocked call never mixed replacement components.
func assertCallerAdmissionOldGeneration(
	t *testing.T,
	fixture *callerAdmissionGenerationFixture,
	result evaluationResult,
) {
	t.Helper()

	if result.err != nil {
		t.Fatalf("old generation Evaluate() error = %v", result.err)
	}

	if result.response.Policy().Generation() != 1 || result.response.DecisionID().String() != "admission-generation-one" {
		t.Fatalf(
			"old generation response = %d/%q, want 1/admission-generation-one",
			result.response.Policy().Generation(),
			result.response.DecisionID().String(),
		)
	}

	assertCallerAdmissionRecordedFact(t, fixture.firstEvaluator.recordedCalls(), 1, callerAdmissionOldField)
}

// assertCallerAdmissionRecordedFact checks exact generation and admitted request provenance.
func assertCallerAdmissionRecordedFact(
	t *testing.T,
	calls []recordedCheckpointEvaluation,
	generation uint64,
	field string,
) {
	t.Helper()

	if len(calls) != 1 || calls[0].generation != generation {
		t.Fatalf("recorded calls = %+v, want one generation-%d call", calls, generation)
	}

	fact, exists := calls[0].facts.Get("input." + field)
	if !exists {
		t.Fatalf("admitted fact input.%s missing", field)
	}

	value, ok := fact.Value().StringValue()
	if !ok || value != field || fact.Provenance().Source() != decision.FactSourceCaller {
		t.Fatalf("admitted fact input.%s = %q/%q, want %q/caller", field, value, fact.Provenance().Source(), field)
	}
}

// assertCallerAdmissionOldLimitWasReleased proves session close returned old profile capacity exactly in scope.
func assertCallerAdmissionOldLimitWasReleased(
	t *testing.T,
	fixture *callerAdmissionGenerationFixture,
	invocation decision.Invocation,
) {
	t.Helper()

	authenticator, authority := fixture.authorities.generation(1)
	caller, request := mustCallerAdmissionGenerationRequest(t, authenticator, invocation)

	permit, err := authority.Admit(context.Background(), caller, request)
	if err != nil {
		t.Fatalf("old generation admission after release error = %v", err)
	}

	if permit == nil {
		t.Fatal("old generation admission after release returned nil permit")
	}

	permit.Release()
}

// mustCallerAdmissionGenerationRequest recreates the exact trusted request for direct limit inspection.
func mustCallerAdmissionGenerationRequest(
	t *testing.T,
	authenticator policyruntime.CallerAuthenticator,
	invocation decision.Invocation,
) (decision.CallerContext, decision.DecisionRequest) {
	t.Helper()

	if authenticator == nil {
		t.Fatal("captured authenticator is nil")
	}

	caller, err := authenticator.Authenticate(context.Background(), invocation.Authentication)
	if err != nil {
		t.Fatalf("captured Authenticate() error = %v", err)
	}

	request, err := decision.NewDecisionRequest(invocation.Request, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	return caller, request
}

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
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/callerauth"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/secret"
)

const (
	policyCallerAuthGenerationUsername = "generation-policy-user"
	policyCallerAuthGenerationOld      = "generation-old-password"
	policyCallerAuthGenerationNew      = "generation-new-password"
)

type policyCallerAuthBlockingThrottler struct {
	started chan struct{}
	release <-chan struct{}
	once    sync.Once
}

type policyCallerAuthReloadFixture struct {
	service         *DecisionService
	coordinator     *policyruntime.Coordinator
	firstEvaluator  *recordingCheckpointEvaluator
	secondEvaluator *recordingCheckpointEvaluator
	started         chan struct{}
	release         chan struct{}
	releaseOnce     sync.Once
}

// BeforeAttempt blocks the first generation-specific Basic attempt after generation capture.
func (t *policyCallerAuthBlockingThrottler) BeforeAttempt(ctx context.Context, _ callerauth.BasicThrottleKey) error {
	t.once.Do(func() {
		close(t.started)
	})

	select {
	case <-t.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RecordFailure records no state because the generation test observes only the preparation boundary.
func (*policyCallerAuthBlockingThrottler) RecordFailure(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// RecordSuccess records no state because the generation test observes only the preparation boundary.
func (*policyCallerAuthBlockingThrottler) RecordSuccess(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// TestPolicyBasicAuthenticationRetainsCredentialGenerationAcrossConcurrentReload proves caller rules and evaluation stay coherent.
func TestPolicyBasicAuthenticationRetainsCredentialGenerationAcrossConcurrentReload(t *testing.T) {
	fixture := newPolicyCallerAuthReloadFixture(t)
	oldInvocation := mustPolicyCallerAuthBasicInvocation(t, policyCallerAuthGenerationOld)
	result := exercisePolicyCallerAuthConcurrentReload(t, fixture, oldInvocation)

	assertPolicyCallerAuthInFlightResult(t, result)
	assertPolicyCallerAuthReloadedCredentials(t, fixture)
}

// newPolicyCallerAuthReloadFixture publishes the first complete caller-authentication generation.
func newPolicyCallerAuthReloadFixture(t *testing.T) *policyCallerAuthReloadFixture {
	t.Helper()

	store := policyruntime.NewGenerationStore()
	started := make(chan struct{})
	release := make(chan struct{})
	firstEvaluator := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 1, "policy-auth-generation-one")}
	secondEvaluator := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 2, "policy-auth-generation-two")}
	coordinator := newPolicyCallerAuthGenerationCoordinator(
		t,
		store,
		map[uint64]callerauth.Configuration{
			1: policyCallerAuthBasicConfiguration(
				policyCallerAuthGenerationOld,
				&policyCallerAuthBlockingThrottler{started: started, release: release},
				true,
			),
			2: policyCallerAuthBasicConfiguration(policyCallerAuthGenerationNew, nil, true),
		},
		map[uint64]checkpointEvaluator{1: firstEvaluator, 2: secondEvaluator},
	)
	applyPolicyCallerAuthGeneration(t, coordinator, 1)

	source, err := NewStoreGenerationSource(store)
	if err != nil {
		t.Fatalf("NewStoreGenerationSource() error = %v", err)
	}

	fixture := &policyCallerAuthReloadFixture{
		service:         mustDecisionService(t, source),
		coordinator:     coordinator,
		firstEvaluator:  firstEvaluator,
		secondEvaluator: secondEvaluator,
		started:         started,
		release:         release,
	}
	shutdownPolicyCallerAuthStore(t, store)

	t.Cleanup(fixture.releaseAttempt)

	return fixture
}

// exercisePolicyCallerAuthConcurrentReload replaces the active generation while old Basic verification is blocked.
func exercisePolicyCallerAuthConcurrentReload(
	t *testing.T,
	fixture *policyCallerAuthReloadFixture,
	oldInvocation decision.Invocation,
) evaluationResult {
	t.Helper()

	resultChannel := make(chan evaluationResult, 1)

	go func() {
		response, err := fixture.service.Evaluate(context.Background(), oldInvocation)
		resultChannel <- evaluationResult{response: response, err: err}
	}()

	waitPolicyCallerAuthSignal(t, fixture.started, "first Basic attempt")
	applyPolicyCallerAuthGeneration(t, fixture.coordinator, 2)
	fixture.releaseAttempt()

	return waitPolicyCallerAuthEvaluation(t, resultChannel)
}

// releaseAttempt unblocks the generation-one password check exactly once.
func (f *policyCallerAuthReloadFixture) releaseAttempt() {
	f.releaseOnce.Do(func() {
		close(f.release)
	})
}

// assertPolicyCallerAuthInFlightResult verifies the captured authenticator and evaluator both came from generation one.
func assertPolicyCallerAuthInFlightResult(t *testing.T, result evaluationResult) {
	t.Helper()

	if result.err != nil {
		t.Fatalf("in-flight DecisionService.Evaluate() error = %v", result.err)
	}

	if result.response.Policy().Generation() != 1 || result.response.DecisionID().String() != "policy-auth-generation-one" {
		t.Fatalf(
			"in-flight response generation/decision = %d/%q, want 1/policy-auth-generation-one",
			result.response.Policy().Generation(),
			result.response.DecisionID().String(),
		)
	}
}

// assertPolicyCallerAuthReloadedCredentials verifies only the new password reaches generation two.
func assertPolicyCallerAuthReloadedCredentials(t *testing.T, fixture *policyCallerAuthReloadFixture) {
	t.Helper()

	_, err := fixture.service.Evaluate(
		context.Background(),
		mustPolicyCallerAuthBasicInvocation(t, policyCallerAuthGenerationOld),
	)
	if !errors.Is(err, ErrDecisionAuthentication) {
		t.Fatalf("old credential after reload error = %v, want ErrDecisionAuthentication", err)
	}

	if fixture.secondEvaluator.callCount() != 0 {
		t.Fatalf("second evaluator calls after rejected old credential = %d, want 0", fixture.secondEvaluator.callCount())
	}

	response, err := fixture.service.Evaluate(
		context.Background(),
		mustPolicyCallerAuthBasicInvocation(t, policyCallerAuthGenerationNew),
	)
	if err != nil {
		t.Fatalf("new credential DecisionService.Evaluate() error = %v", err)
	}

	if response.Policy().Generation() != 2 || response.DecisionID().String() != "policy-auth-generation-two" {
		t.Fatalf(
			"new credential response generation/decision = %d/%q, want 2/policy-auth-generation-two",
			response.Policy().Generation(),
			response.DecisionID().String(),
		)
	}

	if fixture.firstEvaluator.callCount() != 1 || fixture.secondEvaluator.callCount() != 1 {
		t.Fatalf(
			"evaluator calls = first:%d second:%d, want first:1 second:1",
			fixture.firstEvaluator.callCount(),
			fixture.secondEvaluator.callCount(),
		)
	}
}

// TestPolicyBasicAuthenticationInvalidReloadPreservesActiveGeneration proves preparation fails before publication.
func TestPolicyBasicAuthenticationInvalidReloadPreservesActiveGeneration(t *testing.T) {
	store := policyruntime.NewGenerationStore()
	shutdownPolicyCallerAuthStore(t, store)

	evaluator := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 1, "policy-auth-active")}
	coordinator := newPolicyCallerAuthGenerationCoordinator(
		t,
		store,
		map[uint64]callerauth.Configuration{
			1: policyCallerAuthBasicConfiguration(policyCallerAuthGenerationOld, nil, true),
			2: policyCallerAuthBasicConfiguration(policyCallerAuthGenerationNew, nil, false),
		},
		map[uint64]checkpointEvaluator{1: evaluator},
	)
	applyPolicyCallerAuthGeneration(t, coordinator, 1)

	active := store.Active()

	_, err := coordinator.Apply(context.Background(), policyruntime.PrepareInput{
		Config: &config.FileSettings{},
		ID:     2,
	})
	if !errors.Is(err, callerauth.ErrConfiguration) {
		t.Fatalf("invalid Basic Apply() error = %v, want ErrConfiguration", err)
	}

	if store.Active() != active || store.Active().ID() != 1 {
		t.Fatal("invalid Basic candidate changed the active generation")
	}

	source, err := NewStoreGenerationSource(store)
	if err != nil {
		t.Fatalf("NewStoreGenerationSource() error = %v", err)
	}

	response, err := mustDecisionService(t, source).Evaluate(
		context.Background(),
		mustPolicyCallerAuthBasicInvocation(t, policyCallerAuthGenerationOld),
	)
	if err != nil {
		t.Fatalf("active credential DecisionService.Evaluate() error = %v", err)
	}

	if response.Policy().Generation() != 1 || evaluator.callCount() != 1 {
		t.Fatalf("active generation/evaluator calls = %d/%d, want 1/1", response.Policy().Generation(), evaluator.callCount())
	}
}

// newPolicyCallerAuthGenerationCoordinator assembles generation-specific authenticators and evaluators.
func newPolicyCallerAuthGenerationCoordinator(
	t *testing.T,
	store *policyruntime.GenerationStore,
	configurations map[uint64]callerauth.Configuration,
	evaluators map[uint64]checkpointEvaluator,
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
		_ context.Context,
		input policyruntime.AuthorityPreparationInput,
	) (policyruntime.CallerAuthenticationPreparation, error) {
		configuration, exists := configurations[input.ID()]
		if !exists {
			return policyruntime.CallerAuthenticationPreparation{}, fmt.Errorf("missing test caller authentication generation %d", input.ID())
		}

		return callerauth.Prepare(configuration)
	})
	slots.Admission = policyruntime.AdmissionPreparationFunc(func(
		_ context.Context,
		input policyruntime.AdmissionPreparationInput,
	) (policyruntime.AdmissionPreparation, error) {
		profiles, profileErr := policyruntime.NewAdmissionProfiles(input.CredentialProfiles().IDs())
		if profileErr != nil {
			return policyruntime.AdmissionPreparation{}, profileErr
		}

		return policyruntime.AdmissionPreparation{
			Authority: &recordingAdmissionAuthority{},
			Profiles:  profiles,
		}, nil
	})
	slots.Application = policyruntime.ApplicationPreparationFunc(func(
		_ context.Context,
		input policyruntime.ApplicationPreparationInput,
	) (policyruntime.ApplicationPreparation, error) {
		evaluator, exists := evaluators[input.ID()]
		if !exists {
			return policyruntime.ApplicationPreparation{}, fmt.Errorf("missing test evaluator generation %d", input.ID())
		}

		generation, generationErr := newRuntimeGeneration(input.ID(), runtimeGenerationDependencies{
			authenticator: input.CallerAuthenticator(),
			admission:     input.AdmissionAuthority(),
			evaluator:     evaluator,
			supervisor:    bindings.PostActionAcceptance(),
		})
		if generationErr != nil {
			return policyruntime.ApplicationPreparation{}, generationErr
		}

		application := generation.(policyruntime.Application)

		return policyruntime.ApplicationPreparation{Application: application}, nil
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

// policyCallerAuthBasicConfiguration creates one immutable dedicated Basic credential rule.
func policyCallerAuthBasicConfiguration(
	password string,
	throttler callerauth.BasicThrottler,
	protectedCapability bool,
) callerauth.Configuration {
	return callerauth.Configuration{
		Throttler: throttler,
		TransportCapabilities: callerauth.TransportCapabilities{
			HTTPProtected: protectedCapability,
		},
		ExternalProfiles: []callerauth.ExternalProfile{{
			Basic: &callerauth.BasicCredential{
				Password: secret.New(password),
				Username: policyCallerAuthGenerationUsername,
			},
			AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic},
			Principal:           "generation-policy-client",
		}},
	}
}

// mustPolicyCallerAuthBasicInvocation replaces only opaque authentication evidence on a generic request.
func mustPolicyCallerAuthBasicInvocation(t *testing.T, password string) decision.Invocation {
	t.Helper()

	invocation := mustAuthorityInvocation(t, false)

	authentication, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          policy.CallerAuthenticationKindBasic,
		Credential:    []byte(policyCallerAuthGenerationUsername + ":" + password),
		TransportKind: "http",
		Listener:      "policy-http",
		HTTPRoute:     "/api/v1/policy/evaluate",
		Peer:          "192.0.2.15:443",
		Protected:     true,
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	invocation.Authentication = authentication

	return invocation
}

// applyPolicyCallerAuthGeneration prepares and commits one exact candidate identity.
func applyPolicyCallerAuthGeneration(t *testing.T, coordinator *policyruntime.Coordinator, id uint64) {
	t.Helper()

	if _, err := coordinator.Apply(context.Background(), policyruntime.PrepareInput{
		Config: &config.FileSettings{},
		ID:     id,
	}); err != nil {
		t.Fatalf("Apply(%d) error = %v", id, err)
	}
}

// waitPolicyCallerAuthSignal bounds synchronization failures without leaking an evaluation goroutine.
func waitPolicyCallerAuthSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()

	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

// waitPolicyCallerAuthEvaluation bounds completion of the in-flight generation evaluation.
func waitPolicyCallerAuthEvaluation(t *testing.T, results <-chan evaluationResult) evaluationResult {
	t.Helper()

	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Policy caller authentication evaluation")

		return evaluationResult{}
	}
}

// shutdownPolicyCallerAuthStore registers bounded generation cleanup for one test.
func shutdownPolicyCallerAuthStore(t *testing.T, store *policyruntime.GenerationStore) {
	t.Helper()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := store.Shutdown(ctx); err != nil {
			t.Errorf("GenerationStore.Shutdown() error = %v", err)
		}
	})
}

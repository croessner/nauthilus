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
	"strings"
	"sync"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
)

// Test aliases keep explicit fakes focused on the application package boundary.
type AuthenticationEvidence = decision.AuthenticationEvidence
type AuthenticationInput = decision.AuthenticationInput
type CallerContext = decision.CallerContext
type Checkpoint = decision.Checkpoint
type DecisionRequest = decision.DecisionRequest
type DecisionRequestInput = decision.DecisionRequestInput
type FactSet = decision.FactSet
type Invocation = decision.Invocation
type TrustedCallerInput = decision.TrustedCallerInput

const (
	CheckpointFinalDecision = decision.CheckpointFinalDecision
	ContractVersion         = decision.ContractVersion
	EffectPermit            = decision.EffectPermit
	StatusCodePermit        = decision.StatusCodePermit
)

var (
	NewAuthenticationInput = decision.NewAuthenticationInput
	NewCallerContext       = decision.NewCallerContext
	NewCheckpoint          = decision.NewCheckpoint
	NewDecisionResponse    = decision.NewDecisionResponse
	NewFactSet             = decision.NewFactSet
	NewPolicyMetadata      = decision.NewPolicyMetadata
	NewStatus              = decision.NewStatus
	NewTarget              = decision.NewTarget
)

func TestDecisionServiceConstructorRejectsMissingMandatoryAuthorities(t *testing.T) {
	authenticator := &recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)}
	admission := &recordingAdmissionAuthority{}
	evaluator := &recordingCheckpointEvaluator{}
	supervisor := &recordingEffectAcceptor{}

	var (
		nilAuthenticator *recordingCallerAuthenticator
		nilAdmission     *recordingAdmissionAuthority
		nilEvaluator     *recordingCheckpointEvaluator
		nilSupervisor    *recordingEffectAcceptor
	)

	tests := []struct {
		name string
		deps runtimeGenerationDependencies
	}{
		{name: "caller authenticator", deps: runtimeGenerationDependencies{admission: admission, evaluator: evaluator, supervisor: supervisor}},
		{name: "admission authority", deps: runtimeGenerationDependencies{authenticator: authenticator, evaluator: evaluator, supervisor: supervisor}},
		{name: "checkpoint evaluator", deps: runtimeGenerationDependencies{authenticator: authenticator, admission: admission, supervisor: supervisor}},
		{name: "post-action supervisor", deps: runtimeGenerationDependencies{authenticator: authenticator, admission: admission, evaluator: evaluator}},
		{name: "typed-nil caller authenticator", deps: runtimeGenerationDependencies{authenticator: nilAuthenticator, admission: admission, evaluator: evaluator, supervisor: supervisor}},
		{name: "typed-nil admission authority", deps: runtimeGenerationDependencies{authenticator: authenticator, admission: nilAdmission, evaluator: evaluator, supervisor: supervisor}},
		{name: "typed-nil checkpoint evaluator", deps: runtimeGenerationDependencies{authenticator: authenticator, admission: admission, evaluator: nilEvaluator, supervisor: supervisor}},
		{name: "typed-nil post-action supervisor", deps: runtimeGenerationDependencies{authenticator: authenticator, admission: admission, evaluator: evaluator, supervisor: nilSupervisor}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newRuntimeGeneration(1, test.deps); !errors.Is(err, ErrDecisionServiceDependencyMissing) {
				t.Fatalf("newRuntimeGeneration() error = %v, want ErrDecisionServiceDependencyMissing", err)
			}
		})
	}

	if _, err := NewDecisionService(nil); !errors.Is(err, ErrDecisionServiceDependencyMissing) {
		t.Fatalf("NewDecisionService(nil) error = %v, want ErrDecisionServiceDependencyMissing", err)
	}

	var nilSource *replaceableGenerationSource
	if _, err := NewDecisionService(nilSource); !errors.Is(err, ErrDecisionServiceDependencyMissing) {
		t.Fatalf("NewDecisionService(typed nil) error = %v, want ErrDecisionServiceDependencyMissing", err)
	}
}

func TestDecisionServiceAuthenticationAndAdmissionCannotBeBypassed(t *testing.T) {
	authenticationFailure := errors.New("credential rejected")
	admissionFailure := errors.New("caller not admitted")

	tests := []struct {
		name              string
		authenticationErr error
		admissionErr      error
		wantAdmission     int
	}{
		{name: "authentication rejection", authenticationErr: authenticationFailure},
		{name: "admission rejection", admissionErr: admissionFailure, wantAdmission: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authenticator := &recordingCallerAuthenticator{
				caller: mustAuthorityCaller(t, false),
				err:    test.authenticationErr,
			}
			admission := &recordingAdmissionAuthority{err: test.admissionErr}
			evaluator := &recordingCheckpointEvaluator{}
			generation := mustRuntimeGeneration(t, 1, authenticator, admission, evaluator)
			source := &replaceableGenerationSource{generation: generation}
			service := mustDecisionService(t, source)

			_, err := service.Evaluate(context.Background(), mustAuthorityInvocation(t, false))
			if err == nil {
				t.Fatal("DecisionService.Evaluate() error = nil, want rejection")
			}

			if authenticator.callCount() != 1 {
				t.Fatalf("authenticator calls = %d, want 1", authenticator.callCount())
			}

			if admission.callCount() != test.wantAdmission {
				t.Fatalf("admission calls = %d, want %d", admission.callCount(), test.wantAdmission)
			}

			if evaluator.callCount() != 0 {
				t.Fatalf("evaluator calls = %d, want 0", evaluator.callCount())
			}
		})
	}
}

func TestDecisionServiceAdmissionPermitScopesFactsAndRelease(t *testing.T) {
	permit := &recordingAdmissionPermit{facts: mustAuthorityAdmissionFacts(t)}
	admission := &recordingAdmissionAuthority{permit: permit}
	evaluator := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 1, "decision-admitted")}
	generation := mustRuntimeGeneration(
		t,
		1,
		&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, false)},
		admission,
		evaluator,
	)
	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	if _, err := service.Evaluate(context.Background(), mustAuthorityInvocation(t, false)); err != nil {
		t.Fatalf("DecisionService.Evaluate() error = %v", err)
	}

	calls := evaluator.recordedCalls()
	if len(calls) != 1 || calls[0].facts.Len() != 1 {
		t.Fatalf("evaluator admitted facts = %d calls/%d facts, want 1/1", len(calls), calls[0].facts.Len())
	}

	if _, exists := calls[0].facts.Get("input.admitted"); !exists {
		t.Fatal("evaluator did not receive the admission-owned fact set")
	}

	if permit.releaseCount() != 1 {
		t.Fatalf("admission permit releases = %d, want 1", permit.releaseCount())
	}
}

func TestDecisionServiceReleasesPermitReturnedWithAdmissionError(t *testing.T) {
	permit := &recordingAdmissionPermit{facts: mustAuthorityEmptyFacts(t)}
	admission := &recordingAdmissionAuthority{
		permit:              permit,
		err:                 errors.New("rejected after capacity acquisition"),
		returnPermitOnError: true,
	}
	evaluator := &recordingCheckpointEvaluator{}
	generation := mustRuntimeGeneration(
		t,
		1,
		&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, false)},
		admission,
		evaluator,
	)
	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	if _, err := service.Evaluate(context.Background(), mustAuthorityInvocation(t, false)); !errors.Is(err, ErrDecisionAdmission) {
		t.Fatalf("DecisionService.Evaluate() error = %v, want ErrDecisionAdmission", err)
	}

	if permit.releaseCount() != 1 || evaluator.callCount() != 0 {
		t.Fatalf("permit releases/evaluator calls = %d/%d, want 1/0", permit.releaseCount(), evaluator.callCount())
	}
}

func TestDecisionServiceUnaryCallCapturesOneGenerationDuringReplacement(t *testing.T) {
	firstEvaluator := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 1, "decision-first")}
	secondEvaluator := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 2, "decision-second")}
	admission := &recordingAdmissionAuthority{}
	source := &replaceableGenerationSource{}
	authenticationStarted := make(chan struct{})
	authenticationContinues := make(chan struct{})
	secondGeneration := mustRuntimeGeneration(
		t,
		2,
		&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, false)},
		admission,
		secondEvaluator,
	)
	firstAuthenticator := &recordingCallerAuthenticator{
		caller: mustAuthorityCaller(t, false),
		after: func() {
			close(authenticationStarted)
			<-authenticationContinues
		},
	}
	firstGeneration := mustRuntimeGeneration(t, 1, firstAuthenticator, admission, firstEvaluator)
	source.replace(firstGeneration)
	service := mustDecisionService(t, source)
	response := evaluateDuringGenerationReplacement(
		t,
		service,
		source,
		secondGeneration,
		authenticationStarted,
		authenticationContinues,
	)

	if response.Policy().Generation() != 1 || response.DecisionID().String() != "decision-first" {
		t.Fatalf(
			"response generation/decision = %d/%q, want 1/decision-first",
			response.Policy().Generation(),
			response.DecisionID().String(),
		)
	}

	if source.captureCount() != 1 {
		t.Fatalf("generation captures = %d, want 1", source.captureCount())
	}

	if firstEvaluator.callCount() != 1 || secondEvaluator.callCount() != 0 {
		t.Fatalf("evaluator calls = first:%d second:%d, want first:1 second:0", firstEvaluator.callCount(), secondEvaluator.callCount())
	}

	calls := firstEvaluator.recordedCalls()
	if calls[0].generation != 1 || calls[0].checkpoint.Name() != CheckpointFinalDecision {
		t.Fatalf("evaluation generation/checkpoint = %d/%q", calls[0].generation, calls[0].checkpoint.Name())
	}
}

func TestDecisionSessionReusesGenerationAndRuntimeAcrossCheckpoints(t *testing.T) {
	evaluator := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 7, "decision-session")}
	replacementEvaluator := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 8, "replacement-session")}
	authenticator := &recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)}
	admission := &recordingAdmissionAuthority{}
	generation := mustRuntimeGeneration(t, 7, authenticator, admission, evaluator)
	source := &replaceableGenerationSource{generation: generation}
	service := mustDecisionService(t, source)

	err := service.WithSession(context.Background(), mustAuthorityInvocation(t, true), func(session DecisionSession) error {
		evaluateSessionCheckpoints(t, session, []string{"pre_auth"})
		source.replace(mustRuntimeGeneration(
			t,
			8,
			&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)},
			&recordingAdmissionAuthority{},
			replacementEvaluator,
		))
		evaluateSessionCheckpoints(t, session, []string{"auth_decision"})

		return nil
	})
	if err != nil {
		t.Fatalf("DecisionService.WithSession() error = %v", err)
	}

	assertSessionAuthorityCalls(t, source, authenticator, admission)
	assertRecordedSessionCheckpoints(t, evaluator.recordedCalls())

	if replacementEvaluator.callCount() != 0 {
		t.Fatalf("replacement evaluator calls = %d, want 0", replacementEvaluator.callCount())
	}
}

func TestDecisionSessionCannotEscapeCapturedGenerationLifetime(t *testing.T) {
	generation := mustRuntimeGeneration(
		t,
		1,
		&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)},
		&recordingAdmissionAuthority{},
		&recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 1, "scoped-session")},
	)
	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	var escaped DecisionSession

	err := service.WithSession(context.Background(), mustAuthorityInvocation(t, true), func(session DecisionSession) error {
		escaped = session

		return nil
	})
	if err != nil {
		t.Fatalf("DecisionService.WithSession() error = %v", err)
	}

	facts, err := NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	checkpoint, err := NewCheckpoint("escaped", facts)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}

	if _, err = escaped.Evaluate(context.Background(), checkpoint); !errors.Is(err, ErrDecisionEvaluation) {
		t.Fatalf("escaped DecisionSession.Evaluate() error = %v, want ErrDecisionEvaluation", err)
	}
}

func TestDecisionSessionRequiresAdmittedBuiltinInternalAuthnCaller(t *testing.T) {
	tests := []struct {
		name      string
		internal  bool
		namespace string
		action    string
	}{
		{name: "external caller", namespace: "authn", action: "authenticate"},
		{name: "non-authn target", internal: true, namespace: "dkim2", action: "sign-message-instance"},
		{name: "unsupported authn action", internal: true, namespace: "authn", action: "custom"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluator := &recordingCheckpointEvaluator{}
			permit := &recordingAdmissionPermit{facts: mustAuthorityEmptyFacts(t)}
			admission := &recordingAdmissionAuthority{permit: permit}
			generation := mustRuntimeGeneration(
				t,
				1,
				&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, test.internal)},
				admission,
				evaluator,
			)
			service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

			err := service.WithSession(
				context.Background(),
				mustAuthorityTargetInvocation(t, test.namespace, test.action),
				func(DecisionSession) error {
					t.Fatal("rejected session callback was invoked")

					return nil
				},
			)
			if !errors.Is(err, ErrDecisionAdmission) {
				t.Fatalf("DecisionService.WithSession() error = %v, want ErrDecisionAdmission", err)
			}

			if evaluator.callCount() != 0 {
				t.Fatalf("evaluator calls = %d, want 0", evaluator.callCount())
			}

			if permit.releaseCount() != 1 {
				t.Fatalf("admission permit releases = %d, want 1", permit.releaseCount())
			}
		})
	}
}

func TestDecisionServiceSanitizesAuthorityAndEvaluatorErrors(t *testing.T) {
	secret := "secret-bearing internal failure"

	tests := []struct {
		name          string
		authenticator *recordingCallerAuthenticator
		admission     *recordingAdmissionAuthority
		evaluator     *recordingCheckpointEvaluator
	}{
		{
			name:          "authentication",
			authenticator: &recordingCallerAuthenticator{err: errors.New(secret)},
			admission:     &recordingAdmissionAuthority{},
			evaluator:     &recordingCheckpointEvaluator{},
		},
		{
			name:          "admission",
			authenticator: &recordingCallerAuthenticator{caller: mustAuthorityCaller(t, false)},
			admission:     &recordingAdmissionAuthority{err: errors.New(secret)},
			evaluator:     &recordingCheckpointEvaluator{},
		},
		{
			name:          "evaluation",
			authenticator: &recordingCallerAuthenticator{caller: mustAuthorityCaller(t, false)},
			admission:     &recordingAdmissionAuthority{},
			evaluator:     &recordingCheckpointEvaluator{err: errors.New(secret)},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generation := mustRuntimeGeneration(t, 1, test.authenticator, test.admission, test.evaluator)
			service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

			_, err := service.Evaluate(context.Background(), mustAuthorityInvocation(t, false))
			if err == nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("DecisionService.Evaluate() error = %v, want sanitized application error", err)
			}
		})
	}
}

func TestDecisionServiceRejectsInvalidAuthenticatorOutputBeforeAdmission(t *testing.T) {
	admission := &recordingAdmissionAuthority{}
	evaluator := &recordingCheckpointEvaluator{}
	generation := mustRuntimeGeneration(
		t,
		1,
		&recordingCallerAuthenticator{},
		admission,
		evaluator,
	)
	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	_, err := service.Evaluate(context.Background(), mustAuthorityInvocation(t, false))
	if !errors.Is(err, ErrDecisionAuthentication) {
		t.Fatalf("DecisionService.Evaluate() error = %v, want ErrDecisionAuthentication", err)
	}

	if admission.callCount() != 0 || evaluator.callCount() != 0 {
		t.Fatalf("admission/evaluator calls = %d/%d, want 0/0", admission.callCount(), evaluator.callCount())
	}
}

type recordingCallerAuthenticator struct {
	after  func()
	caller CallerContext
	err    error
	mu     sync.Mutex
	calls  int
}

type evaluationResult struct {
	response decision.DecisionResponse
	err      error
}

// Authenticate records one explicit credential-verification attempt.
func (a *recordingCallerAuthenticator) Authenticate(_ context.Context, _ AuthenticationInput) (CallerContext, error) {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()

	if a.after != nil {
		a.after()
	}

	return a.caller, a.err
}

// callCount returns the synchronized authentication call count.
func (a *recordingCallerAuthenticator) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.calls
}

type recordingAdmissionAuthority struct {
	permit              *recordingAdmissionPermit
	err                 error
	mu                  sync.Mutex
	calls               int
	returnPermitOnError bool
}

// Admit records one explicit caller/request authorization attempt.
func (a *recordingAdmissionAuthority) Admit(
	_ context.Context,
	_ CallerContext,
	_ DecisionRequest,
) (admissionPermit, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.calls++
	if a.err != nil {
		if a.returnPermitOnError {
			return a.permit, a.err
		}

		return nil, a.err
	}

	if a.permit == nil {
		facts, _ := decision.NewFactSet(nil)
		a.permit = &recordingAdmissionPermit{facts: facts}
	}

	return a.permit, nil
}

// callCount returns the synchronized admission call count.
func (a *recordingAdmissionAuthority) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.calls
}

type recordingAdmissionPermit struct {
	facts    FactSet
	mu       sync.Mutex
	releases int
}

// Facts returns the immutable fact set assembled during admission.
func (p *recordingAdmissionPermit) Facts() FactSet {
	return p.facts
}

// Release records deterministic permit ownership release.
func (p *recordingAdmissionPermit) Release() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.releases++
}

// releaseCount returns the synchronized permit release count.
func (p *recordingAdmissionPermit) releaseCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.releases
}

type recordedCheckpointEvaluation struct {
	checkpoint Checkpoint
	facts      FactSet
	supervisor effectsupervisor.Acceptor
	generation uint64
}

type recordingCheckpointEvaluator struct {
	outcome runtimeEvaluation
	err     error
	mu      sync.Mutex
	calls   []recordedCheckpointEvaluation
}

// Checkpoints returns the operation-specific plan used by recording authn sessions.
func (e *recordingCheckpointEvaluator) Checkpoints(target decision.Target) ([]CheckpointPlan, error) {
	if target.Namespace() != "authn" {
		return []CheckpointPlan{newCheckpointPlan(decision.CheckpointFinalDecision, nil)}, nil
	}

	if target.Action() == "list_accounts" {
		return []CheckpointPlan{newCheckpointPlan("auth_decision", nil)}, nil
	}

	return []CheckpointPlan{
		newCheckpointPlan("pre_auth", nil),
		newCheckpointPlan("auth_decision", nil),
	}, nil
}

// Evaluate records the package-private checkpoint runtime input.
func (e *recordingCheckpointEvaluator) Evaluate(_ context.Context, input checkpointEvaluation) (runtimeEvaluation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.calls = append(e.calls, recordedCheckpointEvaluation{
		checkpoint: input.checkpoint,
		facts:      input.facts,
		supervisor: input.supervisor,
		generation: input.generation,
	})

	outcome := e.outcome
	outcome.report.checkpoint = input.checkpoint.Name()

	return outcome, e.err
}

// mustAuthorityEmptyFacts constructs one valid empty admission fact set.
func mustAuthorityEmptyFacts(t *testing.T) FactSet {
	t.Helper()

	facts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	return facts
}

// mustAuthorityAdmissionFacts constructs one caller-owned fact for permit propagation.
func mustAuthorityAdmissionFacts(t *testing.T) FactSet {
	t.Helper()

	valueText := "yes"

	value, err := decision.NewValue(decision.ValueInput{String: &valueText})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	provenance, err := decision.NewProvenance(decision.FactSourceCaller, "test-authority", "request")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	fact, err := decision.NewFact("input.admitted", decision.FactCategoryEnvironment, value, provenance)
	if err != nil {
		t.Fatalf("NewFact() error = %v", err)
	}

	facts, err := decision.NewFactSet([]decision.Fact{fact})
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	return facts
}

// callCount returns the synchronized evaluator call count.
func (e *recordingCheckpointEvaluator) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return len(e.calls)
}

// recordedCalls returns detached evaluator call evidence.
func (e *recordingCheckpointEvaluator) recordedCalls() []recordedCheckpointEvaluation {
	e.mu.Lock()
	defer e.mu.Unlock()

	return append([]recordedCheckpointEvaluation(nil), e.calls...)
}

type recordingEffectAcceptor struct{}

// Accept satisfies the mandatory supervisor boundary without permissive production wiring.
func (a *recordingEffectAcceptor) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

type replaceableGenerationSource struct {
	mu         sync.Mutex
	generation Generation
	captures   int
}

// WithGeneration returns one generation for the complete callback scope.
func (s *replaceableGenerationSource) WithGeneration(
	_ context.Context,
	use func(Generation) error,
) error {
	s.mu.Lock()
	s.captures++
	generation := s.generation
	s.mu.Unlock()

	return use(generation)
}

// replace atomically changes the generation observed by the next capture.
func (s *replaceableGenerationSource) replace(generation Generation) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.generation = generation
}

// captureCount returns the synchronized generation capture count.
func (s *replaceableGenerationSource) captureCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.captures
}

// mustRuntimeGeneration constructs one complete explicit test generation.
func mustRuntimeGeneration(
	t *testing.T,
	id uint64,
	authenticator callerAuthenticator,
	admission admissionAuthority,
	evaluator checkpointEvaluator,
) Generation {
	t.Helper()

	generation, err := newRuntimeGeneration(id, runtimeGenerationDependencies{
		material:      mustRuntimeGenerationMaterial(t, testPolicyAPIConfig(true, true, true), nil),
		authenticator: authenticator,
		admission:     admission,
		evaluator:     evaluator,
		supervisor:    &recordingEffectAcceptor{},
	})
	if err != nil {
		t.Fatalf("newRuntimeGeneration() error = %v", err)
	}

	return generation
}

// mustDecisionService constructs the application authority with one explicit generation source.
func mustDecisionService(t *testing.T, source GenerationSource) *DecisionService {
	t.Helper()

	service, err := NewDecisionService(source)
	if err != nil {
		t.Fatalf("NewDecisionService() error = %v", err)
	}

	return service
}

// mustAuthorityInvocation constructs one transport-neutral generic or authn invocation.
func mustAuthorityInvocation(t *testing.T, authn bool) Invocation {
	t.Helper()

	namespace := "dkim2"
	action := "sign-message-instance"

	if authn {
		namespace = "authn"
		action = "authenticate"
	}

	return mustAuthorityTargetInvocation(t, namespace, action)
}

// evaluateDuringGenerationReplacement replaces the current generation while authentication is in flight.
func evaluateDuringGenerationReplacement(
	t *testing.T,
	service *DecisionService,
	source *replaceableGenerationSource,
	replacement Generation,
	authenticationStarted <-chan struct{},
	authenticationContinues chan<- struct{},
) decision.DecisionResponse {
	t.Helper()

	invocation := mustAuthorityInvocation(t, false)
	resultChannel := make(chan evaluationResult, 1)

	go func() {
		response, err := service.Evaluate(context.Background(), invocation)
		resultChannel <- evaluationResult{response: response, err: err}
	}()

	<-authenticationStarted
	source.replace(replacement)
	close(authenticationContinues)

	result := <-resultChannel
	if result.err != nil {
		t.Fatalf("DecisionService.Evaluate() error = %v", result.err)
	}

	return result.response
}

// mustAuthorityTargetInvocation constructs one invocation for an exact target.
func mustAuthorityTargetInvocation(t *testing.T, namespace string, action string) Invocation {
	t.Helper()

	target, err := NewTarget(namespace, action)
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	authentication, err := NewAuthenticationInput(AuthenticationEvidence{
		Kind:          "test",
		Credential:    []byte("opaque-test-evidence"),
		TransportKind: "internal",
		Protected:     true,
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	return Invocation{
		Request: DecisionRequestInput{
			Version:   ContractVersion,
			RequestID: "request-authority",
			Target:    target,
		},
		Authentication: authentication,
	}
}

// evaluateSessionCheckpoints runs ordered checkpoints through one captured session.
func evaluateSessionCheckpoints(t *testing.T, session DecisionSession, names []string) {
	t.Helper()

	facts, err := NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	for _, name := range names {
		if concrete, ok := session.(*decisionSession); ok {
			if _, scheduled := concrete.generation.evaluator.(authnHostScheduler); scheduled {
				evaluateAuthnCheckpoint(t, session, name)

				continue
			}
		}

		checkpoint, err := NewCheckpoint(name, facts)
		if err != nil {
			t.Fatalf("NewCheckpoint(%q) error = %v", name, err)
		}

		if _, err := session.Evaluate(context.Background(), checkpoint); err != nil {
			t.Fatalf("DecisionSession.Evaluate(%q) error = %v", name, err)
		}
	}
}

// assertSessionAuthorityCalls proves authentication and admission occur once per session.
func assertSessionAuthorityCalls(
	t *testing.T,
	source *replaceableGenerationSource,
	authenticator *recordingCallerAuthenticator,
	admission *recordingAdmissionAuthority,
) {
	t.Helper()

	if source.captureCount() != 1 || authenticator.callCount() != 1 || admission.callCount() != 1 {
		t.Fatalf(
			"captures/authentication/admission = %d/%d/%d, want 1/1/1",
			source.captureCount(),
			authenticator.callCount(),
			admission.callCount(),
		)
	}
}

// assertRecordedSessionCheckpoints proves one runtime generation serves the complete plan.
func assertRecordedSessionCheckpoints(t *testing.T, calls []recordedCheckpointEvaluation) {
	t.Helper()

	if len(calls) != 2 || calls[0].generation != 7 || calls[1].generation != 7 {
		t.Fatalf("recorded evaluation calls = %+v, want two generation-7 calls", calls)
	}

	if calls[0].checkpoint.Name() != "pre_auth" || calls[1].checkpoint.Name() != "auth_decision" {
		t.Fatalf("recorded checkpoints = %q/%q", calls[0].checkpoint.Name(), calls[1].checkpoint.Name())
	}

	if calls[0].supervisor == nil || calls[0].supervisor != calls[1].supervisor {
		t.Fatal("recorded checkpoints did not retain the same generation-owned post-action supervisor")
	}
}

// mustAuthorityCaller constructs explicit authenticator output for tests.
func mustAuthorityCaller(t *testing.T, internal bool) CallerContext {
	t.Helper()

	caller, err := NewCallerContext(TrustedCallerInput{
		Principal:          "test-authority",
		AuthenticationKind: "test",
		TransportKind:      "internal",
		Internal:           internal,
	})
	if err != nil {
		t.Fatalf("NewCallerContext() error = %v", err)
	}

	return caller
}

// mustRuntimeEvaluation constructs one sanitized result and internal report boundary.
func mustRuntimeEvaluation(t *testing.T, generation uint64, decisionID string) runtimeEvaluation {
	t.Helper()

	status, err := NewStatus(StatusCodePermit, "permitted", nil)
	if err != nil {
		t.Fatalf("NewStatus() error = %v", err)
	}

	metadata, err := NewPolicyMetadata("authn/standard_auth", "1", "permit", generation)
	if err != nil {
		t.Fatalf("NewPolicyMetadata() error = %v", err)
	}

	response, err := NewDecisionResponse(decision.DecisionResponseInput{
		RequestID:  "request-authority",
		DecisionID: decisionID,
		Effect:     EffectPermit,
		Status:     status,
		Policy:     metadata,
	})
	if err != nil {
		t.Fatalf("NewDecisionResponse() error = %v", err)
	}

	return runtimeEvaluation{
		response: response,
		report: internalDecisionReport{
			generation: generation,
			checkpoint: CheckpointFinalDecision,
		},
	}
}

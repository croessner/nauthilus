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

// Package service owns the admission-enforcing policy decision application authority.
package service

import (
	"context"
	"errors"
	"fmt"
	"sync"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

var _ decision.Service = (*DecisionService)(nil)

// PreparedService is the production transport boundary for capture-first invocation construction.
type PreparedService interface {
	decision.Service
	EvaluatePrepared(
		context.Context,
		string,
		func(policyruntime.GenerationConfig) (decision.Invocation, error),
	) (decision.DecisionResponse, error)
}

var _ PreparedService = (*DecisionService)(nil)

// DecisionSessionFactory is the scoped authn adapter boundary of the same authority.
type DecisionSessionFactory interface {
	WithSession(context.Context, decision.Invocation, func(DecisionSession) error) error
	WithInternalSession(context.Context, InternalSessionInput, func(DecisionSession) error) error
}

// DecisionSession evaluates multiple checkpoints on one admitted captured generation.
type DecisionSession interface {
	Checkpoints() []CheckpointPlan
	RequestContext(context.Context) context.Context
	Evaluate(context.Context, decision.Checkpoint) (decision.DecisionResponse, error)
}

// AuthnHostProvider is the narrow generation-owned host-source boundary.
type AuthnHostProvider = policyruntime.AuthnHostProvider

// AuthnLuaFactDeclaration is one immutable generation-owned registry-script fact declaration.
type AuthnLuaFactDeclaration = registry.AuthnLuaFactDeclaration

// AuthnPolicyAttributeDefinition is one immutable generation-owned native auth fact declaration.
type AuthnPolicyAttributeDefinition = registry.AttributeDefinition

const (
	// AuthnHostProviderKindLuaEnvironment identifies one captured environment source.
	AuthnHostProviderKindLuaEnvironment = policyruntime.AuthnHostProviderKindLuaEnvironment
	// AuthnHostProviderKindLuaSubject identifies one captured subject source.
	AuthnHostProviderKindLuaSubject = policyruntime.AuthnHostProviderKindLuaSubject
	// AuthnHostProviderKindNativeEnvironment identifies one captured native environment source.
	AuthnHostProviderKindNativeEnvironment = policyruntime.AuthnHostProviderKindNativeEnvironment
	// AuthnHostProviderKindNativeSubject identifies one captured native subject source.
	AuthnHostProviderKindNativeSubject = policyruntime.AuthnHostProviderKindNativeSubject
)

// AuthnNativeEnvironmentProvider is one exact captured public environment source.
type AuthnNativeEnvironmentProvider interface {
	AuthnHostProvider
	Capabilities() []pluginapi.Capability
	EvaluateEnvironment(context.Context, pluginapi.EnvironmentRequest) (pluginapi.EnvironmentResult, error)
}

// AuthnNativeSubjectProvider is one exact captured public subject source.
type AuthnNativeSubjectProvider interface {
	AuthnHostProvider
	Capabilities() []pluginapi.Capability
	EvaluateSubject(context.Context, pluginapi.SubjectRequest) (pluginapi.SubjectResult, error)
}

// AuthnNativeEffectProgram is one immutable generation-owned public auth extension target.
type AuthnNativeEffectProgram = policyruntime.AuthnNativeEffectProgram

// AuthnNativeEffectHost is the request-local owner of selected public auth extension effects.
type AuthnNativeEffectHost = policyruntime.AuthnNativeEffectHost

// ContextWithAuthnNativeEffectHost binds one request-local native effect host to an admitted context.
func ContextWithAuthnNativeEffectHost(ctx context.Context, host AuthnNativeEffectHost) context.Context {
	return policyruntime.ContextWithAuthnNativeEffectHost(ctx, host)
}

// AuthnHostProviderSession exposes exact configured host sources on production sessions.
type AuthnHostProviderSession interface {
	DecisionSession
	AuthnHostProvider(string) (AuthnHostProvider, bool)
}

// AuthnLuaFactSession exposes registry-script declarations captured by one production session.
type AuthnLuaFactSession interface {
	DecisionSession
	AuthnLuaFacts() []AuthnLuaFactDeclaration
}

// AuthnPolicyAttributeSession exposes exact native fact metadata captured by one production session.
type AuthnPolicyAttributeSession interface {
	DecisionSession
	AuthnPolicyAttributes() map[string]AuthnPolicyAttributeDefinition
}

// CapturedGenerationIDFromContext returns the generation identity retained by a session request context.
func CapturedGenerationIDFromContext(ctx context.Context) (uint64, bool) {
	return policyruntime.GenerationFromContext(ctx)
}

// CheckpointProviderInstance is one exact scheduled provider instance with immutable guard metadata.
type CheckpointProviderInstance struct {
	actions             []string
	after               []string
	dependencies        []string
	skipIf              []string
	name                string
	use                 string
	runIfAuthState      string
	output              string
	observeSafe         bool
	observeSafeAuthored bool
}

// Name returns the checkpoint-local instance identity.
func (i CheckpointProviderInstance) Name() string { return i.name }

// Use returns the exact provider definition identity.
func (i CheckpointProviderInstance) Use() string { return i.use }

// Actions returns detached target-action restrictions.
func (i CheckpointProviderInstance) Actions() []string { return append([]string(nil), i.actions...) }

// After returns detached authored dependency edges.
func (i CheckpointProviderInstance) After() []string { return append([]string(nil), i.after...) }

// Dependencies returns detached compiled dependency edges.
func (i CheckpointProviderInstance) Dependencies() []string {
	return append([]string(nil), i.dependencies...)
}

// RunIfAuthState returns the closed dynamic authentication-state guard.
func (i CheckpointProviderInstance) RunIfAuthState() string { return i.runIfAuthState }

// SkipIf returns detached plan-local scheduler guard names.
func (i CheckpointProviderInstance) SkipIf() []string { return append([]string(nil), i.skipIf...) }

// ObserveSafe reports whether this provider may execute in observe mode.
func (i CheckpointProviderInstance) ObserveSafe() bool { return i.observeSafe }

// ObserveSafeAuthored reports whether observe safety was explicitly configured.
func (i CheckpointProviderInstance) ObserveSafeAuthored() bool { return i.observeSafeAuthored }

// Output returns the optional checkpoint-local output fact identity.
func (i CheckpointProviderInstance) Output() string { return i.output }

// clone returns a deeply detached provider instance.
func (i CheckpointProviderInstance) clone() CheckpointProviderInstance {
	i.actions = i.Actions()
	i.after = i.After()
	i.dependencies = i.Dependencies()
	i.skipIf = i.SkipIf()

	return i
}

// CheckpointPlan is one detached checkpoint and its exact immutable provider instances.
type CheckpointPlan struct {
	instances []CheckpointProviderInstance
	name      string
}

// newCheckpointPlan constructs one detached runtime-owned checkpoint plan.
func newCheckpointPlan(name string, instances []CheckpointProviderInstance) CheckpointPlan {
	return CheckpointPlan{name: name, instances: cloneCheckpointProviderInstances(instances)}
}

// NewCheckpointPlan constructs one detached session-boundary checkpoint descriptor.
func NewCheckpointPlan(name string, instances []CheckpointProviderInstance) (CheckpointPlan, error) {
	if name == "" {
		return CheckpointPlan{}, fmt.Errorf("%w: checkpoint name is required", ErrDecisionEvaluation)
	}

	seen := make(map[string]struct{}, len(instances))
	for _, instance := range instances {
		if instance.Name() == "" || instance.Use() == "" {
			return CheckpointPlan{}, fmt.Errorf("%w: provider instance identity is required", ErrDecisionEvaluation)
		}

		if _, exists := seen[instance.Name()]; exists {
			return CheckpointPlan{}, fmt.Errorf("%w: duplicate provider instance identity", ErrDecisionEvaluation)
		}

		seen[instance.Name()] = struct{}{}
	}

	return newCheckpointPlan(name, instances), nil
}

// Name returns the exact checkpoint identity.
func (p CheckpointPlan) Name() string {
	return p.name
}

// ProviderInstances returns the exact detached scheduled instance order.
func (p CheckpointPlan) ProviderInstances() []CheckpointProviderInstance {
	return cloneCheckpointProviderInstances(p.instances)
}

// ProviderIDs derives the scheduled provider-use order from exact instances.
func (p CheckpointPlan) ProviderIDs() []string {
	result := make([]string, 0, len(p.instances))
	for _, instance := range p.instances {
		result = append(result, instance.Use())
	}

	return result
}

// clone returns one deeply detached checkpoint plan.
func (p CheckpointPlan) clone() CheckpointPlan {
	return newCheckpointPlan(p.name, p.instances)
}

// cloneCheckpointProviderInstances deeply detaches one exact schedule.
func cloneCheckpointProviderInstances(input []CheckpointProviderInstance) []CheckpointProviderInstance {
	result := make([]CheckpointProviderInstance, len(input))
	for index, instance := range input {
		result[index] = instance.clone()
	}

	return result
}

// DecisionService is the sole callable policy decision application authority.
type DecisionService struct {
	generations GenerationSource
	observer    decision.Observer
}

// NewDecisionService constructs the authority with a mandatory generation source.
func NewDecisionService(generations GenerationSource, options ...DecisionServiceOption) (*DecisionService, error) {
	if nilDependency(generations) {
		return nil, fmt.Errorf("%w: generation source is required", ErrDecisionServiceDependencyMissing)
	}

	service := &DecisionService{generations: generations, observer: nopDecisionObserver{}}

	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: service option is required", ErrDecisionServiceDependencyMissing)
		}

		if err := option(service); err != nil {
			return nil, fmt.Errorf("%w: invalid service option", err)
		}
	}

	return service, nil
}

// Evaluate authenticates and admits one unary invocation before one final checkpoint.
func (s *DecisionService) Evaluate(
	ctx context.Context,
	invocation decision.Invocation,
) (decision.DecisionResponse, error) {
	var response decision.DecisionResponse

	err := s.withGeneration(normalizeContext(ctx), func(generation *runtimeGeneration) error {
		var evaluationErr error

		response, evaluationErr = s.evaluateCaptured(ctx, generation, invocation)

		return evaluationErr
	})

	return response, err
}

// EvaluatePrepared captures configuration before the transport creates trusted invocation evidence.
func (s *DecisionService) EvaluatePrepared(
	ctx context.Context,
	transportKind string,
	prepare func(policyruntime.GenerationConfig) (decision.Invocation, error),
) (decision.DecisionResponse, error) {
	if prepare == nil {
		return decision.DecisionResponse{}, fmt.Errorf(
			"%w: invocation preparation callback is required",
			ErrDecisionServiceDependencyMissing,
		)
	}

	var response decision.DecisionResponse

	err := s.withGeneration(normalizeContext(ctx), func(generation *runtimeGeneration) error {
		if err := validateDecisionRoute(generation.apiAvailability, transportKind); err != nil {
			return err
		}

		if generation.config == nil {
			return fmt.Errorf("%w: captured configuration is unavailable", ErrDecisionGenerationUnavailable)
		}

		invocation, err := prepare(generation.config)
		if err != nil {
			return err
		}

		response, err = s.evaluateRouteValidated(ctx, generation, invocation)

		return err
	})

	return response, err
}

// evaluateCaptured runs one unary decision without recapturing the generation lease.
func (s *DecisionService) evaluateCaptured(
	ctx context.Context,
	generation *runtimeGeneration,
	invocation decision.Invocation,
) (decision.DecisionResponse, error) {
	if err := validateDecisionRoute(generation.apiAvailability, invocation.Authentication.TransportKind()); err != nil {
		return decision.DecisionResponse{}, err
	}

	return s.evaluateRouteValidated(ctx, generation, invocation)
}

// evaluateRouteValidated runs one unary decision under an already validated transport route.
func (s *DecisionService) evaluateRouteValidated(
	ctx context.Context,
	generation *runtimeGeneration,
	invocation decision.Invocation,
) (decision.DecisionResponse, error) {
	generationCtx := policyruntime.ContextWithGeneration(normalizeContext(ctx), generation.id)
	observedCtx, finish := startDecisionObservation(generationCtx, s.observer, decision.Observation{
		Transport: invocation.Authentication.TransportKind(), AuthenticationKind: invocation.Authentication.Kind(),
		Generation: generation.id, DiagnosticsRequested: invocation.Request.Options.IncludeDiagnostics,
	})

	details := decision.ObservationResult{}
	response, err := s.evaluateObservedRoute(observedCtx, generation, invocation, &details)
	finish(decisionObservationResult(response, err, details))

	return response, err
}

// evaluateObservedRoute authenticates, admits, and evaluates one already observed invocation.
func (s *DecisionService) evaluateObservedRoute(
	ctx context.Context,
	generation *runtimeGeneration,
	invocation decision.Invocation,
	details *decision.ObservationResult,
) (decision.DecisionResponse, error) {
	session, err := s.openSession(ctx, generation, invocation, false)
	if err != nil {
		return decision.DecisionResponse{}, err
	}
	defer session.close()

	details.RequestID = session.request.RequestID()
	details.Target = session.request.Target()
	details.Principal = session.request.Caller().Principal()
	details.Admitted = true

	facts, err := decision.NewFactSet(nil)
	if err != nil {
		return decision.DecisionResponse{}, fmt.Errorf("%w: create unary fact set", ErrDecisionEvaluation)
	}

	checkpoint, err := decision.NewCheckpoint(decision.CheckpointFinalDecision, facts)
	if err != nil {
		return decision.DecisionResponse{}, fmt.Errorf("%w: create unary checkpoint", ErrDecisionEvaluation)
	}

	return session.Evaluate(ctx, checkpoint)
}

// WithSession owns one admitted builtin authn session for the complete callback scope.
func (s *DecisionService) WithSession(
	ctx context.Context,
	invocation decision.Invocation,
	use func(DecisionSession) error,
) error {
	return s.withSession(ctx, invocation, true, use)
}

// withSession owns capture, authentication, admission, and scoped session release.
func (s *DecisionService) withSession(
	ctx context.Context,
	invocation decision.Invocation,
	requireInternalAuthn bool,
	use func(DecisionSession) error,
) error {
	ctx = normalizeContext(ctx)

	if use == nil {
		return fmt.Errorf("%w: session callback is required", ErrDecisionServiceDependencyMissing)
	}

	return s.withGeneration(ctx, func(generation *runtimeGeneration) error {
		generationCtx := policyruntime.ContextWithGeneration(ctx, generation.id)
		if err := validateDecisionRoute(generation.apiAvailability, invocation.Authentication.TransportKind()); err != nil {
			return err
		}

		session, err := s.openSession(generationCtx, generation, invocation, requireInternalAuthn)
		if err != nil {
			return err
		}
		defer session.close()

		return use(session)
	})
}

// openSession authenticates and admits one invocation against an already captured generation.
func (s *DecisionService) openSession(
	ctx context.Context,
	generation *runtimeGeneration,
	invocation decision.Invocation,
	requireInternalAuthn bool,
) (*decisionSession, error) {
	caller, request, err := authenticateInvocation(ctx, generation, invocation)
	if err != nil {
		return nil, err
	}

	permit, err := generation.admission.Admit(ctx, caller, request)
	if err != nil {
		if !nilDependency(permit) {
			permit.Release()
		}

		return nil, newDecisionAdmissionError(err)
	}

	if nilDependency(permit) {
		return nil, fmt.Errorf("%w: caller or invocation was rejected", ErrDecisionAdmission)
	}

	if requireInternalAuthn && (!caller.Internal() || !validAuthnTarget(request.Target())) {
		permit.Release()

		return nil, fmt.Errorf("%w: authn sessions require the admitted builtin internal caller", ErrDecisionAdmission)
	}

	checkpoints, err := sessionCheckpointPlan(generation.evaluator, request.Target(), requireInternalAuthn)
	if err != nil {
		permit.Release()

		return nil, err
	}

	facts, err := decision.NewFactSet(permit.Facts().Facts())
	if err != nil {
		permit.Release()

		return nil, fmt.Errorf("%w: admission returned invalid facts", ErrDecisionAdmission)
	}

	return &decisionSession{
		generation:   generation,
		request:      request,
		facts:        facts,
		permit:       permit,
		finalization: invocation.Finalization,
		checkpoints:  checkpoints,
		hostStates:   make(map[string]providerState),
		hostReasons:  make(map[string]string),
	}, nil
}

// sessionCheckpointPlan captures one target plan from the same generation evaluator.
func sessionCheckpointPlan(
	evaluator checkpointEvaluator,
	target decision.Target,
	requireCompiledPlan bool,
) ([]CheckpointPlan, error) {
	source, ok := evaluator.(checkpointPlanSource)
	if !ok {
		if requireCompiledPlan {
			return nil, fmt.Errorf("%w: authn evaluator has no compiled checkpoint plan", ErrDecisionEvaluation)
		}

		return []CheckpointPlan{newCheckpointPlan(decision.CheckpointFinalDecision, nil)}, nil
	}

	checkpoints, err := source.Checkpoints(target)
	if err != nil || len(checkpoints) == 0 {
		return nil, fmt.Errorf("%w: target has no compiled checkpoint plan", ErrDecisionEvaluation)
	}

	return cloneCheckpointPlans(checkpoints), nil
}

// validAuthnTarget restricts reusable sessions to the exact builtin authn operations.
func validAuthnTarget(target decision.Target) bool {
	if target.Namespace() != policy.AuthnNamespace {
		return false
	}

	switch policy.Operation(target.Action()) {
	case policy.OperationAuthenticate, policy.OperationLookupIdentity, policy.OperationListAccounts:
		return true
	default:
		return false
	}
}

// withGeneration validates and uses the sole generation owned by one call or session.
func (s *DecisionService) withGeneration(
	ctx context.Context,
	use func(*runtimeGeneration) error,
) error {
	if s == nil || nilDependency(s.generations) {
		return fmt.Errorf("%w: generation source is required", ErrDecisionServiceDependencyMissing)
	}

	return s.generations.WithGeneration(ctx, func(captured Generation) error {
		if nilDependency(captured) {
			return fmt.Errorf("%w: capture returned no generation", ErrDecisionGenerationUnavailable)
		}

		generation := captured.decisionGeneration()
		if !generation.valid() {
			return fmt.Errorf("%w: capture returned an incomplete generation", ErrDecisionGenerationUnavailable)
		}

		return use(generation)
	})
}

// authenticateInvocation creates the sole trusted caller-bound request representation.
func authenticateInvocation(
	ctx context.Context,
	generation *runtimeGeneration,
	invocation decision.Invocation,
) (decision.CallerContext, decision.DecisionRequest, error) {
	if !validAuthenticationInput(invocation.Authentication) {
		return decision.CallerContext{}, decision.DecisionRequest{}, fmt.Errorf(
			"%w: invalid authentication presentation",
			ErrDecisionAuthentication,
		)
	}

	caller, err := generation.authenticator.Authenticate(ctx, invocation.Authentication)
	if err != nil {
		return decision.CallerContext{}, decision.DecisionRequest{}, fmt.Errorf(
			"%w: credential evidence was rejected",
			ErrDecisionAuthentication,
		)
	}

	request, err := decision.NewDecisionRequest(invocation.Request, caller)
	if err != nil {
		if errors.Is(err, decision.ErrInvalidCaller) {
			return decision.CallerContext{}, decision.DecisionRequest{}, fmt.Errorf(
				"%w: authenticator returned invalid caller evidence",
				ErrDecisionAuthentication,
			)
		}

		return decision.CallerContext{}, decision.DecisionRequest{}, err
	}

	return caller, request, nil
}

// normalizeContext supplies a non-nil application context for direct callers.
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}

	return ctx
}

// validAuthenticationInput reuses the transport-neutral constructor invariant.
func validAuthenticationInput(input decision.AuthenticationInput) bool {
	_, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          input.Kind(),
		Credential:    input.Credential(),
		TransportKind: input.TransportKind(),
		Listener:      input.Listener(),
		HTTPRoute:     input.HTTPRoute(),
		GRPCMethod:    input.GRPCMethod(),
		Peer:          input.Peer(),
		MTLSIdentity:  input.MTLSIdentity(),
		Protected:     input.Protected(),
	})

	return err == nil
}

type decisionSession struct {
	generation      *runtimeGeneration
	request         decision.DecisionRequest
	facts           decision.FactSet
	permit          admissionPermit
	finalization    decision.EvaluationFinalization
	checkpoints     []CheckpointPlan
	hostStates      map[string]providerState
	hostReasons     map[string]string
	mu              sync.Mutex
	evaluations     sync.WaitGroup
	hostPending     string
	hostPlan        string
	hostLastReceipt string
	hostCursor      int
	next            int
	hostAuthn       bool
	hostExhausted   bool
	hostTerminal    bool
	evaluating      bool
	closed          bool
}

var _ AuthnHostProviderSession = (*decisionSession)(nil)
var _ AuthnLuaFactSession = (*decisionSession)(nil)
var _ AuthnPolicyAttributeSession = (*decisionSession)(nil)

// RequestContext binds host work to the exact policy view captured by this session.
func (s *decisionSession) RequestContext(ctx context.Context) context.Context {
	ctx = normalizeContext(ctx)
	if s == nil || s.generation == nil {
		return ctx
	}

	ctx = policyruntime.ContextWithGeneration(ctx, s.generation.id)
	if s.generation.config != nil {
		ctx = contextWithCapturedConfig(ctx, s.generation.config)
	}

	if s.generation.messageResolver != nil {
		ctx = contextWithCapturedMessageResolver(ctx, s.generation.messageResolver)
	}

	if source, ok := s.generation.evaluator.(authorityModeSource); ok {
		if mode, exists := source.AuthorityMode(s.request.Target()); exists {
			ctx = contextWithCapturedPolicyMode(ctx, mode)
		}
	}

	return ctx
}

// AuthnHostProvider resolves one exact configured source from the captured generation.
func (s *decisionSession) AuthnHostProvider(id string) (AuthnHostProvider, bool) {
	if s == nil || s.generation == nil {
		return nil, false
	}

	provider, found := s.generation.authnHostProviders[id]

	return provider, found
}

// AuthnLuaFacts returns the exact registry-script declarations captured by this session.
func (s *decisionSession) AuthnLuaFacts() []AuthnLuaFactDeclaration {
	if s == nil || s.generation == nil {
		return nil
	}

	return cloneAuthnLuaFacts(s.generation.authnLuaFacts)
}

// AuthnPolicyAttributes returns exact native fact declarations captured by this session.
func (s *decisionSession) AuthnPolicyAttributes() map[string]AuthnPolicyAttributeDefinition {
	if s == nil || s.generation == nil {
		return nil
	}

	return cloneAuthnPolicyAttributes(s.generation.authnPolicyAttributes)
}

// Checkpoints returns the detached compiled plan while the session is in scope.
func (s *decisionSession) Checkpoints() []CheckpointPlan {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	return cloneCheckpointPlans(s.checkpoints)
}

// cloneCheckpointPlans detaches checkpoint identities and provider schedules together.
func cloneCheckpointPlans(plans []CheckpointPlan) []CheckpointPlan {
	result := make([]CheckpointPlan, 0, len(plans))
	for _, plan := range plans {
		result = append(result, plan.clone())
	}

	return result
}

// Evaluate runs one checkpoint on the generation and evaluator captured by the session.
func (s *decisionSession) Evaluate(
	ctx context.Context,
	checkpoint decision.Checkpoint,
) (decision.DecisionResponse, error) {
	if s == nil {
		return decision.DecisionResponse{}, fmt.Errorf("%w: invalid session or checkpoint", ErrDecisionEvaluation)
	}

	hostStates, hostReasons, authenticated, ok := s.beginEvaluation(checkpoint.Name())
	if !ok {
		return decision.DecisionResponse{}, fmt.Errorf("%w: invalid session or checkpoint", ErrDecisionEvaluation)
	}

	defer s.endEvaluation()

	ctx = policyruntime.ContextWithGeneration(ctx, s.generation.id)

	ownedCheckpoint, err := decision.NewCheckpoint(checkpoint.Name(), checkpoint.Facts())
	if err != nil {
		return decision.DecisionResponse{}, fmt.Errorf("%w: invalid session or checkpoint", ErrDecisionEvaluation)
	}

	evaluation := checkpointEvaluation{
		request:       s.request,
		checkpoint:    ownedCheckpoint,
		facts:         s.facts,
		hostStates:    hostStates,
		hostReasons:   hostReasons,
		finalization:  s.finalization,
		supervisor:    s.generation.supervisor,
		generation:    s.generation.id,
		authenticated: authenticated,
	}
	if !evaluation.valid() {
		return decision.DecisionResponse{}, fmt.Errorf("%w: incomplete checkpoint runtime input", ErrDecisionEvaluation)
	}

	outcome, err := s.generation.evaluator.Evaluate(normalizeContext(ctx), evaluation)
	if err != nil {
		return decision.DecisionResponse{}, fmt.Errorf("%w: checkpoint execution failed", ErrDecisionEvaluation)
	}

	if !outcome.valid(s.generation.id, ownedCheckpoint.Name()) {
		return decision.DecisionResponse{}, fmt.Errorf("%w: evaluator returned an invalid boundary result", ErrDecisionEvaluation)
	}

	return outcome.response, nil
}

// beginEvaluation enforces compiled checkpoint order and serial session execution.
func (s *decisionSession) beginEvaluation(checkpoint string) (map[string]providerState, map[string]string, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.evaluationInputValid(checkpoint) || !s.hostScheduleReady(checkpoint) {
		return nil, nil, false, false
	}

	hostStates := cloneProviderStates(s.hostStates)
	hostReasons := cloneProviderReasons(s.hostReasons)
	authenticated := s.hostAuthn

	s.next++
	s.evaluating = true
	s.evaluations.Add(1)
	s.resetAuthnHostSchedule()

	return hostStates, hostReasons, authenticated, true
}

// evaluationInputValid enforces checkpoint order and the serial callback boundary.
func (s *decisionSession) evaluationInputValid(checkpoint string) bool {
	return !s.closed && !s.evaluating && s.generation.valid() && s.next < len(s.checkpoints) &&
		s.checkpoints[s.next].Name() == checkpoint && s.hostPending == "" &&
		(s.hostPlan == "" || s.hostPlan == checkpoint)
}

// hostScheduleReady requires exact host traversal whenever the captured evaluator schedules host work.
func (s *decisionSession) hostScheduleReady(checkpoint string) bool {
	scheduler, ok := s.generation.evaluator.(authnHostScheduler)
	if !ok || !scheduler.hasAuthnHostProviders(s.request.Target(), checkpoint) {
		return true
	}

	return s.hostPlan == checkpoint && s.hostExhausted
}

// resetAuthnHostSchedule clears checkpoint-local scheduler state after evaluation begins.
func (s *decisionSession) resetAuthnHostSchedule() {
	s.hostStates = make(map[string]providerState)
	s.hostReasons = make(map[string]string)
	s.hostPending = ""
	s.hostPlan = ""
	s.hostLastReceipt = ""
	s.hostCursor = 0
	s.hostAuthn = false
	s.hostExhausted = false
	s.hostTerminal = false
}

// endEvaluation releases the serial checkpoint slot before session closure can finish.
func (s *decisionSession) endEvaluation() {
	s.mu.Lock()
	s.evaluating = false
	s.mu.Unlock()

	s.evaluations.Done()
}

// close rejects escaped checkpoints and waits for callbacks already in progress.
func (s *decisionSession) close() {
	if s == nil {
		return
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()

		return
	}

	s.closed = true
	permit := s.permit
	s.permit = nil
	s.mu.Unlock()

	s.evaluations.Wait()

	if permit != nil {
		permit.Release()
	}
}

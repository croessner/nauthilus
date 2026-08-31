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
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/admission"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

const (
	callerAdmissionServicePrincipal = "Policy.Service-Case"
	callerAdmissionServiceProvider  = "mail/admission_service_probe"
	callerAdmissionServiceFact      = "plugin.admission_service.probe"
)

type callerAdmissionServiceFixture struct {
	catalog   *policyruntime.TargetCatalog
	target    decision.Target
	reference registry.ClientAdmissionReference
}

type callerAdmissionServiceEvaluator struct {
	delegate checkpointEvaluator
	mu       sync.Mutex
	calls    int
}

type callerAdmissionServiceRejection uint8

const (
	callerAdmissionUnregistered callerAdmissionServiceRejection = iota
	callerAdmissionWrongTarget
	callerAdmissionBasicBypass
	callerAdmissionDisallowedFact
	callerAdmissionTokenCollision
	callerAdmissionBearerScopeMissing
	callerAdmissionBearerProfileMissing
	callerAdmissionBasicDiagnosticsDisabled
	callerAdmissionFactLimit
	callerAdmissionRequestSizeLimit
	callerAdmissionUnregisteredInternal
)

type callerAdmissionServiceRejectionCase struct {
	name      string
	rejection callerAdmissionServiceRejection
}

type callerAdmissionServiceDiagnosticsCase struct {
	scopes             []string
	name               string
	kind               string
	includeDiagnostics bool
	profileDiagnostics bool
}

type callerAdmissionServiceCallResult struct {
	authenticator *recordingCallerAuthenticator
	evaluator     *callerAdmissionServiceEvaluator
	provider      *countingFactProvider
	response      decision.DecisionResponse
	err           error
}

// Evaluate records and delegates one admitted checkpoint evaluation.
func (e *callerAdmissionServiceEvaluator) Evaluate(
	ctx context.Context,
	input checkpointEvaluation,
) (runtimeEvaluation, error) {
	e.mu.Lock()
	e.calls++
	e.mu.Unlock()

	return e.delegate.Evaluate(ctx, input)
}

// callCount returns the synchronized evaluator invocation count.
func (e *callerAdmissionServiceEvaluator) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.calls
}

func TestDecisionServiceRealAdmissionRejectsBeforeEvaluation(t *testing.T) {
	fixture := newCallerAdmissionServiceFixture(t)

	for _, test := range callerAdmissionServiceRejectionCases() {
		t.Run(test.name, func(t *testing.T) {
			callerAdmissionServiceAssertRejected(t, fixture, test.rejection)
		})
	}
}

func TestDecisionServiceRealAdmissionAllowsOmittedAndBasicDiagnostics(t *testing.T) {
	fixture := newCallerAdmissionServiceFixture(t)

	for _, test := range callerAdmissionServiceDiagnosticsCases() {
		t.Run(test.name, func(t *testing.T) {
			callerAdmissionServiceAssertDiagnosticsAllowed(t, fixture, test)
		})
	}
}

func TestDecisionServiceUnauthorizedDiagnosticsPreservesAdmissionCategory(t *testing.T) {
	fixture := newCallerAdmissionServiceFixture(t)
	profile := callerAdmissionServiceProfile(fixture.reference)
	profile.Diagnostics = true
	invocation := callerAdmissionServiceInvocation(t, fixture.target, nil, nil, true)
	result := callerAdmissionServiceCall(
		t, fixture, profile, callerAdmissionServiceDefaultCaller(t), invocation,
	)

	if !errors.Is(result.err, ErrDecisionAdmission) {
		t.Fatalf("DecisionService.Evaluate() error = %v, want ErrDecisionAdmission", result.err)
	}

	if !errors.Is(result.err, admission.ErrPermissionDenied) {
		t.Fatalf("DecisionService.Evaluate() error = %v, want admission.ErrPermissionDenied", result.err)
	}

	callerAdmissionServiceAssertCalls(
		t, result.authenticator, result.evaluator, result.provider, 0, 0,
	)
}

// callerAdmissionServiceRejectionCases enumerates every direct-call admission denial.
func callerAdmissionServiceRejectionCases() []callerAdmissionServiceRejectionCase {
	return []callerAdmissionServiceRejectionCase{
		{name: "authenticated but unregistered principal", rejection: callerAdmissionUnregistered},
		{name: "wrong target action", rejection: callerAdmissionWrongTarget},
		{name: "Basic cannot bypass Bearer profile", rejection: callerAdmissionBasicBypass},
		{name: "disallowed submitted fact", rejection: callerAdmissionDisallowedFact},
		{name: "token body collision", rejection: callerAdmissionTokenCollision},
		{name: "Bearer diagnostics scope missing", rejection: callerAdmissionBearerScopeMissing},
		{name: "Bearer diagnostics profile permission missing", rejection: callerAdmissionBearerProfileMissing},
		{name: "Basic diagnostics default disabled", rejection: callerAdmissionBasicDiagnosticsDisabled},
		{name: "submitted fact limit exceeded", rejection: callerAdmissionFactLimit},
		{name: "logical request byte limit exceeded", rejection: callerAdmissionRequestSizeLimit},
		{name: "unregistered internal caller", rejection: callerAdmissionUnregisteredInternal},
	}
}

// callerAdmissionServiceDiagnosticsCases enumerates successful diagnostics admission variants.
func callerAdmissionServiceDiagnosticsCases() []callerAdmissionServiceDiagnosticsCase {
	return []callerAdmissionServiceDiagnosticsCase{
		{
			name:   "omitted diagnostics needs no permission",
			kind:   policy.CallerAuthenticationKindBearer,
			scopes: []string{definitions.ScopePolicyEvaluate},
		},
		{
			name:               "Basic diagnostics is profile only",
			kind:               policy.CallerAuthenticationKindBasic,
			includeDiagnostics: true,
			profileDiagnostics: true,
		},
		{
			name:               "Bearer diagnostics needs scope and profile",
			kind:               policy.CallerAuthenticationKindBearer,
			scopes:             []string{definitions.ScopePolicyEvaluate, definitions.ScopePolicyDiagnostics},
			includeDiagnostics: true,
			profileDiagnostics: true,
		},
	}
}

// callerAdmissionServiceAssertRejected proves authentication succeeds before both runtime boundaries stay idle.
func callerAdmissionServiceAssertRejected(
	t *testing.T,
	fixture callerAdmissionServiceFixture,
	rejection callerAdmissionServiceRejection,
) {
	t.Helper()

	profile := callerAdmissionServiceRejectionProfile(fixture.reference, rejection)
	caller := callerAdmissionServiceRejectionCaller(t, rejection)
	invocation := callerAdmissionServiceRejectionInvocation(t, fixture.target, rejection)
	authenticator, evaluator, provider := callerAdmissionServiceEvaluate(
		t, fixture, profile, caller, invocation, true,
	)

	callerAdmissionServiceAssertCalls(t, authenticator, evaluator, provider, 0, 0)
}

// callerAdmissionServiceRejectionProfile applies only the profile mutation owned by one denial.
func callerAdmissionServiceRejectionProfile(
	reference registry.ClientAdmissionReference,
	rejection callerAdmissionServiceRejection,
) admission.Profile {
	profile := callerAdmissionServiceProfile(reference)

	switch rejection {
	case callerAdmissionBearerScopeMissing:
		profile.Diagnostics = true
	case callerAdmissionBasicDiagnosticsDisabled:
		profile.AuthenticationKinds = []string{policy.CallerAuthenticationKindBasic}
	case callerAdmissionFactLimit:
		profile.Limits.MaxFacts = 1
	case callerAdmissionRequestSizeLimit:
		profile.Limits.MaxRequestBytes = 1
	}

	return profile
}

// callerAdmissionServiceRejectionCaller selects the authenticated evidence for one denial.
func callerAdmissionServiceRejectionCaller(
	t *testing.T,
	rejection callerAdmissionServiceRejection,
) decision.CallerContext {
	t.Helper()

	switch rejection {
	case callerAdmissionUnregistered:
		return callerAdmissionServiceCaller(
			t, "Unregistered.Policy.Client", policy.CallerAuthenticationKindBearer,
			[]string{definitions.ScopePolicyEvaluate}, false,
		)
	case callerAdmissionBasicBypass, callerAdmissionBasicDiagnosticsDisabled:
		return callerAdmissionServiceCaller(
			t, callerAdmissionServicePrincipal, policy.CallerAuthenticationKindBasic, nil, false,
		)
	case callerAdmissionBearerProfileMissing:
		return callerAdmissionServiceCaller(
			t, callerAdmissionServicePrincipal, policy.CallerAuthenticationKindBearer,
			[]string{definitions.ScopePolicyEvaluate, definitions.ScopePolicyDiagnostics}, false,
		)
	case callerAdmissionUnregisteredInternal:
		return callerAdmissionServiceCaller(
			t, "Unregistered.Internal.Policy.Client", policy.CallerAuthenticationKindInternal, nil, true,
		)
	default:
		return callerAdmissionServiceDefaultCaller(t)
	}
}

// callerAdmissionServiceRejectionInvocation constructs the request mutation for one denial.
func callerAdmissionServiceRejectionInvocation(
	t *testing.T,
	target decision.Target,
	rejection callerAdmissionServiceRejection,
) decision.Invocation {
	t.Helper()

	switch rejection {
	case callerAdmissionWrongTarget:
		wrongTarget := callerAdmissionServiceTarget(t, "inspect")

		return callerAdmissionServiceInvocation(t, wrongTarget, nil, nil, false)
	case callerAdmissionDisallowedFact:
		return callerAdmissionServiceInvocation(
			t, target, map[string]decision.Value{"other": runtimeStringValue(t, "forged")}, nil, false,
		)
	case callerAdmissionTokenCollision:
		return callerAdmissionServiceInvocation(t, target, nil, map[string]decision.Value{
			"token.subject": runtimeStringValue(t, "forged-token-subject"),
		}, false)
	case callerAdmissionBearerScopeMissing,
		callerAdmissionBearerProfileMissing,
		callerAdmissionBasicDiagnosticsDisabled:
		return callerAdmissionServiceInvocation(t, target, nil, nil, true)
	case callerAdmissionFactLimit:
		return callerAdmissionServiceInvocation(t, target, nil, map[string]decision.Value{
			"first": runtimeStringValue(t, "one"), "second": runtimeStringValue(t, "two"),
		}, false)
	default:
		return callerAdmissionServiceInvocation(t, target, nil, nil, false)
	}
}

// callerAdmissionServiceDefaultCaller constructs the standard admitted Bearer caller.
func callerAdmissionServiceDefaultCaller(t *testing.T) decision.CallerContext {
	t.Helper()

	return callerAdmissionServiceCaller(
		t, callerAdmissionServicePrincipal, policy.CallerAuthenticationKindBearer,
		[]string{definitions.ScopePolicyEvaluate}, false,
	)
}

// callerAdmissionServiceTarget constructs one mail target for a test-owned action.
func callerAdmissionServiceTarget(t *testing.T, action string) decision.Target {
	t.Helper()

	target, err := decision.NewTarget("mail", action)
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return target
}

// callerAdmissionServiceAssertDiagnosticsAllowed proves an admitted request reaches both runtime boundaries.
func callerAdmissionServiceAssertDiagnosticsAllowed(
	t *testing.T,
	fixture callerAdmissionServiceFixture,
	test callerAdmissionServiceDiagnosticsCase,
) {
	t.Helper()

	profile := callerAdmissionServiceProfile(fixture.reference)
	profile.AuthenticationKinds = []string{test.kind}
	profile.Diagnostics = test.profileDiagnostics
	caller := callerAdmissionServiceCaller(
		t, callerAdmissionServicePrincipal, test.kind, test.scopes, false,
	)
	invocation := callerAdmissionServiceInvocation(
		t, fixture.target, nil, nil, test.includeDiagnostics,
	)
	authenticator, evaluator, provider := callerAdmissionServiceEvaluate(
		t, fixture, profile, caller, invocation, false,
	)

	callerAdmissionServiceAssertCalls(t, authenticator, evaluator, provider, 1, 1)
}

// callerAdmissionServiceAssertCalls checks the mandatory boundary invocation counts.
func callerAdmissionServiceAssertCalls(
	t *testing.T,
	authenticator *recordingCallerAuthenticator,
	evaluator *callerAdmissionServiceEvaluator,
	provider *countingFactProvider,
	wantEvaluator int,
	wantProvider int,
) {
	t.Helper()

	if authenticator.callCount() != 1 || evaluator.callCount() != wantEvaluator {
		t.Fatalf(
			"authenticator/evaluator calls = %d/%d, want 1/%d",
			authenticator.callCount(), evaluator.callCount(), wantEvaluator,
		)
	}

	if provider.callCount() != wantProvider {
		t.Fatalf("provider calls = %d, want %d", provider.callCount(), wantProvider)
	}
}

func TestDecisionServiceNamedInternalAdmissionRemainsTargetConstrained(t *testing.T) {
	fixture := newCallerAdmissionServiceFixture(t)
	profile := callerAdmissionServiceProfile(fixture.reference)
	profile.AuthenticationKinds = []string{policy.CallerAuthenticationKindInternal}
	profile.Internal = true
	caller := callerAdmissionServiceCaller(
		t,
		callerAdmissionServicePrincipal,
		policy.CallerAuthenticationKindInternal,
		nil,
		true,
	)

	_, admittedEvaluator, admittedProvider := callerAdmissionServiceEvaluate(
		t,
		fixture,
		profile,
		caller,
		callerAdmissionServiceInvocation(t, fixture.target, nil, nil, false),
		false,
	)
	if admittedEvaluator.callCount() != 1 {
		t.Fatalf("admitted internal evaluator calls = %d, want 1", admittedEvaluator.callCount())
	}

	if admittedProvider.callCount() != 1 {
		t.Fatalf("admitted internal provider calls = %d, want 1", admittedProvider.callCount())
	}

	wrongTarget, err := decision.NewTarget("mail", "inspect")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	_, rejectedEvaluator, rejectedProvider := callerAdmissionServiceEvaluate(
		t,
		fixture,
		profile,
		caller,
		callerAdmissionServiceInvocation(t, wrongTarget, nil, nil, false),
		true,
	)
	if rejectedEvaluator.callCount() != 0 {
		t.Fatalf("rejected internal evaluator calls = %d, want 0", rejectedEvaluator.callCount())
	}

	if rejectedProvider.callCount() != 0 {
		t.Fatalf("rejected internal provider calls = %d, want 0", rejectedProvider.callCount())
	}
}

func TestDecisionServiceCallerAdmissionRejectsWrongSchemaProfileAtPreparation(t *testing.T) {
	fixture := newCallerAdmissionServiceFixture(t)

	wrongReference, err := registry.NewClientAdmissionReference(
		"policy.api.clients[0].targets[0]",
		fixture.target.Namespace(),
		fixture.target.Action(),
		"mail/submit/v2",
	)
	if err != nil {
		t.Fatalf("NewClientAdmissionReference() error = %v", err)
	}

	credentials, err := policyruntime.NewCredentialProfiles([]string{callerAdmissionServicePrincipal})
	if err != nil {
		t.Fatalf("NewCredentialProfiles() error = %v", err)
	}

	configuration := callerAdmissionServiceConfiguration(callerAdmissionServiceProfile(wrongReference))

	prepared, err := admission.Prepare(configuration, fixture.catalog, credentials)
	if !errors.Is(err, admission.ErrConfiguration) {
		t.Fatalf("Prepare() error = %v, want admission.ErrConfiguration", err)
	}

	if prepared.Authority != nil {
		t.Fatal("wrong-schema profile produced a callable admission authority")
	}
}

// newCallerAdmissionServiceFixture constructs one exact target/schema pair for direct-call tests.
func newCallerAdmissionServiceFixture(t *testing.T) callerAdmissionServiceFixture {
	t.Helper()

	facts := []registry.FactSchema{
		decisionRuntimeFactSchema(t, "subject.account", decision.FactSourceCaller, false),
		decisionRuntimeFactSchema(t, "input.first", decision.FactSourceCaller, false),
		decisionRuntimeFactSchema(t, "input.second", decision.FactSourceCaller, false),
		decisionRuntimeFactSchema(t, callerAdmissionServiceFact, decision.FactSourcePlugin, false),
	}
	provider := decisionRuntimeProvider(
		t,
		callerAdmissionServiceProvider,
		callerAdmissionServiceFact,
		registry.ProviderFailureIndeterminate,
		nil,
	)
	catalog, compiledTarget := decisionRuntimeCatalog(
		t,
		decision.EffectPermit,
		registry.NoMatchDeny,
		facts,
		[]registry.ProviderDefinition{provider},
		nil,
	)

	reference, err := registry.NewClientAdmissionReference(
		"policy.api.clients[0].targets[0]",
		compiledTarget.Namespace(),
		compiledTarget.Action(),
		"mail/submit/v1",
	)
	if err != nil {
		t.Fatalf("NewClientAdmissionReference() error = %v", err)
	}

	return callerAdmissionServiceFixture{catalog: catalog, target: compiledTarget, reference: reference}
}

// callerAdmissionServiceProfile constructs one explicit external profile for the exact fixture target.
func callerAdmissionServiceProfile(reference registry.ClientAdmissionReference) admission.Profile {
	return admission.Profile{
		Principal:                callerAdmissionServicePrincipal,
		AuthenticationKinds:      []string{policy.CallerAuthenticationKindBearer},
		References:               []registry.ClientAdmissionReference{reference},
		AllowedSubjectAttributes: []string{"account"},
		AllowedInputAttributes:   []string{"first", "second"},
	}
}

// callerAdmissionServiceConfiguration adds deterministic global bounds around one profile.
func callerAdmissionServiceConfiguration(profile admission.Profile) admission.Configuration {
	return admission.Configuration{
		GlobalLimits: admission.Limits{
			MaxRequestBytes:   4096,
			MaxFacts:          16,
			MaxConcurrency:    8,
			RequestsPerSecond: 1000,
		},
		Profiles: []admission.Profile{profile},
	}
}

// callerAdmissionServiceCaller constructs trusted authenticator output for one profile case.
func callerAdmissionServiceCaller(
	t *testing.T,
	principal string,
	kind string,
	scopes []string,
	internal bool,
) decision.CallerContext {
	t.Helper()

	transportKind := "http"
	if internal {
		transportKind = "internal"
	}

	input := decision.TrustedCallerInput{
		Principal:          principal,
		Scopes:             scopes,
		AuthenticationKind: kind,
		TransportKind:      transportKind,
		Internal:           internal,
	}
	if !internal {
		input.ClientID = principal
		input.Subject = "trusted-token-subject"
		input.Issuer = "https://issuer.policy.test"
	}

	caller, err := decision.NewCallerContext(input)
	if err != nil {
		t.Fatalf("NewCallerContext() error = %v", err)
	}

	return caller
}

// callerAdmissionServiceInvocation constructs one transport-neutral direct request.
func callerAdmissionServiceInvocation(
	t *testing.T,
	target decision.Target,
	subjectAttributes map[string]decision.Value,
	inputAttributes map[string]decision.Value,
	includeDiagnostics bool,
) decision.Invocation {
	t.Helper()

	invocation := mustAuthorityTargetInvocation(t, target.Namespace(), target.Action())

	subject, err := decision.NewEntity(decision.EntityInput{Attributes: subjectAttributes})
	if err != nil {
		t.Fatalf("NewEntity() error = %v", err)
	}

	invocation.Request.Subject = subject
	invocation.Request.Attributes = inputAttributes
	invocation.Request.Options.IncludeDiagnostics = includeDiagnostics

	return invocation
}

// callerAdmissionServiceEvaluate invokes the sealed service with a real admission authority.
func callerAdmissionServiceEvaluate(
	t *testing.T,
	fixture callerAdmissionServiceFixture,
	profile admission.Profile,
	caller decision.CallerContext,
	invocation decision.Invocation,
	wantError bool,
) (*recordingCallerAuthenticator, *callerAdmissionServiceEvaluator, *countingFactProvider) {
	t.Helper()

	result := callerAdmissionServiceCall(t, fixture, profile, caller, invocation)
	callerAdmissionServiceAssertResult(t, result, invocation, wantError)

	return result.authenticator, result.evaluator, result.provider
}

// callerAdmissionServiceCall invokes the service and retains exact error taxonomy evidence.
func callerAdmissionServiceCall(
	t *testing.T,
	fixture callerAdmissionServiceFixture,
	profile admission.Profile,
	caller decision.CallerContext,
	invocation decision.Invocation,
) callerAdmissionServiceCallResult {
	t.Helper()

	authority := callerAdmissionServiceAuthority(t, fixture, profile)
	authenticator, evaluator, provider, service := callerAdmissionServiceRuntime(t, fixture, caller, authority)
	response, err := service.Evaluate(context.Background(), invocation)

	return callerAdmissionServiceCallResult{
		authenticator: authenticator, evaluator: evaluator, provider: provider, response: response, err: err,
	}
}

// callerAdmissionServiceAuthority prepares one real immutable admission authority.
func callerAdmissionServiceAuthority(
	t *testing.T,
	fixture callerAdmissionServiceFixture,
	profile admission.Profile,
) policyruntime.AdmissionAuthority {
	t.Helper()

	credentials, err := policyruntime.NewCredentialProfiles([]string{profile.Principal})
	if err != nil {
		t.Fatalf("NewCredentialProfiles() error = %v", err)
	}

	prepared, err := admission.Prepare(
		callerAdmissionServiceConfiguration(profile),
		fixture.catalog,
		credentials,
	)
	if err != nil {
		t.Fatalf("admission.Prepare() error = %v", err)
	}

	return prepared.Authority
}

// callerAdmissionServiceRuntime wires the captured generation to recording runtime boundaries.
func callerAdmissionServiceRuntime(
	t *testing.T,
	fixture callerAdmissionServiceFixture,
	caller decision.CallerContext,
	authority policyruntime.AdmissionAuthority,
) (*recordingCallerAuthenticator, *callerAdmissionServiceEvaluator, *countingFactProvider, *DecisionService) {
	t.Helper()

	authenticator := &recordingCallerAuthenticator{caller: caller}
	provider := &countingFactProvider{facts: []providedFact{{
		id:       callerAdmissionServiceFact,
		value:    runtimeStringValue(t, "collected"),
		category: decision.FactCategoryEnvironment,
	}}}
	evaluator := &callerAdmissionServiceEvaluator{delegate: mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: fixture.catalog,
		factProviders: map[string]factProviderBinding{
			callerAdmissionServiceProvider: decisionRuntimeFactBinding(provider, "admission-service"),
		},
		ids:               &sequenceIDGenerator{},
		evaluationTimeout: time.Second,
	})}
	generation := mustRuntimeGeneration(t, 1, authenticator, authority, evaluator)
	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	return authenticator, evaluator, provider, service
}

// callerAdmissionServiceAssertResult checks the expected service outcome and diagnostics projection.
func callerAdmissionServiceAssertResult(
	t *testing.T,
	result callerAdmissionServiceCallResult,
	invocation decision.Invocation,
	wantError bool,
) {
	t.Helper()

	if wantError {
		if !errors.Is(result.err, ErrDecisionAdmission) {
			t.Fatalf("DecisionService.Evaluate() error = %v, want ErrDecisionAdmission", result.err)
		}

		return
	}

	if result.err != nil {
		t.Fatalf("DecisionService.Evaluate() error = %v", result.err)
	}

	if !invocation.Request.Options.IncludeDiagnostics && result.response.Diagnostics() != nil {
		t.Fatal("omitted diagnostics returned a diagnostics object")
	}

	if invocation.Request.Options.IncludeDiagnostics && result.response.Diagnostics() == nil {
		t.Fatal("admitted explicit diagnostics returned no diagnostics object")
	}
}

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

package core

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/croessner/nauthilus/v3/server/secret"
)

func TestAuthnApplicationAdapterTraversesOneDecisionSessionForEveryOperation(t *testing.T) {
	tests := authnApplicationOperationCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := newRecordingAuthApplicationService()
			session := newRecordingAuthnDecisionSession(
				test.checkpointNames(),
				repeatAuthnDecisionEffect(t, decision.EffectNotApplicable, len(test.checkpointNames()))...,
			)
			factory := &recordingAuthnDecisionSessionFactory{session: session}

			adapter, err := NewAuthnCandidateApplicationService(current, factory, mustAuthnCandidateAuthentication(t))
			if err != nil {
				t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
			}

			input := authnApplicationTestInput(test.mode)

			ctx := ContextWithGRPCMethod(context.Background(), "/nauthilus.auth.v1.AuthService/"+test.grpcMethod)
			if err := test.run(ctx, adapter, input); err != nil {
				t.Fatalf("candidate operation error = %v", err)
			}

			if factory.calls != 1 || session.calls != len(test.checkpointNames()) {
				t.Fatalf("session calls = %d/%d, want 1/%d", factory.calls, session.calls, len(test.checkpointNames()))
			}

			if current.callCount(test.operation) != 1 || current.totalCalls() != 1 {
				t.Fatalf("current service calls = %#v, want only %q once", current.calls, test.operation)
			}

			invocation := factory.invocations[0]
			if got := invocation.Request.Target.String(); got != policy.AuthnNamespace+"/"+string(test.operation) {
				t.Fatalf("target = %q, want authn operation target", got)
			}

			if got := invocation.Request.Subject.ID(); got != input.Credentials.Username {
				t.Fatalf("subject ID = %q, want %q", got, input.Credentials.Username)
			}

			if got := invocation.Request.Environment.Service(); got != input.Service {
				t.Fatalf("environment service = %q, want %q", got, input.Service)
			}

			assertAuthnRequestAssertions(t, invocation.Request, input)
			assertAuthnInvocationTransport(t, invocation.Authentication, input.Context.Transport, test.grpcMethod)
			assertAuthnCheckpointSequence(t, session.checkpoints, test.checkpointNames())
			assertAuthnOperationFacts(t, session.checkpoints[len(session.checkpoints)-1].Facts(), test)
		})
	}
}

func TestAuthnApplicationAdapterBruteForceCheckpointStopsLaterWork(t *testing.T) {
	tests := []struct {
		name         string
		effect       decision.Effect
		wantDecision AuthDecision
	}{
		{name: "deny", effect: decision.EffectDeny, wantDecision: AuthDecisionFail},
		{name: "indeterminate", effect: decision.EffectIndeterminate, wantDecision: AuthDecisionTempFail},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := newRecordingAuthApplicationService()
			session := newRecordingAuthnDecisionSession(
				[]string{string(policy.StagePreAuth), string(policy.StageAuthDecision)},
				mustAuthnDecisionResponse(t, test.effect),
				mustAuthnDecisionResponse(t, decision.EffectPermit),
			)
			factory := &recordingAuthnDecisionSessionFactory{session: session}

			adapter, err := NewAuthnCandidateApplicationService(current, factory, mustAuthnCandidateAuthentication(t))
			if err != nil {
				t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
			}

			outcome, err := adapter.Authenticate(context.Background(), authnApplicationTestInput(AuthModeAuthenticate))
			if err != nil {
				t.Fatalf("Authenticate() error = %v", err)
			}

			if outcome.Decision != test.wantDecision {
				t.Fatalf("terminal checkpoint decision = %q, want %q", outcome.Decision, test.wantDecision)
			}

			if current.totalCalls() != 0 {
				t.Fatalf("later environment/backend/subject calls = %d, want 0", current.totalCalls())
			}

			if session.calls != 1 || len(session.checkpoints) != 1 || session.checkpoints[0].Name() != string(policy.StagePreAuth) {
				t.Fatalf("evaluated checkpoints = %#v, want only pre_auth", checkpointNames(session.checkpoints))
			}
		})
	}
}

func TestAuthnApplicationAdapterMapsEffectsWithoutReplacingOutcomePayloads(t *testing.T) {
	effects := []struct {
		name         string
		effect       decision.Effect
		wantDecision AuthDecision
	}{
		{name: "neutral", effect: decision.EffectNotApplicable, wantDecision: AuthDecisionOK},
		{name: "permit", effect: decision.EffectPermit, wantDecision: AuthDecisionOK},
		{name: "deny", effect: decision.EffectDeny, wantDecision: AuthDecisionFail},
		{name: "indeterminate", effect: decision.EffectIndeterminate, wantDecision: AuthDecisionTempFail},
	}

	for _, operation := range authnApplicationOperationCases() {
		for _, effect := range effects {
			t.Run(operation.name+"/"+effect.name, func(t *testing.T) {
				current := newRecordingAuthApplicationService()
				originalAuth := current.authOutcome
				originalAccounts := current.listOutcome

				responses := []decision.DecisionResponse{mustAuthnDecisionResponse(t, effect.effect)}
				if operation.operation != policy.OperationListAccounts {
					responses = append(
						[]decision.DecisionResponse{mustAuthnDecisionResponse(t, decision.EffectNotApplicable)},
						responses...,
					)
				}

				session := newRecordingAuthnDecisionSession(operation.checkpointNames(), responses...)
				factory := &recordingAuthnDecisionSessionFactory{session: session}

				adapter, err := NewAuthnCandidateApplicationService(current, factory, mustAuthnCandidateAuthentication(t))
				if err != nil {
					t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
				}

				result, err := operation.runForDecision(context.Background(), adapter, authnApplicationTestInput(operation.mode))
				if err != nil {
					t.Fatalf("candidate operation error = %v", err)
				}

				if result.decision != effect.wantDecision {
					t.Fatalf("decision = %q, want %q", result.decision, effect.wantDecision)
				}

				if result.status != "existing-status" || result.session != "existing-session" {
					t.Fatalf("preserved payload = %q/%q, want existing values", result.status, result.session)
				}

				if operation.operation == policy.OperationListAccounts && !reflect.DeepEqual(result.accounts, []string{"alpha", "beta"}) {
					t.Fatalf("accounts = %#v, want preserved account list", result.accounts)
				}

				if current.authOutcome != originalAuth || current.listOutcome != originalAccounts {
					t.Fatal("candidate mapping replaced or mutated the current service outcome")
				}
			})
		}
	}
}

func TestAuthnApplicationAdapterFailsBeforeCurrentPipelineWhenSessionCannotOpen(t *testing.T) {
	failures := []struct {
		name string
		err  error
	}{
		{name: "generation capture", err: decisionservice.ErrDecisionGenerationUnavailable},
		{name: "admission", err: decisionservice.ErrDecisionAdmission},
	}

	for _, test := range authnApplicationOperationCases() {
		for _, failure := range failures {
			t.Run(test.name+"/"+failure.name, func(t *testing.T) {
				current := newRecordingAuthApplicationService()
				factory := &recordingAuthnDecisionSessionFactory{
					openErr: fmt.Errorf("candidate session: %w", failure.err),
				}

				adapter, err := NewAuthnCandidateApplicationService(current, factory, mustAuthnCandidateAuthentication(t))
				if err != nil {
					t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
				}

				err = test.run(context.Background(), adapter, authnApplicationTestInput(test.mode))
				if !errors.Is(err, failure.err) {
					t.Fatalf("operation error = %v, want %v", err, failure.err)
				}

				if current.totalCalls() != 0 {
					t.Fatalf("current pipeline calls = %d, want 0 before admission", current.totalCalls())
				}
			})
		}
	}
}

func TestAuthnApplicationAdapterRequiresExplicitAdmissionPresentation(t *testing.T) {
	current := newRecordingAuthApplicationService()
	factory := &recordingAuthnDecisionSessionFactory{session: &recordingAuthnDecisionSession{}}

	_, err := NewAuthnCandidateApplicationService(current, factory, decision.AuthenticationInput{})
	if !errors.Is(err, ErrAuthApplicationDependencyMissing) {
		t.Fatalf("constructor error = %v, want missing admission presentation", err)
	}
}

func TestAuthnFactBuilderRejectsTrustedFactCollision(t *testing.T) {
	provenance, err := decision.NewProvenance(decision.FactSourceNauthilus, "nauthilus", "forged")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	value := mustAuthnStringValue(t, "forged")

	forged, err := decision.NewFact(
		policy.AuthnFactOperation,
		decision.FactCategoryEnvironment,
		value,
		provenance,
	)
	if err != nil {
		t.Fatalf("NewFact() error = %v", err)
	}

	existing, err := decision.NewFactSet([]decision.Fact{forged})
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	builder, err := newAuthnFactBuilder()
	if err != nil {
		t.Fatalf("newAuthnFactBuilder() error = %v", err)
	}

	_, err = builder.Build(
		authnApplicationTestInput(AuthModeAuthenticate),
		policy.OperationAuthenticate,
		authnApplicationResult{auth: newRecordingAuthApplicationService().authOutcome},
		existing,
	)
	if !errors.Is(err, decision.ErrFactCollision) {
		t.Fatalf("Build() error = %v, want trusted collision rejection", err)
	}
}

type authnApplicationOperationCase struct {
	name       string
	grpcMethod string
	operation  policy.Operation
	mode       AuthMode
	wantFact   string
}

// authnApplicationOperationCases returns the shared three-operation adapter matrix.
func authnApplicationOperationCases() []authnApplicationOperationCase {
	return []authnApplicationOperationCase{
		{
			name:       "authenticate",
			grpcMethod: "Authenticate",
			operation:  policy.OperationAuthenticate,
			mode:       AuthModeAuthenticate,
			wantFact:   policy.AuthnFactAuthenticated,
		},
		{
			name:       "lookup identity",
			grpcMethod: "LookupIdentity",
			operation:  policy.OperationLookupIdentity,
			mode:       AuthModeLookupIdentity,
			wantFact:   policy.AuthnFactIdentityFound,
		},
		{
			name:       "list accounts",
			grpcMethod: "ListAccounts",
			operation:  policy.OperationListAccounts,
			mode:       AuthModeListAccounts,
			wantFact:   policy.AuthnFactAccountCount,
		},
	}
}

// run invokes one operation and discards only its returned payload.
func (c authnApplicationOperationCase) run(
	ctx context.Context,
	service AuthApplicationService,
	input AuthInput,
) error {
	_, err := c.runForDecision(ctx, service, input)

	return err
}

// runForDecision invokes one operation and projects its shared assertion fields.
func (c authnApplicationOperationCase) runForDecision(
	ctx context.Context,
	service AuthApplicationService,
	input AuthInput,
) (authnMappedTestResult, error) {
	switch c.operation {
	case policy.OperationAuthenticate:
		outcome, err := service.Authenticate(ctx, input)

		return mappedAuthnTestResult(outcome, err)
	case policy.OperationLookupIdentity:
		outcome, err := service.LookupIdentity(ctx, input)

		return mappedAuthnTestResult(outcome, err)
	case policy.OperationListAccounts:
		outcome, err := service.ListAccounts(ctx, input)
		if err != nil {
			return authnMappedTestResult{}, err
		}

		return authnMappedTestResult{
			decision: outcome.Decision,
			status:   outcome.StatusMessage,
			session:  outcome.Session,
			accounts: append([]string(nil), outcome.Accounts...),
		}, nil
	default:
		return authnMappedTestResult{}, fmt.Errorf("unsupported test operation %q", c.operation)
	}
}

// checkpointNames returns the exact compiled checkpoint topology for one authn operation.
func (c authnApplicationOperationCase) checkpointNames() []string {
	if c.operation == policy.OperationListAccounts {
		return []string{string(policy.StageAuthDecision)}
	}

	return []string{string(policy.StagePreAuth), string(policy.StageAuthDecision)}
}

// mappedAuthnTestResult projects one current auth outcome for shared assertions.
func mappedAuthnTestResult(outcome *AuthOutcome, err error) (authnMappedTestResult, error) {
	if err != nil {
		return authnMappedTestResult{}, err
	}

	return authnMappedTestResult{
		decision: outcome.Decision,
		status:   outcome.StatusMessage,
		session:  outcome.Session,
	}, nil
}

type authnMappedTestResult struct {
	accounts []string
	status   string
	session  string
	decision AuthDecision
}

// authnApplicationTestInput constructs transport-neutral candidate input without exporting credentials as facts.
func authnApplicationTestInput(mode AuthMode) AuthInput {
	return AuthInput{
		Credentials: Credentials{
			Username: "alice@example.test",
			Password: secret.New("must-never-be-a-policy-fact"),
		},
		Context: AuthContext{
			Method:            "plain",
			UserAgent:         "authn-adapter-test/1.0",
			ClientIP:          "198.51.100.25",
			ClientPort:        "43123",
			ClientHostname:    "mail.example.test",
			ClientID:          "mail-client",
			ExternalSessionID: "existing-session",
			LocalIP:           "192.0.2.20",
			LocalPort:         "993",
			Protocol:          "imap",
			OIDCCID:           "oidc-client",
			SAMLEntityID:      "https://sp.example.test/metadata",
			Transport: AuthTransportContext{
				Kind:         "grpc",
				Listener:     "grpc.authority",
				Peer:         "192.0.2.50",
				MTLSIdentity: "spiffe://example.test/authn-client",
				Protected:    true,
			},
		},
		Mode:             mode,
		Service:          definitions.ServGRPC,
		AuthLoginAttempt: 3,
	}
}

// assertAuthnInvocationTransport verifies transport evidence remains detached from operation facts.
func assertAuthnInvocationTransport(
	t *testing.T,
	input decision.AuthenticationInput,
	want AuthTransportContext,
	wantGRPCMethod string,
) {
	t.Helper()

	if input.TransportKind() != want.Kind || input.Listener() != want.Listener || input.Peer() != want.Peer {
		t.Fatalf("transport = %q/%q/%q, want %q/%q/%q", input.TransportKind(), input.Listener(), input.Peer(), want.Kind, want.Listener, want.Peer)
	}

	if input.GRPCMethod() != "/nauthilus.auth.v1.AuthService/"+wantGRPCMethod {
		t.Fatalf("gRPC method = %q, want preserved application method", input.GRPCMethod())
	}

	if input.MTLSIdentity() != want.MTLSIdentity || !input.Protected() {
		t.Fatalf("protected mTLS evidence = %q/%t, want %q/true", input.MTLSIdentity(), input.Protected(), want.MTLSIdentity)
	}

	if input.Kind() != "test-internal-authn" || string(input.Credential()) != "test-only-authn-evidence" {
		t.Fatal("candidate invocation did not preserve caller-admission presentation")
	}
}

// assertAuthnOperationFacts verifies exact shared and operation-specific fact state.
func assertAuthnOperationFacts(
	t *testing.T,
	facts decision.FactSet,
	test authnApplicationOperationCase,
) {
	t.Helper()

	assertAuthnStringFact(t, facts, policy.AuthnFactOperation, string(test.operation), decision.FactSourceNauthilus)

	if test.operation != policy.OperationListAccounts {
		assertAuthnStringFact(t, facts, policy.AuthnFactBackend, definitions.BackendLDAP.String(), decision.FactSourceBackend)
	}

	operationFact, found := facts.Get(test.wantFact)
	if !found {
		t.Fatalf("operation fact %q missing from %#v", test.wantFact, facts.Facts())
	}

	if test.operation == policy.OperationListAccounts {
		if count, ok := operationFact.Value().Integer(); !ok || count != 2 {
			t.Fatalf("account count = %d/%t, want 2/true", count, ok)
		}
	} else if value, ok := operationFact.Value().Boolean(); !ok || !value {
		t.Fatalf("operation boolean = %t/%t, want true/true", value, ok)
	}

	if operationFact.Provenance().Source() != decision.FactSourceBackend {
		t.Fatalf("operation provenance = %#v, want backend", operationFact.Provenance())
	}

	for _, fact := range facts.Facts() {
		if value, ok := fact.Value().StringValue(); ok && value == "must-never-be-a-policy-fact" {
			t.Fatalf("credential leaked through fact %q", fact.ID())
		}
	}
}

// assertAuthnCheckpointSequence verifies plan order and the pre-backend fact boundary.
func assertAuthnCheckpointSequence(t *testing.T, checkpoints []decision.Checkpoint, want []string) {
	t.Helper()

	if got := checkpointNames(checkpoints); !reflect.DeepEqual(got, want) {
		t.Fatalf("checkpoint sequence = %v, want %v", got, want)
	}

	for _, checkpoint := range checkpoints[:len(checkpoints)-1] {
		if len(checkpoint.Facts().Facts()) != 0 {
			t.Fatalf("pre-backend checkpoint %q facts = %#v, want none", checkpoint.Name(), checkpoint.Facts().Facts())
		}
	}
}

// checkpointNames projects exact checkpoint names for concise test failures.
func checkpointNames(checkpoints []decision.Checkpoint) []string {
	result := make([]string, 0, len(checkpoints))
	for _, checkpoint := range checkpoints {
		result = append(result, checkpoint.Name())
	}

	return result
}

// assertAuthnRequestAssertions verifies typed caller facts before admitted provenance is attached.
func assertAuthnRequestAssertions(t *testing.T, request decision.DecisionRequestInput, input AuthInput) {
	t.Helper()

	assertAuthnRequestString(t, request.Attributes, "auth.username", input.Credentials.Username)
	assertAuthnRequestString(t, request.Environment.Attributes().Values(), "protocol", input.Context.Protocol)

	loginAttempt, found := request.Attributes["auth.login_attempt"]
	if !found {
		t.Fatal("input.auth.login_attempt assertion missing")
	}

	if value, ok := loginAttempt.Integer(); !ok || value != int64(input.AuthLoginAttempt) {
		t.Fatalf("login-attempt assertion = %d/%t, want %d/true", value, ok, input.AuthLoginAttempt)
	}

	for key, value := range request.Attributes {
		if text, ok := value.StringValue(); ok && text == "must-never-be-a-policy-fact" {
			t.Fatalf("credential leaked through request assertion %q", key)
		}
	}
}

// assertAuthnRequestString verifies one strict request assertion by category-local key.
func assertAuthnRequestString(
	t *testing.T,
	attributes map[string]decision.Value,
	key string,
	want string,
) {
	t.Helper()

	attribute, found := attributes[key]
	if !found {
		t.Fatalf("request assertion %q missing", key)
	}

	value, ok := attribute.StringValue()
	if !ok || value != want {
		t.Fatalf("request assertion %q = %q/%t, want %q/true", key, value, ok, want)
	}
}

// assertAuthnStringFact verifies one exact typed fact and its source class.
func assertAuthnStringFact(
	t *testing.T,
	facts decision.FactSet,
	id string,
	want string,
	wantSource decision.FactSource,
) {
	t.Helper()

	fact, found := facts.Get(id)
	if !found {
		t.Fatalf("fact %q missing", id)
	}

	value, ok := fact.Value().StringValue()
	if !ok || value != want {
		t.Fatalf("fact %q value = %q/%t, want %q/true", id, value, ok, want)
	}

	provenance := fact.Provenance()
	if provenance.Source() != wantSource || provenance.Authority() == "" || provenance.Component() == "" {
		t.Fatalf("fact %q provenance = %#v, want %q with authority/component", id, provenance, wantSource)
	}
}

// mustAuthnStringValue constructs one strict string value for collision tests.
func mustAuthnStringValue(t *testing.T, input string) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &input})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	return value
}

// mustAuthnCandidateAuthentication constructs explicit test-only internal admission evidence.
func mustAuthnCandidateAuthentication(t *testing.T) decision.AuthenticationInput {
	t.Helper()

	input, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          "test-internal-authn",
		Credential:    []byte("test-only-authn-evidence"),
		TransportKind: "test",
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	return input
}

// mustAuthnDecisionResponse constructs one valid response for adapter tests.
func mustAuthnDecisionResponse(t *testing.T, effect decision.Effect) decision.DecisionResponse {
	t.Helper()

	code := decision.StatusCodeNotApplicable

	switch effect {
	case decision.EffectPermit:
		code = decision.StatusCodePermit
	case decision.EffectDeny:
		code = decision.StatusCodePolicyDenied
	case decision.EffectIndeterminate:
		code = decision.StatusCodeEvaluationFailed
	}

	status, err := decision.NewStatus(code, "candidate result", nil)
	if err != nil {
		t.Fatalf("NewStatus() error = %v", err)
	}

	metadata, err := decision.NewPolicyMetadata("authn/standard_auth", "v1", "candidate", 42)
	if err != nil {
		t.Fatalf("NewPolicyMetadata() error = %v", err)
	}

	response, err := decision.NewDecisionResponse(decision.DecisionResponseInput{
		RequestID:  "request-authn-adapter",
		DecisionID: "decision-authn-adapter",
		Effect:     effect,
		Status:     status,
		Policy:     metadata,
	})
	if err != nil {
		t.Fatalf("NewDecisionResponse() error = %v", err)
	}

	return response
}

// repeatAuthnDecisionEffect constructs one response per planned checkpoint.
func repeatAuthnDecisionEffect(t *testing.T, effect decision.Effect, count int) []decision.DecisionResponse {
	t.Helper()

	responses := make([]decision.DecisionResponse, 0, count)
	for range count {
		responses = append(responses, mustAuthnDecisionResponse(t, effect))
	}

	return responses
}

type recordingAuthnDecisionSessionFactory struct {
	session     *recordingAuthnDecisionSession
	openErr     error
	invocations []decision.Invocation
	calls       int
}

// WithSession records admission before exposing the recording checkpoint session.
func (f *recordingAuthnDecisionSessionFactory) WithSession(
	_ context.Context,
	invocation decision.Invocation,
	use func(decisionservice.DecisionSession) error,
) error {
	f.calls++
	f.invocations = append(f.invocations, invocation)

	if f.openErr != nil {
		return f.openErr
	}

	return use(f.session)
}

type recordingAuthnDecisionSession struct {
	plan        []string
	responses   []decision.DecisionResponse
	evaluateErr error
	checkpoints []decision.Checkpoint
	calls       int
}

// newRecordingAuthnDecisionSession returns one immutable plan-driven response sequence.
func newRecordingAuthnDecisionSession(
	plan []string,
	responses ...decision.DecisionResponse,
) *recordingAuthnDecisionSession {
	return &recordingAuthnDecisionSession{
		plan:      append([]string(nil), plan...),
		responses: append([]decision.DecisionResponse(nil), responses...),
	}
}

// Checkpoints returns a detached recording copy of the compiled plan order.
func (s *recordingAuthnDecisionSession) Checkpoints() []string {
	return append([]string(nil), s.plan...)
}

// Evaluate records one candidate checkpoint and returns the configured generic result.
func (s *recordingAuthnDecisionSession) Evaluate(
	_ context.Context,
	checkpoint decision.Checkpoint,
) (decision.DecisionResponse, error) {
	s.calls++
	s.checkpoints = append(s.checkpoints, checkpoint)
	if len(s.responses) == 0 {
		return decision.DecisionResponse{}, s.evaluateErr
	}

	index := s.calls - 1
	if index >= len(s.responses) {
		index = len(s.responses) - 1
	}

	return s.responses[index], s.evaluateErr
}

type recordingAuthApplicationService struct {
	authOutcome *AuthOutcome
	listOutcome *ListAccountsOutcome
	calls       map[policy.Operation]int
}

// newRecordingAuthApplicationService returns stable current-pipeline outcomes for adapter tests.
func newRecordingAuthApplicationService() *recordingAuthApplicationService {
	return &recordingAuthApplicationService{
		authOutcome: &AuthOutcome{
			Attributes:              bktype.AttributeMapping{"uid": {"alice@example.test"}},
			Decision:                AuthDecisionOK,
			Session:                 "existing-session",
			AccountField:            "uid",
			StatusMessage:           "existing-status",
			Groups:                  []string{"users", "mail"},
			GroupDistinguishedNames: []string{"cn=users,dc=example,dc=test"},
			Backend:                 definitions.BackendLDAP,
		},
		listOutcome: &ListAccountsOutcome{
			Accounts:      AccountList{"alpha", "beta"},
			Decision:      AuthDecisionOK,
			Session:       "existing-session",
			StatusMessage: "existing-status",
		},
		calls: make(map[policy.Operation]int),
	}
}

// Authenticate records current password-pipeline execution.
func (s *recordingAuthApplicationService) Authenticate(context.Context, AuthInput) (*AuthOutcome, error) {
	s.calls[policy.OperationAuthenticate]++

	return s.authOutcome, nil
}

// LookupIdentity records current identity-pipeline execution.
func (s *recordingAuthApplicationService) LookupIdentity(context.Context, AuthInput) (*AuthOutcome, error) {
	s.calls[policy.OperationLookupIdentity]++

	return s.authOutcome, nil
}

// ListAccounts records current account-provider execution.
func (s *recordingAuthApplicationService) ListAccounts(context.Context, AuthInput) (*ListAccountsOutcome, error) {
	s.calls[policy.OperationListAccounts]++

	return s.listOutcome, nil
}

// callCount returns the invocation count for one current operation.
func (s *recordingAuthApplicationService) callCount(operation policy.Operation) int {
	return s.calls[operation]
}

// totalCalls returns every current-pipeline invocation count.
func (s *recordingAuthApplicationService) totalCalls() int {
	count := 0
	for _, calls := range s.calls {
		count += calls
	}

	return count
}

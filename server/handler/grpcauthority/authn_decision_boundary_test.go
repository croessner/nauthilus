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

package grpcauthority

import (
	"context"
	"testing"

	authv1 "github.com/croessner/nauthilus/v4/api/auth/v1"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	grpcBoundaryUsername          = "grpc-boundary@example.test"
	grpcBoundaryClientIP          = "198.51.100.70"
	grpcBoundaryClientPort        = "43123"
	grpcBoundaryProtocol          = "imap"
	grpcBoundaryMethod            = "plain"
	grpcBoundaryUserAgent         = "grpc-boundary-test/1.0"
	grpcBoundaryMetadataKey       = "x-company-domain"
	grpcBoundaryMetadata          = " ExampleDE "
	grpcBoundaryTransportKind     = "grpc"
	grpcBoundaryListener          = "grpc.authority"
	grpcBoundaryPeer              = "203.0.113.45"
	grpcBoundaryMTLSIdentity      = "verified-backchannel-client"
	grpcBoundaryAuthenticateKind  = "grpc-internal-authenticate"
	grpcBoundaryAuthenticateProof = "grpc-opaque-authenticate"
	grpcBoundaryLookupKind        = "grpc-internal-lookup-identity"
	grpcBoundaryLookupProof       = "grpc-opaque-lookup-identity"
	grpcBoundaryListAccountsKind  = "grpc-internal-list-accounts"
	grpcBoundaryListAccountsProof = "grpc-opaque-list-accounts"
)

func TestGRPCBackchannelDecisionServiceUsesExactOperationProfilesAndTransportFacts(t *testing.T) {
	profiles := mustGRPCBoundaryProfiles(t)

	for _, operation := range grpcBoundaryOperationCases() {
		t.Run(operation.name, func(t *testing.T) {
			current := newRecordingGRPCBoundaryCurrentService()
			session := newRecordingGRPCBoundaryDecisionSession(t, operation.checkpoints)
			factory := &recordingGRPCBoundaryDecisionSessionFactory{session: session}

			service, err := core.NewAuthnCandidateApplicationServiceWithInternalProfiles(
				current,
				factory,
				profiles,
			)
			if err != nil {
				t.Fatalf("NewAuthnCandidateApplicationServiceWithInternalProfiles() error = %v", err)
			}

			handler := New(service)

			ctx, gate := grpcBoundaryRequestContext()
			defer gate.Complete()

			if err = operation.invoke(ctx, handler); err != nil {
				t.Fatalf("backchannel RPC error = %v", err)
			}

			if factory.calls != 1 || factory.callbackCalls != 1 {
				t.Fatalf(
					"decision session calls/callbacks = %d/%d, want 1/1",
					factory.calls,
					factory.callbackCalls,
				)
			}

			if current.hostCalls[operation.operation] != 1 || current.totalHostCalls() != 1 {
				t.Fatalf("current host calls = %#v, want only %q once", current.hostCalls, operation.operation)
			}

			if current.backendProxyCalls != 1 || current.effectProxyCalls != 1 {
				t.Fatalf(
					"current backend/effect proxy calls = %d/%d, want 1/1",
					current.backendProxyCalls,
					current.effectProxyCalls,
				)
			}

			if len(factory.invocations) != 1 {
				t.Fatalf("recorded invocations = %d, want 1", len(factory.invocations))
			}

			assertGRPCBoundaryInvocation(t, factory.invocations[0], operation)
			assertGRPCBoundaryCurrentInput(t, current.inputs[operation.operation], operation)
			assertGRPCBoundaryCheckpointFacts(t, session.checkpoints, operation)
		})
	}
}

func TestGRPCBackchannelDecisionServiceRejectsBeforeCurrentBackendOrEffects(t *testing.T) {
	profiles := mustGRPCBoundaryProfiles(t)

	for _, operation := range grpcBoundaryOperationCases() {
		for _, failure := range grpcBoundaryFailureCases() {
			t.Run(operation.name+"/"+failure.name, func(t *testing.T) {
				assertGRPCBoundaryRejection(t, profiles, operation, failure)
			})
		}
	}
}

type grpcBoundaryFailureCase struct {
	err  error
	name string
}

// grpcBoundaryFailureCases returns admission failures that must stop before host execution.
func grpcBoundaryFailureCases() []grpcBoundaryFailureCase {
	return []grpcBoundaryFailureCase{
		{name: "generation capture", err: decisionservice.ErrDecisionGenerationUnavailable},
		{name: "admission", err: decisionservice.ErrDecisionAdmission},
	}
}

// assertGRPCBoundaryRejection runs one rejected operation and verifies its transport status.
func assertGRPCBoundaryRejection(
	t *testing.T,
	profiles core.AuthnInternalCallerProfiles,
	operation grpcBoundaryOperationCase,
	failure grpcBoundaryFailureCase,
) {
	t.Helper()

	current := newRecordingGRPCBoundaryCurrentService()
	session := newRecordingGRPCBoundaryDecisionSession(t, operation.checkpoints)
	factory := &recordingGRPCBoundaryDecisionSessionFactory{
		session: session,
		openErr: failure.err,
	}

	service, err := core.NewAuthnCandidateApplicationServiceWithInternalProfiles(current, factory, profiles)
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationServiceWithInternalProfiles() error = %v", err)
	}

	handler := New(service)

	ctx, gate := grpcBoundaryRequestContext()
	defer gate.Complete()

	err = operation.invoke(ctx, handler)

	if status.Code(err) != codes.Internal {
		t.Fatalf("backchannel RPC code = %v, want %v for %v", status.Code(err), codes.Internal, failure.err)
	}

	assertGRPCBoundaryRejectedState(t, current, session, factory)
}

// assertGRPCBoundaryRejectedState verifies rejection reached no runtime, backend, or effect boundary.
func assertGRPCBoundaryRejectedState(
	t *testing.T,
	current *recordingGRPCBoundaryCurrentService,
	session *recordingGRPCBoundaryDecisionSession,
	factory *recordingGRPCBoundaryDecisionSessionFactory,
) {
	t.Helper()

	if factory.calls != 1 || factory.callbackCalls != 0 || len(factory.invocations) != 1 {
		t.Fatalf(
			"decision session calls/callbacks/invocations = %d/%d/%d, want 1/0/1",
			factory.calls,
			factory.callbackCalls,
			len(factory.invocations),
		)
	}

	if session.evaluations != 0 || len(session.checkpoints) != 0 {
		t.Fatalf(
			"decision evaluations/checkpoints = %d/%d, want 0/0",
			session.evaluations,
			len(session.checkpoints),
		)
	}

	if current.totalHostCalls() != 0 || current.backendProxyCalls != 0 || current.effectProxyCalls != 0 {
		t.Fatalf(
			"current host/backend/effect calls = %d/%d/%d, want 0/0/0",
			current.totalHostCalls(),
			current.backendProxyCalls,
			current.effectProxyCalls,
		)
	}
}

type grpcBoundaryOperationCase struct {
	invoke          func(context.Context, *Handler) error
	checkpoints     []string
	name            string
	fullMethod      string
	profileKind     string
	profileEvidence string
	operation       policy.Operation
}

// grpcBoundaryOperationCases returns the exact three-operation gRPC boundary matrix.
func grpcBoundaryOperationCases() []grpcBoundaryOperationCase {
	return []grpcBoundaryOperationCase{
		{
			name:            "authenticate",
			operation:       policy.OperationAuthenticate,
			fullMethod:      authv1.AuthService_Authenticate_FullMethodName,
			profileKind:     grpcBoundaryAuthenticateKind,
			profileEvidence: grpcBoundaryAuthenticateProof,
			checkpoints:     []string{string(policy.StagePreAuth), string(policy.StageAuthDecision)},
			invoke:          invokeGRPCBoundaryAuthenticate,
		},
		{
			name:            "lookup identity",
			operation:       policy.OperationLookupIdentity,
			fullMethod:      authv1.AuthService_LookupIdentity_FullMethodName,
			profileKind:     grpcBoundaryLookupKind,
			profileEvidence: grpcBoundaryLookupProof,
			checkpoints:     []string{string(policy.StagePreAuth), string(policy.StageAuthDecision)},
			invoke:          invokeGRPCBoundaryLookupIdentity,
		},
		{
			name:            "list accounts",
			operation:       policy.OperationListAccounts,
			fullMethod:      authv1.AuthService_ListAccounts_FullMethodName,
			profileKind:     grpcBoundaryListAccountsKind,
			profileEvidence: grpcBoundaryListAccountsProof,
			checkpoints:     []string{string(policy.StageAuthDecision)},
			invoke:          invokeGRPCBoundaryListAccounts,
		},
	}
}

// invokeGRPCBoundaryAuthenticate calls authenticate with the shared boundary fixture.
func invokeGRPCBoundaryAuthenticate(ctx context.Context, handler *Handler) error {
	_, err := handler.Authenticate(ctx, &authv1.AuthRequest{
		Username:   grpcBoundaryUsername,
		Password:   "test-only-password",
		ClientIp:   grpcBoundaryClientIP,
		UserAgent:  grpcBoundaryUserAgent,
		Protocol:   grpcBoundaryProtocol,
		Method:     grpcBoundaryMethod,
		ClientPort: grpcBoundaryClientPort,
	})

	return err
}

// invokeGRPCBoundaryLookupIdentity calls identity lookup with the shared boundary fixture.
func invokeGRPCBoundaryLookupIdentity(ctx context.Context, handler *Handler) error {
	_, err := handler.LookupIdentity(ctx, &authv1.LookupIdentityRequest{
		Username:   grpcBoundaryUsername,
		ClientIp:   grpcBoundaryClientIP,
		UserAgent:  grpcBoundaryUserAgent,
		Protocol:   grpcBoundaryProtocol,
		Method:     grpcBoundaryMethod,
		ClientPort: grpcBoundaryClientPort,
	})

	return err
}

// invokeGRPCBoundaryListAccounts calls account listing with the shared boundary fixture.
func invokeGRPCBoundaryListAccounts(ctx context.Context, handler *Handler) error {
	_, err := handler.ListAccounts(ctx, &authv1.ListAccountsRequest{
		Username:   grpcBoundaryUsername,
		ClientIp:   grpcBoundaryClientIP,
		UserAgent:  grpcBoundaryUserAgent,
		Protocol:   grpcBoundaryProtocol,
		Method:     grpcBoundaryMethod,
		ClientPort: grpcBoundaryClientPort,
	})

	return err
}

// grpcBoundaryRequestContext returns verified server transport evidence and a unary finalization gate.
func grpcBoundaryRequestContext() (context.Context, *core.PostActionExecutionGate) {
	ctx := verifiedBackchannelGRPCContext(metadata.Pairs(grpcBoundaryMetadataKey, grpcBoundaryMetadata))

	return core.ContextWithPostActionExecutionGate(ctx)
}

// mustGRPCBoundaryProfiles constructs distinct host-owned evidence for every operation.
func mustGRPCBoundaryProfiles(t *testing.T) core.AuthnInternalCallerProfiles {
	t.Helper()

	profiles, err := core.NewAuthnInternalCallerProfiles(
		mustGRPCBoundaryAuthentication(t, grpcBoundaryAuthenticateKind, grpcBoundaryAuthenticateProof),
		mustGRPCBoundaryAuthentication(t, grpcBoundaryLookupKind, grpcBoundaryLookupProof),
		mustGRPCBoundaryAuthentication(t, grpcBoundaryListAccountsKind, grpcBoundaryListAccountsProof),
	)
	if err != nil {
		t.Fatalf("NewAuthnInternalCallerProfiles() error = %v", err)
	}

	return profiles
}

// mustGRPCBoundaryAuthentication constructs one test-only internal presentation.
func mustGRPCBoundaryAuthentication(t *testing.T, kind string, credential string) decision.AuthenticationInput {
	t.Helper()

	input, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          kind,
		Credential:    []byte(credential),
		TransportKind: "host-owned",
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	return input
}

// assertGRPCBoundaryInvocation verifies admission identity, transport evidence, and request facts.
func assertGRPCBoundaryInvocation(
	t *testing.T,
	invocation decision.Invocation,
	operation grpcBoundaryOperationCase,
) {
	t.Helper()

	if got := invocation.Request.Target.String(); got != policy.AuthnNamespace+"/"+string(operation.operation) {
		t.Fatalf("decision target = %q, want exact operation target", got)
	}

	assertGRPCBoundaryAuthentication(t, invocation.Authentication, operation)
	assertGRPCBoundaryRequestFacts(t, invocation)
}

// assertGRPCBoundaryAuthentication verifies the selected internal profile and trusted transport.
func assertGRPCBoundaryAuthentication(
	t *testing.T,
	authentication decision.AuthenticationInput,
	operation grpcBoundaryOperationCase,
) {
	t.Helper()

	if authentication.Kind() != operation.profileKind ||
		string(authentication.Credential()) != operation.profileEvidence {
		t.Fatalf(
			"internal presentation = %q/%q, want %q/%q",
			authentication.Kind(),
			authentication.Credential(),
			operation.profileKind,
			operation.profileEvidence,
		)
	}

	if authentication.TransportKind() != grpcBoundaryTransportKind ||
		authentication.Listener() != grpcBoundaryListener {
		t.Fatalf(
			"transport kind/listener = %q/%q, want grpc/grpc.authority",
			authentication.TransportKind(),
			authentication.Listener(),
		)
	}

	if authentication.GRPCMethod() != operation.fullMethod || authentication.Peer() != grpcBoundaryPeer {
		t.Fatalf(
			"gRPC method/peer = %q/%q, want %q/203.0.113.45",
			authentication.GRPCMethod(),
			authentication.Peer(),
			operation.fullMethod,
		)
	}

	if !authentication.Protected() || authentication.MTLSIdentity() != grpcBoundaryMTLSIdentity {
		t.Fatalf(
			"protected/mTLS identity = %t/%q, want true/verified-backchannel-client",
			authentication.Protected(),
			authentication.MTLSIdentity(),
		)
	}
}

// assertGRPCBoundaryRequestFacts verifies application facts and environment projection.
func assertGRPCBoundaryRequestFacts(
	t *testing.T,
	invocation decision.Invocation,
) {
	t.Helper()

	assertGRPCBoundaryStringValue(t, invocation.Request.Attributes, "auth.username", grpcBoundaryUsername)
	assertGRPCBoundaryStringValue(t, invocation.Request.Attributes, "auth.client_ip", grpcBoundaryClientIP)
	assertGRPCBoundaryStringValue(t, invocation.Request.Attributes, "auth.method", grpcBoundaryMethod)
	assertGRPCBoundaryStringValue(
		t,
		invocation.Request.Environment.Attributes().Values(),
		"protocol",
		grpcBoundaryProtocol,
	)

	if invocation.Request.Environment.Service() != definitions.ServGRPC {
		t.Fatalf(
			"decision environment service = %q, want %q",
			invocation.Request.Environment.Service(),
			definitions.ServGRPC,
		)
	}
}

// assertGRPCBoundaryCurrentInput verifies the admitted current host receives detached metadata and transport facts.
func assertGRPCBoundaryCurrentInput(
	t *testing.T,
	input core.AuthInput,
	operation grpcBoundaryOperationCase,
) {
	t.Helper()

	if input.EntryPoint != core.AuthnEntryBackchannel {
		t.Fatalf("current entry point = %q, want explicit backchannel", input.EntryPoint)
	}

	values := input.Context.RequestMetadata[grpcBoundaryMetadataKey]
	if len(values) != 1 || values[0] != grpcBoundaryMetadata {
		t.Fatalf("current request metadata = %#v, want exact domain metadata", input.Context.RequestMetadata)
	}

	transport := input.Context.Transport
	if transport.Kind != grpcBoundaryTransportKind || transport.Listener != grpcBoundaryListener ||
		transport.GRPCMethod != operation.fullMethod || transport.Peer != grpcBoundaryPeer {
		t.Fatalf("current gRPC transport = %#v, want exact server-observed operation transport", transport)
	}
}

// assertGRPCBoundaryCheckpointFacts verifies the final admitted facts name the exact operation and service.
func assertGRPCBoundaryCheckpointFacts(
	t *testing.T,
	checkpoints []decision.Checkpoint,
	operation grpcBoundaryOperationCase,
) {
	t.Helper()

	if len(checkpoints) != len(operation.checkpoints) {
		t.Fatalf("evaluated checkpoints = %d, want %d", len(checkpoints), len(operation.checkpoints))
	}

	for index, checkpoint := range checkpoints {
		if checkpoint.Name() != operation.checkpoints[index] {
			t.Fatalf(
				"checkpoint %d = %q, want %q",
				index,
				checkpoint.Name(),
				operation.checkpoints[index],
			)
		}
	}

	facts := checkpoints[len(checkpoints)-1].Facts()

	assertGRPCBoundaryStringFact(t, facts, policy.AuthnFactOperation, string(operation.operation))
	assertGRPCBoundaryStringFact(t, facts, policy.AuthnFactService, definitions.ServGRPC)
}

// assertGRPCBoundaryStringValue verifies one exact strict string assertion.
func assertGRPCBoundaryStringValue(
	t *testing.T,
	values map[string]decision.Value,
	key string,
	want string,
) {
	t.Helper()

	value, found := values[key]

	if !found {
		t.Fatalf("request assertion %q missing", key)
	}

	got, ok := value.StringValue()

	if !ok || got != want {
		t.Fatalf("request assertion %q = %q/%t, want %q/true", key, got, ok, want)
	}
}

// assertGRPCBoundaryStringFact verifies one exact strict string fact.
func assertGRPCBoundaryStringFact(t *testing.T, facts decision.FactSet, id string, want string) {
	t.Helper()

	fact, found := facts.Get(id)

	if !found {
		t.Fatalf("decision fact %q missing", id)
	}

	got, ok := fact.Value().StringValue()

	if !ok || got != want {
		t.Fatalf("decision fact %q = %q/%t, want %q/true", id, got, ok, want)
	}
}

type recordingGRPCBoundaryCurrentService struct {
	inputs            map[policy.Operation]core.AuthInput
	hostCalls         map[policy.Operation]int
	backendProxyCalls int
	effectProxyCalls  int
}

// newRecordingGRPCBoundaryCurrentService returns stable current-host outcomes and proxy counters.
func newRecordingGRPCBoundaryCurrentService() *recordingGRPCBoundaryCurrentService {
	return &recordingGRPCBoundaryCurrentService{
		inputs:    make(map[policy.Operation]core.AuthInput, 3),
		hostCalls: make(map[policy.Operation]int, 3),
	}
}

// Authenticate records one admitted authenticate-host execution.
func (s *recordingGRPCBoundaryCurrentService) Authenticate(
	_ context.Context,
	input core.AuthInput,
) (*core.AuthOutcome, error) {
	s.record(policy.OperationAuthenticate, input)

	return &core.AuthOutcome{
		Decision:   core.AuthDecisionOK,
		Backend:    definitions.BackendTest,
		HTTPStatus: 200,
	}, nil
}

// LookupIdentity records one admitted lookup-host execution.
func (s *recordingGRPCBoundaryCurrentService) LookupIdentity(
	_ context.Context,
	input core.AuthInput,
) (*core.AuthOutcome, error) {
	s.record(policy.OperationLookupIdentity, input)

	return &core.AuthOutcome{
		Decision:   core.AuthDecisionOK,
		Backend:    definitions.BackendTest,
		HTTPStatus: 200,
	}, nil
}

// ListAccounts records one admitted account-provider host execution.
func (s *recordingGRPCBoundaryCurrentService) ListAccounts(
	_ context.Context,
	input core.AuthInput,
) (*core.ListAccountsOutcome, error) {
	s.record(policy.OperationListAccounts, input)

	return &core.ListAccountsOutcome{
		Accounts:   core.AccountList{"alpha@example.test", "beta@example.test"},
		Decision:   core.AuthDecisionOK,
		HTTPStatus: 200,
	}, nil
}

// record marks the backend/effect proxy boundary reached by one current-host operation.
func (s *recordingGRPCBoundaryCurrentService) record(operation policy.Operation, input core.AuthInput) {
	s.inputs[operation] = input
	s.hostCalls[operation]++
	s.backendProxyCalls++
	s.effectProxyCalls++
}

// totalHostCalls returns the complete current-host callback count.
func (s *recordingGRPCBoundaryCurrentService) totalHostCalls() int {
	total := 0

	for _, calls := range s.hostCalls {
		total += calls
	}

	return total
}

type recordingGRPCBoundaryDecisionSessionFactory struct {
	invocations   []decision.Invocation
	session       *recordingGRPCBoundaryDecisionSession
	openErr       error
	calls         int
	callbackCalls int
}

// WithSession records admission and calls the host only after a successful session open.
func (f *recordingGRPCBoundaryDecisionSessionFactory) WithSession(
	_ context.Context,
	invocation decision.Invocation,
	use func(decisionservice.DecisionSession) error,
) error {
	f.calls++
	f.invocations = append(f.invocations, invocation)

	if f.openErr != nil {
		return f.openErr
	}

	f.callbackCalls++

	return use(f.session)
}

type recordingGRPCBoundaryDecisionSession struct {
	plan        []decisionservice.CheckpointPlan
	checkpoints []decision.Checkpoint
	response    decision.DecisionResponse
	evaluations int
}

// newRecordingGRPCBoundaryDecisionSession constructs an immutable successful checkpoint plan.
func newRecordingGRPCBoundaryDecisionSession(
	t *testing.T,
	checkpointNames []string,
) *recordingGRPCBoundaryDecisionSession {
	t.Helper()

	plan := make([]decisionservice.CheckpointPlan, 0, len(checkpointNames))

	for _, name := range checkpointNames {
		checkpoint, err := decisionservice.NewCheckpointPlan(name, nil)
		if err != nil {
			t.Fatalf("NewCheckpointPlan(%q) error = %v", name, err)
		}

		plan = append(plan, checkpoint)
	}

	return &recordingGRPCBoundaryDecisionSession{
		plan:     plan,
		response: mustGRPCBoundaryDecisionResponse(t),
	}
}

// Checkpoints returns a detached copy of the captured generation plan.
func (s *recordingGRPCBoundaryDecisionSession) Checkpoints() []decisionservice.CheckpointPlan {
	return append([]decisionservice.CheckpointPlan(nil), s.plan...)
}

// RequestContext preserves the real gRPC handler context for host execution.
func (*recordingGRPCBoundaryDecisionSession) RequestContext(ctx context.Context) context.Context {
	return ctx
}

// Evaluate records exact facts and returns a neutral policy result.
func (s *recordingGRPCBoundaryDecisionSession) Evaluate(
	_ context.Context,
	checkpoint decision.Checkpoint,
) (decision.DecisionResponse, error) {
	s.evaluations++
	s.checkpoints = append(s.checkpoints, checkpoint)

	return s.response, nil
}

// mustGRPCBoundaryDecisionResponse constructs one valid neutral policy result.
func mustGRPCBoundaryDecisionResponse(t *testing.T) decision.DecisionResponse {
	t.Helper()

	statusMetadata, err := decision.NewStatus(decision.StatusCodeNotApplicable, "not applicable", nil)
	if err != nil {
		t.Fatalf("NewStatus() error = %v", err)
	}

	policyMetadata, err := decision.NewPolicyMetadata("authn/standard_auth", "v1", "grpc-boundary", 1)
	if err != nil {
		t.Fatalf("NewPolicyMetadata() error = %v", err)
	}

	response, err := decision.NewDecisionResponse(decision.DecisionResponseInput{
		RequestID:  "grpc-boundary-request",
		DecisionID: "grpc-boundary-decision",
		Effect:     decision.EffectNotApplicable,
		Status:     statusMetadata,
		Policy:     policyMetadata,
	})
	if err != nil {
		t.Fatalf("NewDecisionResponse() error = %v", err)
	}

	return response
}

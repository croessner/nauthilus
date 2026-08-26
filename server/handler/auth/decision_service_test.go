// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/gin-gonic/gin"
)

type httpRecordingDecisionSessionFactory struct {
	mu          sync.Mutex
	session     decisionservice.DecisionSession
	openErr     error
	invocations []decision.Invocation
}

// WithSession records one admitted candidate invocation before exposing its immutable plan.
func (f *httpRecordingDecisionSessionFactory) WithSession(
	_ context.Context,
	invocation decision.Invocation,
	use func(decisionservice.DecisionSession) error,
) error {
	f.mu.Lock()
	f.invocations = append(f.invocations, invocation)
	session := f.session
	openErr := f.openErr
	f.mu.Unlock()

	if openErr != nil {
		return openErr
	}

	return use(session)
}

// onlyInvocation returns the single captured candidate invocation.
func (f *httpRecordingDecisionSessionFactory) onlyInvocation(t *testing.T) decision.Invocation {
	t.Helper()

	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.invocations) != 1 {
		t.Fatalf("decision sessions = %d, want 1", len(f.invocations))
	}

	return f.invocations[0]
}

type httpRecordingDecisionSession struct {
	mu          sync.Mutex
	plan        []decisionservice.CheckpointPlan
	response    decision.DecisionResponse
	checkpoints []decision.Checkpoint
}

// httpDecisionRouteTest describes one transport and operation combination.
type httpDecisionRouteTest struct {
	name        string
	service     string
	queryMode   string
	operation   policy.Operation
	profileKind string
	credential  string
	checkpoints []string
}

// Checkpoints returns a detached copy of the captured generation plan.
func (s *httpRecordingDecisionSession) Checkpoints() []decisionservice.CheckpointPlan {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]decisionservice.CheckpointPlan(nil), s.plan...)
}

// RequestContext preserves the admitted caller context for the candidate execution.
func (*httpRecordingDecisionSession) RequestContext(ctx context.Context) context.Context {
	return ctx
}

// Evaluate records one exact checkpoint and returns a stable not-applicable decision.
func (s *httpRecordingDecisionSession) Evaluate(
	_ context.Context,
	checkpoint decision.Checkpoint,
) (decision.DecisionResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.checkpoints = append(s.checkpoints, checkpoint)

	return s.response, nil
}

// checkpointNames returns the exact evaluated checkpoint sequence.
func (s *httpRecordingDecisionSession) checkpointNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	names := make([]string, 0, len(s.checkpoints))
	for _, checkpoint := range s.checkpoints {
		names = append(names, checkpoint.Name())
	}

	return names
}

func TestBackchannelHTTPRoutesTraverseCandidateDecisionService(t *testing.T) {
	gin.SetMode(gin.TestMode)

	profiles := mustHTTPAuthnInternalProfiles(t)

	for _, test := range httpDecisionRouteTests() {
		t.Run(test.name, func(t *testing.T) {
			runHTTPDecisionRouteTest(t, profiles, test)
		})
	}
}

// httpDecisionRouteTests builds the complete surface and operation matrix without duplication.
func httpDecisionRouteTests() []httpDecisionRouteTest {
	surfaces := []struct {
		name    string
		service string
	}{
		{name: "json", service: definitions.ServJSON},
		{name: "cbor", service: definitions.ServCBOR},
		{name: "header", service: definitions.ServHeader},
		{name: "nginx", service: definitions.ServNginx},
	}
	operations := []struct {
		name        string
		queryMode   string
		operation   policy.Operation
		profileKind string
		credential  string
		checkpoints []string
	}{
		{
			name: "authenticate", operation: policy.OperationAuthenticate,
			profileKind: "internal-http-authenticate", credential: "opaque-http-authenticate",
			checkpoints: []string{string(policy.StagePreAuth), string(policy.StageAuthDecision)},
		},
		{
			name: "lookup identity", queryMode: "no-auth", operation: policy.OperationLookupIdentity,
			profileKind: "internal-http-lookup", credential: "opaque-http-lookup",
			checkpoints: []string{string(policy.StagePreAuth), string(policy.StageAuthDecision)},
		},
		{
			name: "list accounts", queryMode: "list-accounts", operation: policy.OperationListAccounts,
			profileKind: "internal-http-list", credential: "opaque-http-list",
			checkpoints: []string{string(policy.StageAuthDecision)},
		},
	}

	tests := make([]httpDecisionRouteTest, 0, len(surfaces)*len(operations))

	for _, surface := range surfaces {
		for _, operation := range operations {
			tests = append(tests, httpDecisionRouteTest{
				name: surface.name + " " + operation.name, service: surface.service,
				queryMode: operation.queryMode, operation: operation.operation,
				profileKind: operation.profileKind, credential: operation.credential,
				checkpoints: operation.checkpoints,
			})
		}
	}

	return tests
}

// runHTTPDecisionRouteTest exercises one route through the candidate decision boundary.
func runHTTPDecisionRouteTest(t *testing.T, profiles core.AuthnInternalCallerProfiles, test httpDecisionRouteTest) {
	t.Helper()

	current := &recordingAuthApplicationService{}
	session := newHTTPRecordingDecisionSession(t, test.checkpoints)
	factory := &httpRecordingDecisionSessionFactory{session: session}

	candidate, err := core.NewAuthnCandidateApplicationServiceWithInternalProfiles(current, factory, profiles)
	if err != nil {
		t.Fatalf("construct candidate application service: %v", err)
	}

	router := applicationBoundaryRouter(applicationBoundaryDeps(), candidate)
	request := applicationBoundaryRequest(t, test.service, test.queryMode)
	request.Header.Set("Authorization", "Bearer forbidden")
	request.Header.Set("Cookie", "session=forbidden")
	request.Header.Set("X-Request-ID", "decision-visible-request-id")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200; body=%q", recorder.Code, recorder.Body.String())
	}

	call := current.onlyCall(t)
	if call.input.EntryPoint != core.AuthnEntryBackchannel {
		t.Fatalf("current entry point = %q, want explicit backchannel", call.input.EntryPoint)
	}

	assertHTTPDecisionRequestMetadata(t, call.input.Context.RequestMetadata)
	assertHTTPDecisionInvocation(t, factory.onlyInvocation(t), test)
	assertHTTPDecisionCheckpoints(t, session.checkpointNames(), test.checkpoints)
}

// assertHTTPDecisionInvocation verifies operation-specific profiles and trusted transport facts.
func assertHTTPDecisionInvocation(t *testing.T, invocation decision.Invocation, test httpDecisionRouteTest) {
	t.Helper()

	wantTarget := policy.AuthnNamespace + "/" + string(test.operation)
	if got := invocation.Request.Target.String(); got != wantTarget {
		t.Fatalf("decision target = %q, want %q", got, wantTarget)
	}

	if got := invocation.Authentication.Kind(); got != test.profileKind {
		t.Fatalf("internal profile = %q, want %q", got, test.profileKind)
	}

	if got := string(invocation.Authentication.Credential()); got != test.credential {
		t.Fatalf("internal presentation = %q, want exact operation presentation", got)
	}

	if got := invocation.Authentication.HTTPRoute(); got != "/api/v1/auth/"+test.service {
		t.Fatalf("decision HTTP route = %q, want real registered route", got)
	}

	if got := invocation.Authentication.Peer(); got != applicationBoundaryPeer {
		t.Fatalf("decision peer = %q, want %q", got, applicationBoundaryPeer)
	}

	if got := invocation.Authentication.MTLSIdentity(); got != "spiffe://example.test/backchannel-client" {
		t.Fatalf("decision mTLS identity = %q, want verified SPIFFE identity", got)
	}

	if got := invocation.Authentication.TransportKind(); got != "http" {
		t.Fatalf("decision transport kind = %q, want http", got)
	}

	if got := invocation.Authentication.Listener(); got != "http" {
		t.Fatalf("decision listener = %q, want http", got)
	}

	if !invocation.Authentication.Protected() || !invocation.Finalization.Valid() {
		t.Fatal("decision session lost protected transport or HTTP finalization evidence")
	}
}

// assertHTTPDecisionRequestMetadata verifies the safe adapter evidence retained beside the public decision contract.
func assertHTTPDecisionRequestMetadata(t *testing.T, metadata map[string][]string) {
	t.Helper()

	for _, secret := range []string{"authorization", "cookie", "auth-pass", "auth-pass-encoded"} {
		if values := metadata[secret]; len(values) != 0 {
			t.Fatalf("secret metadata %q reached application boundary: %#v", secret, values)
		}
	}

	if got := metadata["x-request-id"]; len(got) != 1 || got[0] != "decision-visible-request-id" {
		t.Fatalf("safe request metadata = %#v, want detached X-Request-ID", got)
	}
}

func TestBackchannelHTTPDecisionRejectionStopsCurrentApplication(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name      string
		queryMode string
	}{
		{name: "authenticate"},
		{name: "lookup identity", queryMode: "no-auth"},
		{name: "list accounts", queryMode: "list-accounts"},
	}

	profiles := mustHTTPAuthnInternalProfiles(t)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := &recordingAuthApplicationService{}
			factory := &httpRecordingDecisionSessionFactory{openErr: decisionservice.ErrDecisionAdmission}

			candidate, err := core.NewAuthnCandidateApplicationServiceWithInternalProfiles(current, factory, profiles)
			if err != nil {
				t.Fatalf("construct candidate application service: %v", err)
			}

			router := applicationBoundaryRouter(applicationBoundaryDeps(), candidate)
			request := applicationBoundaryRequest(t, definitions.ServJSON, test.queryMode)
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("HTTP status = %d, want fail-closed 500", recorder.Code)
			}

			if current.totalCalls() != 0 {
				t.Fatalf("current application calls = %d, want 0 before admission", current.totalCalls())
			}

			factory.onlyInvocation(t)
		})
	}
}

// mustHTTPAuthnInternalProfiles constructs distinct test-only operation presentations.
func mustHTTPAuthnInternalProfiles(t *testing.T) core.AuthnInternalCallerProfiles {
	t.Helper()

	profiles, err := core.NewAuthnInternalCallerProfiles(
		mustHTTPInternalAuthentication(t, "internal-http-authenticate", "opaque-http-authenticate"),
		mustHTTPInternalAuthentication(t, "internal-http-lookup", "opaque-http-lookup"),
		mustHTTPInternalAuthentication(t, "internal-http-list", "opaque-http-list"),
	)
	if err != nil {
		t.Fatalf("construct internal caller profiles: %v", err)
	}

	return profiles
}

// mustHTTPInternalAuthentication constructs one host-owned test presentation.
func mustHTTPInternalAuthentication(t *testing.T, kind string, credential string) decision.AuthenticationInput {
	t.Helper()

	input, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          kind,
		Credential:    []byte(credential),
		TransportKind: "host-owned",
	})
	if err != nil {
		t.Fatalf("construct internal authentication: %v", err)
	}

	return input
}

// newHTTPRecordingDecisionSession creates one exact plan with a stable neutral response.
func newHTTPRecordingDecisionSession(t *testing.T, names []string) *httpRecordingDecisionSession {
	t.Helper()

	plan := make([]decisionservice.CheckpointPlan, 0, len(names))
	for _, name := range names {
		checkpoint, err := decisionservice.NewCheckpointPlan(name, nil)
		if err != nil {
			t.Fatalf("construct checkpoint plan: %v", err)
		}

		plan = append(plan, checkpoint)
	}

	status, err := decision.NewStatus(decision.StatusCodeNotApplicable, "no configured rule", nil)
	if err != nil {
		t.Fatalf("construct decision status: %v", err)
	}

	metadata, err := decision.NewPolicyMetadata("authn/standard_auth", "v1", "", 22)
	if err != nil {
		t.Fatalf("construct policy metadata: %v", err)
	}

	response, err := decision.NewDecisionResponse(decision.DecisionResponseInput{
		RequestID:  "http-backchannel-request",
		DecisionID: "http-backchannel-decision",
		Effect:     decision.EffectNotApplicable,
		Status:     status,
		Policy:     metadata,
	})
	if err != nil {
		t.Fatalf("construct decision response: %v", err)
	}

	return &httpRecordingDecisionSession{plan: plan, response: response}
}

// assertHTTPDecisionCheckpoints compares the exact session traversal order.
func assertHTTPDecisionCheckpoints(t *testing.T, got []string, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("evaluated checkpoints = %#v, want %#v", got, want)
	}

	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("evaluated checkpoints = %#v, want %#v", got, want)
		}
	}
}

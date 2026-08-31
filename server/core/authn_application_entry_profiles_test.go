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
	"io"
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/rediscli"

	"github.com/go-redis/redismock/v9"
)

type authnEntryProfileTestCase struct {
	name       string
	wantKind   string
	wantProof  string
	entryPoint AuthnEntryPoint
	operation  policy.Operation
}

type authnEntryRejectionTestCase struct {
	name           string
	entryPoint     AuthnEntryPoint
	operation      policy.Operation
	wantMissing    bool
	wantInputError bool
}

func TestAuthnEntryProfilesSelectExactHostOwnedPresentation(t *testing.T) {
	profiles := mustAuthnEntryProfiles(t)

	for _, test := range authnEntryProfileTestCases() {
		t.Run(test.name, func(t *testing.T) {
			operation := authnOperationCase(t, test.operation)
			current := newRecordingAuthApplicationService()
			session := newRecordingAuthnDecisionSession(
				operation.checkpointNames(),
				repeatAuthnDecisionEffect(t, decision.EffectNotApplicable, len(operation.checkpointNames()))...,
			)
			factory := &recordingAuthnDecisionSessionFactory{session: session}

			adapter, err := NewAuthnCandidateApplicationServiceWithInternalProfiles(current, factory, profiles)
			if err != nil {
				t.Fatalf("NewAuthnCandidateApplicationServiceWithInternalProfiles() error = %v", err)
			}

			input := authnApplicationTestInput(operation.mode)
			input.EntryPoint = test.entryPoint

			if err = operation.run(context.Background(), adapter, input); err != nil {
				t.Fatalf("candidate operation error = %v", err)
			}

			if factory.calls != 1 || len(factory.invocations) != 1 {
				t.Fatalf("decision-session calls/invocations = %d/%d, want 1/1", factory.calls, len(factory.invocations))
			}

			authentication := factory.invocations[0].Authentication

			if authentication.Kind() != test.wantKind || string(authentication.Credential()) != test.wantProof {
				t.Fatalf(
					"entry authentication = %q/%q, want %q/%q",
					authentication.Kind(), authentication.Credential(), test.wantKind, test.wantProof,
				)
			}
		})
	}
}

func TestAuthnInternalProfileIDsReturnCompleteDetachedValidatedMatrix(t *testing.T) {
	first, err := AuthnInternalProfileIDs()
	if err != nil {
		t.Fatalf("AuthnInternalProfileIDs() error = %v", err)
	}

	want := make(map[string]struct{}, len(authnEntryProfileTestCases()))
	for _, test := range authnEntryProfileTestCases() {
		profileID, profileErr := decisionservice.NewInternalProfileID(test.entryPoint.String(), string(test.operation))
		if profileErr != nil {
			t.Fatalf("construct expected profile %s/%s: %v", test.entryPoint, test.operation, profileErr)
		}

		want[profileID.String()] = struct{}{}
	}

	if len(first) != len(want) {
		t.Fatalf("profile count = %d, want %d", len(first), len(want))
	}

	for _, profileID := range first {
		if _, found := want[profileID.String()]; !found {
			t.Fatalf("unexpected internal profile ID %q", profileID.String())
		}
	}

	first[0] = decisionservice.InternalProfileID{}

	second, err := AuthnInternalProfileIDs()
	if err != nil {
		t.Fatalf("second AuthnInternalProfileIDs() error = %v", err)
	}

	if second[0].String() == "" {
		t.Fatal("mutating returned profile slice changed the authoritative matrix")
	}
}

func TestAuthnEntryProfilesRejectMissingUnknownAndNonmatchingBeforeAdmission(t *testing.T) {
	defaults := mustAuthnInternalCallerProfiles(t)

	profiles, err := NewAuthnInternalCallerProfilesWithEntries(defaults, AuthnEntryCallerProfiles{
		EntryPoint:   AuthnEntryIDPOIDCDeviceCode,
		Authenticate: entryAuthentication(t, AuthnEntryIDPOIDCDeviceCode, policy.OperationAuthenticate),
	})
	if err != nil {
		t.Fatalf("NewAuthnInternalCallerProfilesWithEntries() error = %v", err)
	}

	tests := []authnEntryRejectionTestCase{
		{
			name: "known entry missing configured lookup profile", entryPoint: AuthnEntryIDPOIDCDeviceCode,
			operation: policy.OperationLookupIdentity, wantMissing: true,
		},
		{
			name: "unknown nonempty entry", entryPoint: AuthnEntryPoint(255),
			operation: policy.OperationAuthenticate, wantInputError: true,
		},
		{
			name: "known entry does not support operation", entryPoint: AuthnEntryIDPDelayedIdentity,
			operation: policy.OperationAuthenticate, wantInputError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertAuthnEntryProfileRejection(t, profiles, test)
		})
	}
}

// assertAuthnEntryProfileRejection proves profile selection fails before admission and host work.
func assertAuthnEntryProfileRejection(
	t *testing.T,
	profiles AuthnInternalCallerProfiles,
	test authnEntryRejectionTestCase,
) {
	t.Helper()

	operation := authnOperationCase(t, test.operation)
	current := newRecordingAuthApplicationService()
	session := newRecordingAuthnDecisionSession(
		operation.checkpointNames(),
		repeatAuthnDecisionEffect(t, decision.EffectNotApplicable, len(operation.checkpointNames()))...,
	)
	factory := &recordingAuthnDecisionSessionFactory{session: session}

	adapter, err := NewAuthnCandidateApplicationServiceWithInternalProfiles(current, factory, profiles)
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationServiceWithInternalProfiles() error = %v", err)
	}

	input := authnApplicationTestInput(operation.mode)
	input.EntryPoint = test.entryPoint

	operationErr := operation.run(context.Background(), adapter, input)
	if operationErr == nil {
		t.Fatal("candidate operation error = nil, want fail-closed profile rejection")
	}

	if test.wantMissing && !errors.Is(operationErr, ErrAuthApplicationDependencyMissing) {
		t.Fatalf("candidate operation error = %v, want missing profile dependency", operationErr)
	}

	var inputErr *AuthInputError

	if test.wantInputError && !errors.As(operationErr, &inputErr) {
		t.Fatalf("candidate operation error = %v, want AuthInputError", operationErr)
	}

	if factory.calls != 0 || current.totalCalls() != 0 {
		t.Fatalf("decision/current calls = %d/%d, want 0/0 before admission", factory.calls, current.totalCalls())
	}
}

func TestAuthnEntryProfilesNeverInferAuthorityFromRouteOrProtocolFacts(t *testing.T) {
	profiles := mustAuthnEntryProfiles(t)
	operation := authnOperationCase(t, policy.OperationAuthenticate)
	current := newRecordingAuthApplicationService()
	session := newRecordingAuthnDecisionSession(
		operation.checkpointNames(),
		repeatAuthnDecisionEffect(t, decision.EffectNotApplicable, len(operation.checkpointNames()))...,
	)
	factory := &recordingAuthnDecisionSessionFactory{session: session}

	adapter, err := NewAuthnCandidateApplicationServiceWithInternalProfiles(current, factory, profiles)
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationServiceWithInternalProfiles() error = %v", err)
	}

	input := authnApplicationTestInput(operation.mode)
	input.EntryPoint = AuthnEntryBackchannel
	input.Context.Protocol = "oidc"
	input.Context.OIDCCID = "browser-controlled-client"
	input.Context.Transport.HTTPRoute = "/oidc/authorize"

	if err = operation.run(context.Background(), adapter, input); err != nil {
		t.Fatalf("candidate operation error = %v", err)
	}

	authentication := factory.invocations[0].Authentication
	wantKind, wantProof := authnInternalProfileFixture(policy.OperationAuthenticate)

	if authentication.Kind() != wantKind || string(authentication.Credential()) != wantProof {
		t.Fatalf(
			"route-selected authentication = %q/%q, want host-owned default %q/%q",
			authentication.Kind(), authentication.Credential(), wantKind, wantProof,
		)
	}
}

func TestAuthnIDPEntryProfilesTraverseOneRealDecisionRuntime(t *testing.T) {
	profiles := mustAuthnEntryProfiles(t)
	cfg := newCurrentBehaviorConfig(t)
	db, _ := redismock.NewClientMock()
	host := &authnCandidateInjectedHost{base: newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	})}

	installAuthnCandidateServices(t, failingPasswordVerifier{}, testLuaSubject{})
	runtime := newAuthnCandidateDecisionService(t, cfg, &authnCandidateAcceptAll{})
	checkpoints := &authnCandidateCheckpointFactory{delegate: runtime, checkpoints: make(map[string][]string)}
	recorder := &authnEntryInvocationFactory{delegate: checkpoints}

	adapter, err := NewAuthnCandidateApplicationServiceWithInternalProfiles(host, recorder, profiles)
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationServiceWithInternalProfiles() error = %v", err)
	}

	wantCheckpoints := make(map[string][]string)
	wantCalls := 0

	for _, test := range authnEntryProfileTestCases() {
		if test.entryPoint == AuthnEntryBackchannel {
			continue
		}

		operation := authnOperationCase(t, test.operation)
		input := authnApplicationTestInput(operation.mode)
		input.EntryPoint = test.entryPoint

		if err = operation.run(context.Background(), adapter, input); err != nil {
			t.Fatalf("%s candidate operation error = %v", test.name, err)
		}

		invocation := recorder.invocations[len(recorder.invocations)-1]
		if invocation.Authentication.Kind() != test.wantKind ||
			string(invocation.Authentication.Credential()) != test.wantProof {
			t.Fatalf(
				"%s real-runtime authentication = %q/%q, want %q/%q",
				test.name,
				invocation.Authentication.Kind(),
				invocation.Authentication.Credential(),
				test.wantKind,
				test.wantProof,
			)
		}

		target := policy.AuthnNamespace + "/" + string(test.operation)
		wantCheckpoints[target] = append(wantCheckpoints[target], operation.checkpointNames()...)
		wantCalls++
	}

	if len(recorder.invocations) != wantCalls || host.calls.Load() != 0 {
		t.Fatalf(
			"real-runtime invocation/retired-aggregate calls = %d/%d, want %d/0",
			len(recorder.invocations), host.calls.Load(), wantCalls,
		)
	}

	if got := checkpoints.snapshot(); !equalAuthnEntryCheckpoints(got, wantCheckpoints) {
		t.Fatalf("real-runtime entry checkpoints = %#v, want %#v", got, wantCheckpoints)
	}
}

type authnEntryInvocationFactory struct {
	delegate    decisionservice.DecisionSessionFactory
	invocations []decision.Invocation
}

// WithSession records exact entry evidence before delegating to the real Decision Service runtime.
func (f *authnEntryInvocationFactory) WithSession(
	ctx context.Context,
	invocation decision.Invocation,
	use func(decisionservice.DecisionSession) error,
) error {
	f.invocations = append(f.invocations, invocation)

	return f.delegate.WithSession(ctx, invocation, use)
}

// equalAuthnEntryCheckpoints compares the complete operation/checkpoint traversal map.
func equalAuthnEntryCheckpoints(got map[string][]string, want map[string][]string) bool {
	if len(got) != len(want) {
		return false
	}

	for target, wantNames := range want {
		gotNames, found := got[target]
		if !found || len(gotNames) != len(wantNames) {
			return false
		}

		for index, wantName := range wantNames {
			if gotNames[index] != wantName {
				return false
			}
		}
	}

	return true
}

// mustAuthnEntryProfiles constructs the complete test-owned IdP entry bundle.
func mustAuthnEntryProfiles(t *testing.T) AuthnInternalCallerProfiles {
	t.Helper()

	profiles, err := NewAuthnInternalCallerProfilesWithEntries(
		mustAuthnInternalCallerProfiles(t),
		entryProfilePair(t, AuthnEntryIDPInternal),
		entryProfilePair(t, AuthnEntryIDPOIDCAuthorizationCode),
		entryProfilePair(t, AuthnEntryIDPOIDCDeviceCode),
		entryProfilePair(t, AuthnEntryIDPSAML),
		entryLookupProfile(t, AuthnEntryIDPDelayedIdentity),
		entryLookupProfile(t, AuthnEntryIDPMasterFactor),
		entryLookupProfile(t, AuthnEntryIDPMFABackend),
	)
	if err != nil {
		t.Fatalf("NewAuthnInternalCallerProfilesWithEntries() error = %v", err)
	}

	return profiles
}

// entryProfilePair constructs exact authenticate and identity-lookup presentations for one entry.
func entryProfilePair(t *testing.T, entryPoint AuthnEntryPoint) AuthnEntryCallerProfiles {
	t.Helper()

	return AuthnEntryCallerProfiles{
		EntryPoint:     entryPoint,
		Authenticate:   entryAuthentication(t, entryPoint, policy.OperationAuthenticate),
		LookupIdentity: entryAuthentication(t, entryPoint, policy.OperationLookupIdentity),
	}
}

// entryLookupProfile constructs one lookup-only entry presentation.
func entryLookupProfile(t *testing.T, entryPoint AuthnEntryPoint) AuthnEntryCallerProfiles {
	t.Helper()

	return AuthnEntryCallerProfiles{
		EntryPoint:     entryPoint,
		LookupIdentity: entryAuthentication(t, entryPoint, policy.OperationLookupIdentity),
	}
}

// entryAuthentication constructs deterministic host evidence for one exact entry and operation.
func entryAuthentication(t *testing.T, entryPoint AuthnEntryPoint, operation policy.Operation) decision.AuthenticationInput {
	t.Helper()

	kind, proof := authnEntryProfileFixture(entryPoint, operation)

	return mustAuthnProfileAuthentication(t, kind, proof)
}

// authnEntryProfileTestCases returns every required entry/operation selection.
func authnEntryProfileTestCases() []authnEntryProfileTestCase {
	return []authnEntryProfileTestCase{
		entryProfileTestCase("backchannel authenticate", AuthnEntryBackchannel, policy.OperationAuthenticate),
		entryProfileTestCase("backchannel lookup", AuthnEntryBackchannel, policy.OperationLookupIdentity),
		entryProfileTestCase("backchannel list", AuthnEntryBackchannel, policy.OperationListAccounts),
		entryProfileTestCase("internal IDP authenticate", AuthnEntryIDPInternal, policy.OperationAuthenticate),
		entryProfileTestCase("internal IDP lookup", AuthnEntryIDPInternal, policy.OperationLookupIdentity),
		entryProfileTestCase("OIDC code authenticate", AuthnEntryIDPOIDCAuthorizationCode, policy.OperationAuthenticate),
		entryProfileTestCase("OIDC code lookup", AuthnEntryIDPOIDCAuthorizationCode, policy.OperationLookupIdentity),
		entryProfileTestCase("OIDC device authenticate", AuthnEntryIDPOIDCDeviceCode, policy.OperationAuthenticate),
		entryProfileTestCase("OIDC device lookup", AuthnEntryIDPOIDCDeviceCode, policy.OperationLookupIdentity),
		entryProfileTestCase("SAML authenticate", AuthnEntryIDPSAML, policy.OperationAuthenticate),
		entryProfileTestCase("SAML lookup", AuthnEntryIDPSAML, policy.OperationLookupIdentity),
		entryProfileTestCase("delayed identity lookup", AuthnEntryIDPDelayedIdentity, policy.OperationLookupIdentity),
		entryProfileTestCase("master factor lookup", AuthnEntryIDPMasterFactor, policy.OperationLookupIdentity),
		entryProfileTestCase("MFA backend lookup", AuthnEntryIDPMFABackend, policy.OperationLookupIdentity),
	}
}

// entryProfileTestCase builds one exact expected host presentation.
func entryProfileTestCase(
	name string,
	entryPoint AuthnEntryPoint,
	operation policy.Operation,
) authnEntryProfileTestCase {
	kind, proof := authnEntryProfileFixture(entryPoint, operation)

	return authnEntryProfileTestCase{
		name: name, entryPoint: entryPoint, operation: operation, wantKind: kind, wantProof: proof,
	}
}

// authnEntryProfileFixture returns the deterministic profile evidence for one exact pair.
func authnEntryProfileFixture(entryPoint AuthnEntryPoint, operation policy.Operation) (string, string) {
	if entryPoint == AuthnEntryBackchannel {
		return authnInternalProfileFixture(operation)
	}

	base := "internal-" + entryPoint.String() + "-" + string(operation)

	return base, "opaque-" + entryPoint.String() + "-" + string(operation)
}

// authnOperationCase returns the shared operation fixture or fails the test.
func authnOperationCase(t *testing.T, operation policy.Operation) authnApplicationOperationCase {
	t.Helper()

	for _, candidate := range authnApplicationOperationCases() {
		if candidate.operation == operation {
			return candidate
		}
	}

	t.Fatalf("authn operation fixture %q is unavailable", operation)

	return authnApplicationOperationCase{}
}

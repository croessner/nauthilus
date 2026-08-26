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
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
)

func TestAuthnInternalCallerProfilesSelectExactOperationPresentation(t *testing.T) {
	profiles := mustAuthnInternalCallerProfiles(t)

	for _, test := range authnApplicationOperationCases() {
		t.Run(test.name, func(t *testing.T) {
			current := newRecordingAuthApplicationService()
			session := newRecordingAuthnDecisionSession(
				test.checkpointNames(),
				repeatAuthnDecisionEffect(t, decision.EffectNotApplicable, len(test.checkpointNames()))...,
			)
			factory := &recordingAuthnDecisionSessionFactory{session: session}

			adapter, err := NewAuthnCandidateApplicationServiceWithInternalProfiles(current, factory, profiles)
			if err != nil {
				t.Fatalf("NewAuthnCandidateApplicationServiceWithInternalProfiles() error = %v", err)
			}

			input := authnApplicationTestInput(test.mode)
			ctx := ContextWithGRPCMethod(context.Background(), "/nauthilus.auth.v1.AuthService/"+test.grpcMethod)

			if err = test.run(ctx, adapter, input); err != nil {
				t.Fatalf("candidate operation error = %v", err)
			}

			invocation := factory.invocations[0]
			wantKind, wantCredential := authnInternalProfileFixture(test.operation)

			if invocation.Authentication.Kind() != wantKind || string(invocation.Authentication.Credential()) != wantCredential {
				t.Fatalf(
					"authentication = %q/%q, want %q/%q",
					invocation.Authentication.Kind(),
					invocation.Authentication.Credential(),
					wantKind,
					wantCredential,
				)
			}

			if got := invocation.Request.Target.String(); got != policy.AuthnNamespace+"/"+string(test.operation) {
				t.Fatalf("target = %q, want exact operation target", got)
			}

			assertAuthnProfileTransport(t, invocation.Authentication, input.Context.Transport, test.grpcMethod)
		})
	}
}

func TestAuthnInternalCallerProfilesRejectBeforeCurrentHost(t *testing.T) {
	profiles := mustAuthnInternalCallerProfiles(t)

	for _, test := range authnApplicationOperationCases() {
		t.Run(test.name, func(t *testing.T) {
			current := newRecordingAuthApplicationService()
			factory := &recordingAuthnDecisionSessionFactory{
				openErr: decisionservice.ErrDecisionAdmission,
			}

			adapter, err := NewAuthnCandidateApplicationServiceWithInternalProfiles(current, factory, profiles)
			if err != nil {
				t.Fatalf("NewAuthnCandidateApplicationServiceWithInternalProfiles() error = %v", err)
			}

			err = test.run(context.Background(), adapter, authnApplicationTestInput(test.mode))

			if !errors.Is(err, decisionservice.ErrDecisionAdmission) {
				t.Fatalf("operation error = %v, want admission rejection", err)
			}

			if current.totalCalls() != 0 {
				t.Fatalf("current host calls = %d, want 0 before admission", current.totalCalls())
			}
		})
	}
}

func TestAuthnInternalCallerProfilesRequireEveryOperation(t *testing.T) {
	valid := mustAuthnProfileAuthentication(t, "valid-internal-profile", "valid-opaque-evidence")

	_, err := NewAuthnInternalCallerProfiles(valid, decision.AuthenticationInput{}, valid)
	if !errors.Is(err, ErrAuthApplicationDependencyMissing) {
		t.Fatalf("NewAuthnInternalCallerProfiles() error = %v, want missing profile", err)
	}
}

// mustAuthnInternalCallerProfiles constructs distinct host-owned operation evidence.
func mustAuthnInternalCallerProfiles(t *testing.T) AuthnInternalCallerProfiles {
	t.Helper()

	profiles, err := NewAuthnInternalCallerProfiles(
		mustAuthnProfileAuthentication(t, "internal-authenticate", "opaque-authenticate"),
		mustAuthnProfileAuthentication(t, "internal-lookup-identity", "opaque-lookup-identity"),
		mustAuthnProfileAuthentication(t, "internal-list-accounts", "opaque-list-accounts"),
	)
	if err != nil {
		t.Fatalf("NewAuthnInternalCallerProfiles() error = %v", err)
	}

	return profiles
}

// mustAuthnProfileAuthentication constructs one exact host-created presentation.
func mustAuthnProfileAuthentication(t *testing.T, kind string, credential string) decision.AuthenticationInput {
	t.Helper()

	input, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          kind,
		Credential:    []byte(credential),
		TransportKind: "internal",
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	return input
}

// authnInternalProfileFixture returns exact expectations for one operation profile.
func authnInternalProfileFixture(operation policy.Operation) (string, string) {
	switch operation {
	case policy.OperationAuthenticate:
		return "internal-authenticate", "opaque-authenticate"
	case policy.OperationLookupIdentity:
		return "internal-lookup-identity", "opaque-lookup-identity"
	case policy.OperationListAccounts:
		return "internal-list-accounts", "opaque-list-accounts"
	default:
		return "", ""
	}
}

// assertAuthnProfileTransport verifies operation selection does not replace transport evidence.
func assertAuthnProfileTransport(
	t *testing.T,
	input decision.AuthenticationInput,
	want AuthTransportContext,
	wantGRPCMethod string,
) {
	t.Helper()

	if input.TransportKind() != want.Kind || input.Listener() != want.Listener || input.Peer() != want.Peer {
		t.Fatalf(
			"transport = %q/%q/%q, want %q/%q/%q",
			input.TransportKind(),
			input.Listener(),
			input.Peer(),
			want.Kind,
			want.Listener,
			want.Peer,
		)
	}

	if input.GRPCMethod() != "/nauthilus.auth.v1.AuthService/"+wantGRPCMethod {
		t.Fatalf("gRPC method = %q, want preserved application method", input.GRPCMethod())
	}

	if input.MTLSIdentity() != want.MTLSIdentity || input.Protected() != want.Protected {
		t.Fatalf(
			"protected mTLS evidence = %q/%t, want %q/%t",
			input.MTLSIdentity(),
			input.Protected(),
			want.MTLSIdentity,
			want.Protected,
		)
	}
}

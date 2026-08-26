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

package callerauth

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/secret"
)

const (
	policyPreparationInternalCapability = "preparation-internal-capability"
	policyPreparationInternalKind       = "named-internal"
	policyPreparationInternalPrincipal  = "Internal"
)

func TestPolicyCallerAuthenticationPreparationOwnsExactProfiles(t *testing.T) {
	t.Parallel()

	preparation, err := Prepare(policyPreparationConfiguration())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	authenticator := assertPolicyPreparationMetadata(t, preparation)
	assertPolicyPreparationAuthentication(t, preparation)
	assertPolicyPreparationDetachment(t, preparation, authenticator)
}

func TestPolicyCallerAuthenticationPreparationRejectsInvalidCandidate(t *testing.T) {
	t.Parallel()

	preparation, err := Prepare(Configuration{ExternalProfiles: []ExternalProfile{{
		AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer},
		Principal:           "",
	}}})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Prepare() error = %v, want ErrConfiguration", err)
	}

	if preparation.Authenticator != nil || len(preparation.Credentials.IDs()) != 0 || len(preparation.Resources) != 0 {
		t.Fatalf("failed preparation = %#v, want zero", preparation)
	}
}

func TestPolicyCallerAuthenticationPreparationRejectsClientMTLSWithoutVerifiedCertificateTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		capabilities TransportCapabilities
	}{
		{name: "HTTP only", capabilities: TransportCapabilities{HTTPProtected: true}},
		{name: "gRPC without verified client certificates", capabilities: TransportCapabilities{GRPCProtected: true}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			preparation, err := Prepare(Configuration{
				TokenValidator:        policyStaticTokenValidator{},
				TransportCapabilities: test.capabilities,
				ExternalProfiles: []ExternalProfile{{
					AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer},
					Principal:           policyTestPrincipal,
					RequireMTLS:         true,
				}},
			})
			if !errors.Is(err, ErrConfiguration) {
				t.Fatalf("Prepare() error = %v, want ErrConfiguration", err)
			}

			if preparation.Authenticator != nil || len(preparation.Credentials.IDs()) != 0 || len(preparation.Resources) != 0 {
				t.Fatalf("failed preparation = %#v, want zero", preparation)
			}
		})
	}
}

func TestPolicyCallerAuthenticationPreparationAcceptsClientMTLSWithVerifiedCertificateTransport(t *testing.T) {
	t.Parallel()

	preparation, err := Prepare(Configuration{
		TokenValidator: policyStaticTokenValidator{},
		TransportCapabilities: TransportCapabilities{
			GRPCProtected:                 true,
			GRPCVerifiedClientCertificate: true,
		},
		ExternalProfiles: []ExternalProfile{{
			AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer},
			Principal:           policyTestPrincipal,
			RequireMTLS:         true,
		}},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	if preparation.Authenticator == nil {
		t.Fatal("Prepare() returned no authenticator")
	}
}

func TestPolicyCallerAuthenticationPreparationRequiresBasicThrottler(t *testing.T) {
	t.Parallel()

	configuration := policyPreparationConfiguration()
	configuration.Throttler = nil

	preparation, err := Prepare(configuration)
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Prepare() error = %v, want ErrConfiguration", err)
	}

	if preparation.Authenticator != nil || len(preparation.Credentials.IDs()) != 0 || len(preparation.Resources) != 0 {
		t.Fatalf("failed preparation = %#v, want zero", preparation)
	}
}

func TestPolicyCallerAuthenticationPreparationNeedsNoThrottlerWithoutBasic(t *testing.T) {
	t.Parallel()

	preparation, err := Prepare(Configuration{InternalCallers: []InternalCaller{{
		Capability:     secret.New(policyPreparationInternalCapability),
		TransportKinds: []string{"internal"},
		Principal:      policyPreparationInternalPrincipal,
		EvidenceKind:   policyPreparationInternalKind,
	}}})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	if preparation.Authenticator == nil {
		t.Fatal("Prepare() returned no authenticator")
	}
}

// policyPreparationConfiguration builds one mixed case-sensitive preparation fixture.
func policyPreparationConfiguration() Configuration {
	return Configuration{
		TokenValidator:        policyStaticTokenValidator{},
		Throttler:             &policyRecordingThrottler{},
		TransportCapabilities: TransportCapabilities{HTTPProtected: true},
		ExternalProfiles: []ExternalProfile{
			{
				Basic: &BasicCredential{
					Password: secret.New("preparation-policy-password"),
					Username: "preparation-user",
				},
				AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic},
				Principal:           "Client",
			},
			{
				AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer},
				Principal:           "client",
			},
		},
		InternalCallers: []InternalCaller{
			{
				Capability:     secret.New(policyPreparationInternalCapability),
				TransportKinds: []string{"internal"},
				Principal:      policyPreparationInternalPrincipal,
				EvidenceKind:   policyPreparationInternalKind,
			},
		},
	}
}

// assertPolicyPreparationMetadata verifies exact profile metadata and resource-free preparation.
func assertPolicyPreparationMetadata(
	t *testing.T,
	preparation policyruntime.CallerAuthenticationPreparation,
) *Authenticator {
	t.Helper()

	wantProfiles := policyPreparationProfileIDs()
	if got := preparation.Credentials.IDs(); !slices.Equal(got, wantProfiles) {
		t.Fatalf("credential profiles = %v, want %v", got, wantProfiles)
	}

	if len(preparation.Resources) != 0 {
		t.Fatalf("candidate resources = %d, want none", len(preparation.Resources))
	}

	authenticator, ok := preparation.Authenticator.(*Authenticator)
	if !ok || authenticator == nil {
		t.Fatalf("prepared authenticator = %T, want *Authenticator", preparation.Authenticator)
	}

	return authenticator
}

// assertPolicyPreparationAuthentication proves the prepared runtime interface remains usable.
func assertPolicyPreparationAuthentication(t *testing.T, preparation policyruntime.CallerAuthenticationPreparation) {
	t.Helper()

	input := mustPolicyAuthenticationInput(
		t,
		policyPreparationInternalKind,
		policyPreparationInternalCapability,
		"internal",
		false,
		"",
	)

	caller, err := preparation.Authenticator.Authenticate(context.Background(), input)
	if err != nil {
		t.Fatalf("prepared Authenticate() error = %v", err)
	}

	if caller.Principal() != policyPreparationInternalPrincipal || caller.AuthenticationKind() != policy.CallerAuthenticationKindInternal {
		t.Fatalf("prepared caller = %q/%q", caller.Principal(), caller.AuthenticationKind())
	}
}

// assertPolicyPreparationDetachment proves callers cannot mutate either profile view.
func assertPolicyPreparationDetachment(
	t *testing.T,
	preparation policyruntime.CallerAuthenticationPreparation,
	authenticator *Authenticator,
) {
	t.Helper()

	wantProfiles := policyPreparationProfileIDs()
	detached := preparation.Credentials.IDs()
	detached[0] = "mutated"

	if got := preparation.Credentials.IDs(); !slices.Equal(got, wantProfiles) {
		t.Fatalf("credential profiles after caller mutation = %v, want %v", got, wantProfiles)
	}

	if got := authenticator.ProfileIDs(); !slices.Equal(got, wantProfiles) {
		t.Fatalf("authenticator profiles = %v, want %v", got, wantProfiles)
	}
}

// policyPreparationProfileIDs returns the exact sorted metadata fixture.
func policyPreparationProfileIDs() []string {
	return []string{"Client", policyPreparationInternalPrincipal, "client"}
}

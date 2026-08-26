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
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/secret"
)

const (
	policyTestBearerToken = "policy-bearer-token-secret"
	policyTestPassword    = "dedicated-policy-password"
	policyTestPrincipal   = "policy-client"
)

type policyBearerAuthenticationCase struct {
	name        string
	token       ValidatedAccessToken
	wantSuccess bool
}

type policyBasicAuthenticationCase struct {
	name          string
	credential    string
	protected     bool
	wantSuccess   bool
	wantBefore    int
	wantFailure   int
	wantSucceeded int
}

func TestPolicyBearerAuthenticationRequiresExactAudienceScopeAndClientID(t *testing.T) {
	t.Parallel()

	for _, test := range policyBearerAuthenticationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			authenticator := mustPolicyAuthenticator(t, Configuration{
				TokenValidator: policyStaticTokenValidator{token: test.token},
				ExternalProfiles: []ExternalProfile{{
					AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer},
					Principal:           policyTestPrincipal,
				}},
			})
			input := mustPolicyAuthenticationInput(t, policy.CallerAuthenticationKindBearer, policyTestBearerToken, "http", true, "")

			caller, err := authenticator.Authenticate(context.Background(), input)

			assertPolicyBearerAuthenticationResult(t, caller, err, test.wantSuccess)
		})
	}
}

// policyBearerAuthenticationCases covers exact resource, principal, token-type, and scope rejection.
func policyBearerAuthenticationCases() []policyBearerAuthenticationCase {
	policyAudience := []string{definitions.AudiencePolicyAPI}
	evaluateScope := []string{definitions.ScopePolicyEvaluate}
	missingClientID := policyValidatedToken("", policyAudience, evaluateScope)
	missingClientID.Subject = policyTestPrincipal
	missingClientID.Issuer = policyTestPrincipal
	idToken := policyValidatedToken(policyTestPrincipal, policyAudience, evaluateScope)
	idToken.TokenType = definitions.TokenTypeIDToken

	return []policyBearerAuthenticationCase{
		{name: "exact Policy resource and evaluate scope", token: policyValidatedToken(policyTestPrincipal, policyAudience, evaluateScope), wantSuccess: true},
		{name: "duplicate audience normalizes to exact set", token: policyValidatedToken(policyTestPrincipal, []string{definitions.AudiencePolicyAPI, definitions.AudiencePolicyAPI}, evaluateScope), wantSuccess: true},
		{name: "missing audience", token: policyValidatedToken(policyTestPrincipal, nil, evaluateScope)},
		{name: "backchannel audience", token: policyValidatedToken(policyTestPrincipal, []string{definitions.AudienceBackchannelAPI}, evaluateScope)},
		{name: "multiple resource audiences", token: policyValidatedToken(policyTestPrincipal, []string{definitions.AudiencePolicyAPI, definitions.AudienceBackchannelAPI}, evaluateScope)},
		{name: "missing client id never falls back", token: missingClientID},
		{name: "unregistered client id", token: policyValidatedToken("another-client", policyAudience, evaluateScope)},
		{name: "administrative scope never substitutes", token: policyValidatedToken(policyTestPrincipal, policyAudience, []string{definitions.ScopeAdmin})},
		{name: "diagnostics scope never substitutes for evaluate", token: policyValidatedToken(policyTestPrincipal, policyAudience, []string{definitions.ScopePolicyDiagnostics})},
		{name: "mixed backchannel scope is rejected", token: policyValidatedToken(policyTestPrincipal, policyAudience, []string{definitions.ScopePolicyEvaluate, definitions.ScopeAdmin})},
		{name: "id token is rejected", token: idToken},
	}
}

// assertPolicyBearerAuthenticationResult verifies success identity or fail-closed zero-caller semantics.
func assertPolicyBearerAuthenticationResult(
	t *testing.T,
	caller decision.CallerContext,
	err error,
	wantSuccess bool,
) {
	t.Helper()

	if !wantSuccess {
		assertPolicyAuthenticationRejected(t, caller, err)

		return
	}

	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if caller.Principal() != policyTestPrincipal || caller.ClientID() != policyTestPrincipal {
		t.Fatalf("caller principal/client_id = %q/%q", caller.Principal(), caller.ClientID())
	}

	if caller.AuthenticationKind() != policy.CallerAuthenticationKindBearer {
		t.Fatalf("authentication kind = %q", caller.AuthenticationKind())
	}
}

func TestPolicyBearerAuthenticationRetainsOnlyNormalizedPolicyScopes(t *testing.T) {
	t.Parallel()

	authenticator := mustPolicyAuthenticator(t, Configuration{
		TokenValidator: policyStaticTokenValidator{token: policyValidatedToken(
			policyTestPrincipal,
			[]string{definitions.AudiencePolicyAPI},
			[]string{definitions.ScopePolicyEvaluate, definitions.ScopePolicyDiagnostics, definitions.ScopePolicyEvaluate},
		)},
		ExternalProfiles: []ExternalProfile{{
			AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer},
			Principal:           policyTestPrincipal,
		}},
	})
	input := mustPolicyAuthenticationInput(t, policy.CallerAuthenticationKindBearer, policyTestBearerToken, "grpc", true, policyTestPrincipal)

	caller, err := authenticator.Authenticate(context.Background(), input)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	wantScopes := []string{definitions.ScopePolicyDiagnostics, definitions.ScopePolicyEvaluate}
	if !slices.Equal(caller.Scopes(), wantScopes) {
		t.Fatalf("caller scopes = %v, want %v", caller.Scopes(), wantScopes)
	}

	if caller.Subject() != "token-subject" || caller.Issuer() != "https://issuer.example.test" {
		t.Fatalf("token facts = %q/%q", caller.Subject(), caller.Issuer())
	}
}

func TestPolicyBasicAuthenticationRequiresProtectedDedicatedCredentials(t *testing.T) {
	t.Parallel()

	for _, test := range policyBasicAuthenticationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			throttler := &policyRecordingThrottler{}
			authenticator := policyBasicAuthenticator(t, throttler)
			input := mustPolicyAuthenticationInput(t, policy.CallerAuthenticationKindBasic, test.credential, "http", test.protected, "")

			caller, err := authenticator.Authenticate(context.Background(), input)

			assertPolicyBasicAuthenticationResult(t, caller, err, test.wantSuccess)
			assertPolicyThrottleCalls(t, throttler, test)
		})
	}
}

// policyBasicAuthenticationCases covers the transport gate and dedicated credential isolation.
func policyBasicAuthenticationCases() []policyBasicAuthenticationCase {
	return []policyBasicAuthenticationCase{
		{name: "unprotected correct credential is rejected before throttling", credential: "policy-user:" + policyTestPassword},
		{name: "unprotected malformed credential is rejected before parsing", credential: "not-a-basic-presentation"},
		{name: "protected dedicated credential", credential: "policy-user:" + policyTestPassword, protected: true, wantSuccess: true, wantBefore: 1, wantSucceeded: 1},
		{name: "wrong dedicated password", credential: "policy-user:wrong-password", protected: true, wantBefore: 1, wantFailure: 1},
		{name: "management credential is ineligible", credential: "management-admin:management-password", protected: true, wantBefore: 1, wantFailure: 1},
	}
}

// policyBasicAuthenticator builds one dedicated Policy-Basic test authority.
func policyBasicAuthenticator(t *testing.T, throttler BasicThrottler) *Authenticator {
	t.Helper()

	return mustPolicyAuthenticator(t, Configuration{
		Throttler:             throttler,
		TransportCapabilities: TransportCapabilities{HTTPProtected: true},
		ExternalProfiles: []ExternalProfile{{
			Basic:               &BasicCredential{Password: secret.New(policyTestPassword), Username: "policy-user"},
			AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic},
			Principal:           policyTestPrincipal,
		}},
	})
}

// assertPolicyBasicAuthenticationResult verifies the dedicated Basic caller mapping.
func assertPolicyBasicAuthenticationResult(t *testing.T, caller decision.CallerContext, err error, wantSuccess bool) {
	t.Helper()

	if !wantSuccess {
		assertPolicyAuthenticationRejected(t, caller, err)

		return
	}

	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if caller.Principal() != policyTestPrincipal || caller.AuthenticationKind() != policy.CallerAuthenticationKindBasic {
		t.Fatalf("Basic caller = %q/%q", caller.Principal(), caller.AuthenticationKind())
	}

	if len(caller.Scopes()) != 0 {
		t.Fatalf("Basic scopes = %v, want none", caller.Scopes())
	}
}

// assertPolicyThrottleCalls verifies the precheck and outcome callback ordering.
func assertPolicyThrottleCalls(t *testing.T, throttler *policyRecordingThrottler, test policyBasicAuthenticationCase) {
	t.Helper()

	if throttler.before != test.wantBefore || throttler.failure != test.wantFailure || throttler.success != test.wantSucceeded {
		t.Fatalf(
			"throttle calls = before:%d failure:%d success:%d, want %d/%d/%d",
			throttler.before,
			throttler.failure,
			throttler.success,
			test.wantBefore,
			test.wantFailure,
			test.wantSucceeded,
		)
	}
}

func TestPolicyBasicAuthenticationFailsClosedWhenThrottled(t *testing.T) {
	t.Parallel()

	throttler := &policyRecordingThrottler{beforeErr: errors.New("throttled")}
	authenticator := mustPolicyAuthenticator(t, Configuration{
		Throttler:             throttler,
		TransportCapabilities: TransportCapabilities{GRPCProtected: true},
		ExternalProfiles: []ExternalProfile{{
			Basic:               &BasicCredential{Username: "policy-user", Password: secret.New(policyTestPassword)},
			AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic},
			Principal:           policyTestPrincipal,
		}},
	})
	input := mustPolicyAuthenticationInput(t, policy.CallerAuthenticationKindBasic, "policy-user:"+policyTestPassword, "grpc", true, "")

	caller, err := authenticator.Authenticate(context.Background(), input)
	assertPolicyAuthenticationRejected(t, caller, err)

	if throttler.before != 1 || throttler.failure != 0 || throttler.success != 0 {
		t.Fatalf("throttle calls = before:%d failure:%d success:%d", throttler.before, throttler.failure, throttler.success)
	}
}

func TestPolicyBasicThrottleLimitDoesNotPoisonGeneration(t *testing.T) {
	t.Parallel()

	throttler := &policyRecordingThrottler{beforeErr: ErrBasicThrottleLimit}
	authenticator := policyBasicAuthenticator(t, throttler)
	input := mustPolicyAuthenticationInput(t, policy.CallerAuthenticationKindBasic, "policy-user:"+policyTestPassword, "http", true, "")

	caller, err := authenticator.Authenticate(context.Background(), input)
	assertPolicyAuthenticationRejected(t, caller, err)

	throttler.beforeErr = nil
	input = mustPolicyAuthenticationInput(t, policy.CallerAuthenticationKindBasic, "policy-user:"+policyTestPassword, "http", true, "")

	caller, err = authenticator.Authenticate(context.Background(), input)
	assertPolicyBasicAuthenticationResult(t, caller, err, true)

	if throttler.before != 2 || throttler.success != 1 {
		t.Fatalf("throttle calls after limit expiry = before:%d success:%d", throttler.before, throttler.success)
	}
}

func TestPolicyBasicThrottleKeyUsesNormalizedPeerIP(t *testing.T) {
	t.Parallel()

	throttler := &policyRecordingThrottler{}
	authenticator := policyBasicAuthenticator(t, throttler)

	for _, peer := range []string{"192.0.2.44:51001", "192.0.2.44:51002", "malformed-peer"} {
		input := mustPolicyBasicAuthenticationInputForPeer(t, "policy-user:wrong-password", peer)
		caller, err := authenticator.Authenticate(context.Background(), input)

		assertPolicyAuthenticationRejected(t, caller, err)
	}

	if len(throttler.keys) != 3 {
		t.Fatalf("throttle keys = %d, want 3", len(throttler.keys))
	}

	if throttler.keys[0].Peer() != "192.0.2.44" || throttler.keys[1].Peer() != "192.0.2.44" {
		t.Fatalf("normalized peers = %q/%q, want one IP", throttler.keys[0].Peer(), throttler.keys[1].Peer())
	}

	if throttler.keys[2].Peer() != "" {
		t.Fatalf("malformed peer throttle key = %q, want fail-safe empty bucket", throttler.keys[2].Peer())
	}
}

func TestPolicyBasicThrottleStateFailureClosesGeneration(t *testing.T) {
	t.Parallel()

	throttler := &policyRecordingThrottler{failureErr: errors.New("throttle state unavailable")}
	authenticator := policyBasicAuthenticator(t, throttler)

	wrong := mustPolicyAuthenticationInput(t, policy.CallerAuthenticationKindBasic, "policy-user:wrong-password", "http", true, "")
	caller, err := authenticator.Authenticate(context.Background(), wrong)
	assertPolicyAuthenticationRejected(t, caller, err)

	correct := mustPolicyAuthenticationInput(t, policy.CallerAuthenticationKindBasic, "policy-user:"+policyTestPassword, "http", true, "")
	caller, err = authenticator.Authenticate(context.Background(), correct)
	assertPolicyAuthenticationRejected(t, caller, err)

	if throttler.before != 1 || throttler.failure != 1 || throttler.success != 0 {
		t.Fatalf("throttle calls after state failure = before:%d failure:%d success:%d", throttler.before, throttler.failure, throttler.success)
	}
}

func TestPolicyCallerAuthenticationEnforcesMTLSAsCorroboratingEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		kind        string
		transport   string
		mtls        string
		protected   bool
		requireMTLS bool
		requireGRPC bool
		wantSuccess bool
	}{
		{name: "optional matching Bearer mTLS", kind: policy.CallerAuthenticationKindBearer, transport: "http", mtls: policyTestPrincipal, protected: true, wantSuccess: true},
		{name: "optional mismatched Bearer mTLS", kind: policy.CallerAuthenticationKindBearer, transport: "http", mtls: "another-client", protected: true},
		{name: "fabricated unprotected Bearer mTLS", kind: policy.CallerAuthenticationKindBearer, transport: "http", mtls: policyTestPrincipal},
		{name: "profile-required mTLS missing", kind: policy.CallerAuthenticationKindBearer, transport: "http", protected: true, requireMTLS: true},
		{name: "profile-required mTLS matches", kind: policy.CallerAuthenticationKindBearer, transport: "http", protected: true, requireMTLS: true, mtls: policyTestPrincipal, wantSuccess: true},
		{name: "global gRPC mTLS missing", kind: policy.CallerAuthenticationKindBearer, transport: "grpc", protected: true, requireGRPC: true},
		{name: "global gRPC mTLS matches", kind: policy.CallerAuthenticationKindBearer, transport: "grpc", protected: true, requireGRPC: true, mtls: policyTestPrincipal, wantSuccess: true},
		{name: "mTLS-only is not an authenticator", kind: "mtls", transport: "grpc", protected: true, mtls: policyTestPrincipal},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			authenticator := mustPolicyAuthenticator(t, Configuration{
				TokenValidator: policyStaticTokenValidator{token: policyValidatedToken(
					policyTestPrincipal,
					[]string{definitions.AudiencePolicyAPI},
					[]string{definitions.ScopePolicyEvaluate},
				)},
				TransportCapabilities: TransportCapabilities{
					GRPCProtected:                 test.requireGRPC || test.requireMTLS,
					GRPCVerifiedClientCertificate: test.requireGRPC || test.requireMTLS,
				},
				RequireGRPCMTLS: test.requireGRPC,
				ExternalProfiles: []ExternalProfile{{
					AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer},
					Principal:           policyTestPrincipal,
					RequireMTLS:         test.requireMTLS,
				}},
			})
			input := mustPolicyAuthenticationInput(t, test.kind, policyTestBearerToken, test.transport, test.protected, test.mtls)

			caller, err := authenticator.Authenticate(context.Background(), input)

			if test.wantSuccess {
				if err != nil {
					t.Fatalf("Authenticate() error = %v", err)
				}

				if caller.AuthenticationKind() != policy.CallerAuthenticationKindBearer || caller.MTLSIdentity() != test.mtls {
					t.Fatalf("caller kind/mTLS = %q/%q", caller.AuthenticationKind(), caller.MTLSIdentity())
				}

				return
			}

			assertPolicyAuthenticationRejected(t, caller, err)
		})
	}
}

func TestPolicyNamedInternalCallerAuthenticationIsExact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		kind        string
		capability  string
		transport   string
		protected   bool
		mtls        string
		wantSuccess bool
	}{
		{name: "exact named capability", kind: "nauthilus-authn", capability: "internal-capability", transport: "http", protected: true, mtls: "spiffe://example.test/authn", wantSuccess: true},
		{name: "wrong capability", kind: "nauthilus-authn", capability: "wrong-capability", transport: "http", protected: true, mtls: "spiffe://example.test/authn"},
		{name: "wrong evidence kind", kind: "another-internal", capability: "internal-capability", transport: "http", protected: true, mtls: "spiffe://example.test/authn"},
		{name: "wrong transport", kind: "nauthilus-authn", capability: "internal-capability", transport: "grpc", protected: true, mtls: "spiffe://example.test/authn"},
		{name: "unprotected", kind: "nauthilus-authn", capability: "internal-capability", transport: "http", mtls: "spiffe://example.test/authn"},
		{name: "mismatched mTLS", kind: "nauthilus-authn", capability: "internal-capability", transport: "http", protected: true, mtls: "spiffe://example.test/other"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			authenticator := mustPolicyAuthenticator(t, Configuration{InternalCallers: []InternalCaller{{
				Capability:           secret.New("internal-capability"),
				EvidenceKind:         "nauthilus-authn",
				ExpectedMTLSIdentity: "spiffe://example.test/authn",
				Principal:            "builtin-authn",
				TransportKinds:       []string{"http"},
				RequireProtected:     true,
			}}})
			input := mustPolicyAuthenticationInput(t, test.kind, test.capability, test.transport, test.protected, test.mtls)

			caller, err := authenticator.Authenticate(context.Background(), input)

			if test.wantSuccess {
				if err != nil {
					t.Fatalf("Authenticate() error = %v", err)
				}

				if caller.Principal() != "builtin-authn" || caller.AuthenticationKind() != policy.CallerAuthenticationKindInternal || !caller.Internal() {
					t.Fatalf("internal caller = %q/%q/%t", caller.Principal(), caller.AuthenticationKind(), caller.Internal())
				}

				return
			}

			assertPolicyAuthenticationRejected(t, caller, err)
		})
	}
}

func TestPolicyCallerAuthenticatorOwnsCredentialRules(t *testing.T) {
	t.Parallel()

	kinds := []string{policy.CallerAuthenticationKindBasic}
	transports := []string{"internal"}
	profiles := []ExternalProfile{{
		Basic:               &BasicCredential{Username: "policy-user", Password: secret.New(policyTestPassword)},
		AuthenticationKinds: kinds,
		Principal:           policyTestPrincipal,
	}}
	internal := []InternalCaller{{
		Capability:     secret.New("owned-capability"),
		EvidenceKind:   "owned-internal",
		Principal:      "owned-internal-principal",
		TransportKinds: transports,
	}}
	authenticator := mustPolicyAuthenticator(t, Configuration{
		Throttler:             &policyRecordingThrottler{},
		TransportCapabilities: TransportCapabilities{HTTPProtected: true},
		ExternalProfiles:      profiles,
		InternalCallers:       internal,
	})

	kinds[0] = policy.CallerAuthenticationKindBearer
	transports[0] = "grpc"
	profiles[0].Principal = "mutated-principal"
	profiles[0].Basic.Username = "mutated-user"
	internal[0].Principal = "mutated-internal"

	basicInput := mustPolicyAuthenticationInput(t, policy.CallerAuthenticationKindBasic, "policy-user:"+policyTestPassword, "http", true, "")

	basicCaller, err := authenticator.Authenticate(context.Background(), basicInput)

	if err != nil || basicCaller.Principal() != policyTestPrincipal {
		t.Fatalf("owned Basic rule = %q/%v", basicCaller.Principal(), err)
	}

	internalInput := mustPolicyAuthenticationInput(t, "owned-internal", "owned-capability", "internal", false, "")

	internalCaller, err := authenticator.Authenticate(context.Background(), internalInput)

	if err != nil || internalCaller.Principal() != "owned-internal-principal" {
		t.Fatalf("owned internal rule = %q/%v", internalCaller.Principal(), err)
	}

	ids := authenticator.ProfileIDs()
	ids[0] = "mutated-return"

	if slices.Contains(authenticator.ProfileIDs(), "mutated-return") {
		t.Fatal("ProfileIDs() returned mutable generation state")
	}
}

func TestPolicyCallerAuthRejectsBasicWithoutProtectedTransportCapability(t *testing.T) {
	t.Parallel()

	_, err := New(Configuration{Throttler: &policyRecordingThrottler{}, ExternalProfiles: []ExternalProfile{{
		Basic:               &BasicCredential{Username: "policy-user", Password: secret.New(policyTestPassword)},
		AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic},
		Principal:           policyTestPrincipal,
	}}})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("New() error = %v, want ErrConfiguration", err)
	}

	if strings.Contains(err.Error(), policyTestPassword) {
		t.Fatal("configuration error exposed Policy-Basic secret")
	}
}

func TestPolicyCallerAuthRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	var (
		typedNilTokenValidator *policyNilTokenValidator
		typedNilThrottler      *policyNilThrottler
	)

	tests := []struct {
		name          string
		configuration Configuration
	}{
		{name: "Bearer profile without validator", configuration: Configuration{ExternalProfiles: []ExternalProfile{{Principal: policyTestPrincipal, AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer}}}}},
		{name: "Basic kind without material", configuration: Configuration{Throttler: &policyRecordingThrottler{}, TransportCapabilities: TransportCapabilities{HTTPProtected: true}, ExternalProfiles: []ExternalProfile{{Principal: policyTestPrincipal, AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic}}}}},
		{name: "Basic material without kind", configuration: Configuration{Throttler: &policyRecordingThrottler{}, TransportCapabilities: TransportCapabilities{HTTPProtected: true}, ExternalProfiles: []ExternalProfile{{Principal: policyTestPrincipal, Basic: &BasicCredential{Username: "policy-user", Password: secret.New(policyTestPassword)}, AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer}}}, TokenValidator: policyStaticTokenValidator{}}},
		{name: "duplicate principals", configuration: Configuration{TokenValidator: policyStaticTokenValidator{}, ExternalProfiles: []ExternalProfile{{Principal: policyTestPrincipal, AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer}}, {Principal: policyTestPrincipal, AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer}}}}},
		{name: "duplicate Basic usernames", configuration: Configuration{Throttler: &policyRecordingThrottler{}, TransportCapabilities: TransportCapabilities{HTTPProtected: true}, ExternalProfiles: []ExternalProfile{{Principal: "first", Basic: &BasicCredential{Username: "shared", Password: secret.New("first")}, AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic}}, {Principal: "second", Basic: &BasicCredential{Username: "shared", Password: secret.New("second")}, AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic}}}}},
		{name: "global gRPC mTLS without capable transport", configuration: Configuration{RequireGRPCMTLS: true}},
		{name: "verified client certificate without protected gRPC", configuration: Configuration{TransportCapabilities: TransportCapabilities{GRPCVerifiedClientCertificate: true}}},
		{name: "internal caller without transport", configuration: Configuration{InternalCallers: []InternalCaller{{Principal: "internal", EvidenceKind: "internal-kind", Capability: secret.New("capability")}}}},
		{name: "internal caller reuses external evidence kind", configuration: Configuration{InternalCallers: []InternalCaller{{Principal: "internal", EvidenceKind: policy.CallerAuthenticationKindBasic, Capability: secret.New("capability"), TransportKinds: []string{"internal"}}}}},
		{name: "typed nil token validator", configuration: Configuration{TokenValidator: typedNilTokenValidator, ExternalProfiles: []ExternalProfile{{Principal: policyTestPrincipal, AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer}}}}},
		{name: "typed nil Basic throttler", configuration: Configuration{Throttler: typedNilThrottler, TransportCapabilities: TransportCapabilities{HTTPProtected: true}, ExternalProfiles: []ExternalProfile{{Principal: policyTestPrincipal, Basic: &BasicCredential{Username: "policy-user", Password: secret.New(policyTestPassword)}, AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic}}}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := New(test.configuration)
			if !errors.Is(err, ErrConfiguration) {
				t.Fatalf("New() error = %v, want ErrConfiguration", err)
			}
		})
	}
}

func TestPolicyCallerAuthenticationCopiesTrustedTransportFacts(t *testing.T) {
	t.Parallel()

	authenticator := mustPolicyAuthenticator(t, Configuration{InternalCallers: []InternalCaller{{
		Capability:     secret.New("transport-capability"),
		EvidenceKind:   "transport-internal",
		Principal:      "transport-caller",
		TransportKinds: []string{"grpc"},
	}}})

	input, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          "transport-internal",
		Credential:    []byte("transport-capability"),
		TransportKind: "grpc",
		Listener:      "grpc.policy",
		GRPCMethod:    "/nauthilus.policy.v1.Policy/Evaluate",
		Peer:          "192.0.2.44:43123",
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	caller, err := authenticator.Authenticate(context.Background(), input)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if caller.TransportKind() != "grpc" || caller.Listener() != "grpc.policy" || caller.GRPCMethod() != "/nauthilus.policy.v1.Policy/Evaluate" {
		t.Fatalf("transport facts = %q/%q/%q", caller.TransportKind(), caller.Listener(), caller.GRPCMethod())
	}

	if caller.SourceIP() != netip.MustParseAddr("192.0.2.44") {
		t.Fatalf("source IP = %s", caller.SourceIP())
	}
}

func TestPolicyCallerAuthenticationErrorsAreSecretSafe(t *testing.T) {
	t.Parallel()

	const validatorSecret = "validator-leaked-token-secret"

	authenticator := mustPolicyAuthenticator(t, Configuration{
		TokenValidator: policyStaticTokenValidator{err: errors.New(validatorSecret)},
		ExternalProfiles: []ExternalProfile{{
			AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer},
			Principal:           policyTestPrincipal,
		}},
	})
	input := mustPolicyAuthenticationInput(t, policy.CallerAuthenticationKindBearer, policyTestBearerToken, "http", true, "")

	caller, err := authenticator.Authenticate(context.Background(), input)
	assertPolicyAuthenticationRejected(t, caller, err)

	for _, forbidden := range []string{policyTestBearerToken, validatorSecret, policyTestPassword} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("authentication error exposed %q", forbidden)
		}
	}
}

type policyStaticTokenValidator struct {
	token ValidatedAccessToken
	err   error
}

// ValidateAccessToken returns one detached issuer-validation test result.
func (v policyStaticTokenValidator) ValidateAccessToken(context.Context, []byte) (ValidatedAccessToken, error) {
	return v.token, v.err
}

type policyRecordingThrottler struct {
	keys       []BasicThrottleKey
	beforeErr  error
	failureErr error
	failure    int
	success    int
	before     int
}

// BeforeAttempt records the Policy-Basic pre-verification throttle gate.
func (t *policyRecordingThrottler) BeforeAttempt(_ context.Context, key BasicThrottleKey) error {
	t.before++
	t.keys = append(t.keys, key)

	return t.beforeErr
}

// RecordFailure records one failed Policy-Basic verification.
func (t *policyRecordingThrottler) RecordFailure(context.Context, BasicThrottleKey) error {
	t.failure++

	return t.failureErr
}

// RecordSuccess records one successful Policy-Basic verification.
func (t *policyRecordingThrottler) RecordSuccess(context.Context, BasicThrottleKey) error {
	t.success++

	return nil
}

type policyNilTokenValidator struct{}

// ValidateAccessToken must never run through a typed-nil generation dependency.
func (*policyNilTokenValidator) ValidateAccessToken(context.Context, []byte) (ValidatedAccessToken, error) {
	panic("typed-nil token validator invoked")
}

type policyNilThrottler struct{}

// BeforeAttempt must never run through a typed-nil generation dependency.
func (*policyNilThrottler) BeforeAttempt(context.Context, BasicThrottleKey) error {
	panic("typed-nil Basic throttler invoked")
}

// RecordFailure must never run through a typed-nil generation dependency.
func (*policyNilThrottler) RecordFailure(context.Context, BasicThrottleKey) error {
	panic("typed-nil Basic throttler invoked")
}

// RecordSuccess must never run through a typed-nil generation dependency.
func (*policyNilThrottler) RecordSuccess(context.Context, BasicThrottleKey) error {
	panic("typed-nil Basic throttler invoked")
}

// policyValidatedToken builds one structured issuer-validated token result.
func policyValidatedToken(clientID string, audiences []string, scopes []string) ValidatedAccessToken {
	return ValidatedAccessToken{
		Audiences: audiences,
		Scopes:    scopes,
		ClientID:  clientID,
		Issuer:    "https://issuer.example.test",
		Subject:   "token-subject",
		TokenType: definitions.TokenTypeAccessToken,
	}
}

// mustPolicyAuthenticator constructs one valid generation-owned authenticator.
func mustPolicyAuthenticator(t *testing.T, configuration Configuration) *Authenticator {
	t.Helper()

	authenticator, err := New(configuration)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return authenticator
}

// mustPolicyAuthenticationInput constructs one bounded opaque presentation.
func mustPolicyAuthenticationInput(
	t *testing.T,
	kind string,
	credential string,
	transport string,
	protected bool,
	mtlsIdentity string,
) decision.AuthenticationInput {
	t.Helper()

	input, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          kind,
		Credential:    []byte(credential),
		TransportKind: transport,
		Peer:          "192.0.2.10",
		MTLSIdentity:  mtlsIdentity,
		Protected:     protected,
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	return input
}

// mustPolicyBasicAuthenticationInputForPeer constructs a protected Basic presentation with exact peer evidence.
func mustPolicyBasicAuthenticationInputForPeer(t *testing.T, credential string, peer string) decision.AuthenticationInput {
	t.Helper()

	input, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          policy.CallerAuthenticationKindBasic,
		Credential:    []byte(credential),
		TransportKind: "http",
		Peer:          peer,
		Protected:     true,
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	return input
}

// assertPolicyAuthenticationRejected verifies fail-closed zero caller semantics.
func assertPolicyAuthenticationRejected(t *testing.T, caller decision.CallerContext, err error) {
	t.Helper()

	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Authenticate() error = %v, want ErrAuthentication", err)
	}

	if caller.Principal() != "" || caller.AuthenticationKind() != "" || caller.Internal() {
		t.Fatalf("rejected caller = %q/%q/%t, want zero", caller.Principal(), caller.AuthenticationKind(), caller.Internal())
	}
}

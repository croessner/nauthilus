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
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/admission"
	"github.com/croessner/nauthilus/v4/server/policy/callerauth"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

const (
	policyCallerFactsCredential = "policy-bearer-credential-must-not-appear"
	policyCallerFactsPassword   = "policy-basic-password-must-not-appear"
	policyCallerFactsPrincipal  = "facts-policy-client"
)

type policyCallerTransportFixture struct {
	name          string
	transport     string
	listener      string
	httpRoute     string
	grpcMethod    string
	absentFact    string
	transportFact string
}

func TestPolicyCallerAuthenticationBuildsTrustedBearerMTLSFacts(t *testing.T) {
	t.Parallel()

	authenticator := mustPolicyCallerFactsAuthenticator(t, nil)
	for _, fixture := range policyCallerTransportFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			assertPolicyCallerTransportFacts(t, authenticator, fixture)
		})
	}
}

func TestPolicyCallerAuthenticationRejectionBuildsNoTrustedCallerOrFacts(t *testing.T) {
	t.Parallel()

	authenticator := mustPolicyCallerFactsAuthenticator(t, errors.New("issuer validation rejected token"))
	input := mustPolicyCallerFactsAuthenticationInput(t, decision.AuthenticationEvidence{
		Kind:          policy.CallerAuthenticationKindBearer,
		Credential:    []byte(policyCallerFactsCredential),
		TransportKind: "http",
		Listener:      "policy-http",
		HTTPRoute:     "/api/v1/policy/evaluate",
		Peer:          "192.0.2.81:9443",
		Protected:     true,
	})

	caller, authenticateErr := authenticator.Authenticate(context.Background(), input)
	if !errors.Is(authenticateErr, callerauth.ErrAuthentication) {
		t.Fatalf("Authenticate() error = %v, want ErrAuthentication", authenticateErr)
	}

	assertEmptyPolicyCaller(t, caller)
	assertPolicyCallerServiceRejectsBeforeFacts(t, authenticator, input)
}

// policyCallerTransportFixtures declares protected HTTP and gRPC fact-projection cases.
func policyCallerTransportFixtures() []policyCallerTransportFixture {
	return []policyCallerTransportFixture{
		{
			name:          "trusted proxy HTTP route",
			transport:     "http",
			listener:      "policy-http",
			httpRoute:     "/api/v1/policy/evaluate",
			absentFact:    decision.FactTransportGRPCMethod,
			transportFact: decision.FactTransportHTTPRoute,
		},
		{
			name:          "gRPC TLS method",
			transport:     "grpc",
			listener:      "policy-grpc",
			grpcMethod:    "/nauthilus.policy.v1.Policy/Evaluate",
			absentFact:    decision.FactTransportHTTPRoute,
			transportFact: decision.FactTransportGRPCMethod,
		},
	}
}

// mustPolicyCallerFactsAuthenticator constructs one generation-owned Bearer rule.
func mustPolicyCallerFactsAuthenticator(t *testing.T, validationErr error) *callerauth.Authenticator {
	t.Helper()

	validator := policyCallerFactsTokenValidator{
		token: callerauth.ValidatedAccessToken{
			Audiences: []string{definitions.AudiencePolicyAPI},
			Scopes:    []string{definitions.ScopePolicyEvaluate, definitions.ScopePolicyDiagnostics},
			ClientID:  policyCallerFactsPrincipal,
			Subject:   "policy-token-subject",
			Issuer:    "https://issuer.policy.test",
			TokenType: definitions.TokenTypeAccessToken,
		},
		err: validationErr,
	}

	authenticator, err := callerauth.New(callerauth.Configuration{
		TokenValidator: validator,
		ExternalProfiles: []callerauth.ExternalProfile{{
			AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer},
			Principal:           policyCallerFactsPrincipal,
			RequireMTLS:         validationErr == nil,
		}},
		TransportCapabilities: callerauth.TransportCapabilities{
			HTTPProtected:                 true,
			GRPCProtected:                 true,
			GRPCVerifiedClientCertificate: true,
		},
	})
	if err != nil {
		t.Fatalf("callerauth.New() error = %v", err)
	}

	return authenticator
}

// assertPolicyCallerTransportFacts authenticates and verifies one declared transport projection.
func assertPolicyCallerTransportFacts(
	t *testing.T,
	authenticator *callerauth.Authenticator,
	fixture policyCallerTransportFixture,
) {
	t.Helper()

	input := mustPolicyCallerFactsAuthenticationInput(t, decision.AuthenticationEvidence{
		Kind: policy.CallerAuthenticationKindBearer, Credential: []byte(policyCallerFactsCredential),
		TransportKind: fixture.transport, Listener: fixture.listener,
		HTTPRoute: fixture.httpRoute, GRPCMethod: fixture.grpcMethod,
		Peer: "192.0.2.80:9443", MTLSIdentity: policyCallerFactsPrincipal, Protected: true,
	})

	caller, err := authenticator.Authenticate(context.Background(), input)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	admitted := policyCallerFactsFromCaller(t, caller)

	want := policyCallerFactExpectations(fixture)
	if admitted.Len() != len(want) {
		t.Fatalf("trusted fact count = %d, want %d", admitted.Len(), len(want))
	}

	for id, expectation := range want {
		assertPolicyCallerFact(t, admitted, id, expectation)
	}

	if _, exists := admitted.Get(fixture.absentFact); exists {
		t.Fatalf("unset transport fact %q was projected", fixture.absentFact)
	}

	assertPolicyCallerFactsSecretSafe(t, admitted)
}

// policyCallerFactExpectations returns exact caller, token, and transport authority values.
func policyCallerFactExpectations(fixture policyCallerTransportFixture) map[string]policyCallerFactExpectation {
	nauthilus := decision.FactSourceNauthilus
	token := decision.FactSourceToken
	transport := decision.FactSourceTransport
	want := map[string]policyCallerFactExpectation{
		decision.FactCallerPrincipal:          {value: policyCallerFactsPrincipal, source: nauthilus},
		decision.FactCallerClientID:           {value: policyCallerFactsPrincipal, source: nauthilus},
		decision.FactCallerAuthenticationKind: {value: policy.CallerAuthenticationKindBearer, source: nauthilus},
		decision.FactCallerScopes: {
			value: []string{definitions.ScopePolicyDiagnostics, definitions.ScopePolicyEvaluate}, source: nauthilus,
		},
		decision.FactTokenSubject:          {value: "policy-token-subject", source: token},
		decision.FactTokenIssuer:           {value: "https://issuer.policy.test", source: token},
		decision.FactTransportKind:         {value: fixture.transport, source: transport},
		decision.FactTransportListener:     {value: fixture.listener, source: transport},
		decision.FactTransportMTLSIdentity: {value: policyCallerFactsPrincipal, source: transport},
		decision.FactTransportSourceIP:     {value: "192.0.2.80", source: transport},
	}
	want[fixture.transportFact] = policyCallerFactExpectation{
		value: fixture.httpRoute + fixture.grpcMethod, source: transport,
	}

	return want
}

// assertPolicyCallerServiceRejectsBeforeFacts verifies the application stop boundary.
func assertPolicyCallerServiceRejectsBeforeFacts(
	t *testing.T,
	authenticator *callerauth.Authenticator,
	input decision.AuthenticationInput,
) {
	t.Helper()

	admission := &recordingAdmissionAuthority{}
	factConstruction := &recordingCheckpointEvaluator{}
	generation := mustRuntimeGeneration(t, 15, authenticator, admission, factConstruction)
	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	target, targetErr := decision.NewTarget("mail", "submit")
	if targetErr != nil {
		t.Fatalf("NewTarget() error = %v", targetErr)
	}

	_, evaluationErr := service.Evaluate(context.Background(), decision.Invocation{
		Request: decision.DecisionRequestInput{
			Version:   decision.ContractVersion,
			RequestID: "policy-auth-rejected",
			Target:    target,
		},
		Authentication: input,
	})
	if !errors.Is(evaluationErr, ErrDecisionAuthentication) {
		t.Fatalf("DecisionService.Evaluate() error = %v, want ErrDecisionAuthentication", evaluationErr)
	}

	if admission.callCount() != 0 || factConstruction.callCount() != 0 {
		t.Fatalf(
			"admission/fact-construction calls = %d/%d, want 0/0",
			admission.callCount(),
			factConstruction.callCount(),
		)
	}

	if strings.Contains(evaluationErr.Error(), policyCallerFactsCredential) {
		t.Fatal("Decision Service rejection exposed the opaque bearer credential")
	}
}

type policyCallerFactsTokenValidator struct {
	token callerauth.ValidatedAccessToken
	err   error
}

// ValidateAccessToken returns one issuer-validation result without interpreting transport evidence.
func (v policyCallerFactsTokenValidator) ValidateAccessToken(context.Context, []byte) (callerauth.ValidatedAccessToken, error) {
	return v.token, v.err
}

type policyCallerFactExpectation struct {
	value  any
	source decision.FactSource
}

// mustPolicyCallerFactsAuthenticationInput constructs one host-observed opaque presentation.
func mustPolicyCallerFactsAuthenticationInput(t *testing.T, evidence decision.AuthenticationEvidence) decision.AuthenticationInput {
	t.Helper()

	input, err := decision.NewAuthenticationInput(evidence)
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	return input
}

// policyCallerFactsFromCaller projects only authenticator and transport authority through the admitted-fact builder.
func policyCallerFactsFromCaller(t *testing.T, caller decision.CallerContext) decision.FactSet {
	t.Helper()

	declarations := []registry.FactSchema{
		decisionRuntimeFactSchema(t, decision.FactCallerPrincipal, decision.FactSourceNauthilus, false),
		decisionRuntimeFactSchema(t, decision.FactCallerClientID, decision.FactSourceNauthilus, false),
		decisionRuntimeFactSchema(t, decision.FactCallerAuthenticationKind, decision.FactSourceNauthilus, false),
		decisionRuntimeStringListFactSchema(t, decision.FactCallerScopes, decision.FactSourceNauthilus),
		decisionRuntimeFactSchema(t, decision.FactTokenSubject, decision.FactSourceToken, false),
		decisionRuntimeFactSchema(t, decision.FactTokenIssuer, decision.FactSourceToken, false),
		decisionRuntimeFactSchema(t, decision.FactTransportKind, decision.FactSourceTransport, false),
		decisionRuntimeFactSchema(t, decision.FactTransportListener, decision.FactSourceTransport, false),
		decisionRuntimeFactSchema(t, decision.FactTransportHTTPRoute, decision.FactSourceTransport, false),
		decisionRuntimeFactSchema(t, decision.FactTransportGRPCMethod, decision.FactSourceTransport, false),
		decisionRuntimeFactSchema(t, decision.FactTransportMTLSIdentity, decision.FactSourceTransport, false),
		decisionRuntimeFactSchema(t, decision.FactTransportSourceIP, decision.FactSourceTransport, false),
	}
	catalog, target := decisionRuntimeCatalog(t, decision.EffectPermit, registry.NoMatchDeny, declarations, nil, nil)

	compiled, exists := catalog.Lookup(target)
	if !exists {
		t.Fatal("compiled target missing")
	}

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version:   decision.ContractVersion,
		RequestID: "policy-trusted-caller-facts",
		Target:    target,
	}, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	reference, err := registry.NewClientAdmissionReference(
		"test.policy-caller-facts",
		target.Namespace(),
		target.Action(),
		compiled.Schema().Identity().String(),
	)
	if err != nil {
		t.Fatalf("NewClientAdmissionReference() error = %v", err)
	}

	credentials, err := policyruntime.NewCredentialProfiles([]string{policyCallerFactsPrincipal})
	if err != nil {
		t.Fatalf("NewCredentialProfiles() error = %v", err)
	}

	prepared, err := admission.Prepare(admission.Configuration{
		GlobalLimits: admission.Limits{
			MaxRequestBytes:   4096,
			MaxFacts:          16,
			MaxConcurrency:    1,
			RequestsPerSecond: 1000,
		},
		Profiles: []admission.Profile{{
			Principal:           policyCallerFactsPrincipal,
			AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer},
			References:          []registry.ClientAdmissionReference{reference},
		}},
	}, catalog, credentials)
	if err != nil {
		t.Fatalf("admission.Prepare() error = %v", err)
	}

	permit, err := prepared.Authority.Admit(context.Background(), caller, request)
	if err != nil {
		t.Fatalf("AdmissionAuthority.Admit() error = %v", err)
	}
	defer permit.Release()

	return permit.Facts()
}

// assertPolicyCallerFact verifies exact value and host-assigned authentication provenance.
func assertPolicyCallerFact(
	t *testing.T,
	facts decision.FactSet,
	id string,
	expectation policyCallerFactExpectation,
) {
	t.Helper()

	fact, exists := facts.Get(id)
	if !exists {
		t.Fatalf("trusted fact %q missing", id)
	}

	value, valid := fact.Value().Any()
	if !valid || !reflect.DeepEqual(value, expectation.value) {
		t.Fatalf("trusted fact %q value = %#v, want %#v", id, value, expectation.value)
	}

	provenance := fact.Provenance()
	if provenance.Source() != expectation.source ||
		provenance.Authority() != policyCallerFactsPrincipal ||
		provenance.Component() != "authenticator" {
		t.Fatalf(
			"trusted fact %q provenance = %q/%q/%q",
			id,
			provenance.Source(),
			provenance.Authority(),
			provenance.Component(),
		)
	}
}

// assertPolicyCallerFactsSecretSafe proves no opaque credential material reaches trusted facts.
func assertPolicyCallerFactsSecretSafe(t *testing.T, facts decision.FactSet) {
	t.Helper()

	for _, fact := range facts.Facts() {
		value, _ := fact.Value().Any()
		serialized := fmt.Sprint(value)

		for _, secret := range []string{policyCallerFactsCredential, policyCallerFactsPassword} {
			if strings.Contains(serialized, secret) {
				t.Fatalf("trusted fact %q exposed credential material", fact.ID())
			}
		}
	}
}

// assertEmptyPolicyCaller proves rejected evidence produced no trusted identity or transport authority.
func assertEmptyPolicyCaller(t *testing.T, caller decision.CallerContext) {
	t.Helper()

	text := []string{
		caller.Principal(), caller.ClientID(), caller.Subject(), caller.Issuer(),
		caller.AuthenticationKind(), caller.MTLSIdentity(), caller.TransportKind(),
		caller.Listener(), caller.HTTPRoute(), caller.GRPCMethod(),
	}
	for _, value := range text {
		if value != "" {
			t.Fatal("rejected authentication produced non-empty trusted caller text")
		}
	}

	if len(caller.Scopes()) != 0 || caller.SourceIP().IsValid() || caller.Internal() {
		t.Fatal("rejected authentication produced non-empty trusted caller state")
	}
}

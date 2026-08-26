// Copyright (C) 2026 Christian Roessner
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
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	identityv1 "github.com/croessner/nauthilus/v3/api/identity/v1"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	authorityMFATestRecoveryCodeA = "consume-once"
	authorityMFATestRecoveryCodeB = "keep-code"
	authorityMFATestSecretField   = "test_totp_secret"
	authorityMFATestRecoveryField = "test_totp_recovery"
	authorityMFATestTOTPSecret    = "JBSWY3DPEHPK3PXP"
	authorityAttributeMail        = "mail"
	authorityAttributeEmployee    = "employeeNumber"
	authorityAttributeMissing     = "missingAttribute"
	authorityAttributePrivateKey  = "sshPrivateKey"
	authorityAttributeRaw         = "unrequestedRawAttribute"
	authorityAttributeSecret      = "oidcClientSecretFromBackend"
	authorityAttributeBearer      = "upstreamBearerTokenAttribute"
	authoritySnapshotMail         = "snapshot@example.test"
	authorityEmployeeNumber       = "1234"
	authorityTOTPIssuer           = "AuthorityIssuer"
)

var errAuthorityMFAAdmissionStopped = errors.New("stop after recording MFA admission")

type recordingAuthorityMFAApplicationService struct {
	lookupOutcome *core.AuthOutcome
	lookupErr     error
	lookupInput   core.AuthInput
	mu            sync.Mutex
	lookupCalls   int
}

func (s *recordingAuthorityMFAApplicationService) Authenticate(
	context.Context,
	core.AuthInput,
) (*core.AuthOutcome, error) {
	return nil, errors.New("unexpected authenticate call")
}

func (s *recordingAuthorityMFAApplicationService) LookupIdentity(
	_ context.Context,
	input core.AuthInput,
) (*core.AuthOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lookupCalls++
	s.lookupInput = input

	return s.lookupOutcome, s.lookupErr
}

// lookupSnapshot returns the detached recorded invocation count and input.
func (s *recordingAuthorityMFAApplicationService) lookupSnapshot() (int, core.AuthInput) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.lookupCalls, s.lookupInput
}

func (s *recordingAuthorityMFAApplicationService) ListAccounts(
	context.Context,
	core.AuthInput,
) (*core.ListAccountsOutcome, error) {
	return nil, errors.New("unexpected list accounts call")
}

type authorityMFAAdmissionCase struct {
	invoke     func(AuthorityIdentityService, context.Context, AuthorityIdentityInput) error
	name       string
	operation  AuthorityOperation
	fullMethod string
}

func TestBackendManagerIdentityServiceAdmitsEveryCapabilityOperationThroughSharedApplication(t *testing.T) {
	for _, test := range authorityMFAAdmissionCases() {
		t.Run(test.name, func(t *testing.T) {
			recorder := &recordingAuthorityMFAApplicationService{lookupErr: errAuthorityMFAAdmissionStopped}
			deps := authorityMFATestAuthDeps()
			service := NewBackendManagerIdentityService(BackendManagerIdentityServiceDeps{
				AuthService: recorder,
				AuthDeps:    deps,
			})
			input := authorityMFATestInput("admitted-backend", "admitted-user@example.test")
			input.Operation = test.operation
			input.Context = &identityv1.RequestContext{
				Protocol:      definitions.ProtoOIDC,
				OidcCid:       "authority-oidc-client",
				SamlEntityId:  "https://sp.example.test/metadata",
				EdgeRequestId: "edge-request-42",
			}
			input.Attributes = &identityv1.AttributeRequest{
				Names: []string{"mail"}, IncludeStandardIdentity: true,
				IncludeGroups: true, IncludeGroupDns: true, ReportMissing: true,
			}
			input.Code = "123456"
			input.PendingRegistrationID = "pending-registration"
			input.Credential = authorityWebAuthnCredential("credential-a", "Security key", 1)
			input.OldCredential = authorityWebAuthnCredential("credential-a", "Security key", 1)
			input.NewCredential = authorityWebAuthnCredential("credential-a", "Security key", 2)
			input.CredentialID = []byte("credential-a")

			err := test.invoke(service, context.Background(), input)
			if !errors.Is(err, errAuthorityMFAAdmissionStopped) {
				t.Fatalf("operation error = %v, want admission sentinel", err)
			}

			lookupCalls, lookupInput := recorder.lookupSnapshot()
			if lookupCalls != 1 {
				t.Fatalf("LookupIdentity calls = %d, want 1", lookupCalls)
			}

			assertAuthorityMFAApplicationInput(t, lookupInput, input, test.fullMethod)
		})
	}
}

func TestBackendManagerIdentityServiceUsesBackchannelProfileForUnboundResolveUser(t *testing.T) {
	recorder := &recordingAuthorityMFAApplicationService{lookupErr: errAuthorityMFAAdmissionStopped}
	service := NewBackendManagerIdentityService(BackendManagerIdentityServiceDeps{
		AuthService: recorder,
		AuthDeps:    authorityMFATestAuthDeps(),
	})
	input := AuthorityIdentityInput{
		Username: "unbound-user@example.test",
		Context: &identityv1.RequestContext{
			Protocol: definitions.ProtoOIDC,
			OidcCid:  "unbound-client",
		},
	}

	if _, err := service.ResolveUser(context.Background(), input); !errors.Is(err, errAuthorityMFAAdmissionStopped) {
		t.Fatalf("ResolveUser() error = %v, want admission sentinel", err)
	}

	lookupCalls, lookupInput := recorder.lookupSnapshot()
	if lookupCalls != 1 || lookupInput.EntryPoint != core.AuthnEntryBackchannel {
		t.Fatalf("unbound ResolveUser admission = calls:%d entry:%v, want one backchannel lookup", lookupCalls, lookupInput.EntryPoint)
	}

	if lookupInput.Context.Transport.GRPCMethod != identityv1.IdentityBackendService_ResolveUser_FullMethodName {
		t.Fatalf("unbound ResolveUser method = %q", lookupInput.Context.Transport.GRPCMethod)
	}
}

func TestBackendManagerIdentityServiceRejectsMissingApplicationBeforePendingMutation(t *testing.T) {
	service := NewBackendManagerIdentityService(BackendManagerIdentityServiceDeps{AuthDeps: authorityMFATestAuthDeps()})
	input := authorityMFATestInput("missing-app-backend", "missing-app@example.test")
	input.Operation = AuthorityOperationBeginTOTPRegistration

	if _, err := service.BeginTOTPRegistration(context.Background(), input); status.Code(err) != codes.Internal {
		t.Fatalf("BeginTOTPRegistration() error = %v, want Internal", err)
	}

	concrete := service.(*backendManagerIdentityService)
	concrete.totpPending.mu.Lock()
	pendingCount := len(concrete.totpPending.entries)
	concrete.totpPending.mu.Unlock()

	if pendingCount != 0 {
		t.Fatalf("pending TOTP registrations = %d, want 0 after missing application rejection", pendingCount)
	}
}

func TestBackendManagerIdentityServiceRejectsMissingOutcomeBeforeCredentialMutation(t *testing.T) {
	backendName := "missing-outcome-backend"
	username := "missing-outcome@example.test"
	input := authorityMFATestInput(backendName, username)
	input.Credential = authorityWebAuthnCredential("credential-a", "Security key", 1)

	deps := authorityMFATestAuthDeps()
	service := NewBackendManagerIdentityService(BackendManagerIdentityServiceDeps{
		AuthService: &recordingAuthorityMFAApplicationService{},
		AuthDeps:    deps,
	})

	if _, err := service.SaveWebAuthnCredential(context.Background(), input); status.Code(err) != codes.Internal {
		t.Fatalf("SaveWebAuthnCredential() error = %v, want Internal", err)
	}

	if credentials := readAuthorityWebAuthnCredentials(t, deps, backendName, username); len(credentials) != 0 {
		t.Fatalf("credentials after missing-outcome rejection = %#v, want none", credentials)
	}
}

func TestBackendManagerIdentityServiceRejectsBackendAffinityMismatchBeforeCredentialMutation(t *testing.T) {
	for _, test := range authorityBackendAffinityMismatchCases() {
		t.Run(test.name, func(t *testing.T) {
			backendName := "affinity-mismatch-" + test.name
			username := "affinity-mismatch@example.test"
			input := authorityMFATestInput(backendName, username)
			input.Credential = authorityWebAuthnCredential("credential-a", "Security key", 1)
			outcome := authorityMFATestOutcome(input)
			test.mutate(&input, outcome)

			deps := authorityMFATestAuthDeps()
			service := NewBackendManagerIdentityService(BackendManagerIdentityServiceDeps{
				AuthService: &recordingAuthorityMFAApplicationService{lookupOutcome: outcome},
				AuthDeps:    deps,
			})

			if _, err := service.SaveWebAuthnCredential(context.Background(), input); !errors.Is(err, ErrAuthorityBackendAffinityMismatch) {
				t.Fatalf("SaveWebAuthnCredential() error = %v, want ErrAuthorityBackendAffinityMismatch", err)
			}

			if credentials := readAuthorityWebAuthnCredentials(t, deps, backendName, username); len(credentials) != 0 {
				t.Fatalf("credentials after affinity rejection = %#v, want none", credentials)
			}
		})
	}
}

type authorityBackendAffinityMismatchCase struct {
	mutate func(*AuthorityIdentityInput, *core.AuthOutcome)
	name   string
}

// authorityBackendAffinityMismatchCases changes each manager-selection and identity binding independently.
func authorityBackendAffinityMismatchCases() []authorityBackendAffinityMismatchCase {
	return []authorityBackendAffinityMismatchCase{
		{name: "backend type", mutate: func(_ *AuthorityIdentityInput, outcome *core.AuthOutcome) {
			outcome.Backend = definitions.BackendLDAP
		}},
		{name: "backend name", mutate: func(_ *AuthorityIdentityInput, outcome *core.AuthOutcome) {
			outcome.BackendName = "different-backend"
		}},
		{name: "protocol", mutate: func(_ *AuthorityIdentityInput, outcome *core.AuthOutcome) {
			outcome.Protocol = definitions.ProtoSMTP
		}},
		{name: "account", mutate: func(_ *AuthorityIdentityInput, outcome *core.AuthOutcome) {
			outcome.Account = "different-account@example.test"
		}},
		{name: "validated username", mutate: func(input *AuthorityIdentityInput, _ *core.AuthOutcome) {
			input.Backend.Username = "different-user@example.test"
		}},
		{name: "reference type", mutate: func(_ *AuthorityIdentityInput, outcome *core.AuthOutcome) {
			outcome.RemoteBackendRef.Type = definitions.BackendLDAPName
		}},
		{name: "reference name", mutate: func(_ *AuthorityIdentityInput, outcome *core.AuthOutcome) {
			outcome.RemoteBackendRef.Name = "different-backend"
		}},
		{name: "reference protocol", mutate: func(_ *AuthorityIdentityInput, outcome *core.AuthOutcome) {
			outcome.RemoteBackendRef.Protocol = definitions.ProtoSMTP
		}},
		{name: "reference authority", mutate: func(_ *AuthorityIdentityInput, outcome *core.AuthOutcome) {
			outcome.RemoteBackendRef.Authority = "different-authority.example.test"
		}},
		{name: "reference token", mutate: func(_ *AuthorityIdentityInput, outcome *core.AuthOutcome) {
			outcome.RemoteBackendRef.OpaqueToken = "unexpected-token"
		}},
	}
}

// authorityMFAAdmissionCases returns every backend-capability operation and its trusted gRPC method.
func authorityMFAAdmissionCases() []authorityMFAAdmissionCase {
	cases := authorityTOTPAdmissionCases()

	return append(cases, authorityWebAuthnAdmissionCases()...)
}

// authorityTOTPAdmissionCases returns identity, TOTP, and recovery admission cases.
func authorityTOTPAdmissionCases() []authorityMFAAdmissionCase {
	return []authorityMFAAdmissionCase{
		{name: "resolve user", operation: AuthorityOperationResolveUser, fullMethod: identityv1.IdentityBackendService_ResolveUser_FullMethodName, invoke: func(service AuthorityIdentityService, ctx context.Context, input AuthorityIdentityInput) error {
			_, err := service.ResolveUser(ctx, input)

			return err
		}},
		{name: "get MFA state", operation: AuthorityOperationGetMFAState, fullMethod: identityv1.IdentityBackendService_GetMFAState_FullMethodName, invoke: func(service AuthorityIdentityService, ctx context.Context, input AuthorityIdentityInput) error {
			_, err := service.GetMFAState(ctx, input)

			return err
		}},
		{name: "begin TOTP registration", operation: AuthorityOperationBeginTOTPRegistration, fullMethod: identityv1.IdentityBackendService_BeginTOTPRegistration_FullMethodName, invoke: func(service AuthorityIdentityService, ctx context.Context, input AuthorityIdentityInput) error {
			_, err := service.BeginTOTPRegistration(ctx, input)

			return err
		}},
		{name: "finish TOTP registration", operation: AuthorityOperationFinishTOTPRegistration, fullMethod: identityv1.IdentityBackendService_FinishTOTPRegistration_FullMethodName, invoke: func(service AuthorityIdentityService, ctx context.Context, input AuthorityIdentityInput) error {
			_, err := service.FinishTOTPRegistration(ctx, input)

			return err
		}},
		{name: "verify TOTP", operation: AuthorityOperationVerifyTOTP, fullMethod: identityv1.IdentityBackendService_VerifyTOTP_FullMethodName, invoke: func(service AuthorityIdentityService, ctx context.Context, input AuthorityIdentityInput) error {
			_, err := service.VerifyTOTP(ctx, input)

			return err
		}},
		{name: "delete TOTP", operation: AuthorityOperationDeleteTOTP, fullMethod: identityv1.IdentityBackendService_DeleteTOTP_FullMethodName, invoke: func(service AuthorityIdentityService, ctx context.Context, input AuthorityIdentityInput) error {
			_, err := service.DeleteTOTP(ctx, input)

			return err
		}},
		{name: "generate recovery codes", operation: AuthorityOperationGenerateRecoveryCodes, fullMethod: identityv1.IdentityBackendService_GenerateRecoveryCodes_FullMethodName, invoke: func(service AuthorityIdentityService, ctx context.Context, input AuthorityIdentityInput) error {
			_, err := service.GenerateRecoveryCodes(ctx, input)

			return err
		}},
		{name: "use recovery code", operation: AuthorityOperationUseRecoveryCode, fullMethod: identityv1.IdentityBackendService_UseRecoveryCode_FullMethodName, invoke: func(service AuthorityIdentityService, ctx context.Context, input AuthorityIdentityInput) error {
			_, err := service.UseRecoveryCode(ctx, input)

			return err
		}},
		{name: "delete recovery codes", operation: AuthorityOperationDeleteRecoveryCodes, fullMethod: identityv1.IdentityBackendService_DeleteRecoveryCodes_FullMethodName, invoke: func(service AuthorityIdentityService, ctx context.Context, input AuthorityIdentityInput) error {
			_, err := service.DeleteRecoveryCodes(ctx, input)

			return err
		}},
	}
}

// authorityWebAuthnAdmissionCases returns every WebAuthn capability admission case.
func authorityWebAuthnAdmissionCases() []authorityMFAAdmissionCase {
	return []authorityMFAAdmissionCase{
		{name: "get WebAuthn credentials", operation: AuthorityOperationGetWebAuthnCredentials, fullMethod: identityv1.IdentityBackendService_GetWebAuthnCredentials_FullMethodName, invoke: func(service AuthorityIdentityService, ctx context.Context, input AuthorityIdentityInput) error {
			_, err := service.GetWebAuthnCredentials(ctx, input)

			return err
		}},
		{name: "save WebAuthn credential", operation: AuthorityOperationSaveWebAuthnCredential, fullMethod: identityv1.IdentityBackendService_SaveWebAuthnCredential_FullMethodName, invoke: func(service AuthorityIdentityService, ctx context.Context, input AuthorityIdentityInput) error {
			_, err := service.SaveWebAuthnCredential(ctx, input)

			return err
		}},
		{name: "update WebAuthn credential", operation: AuthorityOperationUpdateWebAuthnCredential, fullMethod: identityv1.IdentityBackendService_UpdateWebAuthnCredential_FullMethodName, invoke: func(service AuthorityIdentityService, ctx context.Context, input AuthorityIdentityInput) error {
			_, err := service.UpdateWebAuthnCredential(ctx, input)

			return err
		}},
		{name: "delete WebAuthn credential", operation: AuthorityOperationDeleteWebAuthnCredential, fullMethod: identityv1.IdentityBackendService_DeleteWebAuthnCredential_FullMethodName, invoke: func(service AuthorityIdentityService, ctx context.Context, input AuthorityIdentityInput) error {
			_, err := service.DeleteWebAuthnCredential(ctx, input)

			return err
		}},
	}
}

// assertAuthorityMFAApplicationInput verifies exact host-owned admission and affinity facts.
func assertAuthorityMFAApplicationInput(
	t *testing.T,
	got core.AuthInput,
	want AuthorityIdentityInput,
	fullMethod string,
) {
	t.Helper()
	assertAuthorityMFAOperationInput(t, got)
	assertAuthorityMFATransportInput(t, got, fullMethod)
	assertAuthorityMFAProtocolInput(t, got, want)
	assertAuthorityMFAAttributeInput(t, got)
	assertAuthorityMFABrowserIsolation(t, got)
}

// assertAuthorityMFAOperationInput verifies the exact application operation and entry profile.
func assertAuthorityMFAOperationInput(t *testing.T, got core.AuthInput) {
	t.Helper()

	if got.Mode != core.AuthModeLookupIdentity || got.EntryPoint != core.AuthnEntryIDPMFABackend ||
		got.Service != definitions.ServGRPC {
		t.Fatalf("application operation = %q/%v/%q, want lookup/%v/%q", got.Mode, got.EntryPoint, got.Service, core.AuthnEntryIDPMFABackend, definitions.ServGRPC)
	}
}

// assertAuthorityMFATransportInput verifies host-owned gRPC transport evidence.
func assertAuthorityMFATransportInput(t *testing.T, got core.AuthInput, fullMethod string) {
	t.Helper()

	if got.Context.Transport.Kind != grpcTransportKind || got.Context.Transport.Listener != grpcAuthorityListener ||
		got.Context.Transport.GRPCMethod != fullMethod {
		t.Fatalf("application transport = %#v, want gRPC authority method %q", got.Context.Transport, fullMethod)
	}
}

// assertAuthorityMFAProtocolInput verifies client, service-provider, correlation, and affinity facts.
func assertAuthorityMFAProtocolInput(t *testing.T, got core.AuthInput, want AuthorityIdentityInput) {
	t.Helper()

	if got.Context.OIDCCID != want.Context.GetOidcCid() || got.Context.SAMLEntityID != want.Context.GetSamlEntityId() {
		t.Fatalf("application client/SP = %q/%q, want %q/%q", got.Context.OIDCCID, got.Context.SAMLEntityID, want.Context.GetOidcCid(), want.Context.GetSamlEntityId())
	}

	if got.CorrelationID != want.Context.GetEdgeRequestId() {
		t.Fatalf("application correlation = %q, want %q", got.CorrelationID, want.Context.GetEdgeRequestId())
	}

	wantRef := core.RemoteBackendRef{
		Type: want.Backend.Type, Name: want.Backend.Name, Protocol: want.Backend.Protocol, Authority: want.Backend.Authority,
	}
	if got.IDP.ExistingBackendRef != wantRef {
		t.Fatalf("application backend affinity = %#v, want %#v", got.IDP.ExistingBackendRef, wantRef)
	}
}

// assertAuthorityMFAAttributeInput verifies the detached claim-release request.
func assertAuthorityMFAAttributeInput(t *testing.T, got core.AuthInput) {
	t.Helper()

	attributes := got.IDP.IdentityAttributeRequest
	if attributes == nil || len(attributes.Names) != 1 || attributes.Names[0] != "mail" ||
		!attributes.IncludeStandardIdentity || !attributes.IncludeGroups ||
		!attributes.IncludeGroupDistinguishedNames || !attributes.ReportMissing {
		t.Fatalf("application attribute request = %#v, want detached complete request", attributes)
	}
}

// assertAuthorityMFABrowserIsolation verifies that no browser-owned ceremony state crosses the boundary.
func assertAuthorityMFABrowserIsolation(t *testing.T, got core.AuthInput) {
	t.Helper()

	request := got.IDP.Request
	if request.GrantType != "" || request.RedirectURI != "" || len(request.RequestedScopes) != 0 {
		t.Fatalf("application input captured browser-only state: %#v", request)
	}
}

func TestBackendManagerIdentityServiceMFAStateDoesNotExposeStoredSecrets(t *testing.T) {
	backendName := "authority-mfa-state-secrets"
	username := "secret-state@example.test"
	deps := authorityMFATestAuthDeps()

	seedAuthorityMFATestUser(t, deps, backendName, username, authorityMFATestTOTPSecret, []string{
		authorityMFATestRecoveryCodeA,
		authorityMFATestRecoveryCodeB,
	})

	input := authorityMFATestInput(backendName, username)
	service := newAuthorityMFATestService(deps, input)

	result, err := service.GetMFAState(context.Background(), input)
	if err != nil {
		t.Fatalf("GetMFAState() error = %v", err)
	}

	if !result.MFA.HasTOTP {
		t.Fatal("GetMFAState() HasTOTP = false, want true")
	}

	if result.MFA.RecoveryCodeCount != 2 {
		t.Fatalf("GetMFAState() recovery count = %d, want 2", result.MFA.RecoveryCodeCount)
	}

	if result.TOTPSecret != "" || len(result.RecoveryCodes) != 0 {
		t.Fatalf("GetMFAState() exposed TOTP secret %q or recovery codes %#v", result.TOTPSecret, result.RecoveryCodes)
	}
}

func TestBackendManagerIdentityServiceBeginTOTPRegistrationUsesConfiguredIssuer(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				TotpIssuer: authorityTOTPIssuer,
			},
		},
	}
	input := authorityMFATestInput("authority-totp-issuer", "issuer-user@example.test")
	deps := core.AuthDeps{Cfg: cfg, Env: config.NewTestEnvironmentConfig()}
	service := newAuthorityMFATestService(deps, input)

	result, err := service.BeginTOTPRegistration(
		context.Background(),
		input,
	)
	if err != nil {
		t.Fatalf("BeginTOTPRegistration() error = %v", err)
	}

	parsed, err := url.Parse(result.OTPAuthURL)
	if err != nil {
		t.Fatalf("parse OTPAuthURL: %v", err)
	}

	if got := parsed.Query().Get("issuer"); got != authorityTOTPIssuer {
		t.Fatalf("issuer = %q, want %s", got, authorityTOTPIssuer)
	}
}

func TestBackendManagerIdentityServiceKeepsTOTPRegistrationAfterInvalidCode(t *testing.T) {
	backendName := "authority-totp-retry"
	username := "totp-retry@example.test"
	deps := authorityMFATestAuthDeps()
	input := authorityMFATestInput(backendName, username)
	service := newAuthorityMFATestService(deps, input)

	registration, err := service.BeginTOTPRegistration(context.Background(), input)
	if err != nil {
		t.Fatalf("BeginTOTPRegistration() error = %v", err)
	}

	validCode, err := totp.GenerateCode(registration.TOTPSecret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode() error = %v", err)
	}

	input.PendingRegistrationID = registration.PendingRegistrationID
	input.Code = differentTOTPCode(validCode)

	invalidResult, err := service.FinishTOTPRegistration(context.Background(), input)
	if err != nil {
		t.Fatalf("FinishTOTPRegistration(invalid) error = %v", err)
	}

	if invalidResult.Status.GetErrorCode() != "totp_invalid" {
		t.Fatalf("invalid status = %#v, want totp_invalid", invalidResult.Status)
	}

	input.Code = validCode

	validResult, err := service.FinishTOTPRegistration(context.Background(), input)
	if err != nil {
		t.Fatalf("FinishTOTPRegistration(valid retry) error = %v", err)
	}

	assertOperationOK(t, validResult.Status)
}

// differentTOTPCode changes one digit while preserving the submitted code shape.
func differentTOTPCode(code string) string {
	if code == "" {
		return "000000"
	}

	if code[0] == '0' {
		return "1" + code[1:]
	}

	return "0" + code[1:]
}

func TestAuthorityUserSnapshotFiltersMFASecretAttributes(t *testing.T) {
	outcome := &core.AuthOutcome{
		Decision:          core.AuthDecisionOK,
		AccountField:      authorityTestUID,
		TOTPSecretField:   authorityMFATestSecretField,
		TOTPRecoveryField: authorityMFATestRecoveryField,
		Backend:           definitions.BackendTest,
		Attributes: bktype.AttributeMapping{
			authorityTestUID:              []any{authoritySnapshotMail},
			authorityMFATestSecretField:   []any{authorityMFATestTOTPSecret},
			authorityMFATestRecoveryField: []any{authorityMFATestRecoveryCodeA, authorityMFATestRecoveryCodeB},
		},
	}

	user := userSnapshotFromOutcome(AuthorityIdentityInput{}, outcome, BackendRefPayload{}, AuthorityMFAState{})
	if user == nil {
		t.Fatal("userSnapshotFromOutcome() returned nil")
	}

	if _, ok := user.Attributes[authorityMFATestSecretField]; ok {
		t.Fatalf("user snapshot exposed %s", authorityMFATestSecretField)
	}

	if _, ok := user.Attributes[authorityMFATestRecoveryField]; ok {
		t.Fatalf("user snapshot exposed %s", authorityMFATestRecoveryField)
	}
}

func TestAuthorityRequestedAttributeReleaseDoesNotDefaultToRawAttributes(t *testing.T) {
	release := releaseRequestedAttributes(
		bktype.AttributeMapping{
			authorityTestUID:           []any{authoritySnapshotMail},
			authorityAttributeMail:     []any{authoritySnapshotMail},
			authorityAttributeEmployee: []any{authorityEmployeeNumber},
		},
		&identityv1.AttributeRequest{IncludeStandardIdentity: true},
	)

	if len(release.Attributes) != 0 {
		t.Fatalf("released attributes = %#v, want no raw attributes without requested names", release.Attributes)
	}
}

func TestAuthorityRequestedAttributeReleaseReportsDeniedAndMissingSafely(t *testing.T) {
	release := releaseRequestedAttributes(
		bktype.AttributeMapping{
			authorityAttributeMail:        []any{authoritySnapshotMail},
			authorityAttributeEmployee:    []any{authorityEmployeeNumber},
			authorityMFATestSecretField:   []any{authorityMFATestTOTPSecret},
			authorityMFATestRecoveryField: []any{authorityMFATestRecoveryCodeA},
			authorityAttributePrivateKey:  []any{"private-key-material"},
			authorityAttributeRaw:         []any{"must-not-leak"},
			authorityAttributeSecret:      []any{"client-secret"},
			authorityAttributeBearer:      []any{"bearer-token"},
		},
		&identityv1.AttributeRequest{
			Names: []string{
				authorityAttributeMail,
				authorityAttributeMissing,
				authorityMFATestSecretField,
				authorityMFATestRecoveryField,
				authorityAttributePrivateKey,
				authorityAttributeSecret,
				authorityAttributeBearer,
			},
			ReportMissing: true,
		},
		authorityMFATestSecretField,
		authorityMFATestRecoveryField,
	)

	if got := release.Attributes[authorityAttributeMail]; len(got) != 1 || got[0] != authoritySnapshotMail {
		t.Fatalf("released mail = %#v, want snapshot@example.test", got)
	}

	for _, name := range []string{
		authorityMFATestSecretField,
		authorityMFATestRecoveryField,
		authorityAttributePrivateKey,
		authorityAttributeSecret,
		authorityAttributeBearer,
		authorityAttributeRaw,
	} {
		if _, ok := release.Attributes[name]; ok {
			t.Fatalf("released sensitive or unrequested attribute %q", name)
		}
	}

	assertSameStringSet(t, release.Missing, []string{authorityAttributeMissing})
	assertSameStringSet(t, release.Denied, []string{
		authorityMFATestSecretField,
		authorityMFATestRecoveryField,
		authorityAttributeSecret,
		authorityAttributePrivateKey,
		authorityAttributeBearer,
	})
}

func TestBackendManagerIdentityServiceConsumesRecoveryCodeOnce(t *testing.T) {
	backendName := "authority-recovery-consume-once"
	username := "consume-once@example.test"
	deps := authorityMFATestAuthDeps()

	seedAuthorityMFATestUser(t, deps, backendName, username, "", []string{
		authorityMFATestRecoveryCodeA,
		authorityMFATestRecoveryCodeB,
	})

	input := authorityMFATestInput(backendName, username)
	service := newAuthorityMFATestService(deps, input)
	input.Code = authorityMFATestRecoveryCodeA

	results := useRecoveryCodeConcurrently(t, service, input, 2)
	validResults := 0

	for _, result := range results {
		if result.Valid {
			validResults++
		}

		if result.RemainingRecoveryCodeCount != 1 {
			t.Fatalf("remaining recovery count = %d, want 1", result.RemainingRecoveryCodeCount)
		}
	}

	if validResults != 1 {
		t.Fatalf("valid recovery consumptions = %d, want 1", validResults)
	}

	state, err := service.GetMFAState(context.Background(), authorityMFATestInput(backendName, username))
	if err != nil {
		t.Fatalf("GetMFAState() error = %v", err)
	}

	if state.MFA.RecoveryCodeCount != 1 {
		t.Fatalf("final recovery count = %d, want 1", state.MFA.RecoveryCodeCount)
	}
}

func TestBackendManagerIdentityServiceWebAuthnUpdateComparesPersistentState(t *testing.T) {
	backendName := "authority-webauthn-update"
	username := "webauthn-update@example.test"
	deps := authorityMFATestAuthDeps()
	original := authorityWebAuthnCredential("credential-a", "Security key", 10)
	updated := authorityWebAuthnCredential("credential-a", "Renamed key", 11)

	seedAuthorityWebAuthnCredential(t, deps, backendName, username, original)

	input := authorityMFATestInput(backendName, username)
	service := newAuthorityMFATestService(deps, input)
	input.OldCredential = original
	input.NewCredential = updated

	if _, err := service.UpdateWebAuthnCredential(context.Background(), input); err != nil {
		t.Fatalf("UpdateWebAuthnCredential() error = %v", err)
	}

	credentials := readAuthorityWebAuthnCredentials(t, deps, backendName, username)
	if len(credentials) != 1 || credentials[0].Name != "Renamed key" || credentials[0].Authenticator.SignCount != 11 {
		t.Fatalf("credentials after update = %#v, want renamed sign-count 11 credential", credentials)
	}
}

func assertSameStringSet(t *testing.T, got []string, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("string set = %#v, want %#v", got, want)
	}

	index := make(map[string]struct{}, len(got))
	for _, value := range got {
		index[value] = struct{}{}
	}

	for _, value := range want {
		if _, ok := index[value]; !ok {
			t.Fatalf("string set = %#v, missing %q", got, value)
		}
	}
}

func TestBackendManagerIdentityServiceWebAuthnUpdateRejectsStalePersistentState(t *testing.T) {
	backendName := "authority-webauthn-stale"
	username := "webauthn-stale@example.test"
	deps := authorityMFATestAuthDeps()
	persistent := authorityWebAuthnCredential("credential-a", "Security key", 10)
	staleOld := authorityWebAuthnCredential("credential-a", "Security key", 3)
	newCredential := authorityWebAuthnCredential("credential-a", "Security key", 11)

	seedAuthorityWebAuthnCredential(t, deps, backendName, username, persistent)

	input := authorityMFATestInput(backendName, username)
	service := newAuthorityMFATestService(deps, input)
	input.OldCredential = staleOld
	input.NewCredential = newCredential

	if _, err := service.UpdateWebAuthnCredential(context.Background(), input); err == nil {
		t.Fatal("UpdateWebAuthnCredential() error = nil, want stale-state rejection")
	} else if !errors.Is(err, ErrWebAuthnCredentialStateMismatch) {
		t.Fatalf("UpdateWebAuthnCredential() error = %v, want ErrWebAuthnCredentialStateMismatch", err)
	}

	credentials := readAuthorityWebAuthnCredentials(t, deps, backendName, username)
	if len(credentials) != 1 || credentials[0].Authenticator.SignCount != 10 {
		t.Fatalf("credentials after stale update = %#v, want unchanged sign-count 10 credential", credentials)
	}
}

func useRecoveryCodeConcurrently(
	t *testing.T,
	service AuthorityIdentityService,
	input AuthorityIdentityInput,
	attempts int,
) []*AuthorityIdentityResult {
	t.Helper()

	results := make(chan *AuthorityIdentityResult, attempts)
	errs := make(chan error, attempts)
	start := make(chan struct{})

	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			<-start

			result, err := service.UseRecoveryCode(context.Background(), input)
			if err != nil {
				errs <- err

				return
			}

			results <- result
		})
	}

	close(start)
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Fatalf("UseRecoveryCode() error = %v", err)
	}

	collected := make([]*AuthorityIdentityResult, 0, attempts)
	for result := range results {
		collected = append(collected, result)
	}

	return collected
}

func seedAuthorityWebAuthnCredential(
	t *testing.T,
	deps core.AuthDeps,
	backendName string,
	username string,
	credential *mfa.PersistentCredential,
) {
	t.Helper()

	auth := core.NewAuthStateFromContextWithDeps(nil, deps).(*core.AuthState)
	auth.SetUsername(username)

	manager := core.NewTestBackendManager(backendName, deps)
	if err := manager.SaveWebAuthnCredential(auth, credential); err != nil {
		t.Fatalf("SaveWebAuthnCredential() error = %v", err)
	}
}

func readAuthorityWebAuthnCredentials(
	t *testing.T,
	deps core.AuthDeps,
	backendName string,
	username string,
) []mfa.PersistentCredential {
	t.Helper()

	auth := core.NewAuthStateFromContextWithDeps(nil, deps).(*core.AuthState)
	auth.SetUsername(username)

	manager := core.NewTestBackendManager(backendName, deps)

	credentials, err := manager.GetWebAuthnCredentials(auth)
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials() error = %v", err)
	}

	return credentials
}

func authorityWebAuthnCredential(id string, name string, signCount uint32) *mfa.PersistentCredential {
	return &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte(id),
			Authenticator: webauthn.Authenticator{
				SignCount: signCount,
			},
		},
		Name: name,
	}
}

func seedAuthorityMFATestUser(
	t *testing.T,
	deps core.AuthDeps,
	backendName string,
	username string,
	totpSecret string,
	recoveryCodes []string,
) {
	t.Helper()

	core.InitPassDBResultPool()

	auth := core.NewAuthStateFromContextWithDeps(nil, deps).(*core.AuthState)
	auth.SetUsername(username)

	manager := core.NewTestBackendManager(backendName, deps)
	if totpSecret != "" {
		if err := manager.AddTOTPSecret(auth, core.NewTOTPSecret(totpSecret)); err != nil {
			t.Fatalf("AddTOTPSecret() error = %v", err)
		}
	}

	if len(recoveryCodes) > 0 {
		if err := manager.AddTOTPRecoveryCodes(auth, mfa.NewTOTPRecovery(recoveryCodes)); err != nil {
			t.Fatalf("AddTOTPRecoveryCodes() error = %v", err)
		}
	}
}

func authorityMFATestInput(backendName string, username string) AuthorityIdentityInput {
	return AuthorityIdentityInput{
		Username: username,
		Backend: BackendRefPayload{
			Type:     definitions.BackendTestName,
			Name:     backendName,
			Protocol: definitions.ProtoIMAP,
			Username: username,
			Account:  username,
		},
	}
}

// authorityMFATestAuthDeps returns the minimum specialized-state dependencies for manager tests.
func authorityMFATestAuthDeps() core.AuthDeps {
	return core.AuthDeps{
		Cfg: &config.FileSettings{Server: &config.ServerSection{}},
		Env: config.NewTestEnvironmentConfig(),
	}
}

// authorityMFATestOutcome returns an exact admitted identity projection for one backend binding.
func authorityMFATestOutcome(input AuthorityIdentityInput) *core.AuthOutcome {
	account := nonEmpty(input.Backend.Account, input.Username)

	return &core.AuthOutcome{
		Decision:    core.AuthDecisionOK,
		Account:     account,
		Protocol:    nonEmpty(input.Backend.Protocol, definitions.ProtoDefault),
		Backend:     backendTypeFromRef(input.Backend.Type),
		BackendName: input.Backend.Name,
		RemoteBackendRef: core.RemoteBackendRef{
			Type: input.Backend.Type, Name: input.Backend.Name,
			Protocol: input.Backend.Protocol, Authority: input.Backend.Authority,
		},
	}
}

// newAuthorityMFATestService supplies one admitted lookup outcome bound to the requested backend.
func newAuthorityMFATestService(deps core.AuthDeps, input AuthorityIdentityInput) AuthorityIdentityService {
	return NewBackendManagerIdentityService(BackendManagerIdentityServiceDeps{
		AuthService: &recordingAuthorityMFAApplicationService{lookupOutcome: authorityMFATestOutcome(input)},
		AuthDeps:    deps,
	})
}

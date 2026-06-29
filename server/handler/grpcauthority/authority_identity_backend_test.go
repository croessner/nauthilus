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
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	authv1 "github.com/croessner/nauthilus/v3/server/grpcapi/auth/v1"
	commonv1 "github.com/croessner/nauthilus/v3/server/grpcapi/common/v1"
	identityv1 "github.com/croessner/nauthilus/v3/server/grpcapi/identity/v1"
	"github.com/croessner/nauthilus/v3/server/model/mfa"

	"github.com/go-webauthn/webauthn/webauthn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const (
	authorityTestTOTPPendingID = "pending-totp-a"
	authorityTestDeleteTOTPKey = "delete-totp-key"
)

func TestNewServerRegistersAuthorityServices(t *testing.T) {
	server, err := NewServer(ServerDeps{
		Cfg:             grpcAuthTestConfig(validBasicAuthConfig(), config.OIDCAuth{}),
		Logger:          slog.Default(),
		IdentityService: &recordingAuthorityIdentityService{},
		BackendRefs:     newRecordingBackendRefStore(),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	defer server.Stop()

	services := server.GetServiceInfo()
	if _, found := services["nauthilus.auth.v1.AuthService"]; !found {
		t.Fatalf("registered services = %#v, want AuthService", services)
	}

	if _, found := services["nauthilus.identity.v1.IdentityBackendService"]; !found {
		t.Fatalf("registered services = %#v, want IdentityBackendService", services)
	}
}

//nolint:dupl,gocyclo,funlen
func TestBufconnIdentityBackendServiceOperations(t *testing.T) {
	store := newRecordingBackendRefStore()
	service := &recordingAuthorityIdentityService{
		result: authorityIdentityResultForTest(),
	}
	client := newBufconnIdentityBackendServiceClient(t, service, store, grpcAuthTestConfig(validBasicAuthConfig(), config.OIDCAuth{}))
	ctx := outgoingBasicAuthContext(context.Background())
	ref := backendRefProtoForTest("opaque-input-token")

	cases := []struct {
		name            string
		operation       AuthorityOperation
		validateBackend bool
		call            func(context.Context, identityv1.IdentityBackendServiceClient) error
	}{
		{
			name:      "resolve user",
			operation: AuthorityOperationResolveUser,
			call: func(ctx context.Context, client identityv1.IdentityBackendServiceClient) error {
				response, err := client.ResolveUser(ctx, &identityv1.ResolveUserRequest{
					Context:  identityRequestContextForTest(),
					Username: authorityTestUsername,
					Attributes: &identityv1.AttributeRequest{
						Names:                   []string{authorityTestUID},
						IncludeStandardIdentity: true,
					},
				})
				if err != nil {
					return err
				}

				assertOperationOK(t, response.GetStatus())

				if response.GetUser().GetBackend().GetOpaqueToken() == "" {
					t.Fatal("ResolveUser did not return an authority-issued backend reference")
				}

				return nil
			},
		},
		{
			name:            "get mfa state",
			operation:       AuthorityOperationGetMFAState,
			validateBackend: true,
			call: func(ctx context.Context, client identityv1.IdentityBackendServiceClient) error {
				response, err := client.GetMFAState(ctx, &identityv1.GetMFAStateRequest{
					Context:  identityRequestContextForTest(),
					Username: authorityTestUsername,
					Backend:  ref,
				})
				if err != nil {
					return err
				}

				assertOperationOK(t, response.GetStatus())

				if !response.GetMfa().GetHasTotp() {
					t.Fatal("GetMFAState did not return the service MFA state")
				}

				return nil
			},
		},
		{
			name:            "begin totp registration",
			operation:       AuthorityOperationBeginTOTPRegistration,
			validateBackend: true,
			call: func(ctx context.Context, client identityv1.IdentityBackendServiceClient) error {
				response, err := client.BeginTOTPRegistration(ctx, &identityv1.BeginTOTPRegistrationRequest{
					Context:        identityRequestContextForTest(),
					Username:       authorityTestUsername,
					Backend:        ref,
					IdempotencyKey: "begin-totp-key",
				})
				if err != nil {
					return err
				}

				assertOperationOK(t, response.GetStatus())

				if response.GetTotpSecret() == "" || response.GetPendingRegistrationId() == "" {
					t.Fatal("BeginTOTPRegistration did not return setup material")
				}

				return nil
			},
		},
		{
			name:            "finish totp registration",
			operation:       AuthorityOperationFinishTOTPRegistration,
			validateBackend: true,
			call: func(ctx context.Context, client identityv1.IdentityBackendServiceClient) error {
				response, err := client.FinishTOTPRegistration(ctx, &identityv1.FinishTOTPRegistrationRequest{
					Context:               identityRequestContextForTest(),
					Username:              authorityTestUsername,
					Backend:               ref,
					Code:                  "123456",
					IdempotencyKey:        "finish-totp-key",
					PendingRegistrationId: authorityTestTOTPPendingID,
				})
				if err != nil {
					return err
				}

				assertOperationOK(t, response.GetStatus())

				if !response.GetChanged() {
					t.Fatal("FinishTOTPRegistration did not report a change")
				}

				return nil
			},
		},
		{
			name:            "verify totp",
			operation:       AuthorityOperationVerifyTOTP,
			validateBackend: true,
			call: func(ctx context.Context, client identityv1.IdentityBackendServiceClient) error {
				response, err := client.VerifyTOTP(ctx, &identityv1.VerifyTOTPRequest{
					Context:  identityRequestContextForTest(),
					Username: authorityTestUsername,
					Backend:  ref,
					Code:     "123456",
				})
				if err != nil {
					return err
				}

				assertOperationOK(t, response.GetStatus())

				if !response.GetValid() {
					t.Fatal("VerifyTOTP did not return the service verification result")
				}

				return nil
			},
		},
		{
			name:            "delete totp",
			operation:       AuthorityOperationDeleteTOTP,
			validateBackend: true,
			call: func(ctx context.Context, client identityv1.IdentityBackendServiceClient) error {
				response, err := client.DeleteTOTP(ctx, &identityv1.DeleteTOTPRequest{
					Context:        identityRequestContextForTest(),
					Username:       authorityTestUsername,
					Backend:        ref,
					IdempotencyKey: authorityTestDeleteTOTPKey,
				})
				if err != nil {
					return err
				}

				assertOperationOK(t, response.GetStatus())

				if !response.GetChanged() {
					t.Fatal("DeleteTOTP did not report a change")
				}

				return nil
			},
		},
		{
			name:            "generate recovery codes",
			operation:       AuthorityOperationGenerateRecoveryCodes,
			validateBackend: true,
			call: func(ctx context.Context, client identityv1.IdentityBackendServiceClient) error {
				response, err := client.GenerateRecoveryCodes(ctx, &identityv1.GenerateRecoveryCodesRequest{
					Context:        identityRequestContextForTest(),
					Username:       authorityTestUsername,
					Backend:        ref,
					Count:          2,
					IdempotencyKey: "generate-recovery-key",
				})
				if err != nil {
					return err
				}

				assertOperationOK(t, response.GetStatus())

				if len(response.GetCodes()) != 2 {
					t.Fatalf("recovery codes = %#v, want two codes", response.GetCodes())
				}

				return nil
			},
		},
		{
			name:            "use recovery code",
			operation:       AuthorityOperationUseRecoveryCode,
			validateBackend: true,
			call: func(ctx context.Context, client identityv1.IdentityBackendServiceClient) error {
				response, err := client.UseRecoveryCode(ctx, &identityv1.UseRecoveryCodeRequest{
					Context:        identityRequestContextForTest(),
					Username:       authorityTestUsername,
					Backend:        ref,
					Code:           authorityTestRecoveryCode,
					IdempotencyKey: "use-recovery-key",
				})
				if err != nil {
					return err
				}

				assertOperationOK(t, response.GetStatus())

				if !response.GetValid() {
					t.Fatal("UseRecoveryCode did not return the service verification result")
				}

				return nil
			},
		},
		{
			name:            "delete recovery codes",
			operation:       AuthorityOperationDeleteRecoveryCodes,
			validateBackend: true,
			call: func(ctx context.Context, client identityv1.IdentityBackendServiceClient) error {
				response, err := client.DeleteRecoveryCodes(ctx, &identityv1.DeleteRecoveryCodesRequest{
					Context:        identityRequestContextForTest(),
					Username:       authorityTestUsername,
					Backend:        ref,
					IdempotencyKey: "delete-recovery-key",
				})
				if err != nil {
					return err
				}

				assertOperationOK(t, response.GetStatus())

				if !response.GetChanged() {
					t.Fatal("DeleteRecoveryCodes did not report a change")
				}

				return nil
			},
		},
		{
			name:            "get webauthn credentials",
			operation:       AuthorityOperationGetWebAuthnCredentials,
			validateBackend: true,
			call: func(ctx context.Context, client identityv1.IdentityBackendServiceClient) error {
				response, err := client.GetWebAuthnCredentials(ctx, &identityv1.GetWebAuthnCredentialsRequest{
					Context:  identityRequestContextForTest(),
					Username: authorityTestUsername,
					Backend:  ref,
				})
				if err != nil {
					return err
				}

				assertOperationOK(t, response.GetStatus())

				if len(response.GetCredentials()) != 1 {
					t.Fatalf("credentials = %#v, want one credential", response.GetCredentials())
				}

				return nil
			},
		},
		{
			name:            "save webauthn credential",
			operation:       AuthorityOperationSaveWebAuthnCredential,
			validateBackend: true,
			call: func(ctx context.Context, client identityv1.IdentityBackendServiceClient) error {
				response, err := client.SaveWebAuthnCredential(ctx, &identityv1.SaveWebAuthnCredentialRequest{
					Context:        identityRequestContextForTest(),
					Username:       authorityTestUsername,
					Backend:        ref,
					IdempotencyKey: "save-webauthn-key",
					Credential: &identityv1.WebAuthnCredential{
						CredentialId: []byte("credential-a"),
						PublicKey:    []byte("public-key-a"),
					},
				})
				if err != nil {
					return err
				}

				assertOperationOK(t, response.GetStatus())

				if !response.GetChanged() {
					t.Fatal("SaveWebAuthnCredential did not report a change")
				}

				return nil
			},
		},
		{
			name:            "update webauthn credential",
			operation:       AuthorityOperationUpdateWebAuthnCredential,
			validateBackend: true,
			call: func(ctx context.Context, client identityv1.IdentityBackendServiceClient) error {
				response, err := client.UpdateWebAuthnCredential(ctx, &identityv1.UpdateWebAuthnCredentialRequest{
					Context:        identityRequestContextForTest(),
					Username:       authorityTestUsername,
					Backend:        ref,
					OldCredential:  &identityv1.WebAuthnCredential{CredentialId: []byte("credential-a")},
					NewCredential:  &identityv1.WebAuthnCredential{CredentialId: []byte("credential-a"), PublicKey: []byte("public-key-b")},
					IdempotencyKey: "update-webauthn-key",
				})
				if err != nil {
					return err
				}

				assertOperationOK(t, response.GetStatus())

				if !response.GetChanged() {
					t.Fatal("UpdateWebAuthnCredential did not report a change")
				}

				return nil
			},
		},
		{
			name:            "delete webauthn credential",
			operation:       AuthorityOperationDeleteWebAuthnCredential,
			validateBackend: true,
			call: func(ctx context.Context, client identityv1.IdentityBackendServiceClient) error {
				response, err := client.DeleteWebAuthnCredential(ctx, &identityv1.DeleteWebAuthnCredentialRequest{
					Context:        identityRequestContextForTest(),
					Username:       authorityTestUsername,
					Backend:        ref,
					CredentialId:   []byte("credential-a"),
					IdempotencyKey: "delete-webauthn-key",
				})
				if err != nil {
					return err
				}

				assertOperationOK(t, response.GetStatus())

				if !response.GetChanged() {
					t.Fatal("DeleteWebAuthnCredential did not report a change")
				}

				return nil
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			service.reset()
			store.reset()

			if err := testCase.call(ctx, client); err != nil {
				t.Fatalf("%s returned error: %v", testCase.name, err)
			}

			if service.lastInput.Operation != testCase.operation {
				t.Fatalf("operation = %q, want %q", service.lastInput.Operation, testCase.operation)
			}

			if testCase.validateBackend {
				if store.lastValidation.Operation != testCase.operation {
					t.Fatalf("validated operation = %q, want %q", store.lastValidation.Operation, testCase.operation)
				}
			} else if store.validateCalls != 0 {
				t.Fatalf("Validate calls = %d, want none", store.validateCalls)
			}
		})
	}
}

func TestBufconnIdentityBackendServiceAuthzFailures(t *testing.T) {
	service := &recordingAuthorityIdentityService{
		result: authorityIdentityResultForTest(),
	}
	store := newRecordingBackendRefStore()
	client := newBufconnIdentityBackendServiceClientWithValidator(
		t,
		service,
		store,
		grpcAuthTestConfig(config.BasicAuth{}, config.OIDCAuth{Enabled: true}),
		staticTokenValidator{claims: grpcBackchannelAccessClaims(definitions.ScopeMFARead)},
	)

	_, err := client.GetMFAState(context.Background(), &identityv1.GetMFAStateRequest{
		Context:  identityRequestContextForTest(),
		Username: authorityTestUsername,
		Backend:  backendRefProtoForTest("opaque-input-token"),
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}

	ctx := metadata.AppendToOutgoingContext(context.Background(), authorizationMetadataKey, "Bearer scoped-token")

	store.reset()

	_, err = client.DeleteTOTP(ctx, &identityv1.DeleteTOTPRequest{
		Context:  identityRequestContextForTest(),
		Username: authorityTestUsername,
		Backend:  backendRefProtoForTest("opaque-input-token"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.PermissionDenied)
	}

	if service.calls != 0 {
		t.Fatalf("identity service calls = %d, want none after authorization failure", service.calls)
	}
}

func TestBufconnIdentityBackendServiceRejectsBackendRefFailuresBeforeDomainCalls(t *testing.T) {
	service := &recordingAuthorityIdentityService{
		result: authorityIdentityResultForTest(),
	}
	store := newRecordingBackendRefStore()
	store.validateErr = ErrBackendRefOperationDenied
	client := newBufconnIdentityBackendServiceClient(t, service, store, grpcAuthTestConfig(validBasicAuthConfig(), config.OIDCAuth{}))

	_, err := client.DeleteTOTP(outgoingBasicAuthContext(context.Background()), &identityv1.DeleteTOTPRequest{
		Context:        identityRequestContextForTest(),
		Username:       authorityTestUsername,
		Backend:        backendRefProtoForTest("opaque-input-token"),
		IdempotencyKey: authorityTestDeleteTOTPKey,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.FailedPrecondition)
	}

	if service.calls != 0 {
		t.Fatalf("identity service calls = %d, want none after backend-ref failure", service.calls)
	}
}

func TestBufconnIdentityBackendServiceEnforcesMutatingIdempotencyKeys(t *testing.T) {
	service := &recordingAuthorityIdentityService{
		result: authorityIdentityResultForTest(),
	}
	store := newRecordingBackendRefStore()
	client := newBufconnIdentityBackendServiceClient(t, service, store, grpcAuthTestConfig(validBasicAuthConfig(), config.OIDCAuth{}))
	ctx := outgoingBasicAuthContext(context.Background())
	request := &identityv1.DeleteTOTPRequest{
		Context:  identityRequestContextForTest(),
		Username: authorityTestUsername,
		Backend:  backendRefProtoForTest("opaque-input-token"),
	}

	_, err := client.DeleteTOTP(ctx, request)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing idempotency key code = %v, want %v", status.Code(err), codes.InvalidArgument)
	}

	if service.calls != 0 {
		t.Fatalf("identity service calls = %d, want none when idempotency key is missing", service.calls)
	}

	request.IdempotencyKey = "delete-totp-replay-key"

	if _, err = client.DeleteTOTP(ctx, request); err != nil {
		t.Fatalf("first DeleteTOTP() error = %v", err)
	}

	_, err = client.DeleteTOTP(ctx, request)
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("replayed idempotency key code = %v, want %v", status.Code(err), codes.AlreadyExists)
	}

	if service.calls != 1 {
		t.Fatalf("identity service calls = %d, want one after replay is rejected", service.calls)
	}
}

//nolint:funlen
func TestUnaryServerInterceptorEnforcesIdentityScopeMatrix(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{}, config.OIDCAuth{Enabled: true})

	cases := []struct {
		name       string
		fullMethod string
		request    any
		scopes     string
		wantCode   codes.Code
	}{
		{
			name:       "lookup identity requires lookup scope",
			fullMethod: authv1.AuthService_LookupIdentity_FullMethodName,
			request:    &authv1.LookupIdentityRequest{},
			scopes:     definitions.ScopeAuthenticate,
			wantCode:   codes.PermissionDenied,
		},
		{
			name:       "resolve user attributes require attribute read",
			fullMethod: identityv1.IdentityBackendService_ResolveUser_FullMethodName,
			request: &identityv1.ResolveUserRequest{
				Attributes: &identityv1.AttributeRequest{Names: []string{authorityTestUID}},
			},
			scopes:   definitions.ScopeLookupIdentity,
			wantCode: codes.PermissionDenied,
		},
		{
			name:       "resolve user full read scope succeeds",
			fullMethod: identityv1.IdentityBackendService_ResolveUser_FullMethodName,
			request: &identityv1.ResolveUserRequest{
				Attributes:                 &identityv1.AttributeRequest{Names: []string{authorityTestUID}},
				IncludeMfaState:            true,
				IncludeWebauthnCredentials: true,
			},
			scopes: stringsJoinScopes(
				definitions.ScopeLookupIdentity,
				definitions.ScopeAttributeRead,
				definitions.ScopeMFARead,
				definitions.ScopeWebAuthnRead,
			),
		},
		{
			name:       "using recovery code requires verify and write",
			fullMethod: identityv1.IdentityBackendService_UseRecoveryCode_FullMethodName,
			request:    &identityv1.UseRecoveryCodeRequest{},
			scopes:     definitions.ScopeMFAVerify,
			wantCode:   codes.PermissionDenied,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			interceptor := UnaryServerInterceptor(ServerDeps{
				Cfg: cfg,
				OIDCValidator: staticTokenValidator{
					claims: grpcBackchannelAccessClaims(testCase.scopes),
				},
				Logger: slog.Default(),
			})
			ctx := metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "Bearer scope-token"),
			)

			response, err := interceptor(ctx, testCase.request, &grpc.UnaryServerInfo{
				FullMethod: testCase.fullMethod,
			}, okUnaryHandler)
			if testCase.wantCode != codes.OK {
				if status.Code(err) != testCase.wantCode {
					t.Fatalf("code = %v, want %v", status.Code(err), testCase.wantCode)
				}

				return
			}

			if err != nil {
				t.Fatalf("interceptor returned error: %v", err)
			}

			if response != authorityTestOK {
				t.Fatalf("response = %v, want ok", response)
			}
		})
	}
}

func newBufconnIdentityBackendServiceClient(
	t *testing.T,
	service AuthorityIdentityService,
	store BackendRefStore,
	cfg *config.FileSettings,
) identityv1.IdentityBackendServiceClient {
	t.Helper()

	return newBufconnIdentityBackendServiceClientWithValidator(
		t,
		service,
		store,
		cfg,
		staticTokenValidator{
			claims: grpcBackchannelAccessClaims(stringsJoinScopes(
				definitions.ScopeLookupIdentity,
				definitions.ScopeListAccounts,
				definitions.ScopeMFARead,
				definitions.ScopeMFAVerify,
				definitions.ScopeMFAWrite,
				definitions.ScopeWebAuthnRead,
				definitions.ScopeWebAuthnWrite,
				definitions.ScopeAttributeRead,
			)),
		},
	)
}

//nolint:funlen
func newBufconnIdentityBackendServiceClientWithValidator(
	t *testing.T,
	service AuthorityIdentityService,
	store BackendRefStore,
	cfg *config.FileSettings,
	validator staticTokenValidator,
) identityv1.IdentityBackendServiceClient {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)

	server, err := NewServer(ServerDeps{
		Cfg:             cfg,
		Logger:          slog.Default(),
		IdentityService: service,
		BackendRefs:     store,
		OIDCValidator:   validator,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	serveErr := make(chan error, 1)

	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) && !errors.Is(err, net.ErrClosed) {
			serveErr <- err

			return
		}

		serveErr <- nil
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		server.Stop()

		_ = listener.Close()

		t.Fatalf("bufconn dial failed: %v", err)
	}

	t.Cleanup(func() {
		_ = conn.Close()

		server.Stop()

		_ = listener.Close()

		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("bufconn server returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("bufconn server did not stop")
		}
	})

	return identityv1.NewIdentityBackendServiceClient(conn)
}

type recordingAuthorityIdentityService struct {
	result    *AuthorityIdentityResult
	err       error
	calls     int
	lastInput AuthorityIdentityInput
}

func (s *recordingAuthorityIdentityService) reset() {
	s.calls = 0
	s.lastInput = AuthorityIdentityInput{}
}

func (s *recordingAuthorityIdentityService) record(
	operation AuthorityOperation,
	input AuthorityIdentityInput,
) (*AuthorityIdentityResult, error) {
	input.Operation = operation
	s.calls++
	s.lastInput = input

	return s.result, s.err
}

func (s *recordingAuthorityIdentityService) ResolveUser(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	_ = ctx

	return s.record(AuthorityOperationResolveUser, input)
}

func (s *recordingAuthorityIdentityService) GetMFAState(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	_ = ctx

	return s.record(AuthorityOperationGetMFAState, input)
}

func (s *recordingAuthorityIdentityService) BeginTOTPRegistration(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	_ = ctx

	return s.record(AuthorityOperationBeginTOTPRegistration, input)
}

func (s *recordingAuthorityIdentityService) FinishTOTPRegistration(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	_ = ctx

	return s.record(AuthorityOperationFinishTOTPRegistration, input)
}

func (s *recordingAuthorityIdentityService) VerifyTOTP(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	_ = ctx

	return s.record(AuthorityOperationVerifyTOTP, input)
}

func (s *recordingAuthorityIdentityService) DeleteTOTP(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	_ = ctx

	return s.record(AuthorityOperationDeleteTOTP, input)
}

func (s *recordingAuthorityIdentityService) GenerateRecoveryCodes(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	_ = ctx

	return s.record(AuthorityOperationGenerateRecoveryCodes, input)
}

func (s *recordingAuthorityIdentityService) UseRecoveryCode(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	_ = ctx

	return s.record(AuthorityOperationUseRecoveryCode, input)
}

func (s *recordingAuthorityIdentityService) DeleteRecoveryCodes(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	_ = ctx

	return s.record(AuthorityOperationDeleteRecoveryCodes, input)
}

func (s *recordingAuthorityIdentityService) GetWebAuthnCredentials(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	_ = ctx

	return s.record(AuthorityOperationGetWebAuthnCredentials, input)
}

func (s *recordingAuthorityIdentityService) SaveWebAuthnCredential(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	_ = ctx

	return s.record(AuthorityOperationSaveWebAuthnCredential, input)
}

func (s *recordingAuthorityIdentityService) UpdateWebAuthnCredential(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	_ = ctx

	return s.record(AuthorityOperationUpdateWebAuthnCredential, input)
}

func (s *recordingAuthorityIdentityService) DeleteWebAuthnCredential(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	_ = ctx

	return s.record(AuthorityOperationDeleteWebAuthnCredential, input)
}

type recordingBackendRefStore struct {
	payload        BackendRefPayload
	issued         *commonv1.BackendRef
	issueCalls     int
	validateCalls  int
	lastValidation BackendRefValidation
	validateErr    error
}

func newRecordingBackendRefStore() *recordingBackendRefStore {
	return &recordingBackendRefStore{
		payload: backendRefPayloadForTest(),
		issued:  backendRefProtoForTest("opaque-issued-token"),
	}
}

func (s *recordingBackendRefStore) reset() {
	s.issueCalls = 0
	s.validateCalls = 0
	s.lastValidation = BackendRefValidation{}
}

func (s *recordingBackendRefStore) Issue(_ context.Context, payload BackendRefPayload) (*commonv1.BackendRef, error) {
	s.issueCalls++
	s.payload = payload

	return s.issued, nil
}

func (s *recordingBackendRefStore) Validate(
	_ context.Context,
	_ *commonv1.BackendRef,
	validation BackendRefValidation,
) (*BackendRefPayload, error) {
	s.validateCalls++

	s.lastValidation = validation
	if s.validateErr != nil {
		return nil, s.validateErr
	}

	payload := s.payload

	return &payload, nil
}

func authorityIdentityResultForTest() *AuthorityIdentityResult {
	payload := backendRefPayloadForTest()

	return &AuthorityIdentityResult{
		Status: &commonv1.OperationStatus{
			Result: commonv1.OperationResult_OPERATION_RESULT_OK,
		},
		User: &AuthorityUserSnapshot{
			Username: authorityTestUsername,
			Account:  authorityTestUsername,
			Attributes: map[string][]string{
				authorityTestUID: {authorityTestUsername},
			},
			Backend: payload,
			MFA: AuthorityMFAState{
				HasTOTP: true,
			},
		},
		MFA: AuthorityMFAState{
			HasTOTP:           true,
			RecoveryCodeCount: 2,
			Credentials: []mfa.PersistentCredential{
				{
					Credential: webauthnCredentialForTest("credential-a"),
					Name:       authorityTestSecurityKey,
				},
			},
		},
		Backend:                    payload,
		PendingRegistrationID:      authorityTestTOTPPendingID,
		TOTPSecret:                 "JBSWY3DPEHPK3PXP",
		OTPAuthURL:                 "otpauth://totp/Nauthilus:identity-user@example.test?secret=JBSWY3DPEHPK3PXP",
		ExpiresAt:                  time.Now().Add(5 * time.Minute),
		Valid:                      true,
		Changed:                    true,
		RecoveryCodes:              []string{authorityTestRecoveryCode, "recovery-2"},
		RecoveryCodeCount:          2,
		RemainingRecoveryCodeCount: 1,
		Credentials: []mfa.PersistentCredential{
			{
				Credential: webauthnCredentialForTest("credential-a"),
				Name:       authorityTestSecurityKey,
			},
		},
	}
}

func identityRequestContextForTest() *identityv1.RequestContext {
	return &identityv1.RequestContext{
		Username:          authorityTestUsername,
		ClientIp:          "203.0.113.40",
		Protocol:          authorityTestProtocol,
		EdgeInstance:      authorityTestEdgeInstance,
		EdgeRequestId:     "edge-request-a",
		RequestedLanguage: authorityTestLanguage,
	}
}

func backendRefProtoForTest(token string) *commonv1.BackendRef {
	return &commonv1.BackendRef{
		Type:        authorityTestType,
		Name:        authorityTestBackendName,
		Protocol:    authorityTestProtocol,
		Authority:   authorityTestAuthority,
		OpaqueToken: token,
	}
}

func assertOperationOK(t *testing.T, status *commonv1.OperationStatus) {
	t.Helper()

	if status.GetResult() != commonv1.OperationResult_OPERATION_RESULT_OK {
		t.Fatalf("operation status = %#v, want OK", status)
	}
}

func stringsJoinScopes(scopes ...string) string {
	result := ""

	for _, scope := range scopes {
		if scope == "" {
			continue
		}

		if result != "" {
			result += " "
		}

		result += scope
	}

	return result
}

func webauthnCredentialForTest(id string) webauthn.Credential {
	return webauthn.Credential{
		ID:        []byte(id),
		PublicKey: []byte("public-key-" + id),
	}
}

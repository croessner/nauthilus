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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	authv1 "github.com/croessner/nauthilus/v3/api/auth/v1"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	grpcI18NLockedKey     = "auth.policy.company.account_locked"
	grpcI18NLockedText    = "Login failed because the account is locked."
	grpcI18NLockedGerman  = "Anmeldung abgelehnt."
	grpcI18NLockedEnglish = "Login denied."
	grpcResolvedTarget    = "target@example.test"
)

func TestHandlerAuthenticateConsumesApplicationService(t *testing.T) {
	service := &recordingService{
		authOutcome: &core.AuthOutcome{
			Attributes: bktype.AttributeMapping{
				"uid": []any{"handler-user@example.test"},
				"ids": []any{"1", int64(2)},
			},
			Decision:     core.AuthDecisionOK,
			Session:      "session-1",
			AccountField: "uid",
			Backend:      definitions.BackendTest,
			HTTPStatus:   200,
		},
	}
	handler := New(service)

	response, err := handler.Authenticate(context.Background(), &authv1.AuthRequest{
		Username: "handler-user@example.test",
		Password: "secret",
		ClientIp: "203.0.113.20",
		Protocol: "imap",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	if service.authInput.Service != definitions.ServGRPC {
		t.Fatalf("service = %q, want %q", service.authInput.Service, definitions.ServGRPC)
	}

	if service.authInput.Mode != core.AuthModeAuthenticate {
		t.Fatalf("mode = %q, want %q", service.authInput.Mode, core.AuthModeAuthenticate)
	}

	if service.authInput.Credentials.Username != "handler-user@example.test" {
		t.Fatalf("username = %q, want handler-user@example.test", service.authInput.Credentials.Username)
	}

	if response.GetDecision() != authv1.AuthDecision_AUTH_DECISION_OK {
		t.Fatalf("decision = %v, want OK", response.GetDecision())
	}

	if !response.GetOk() {
		t.Fatal("expected ok response")
	}

	if response.GetAttributes()["ids"].GetValues()[1] != "2" {
		t.Fatalf("ids attribute = %#v, want stringified values", response.GetAttributes()["ids"].GetValues())
	}
}

func TestHandlerAuthenticatePassesIncomingMetadataToApplicationInput(t *testing.T) {
	service := &recordingService{
		authOutcome: &core.AuthOutcome{
			Decision:   core.AuthDecisionOK,
			Session:    "session-metadata",
			HTTPStatus: 200,
		},
	}
	handler := New(service)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-company-domain", " CompanyDE "))

	_, err := handler.Authenticate(ctx, &authv1.AuthRequest{
		Username: "metadata-user@example.test",
		Password: "secret",
		ClientIp: "203.0.113.20",
		Protocol: "imap",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	values := service.authInput.Context.RequestMetadata["x-company-domain"]
	if len(values) != 1 || values[0] != " CompanyDE " {
		t.Fatalf("request metadata = %#v, want x-company-domain value", service.authInput.Context.RequestMetadata)
	}
}

type grpcTransportOperationCase struct {
	invoke     func(*Handler, context.Context) error
	input      func(*recordingService) core.AuthInput
	name       string
	fullMethod string
	wantMode   core.AuthMode
}

func TestHandlerBackchannelOperationsBuildTrustedGRPCTransportInput(t *testing.T) {
	for _, test := range grpcTransportOperationCases() {
		t.Run(test.name, func(t *testing.T) {
			assertGRPCTransportOperation(t, test)
		})
	}
}

// grpcTransportOperationCases returns the transport-mapping case for each backchannel operation.
func grpcTransportOperationCases() []grpcTransportOperationCase {
	return []grpcTransportOperationCase{
		{
			name:       "authenticate",
			fullMethod: authv1.AuthService_Authenticate_FullMethodName,
			wantMode:   core.AuthModeAuthenticate,
			invoke: func(handler *Handler, ctx context.Context) error {
				_, err := handler.Authenticate(ctx, &authv1.AuthRequest{
					Username: "transport-user@example.test",
					Password: "secret",
				})

				return err
			},
			input: func(service *recordingService) core.AuthInput { return service.authInput },
		},
		{
			name:       "lookup identity",
			fullMethod: authv1.AuthService_LookupIdentity_FullMethodName,
			wantMode:   core.AuthModeLookupIdentity,
			invoke: func(handler *Handler, ctx context.Context) error {
				_, err := handler.LookupIdentity(ctx, &authv1.LookupIdentityRequest{
					Username: "transport-user@example.test",
				})

				return err
			},
			input: func(service *recordingService) core.AuthInput { return service.lookupInput },
		},
		{
			name:       "list accounts",
			fullMethod: authv1.AuthService_ListAccounts_FullMethodName,
			wantMode:   core.AuthModeListAccounts,
			invoke: func(handler *Handler, ctx context.Context) error {
				_, err := handler.ListAccounts(ctx, &authv1.ListAccountsRequest{})

				return err
			},
			input: func(service *recordingService) core.AuthInput { return service.listInput },
		},
	}
}

// assertGRPCTransportOperation verifies trusted transport facts for one handler operation.
func assertGRPCTransportOperation(t *testing.T, test grpcTransportOperationCase) {
	t.Helper()

	service := &recordingService{
		authOutcome:   &core.AuthOutcome{Decision: core.AuthDecisionOK},
		lookupOutcome: &core.AuthOutcome{Decision: core.AuthDecisionOK},
		listOutcome:   &core.ListAccountsOutcome{Decision: core.AuthDecisionOK},
	}
	handler := New(service)
	incoming := metadata.Pairs(
		"x-company-domain", " CompanyDE ",
		"x-nauthilus-transport-kind", "http",
		"x-nauthilus-listener", "spoofed-listener",
		"x-nauthilus-grpc-method", "/spoofed.Service/Method",
		"x-nauthilus-peer", "192.0.2.99",
		"x-nauthilus-mtls-identity", "spoofed-client",
		"x-nauthilus-protected", "false",
	)
	ctx := verifiedBackchannelGRPCContext(incoming)

	if err := test.invoke(handler, ctx); err != nil {
		t.Fatalf("operation returned error: %v", err)
	}

	input := test.input(service)

	if input.Mode != test.wantMode {
		t.Fatalf("mode = %q, want %q", input.Mode, test.wantMode)
	}

	if values := input.Context.RequestMetadata["x-company-domain"]; len(values) != 1 || values[0] != " CompanyDE " {
		t.Fatalf("request metadata = %#v, want cloned domain value", input.Context.RequestMetadata)
	}

	incoming["x-company-domain"][0] = "mutated-after-call"

	if got := input.Context.RequestMetadata["x-company-domain"][0]; got != " CompanyDE " {
		t.Fatalf("cloned metadata changed to %q after source mutation", got)
	}

	transport := input.Context.Transport

	if transport.Kind != grpcTransportKind || transport.Listener != grpcAuthorityListener {
		t.Fatalf("transport kind/listener = %q/%q, want grpc/grpc.authority", transport.Kind, transport.Listener)
	}

	if transport.GRPCMethod != test.fullMethod {
		t.Fatalf("gRPC method = %q, want %q", transport.GRPCMethod, test.fullMethod)
	}

	if transport.Peer != "203.0.113.45" {
		t.Fatalf("peer = %q, want server-observed 203.0.113.45", transport.Peer)
	}

	if !transport.Protected || transport.MTLSIdentity != "verified-backchannel-client" {
		t.Fatalf("protected/mTLS = %t/%q, want true/verified-backchannel-client", transport.Protected, transport.MTLSIdentity)
	}
}

func TestHandlerBackchannelTransportDoesNotExportUnverifiedMTLSIdentity(t *testing.T) {
	service := &recordingService{authOutcome: &core.AuthOutcome{Decision: core.AuthDecisionOK}}
	handler := New(service)
	ctx := unverifiedBackchannelGRPCContext(metadata.Pairs(
		"x-nauthilus-mtls-identity", "spoofed-client",
		"x-nauthilus-protected", "true",
	))

	_, err := handler.Authenticate(ctx, &authv1.AuthRequest{
		Username: "unverified-user@example.test",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	transport := service.authInput.Context.Transport
	if !transport.Protected {
		t.Fatal("protected = false, want completed confidential TLS transport")
	}

	if transport.MTLSIdentity != "" {
		t.Fatalf("mTLS identity = %q, want no unverified identity", transport.MTLSIdentity)
	}
}

// verifiedBackchannelGRPCContext constructs server-observed peer evidence with a verified client chain.
func verifiedBackchannelGRPCContext(md metadata.MD) context.Context {
	return backchannelGRPCContext(md, true)
}

// unverifiedBackchannelGRPCContext constructs protected TLS evidence without a verified client chain.
func unverifiedBackchannelGRPCContext(md metadata.MD) context.Context {
	return backchannelGRPCContext(md, false)
}

// backchannelGRPCContext constructs the listener evidence used by transport-mapping tests.
func backchannelGRPCContext(md metadata.MD, verified bool) context.Context {
	certificate := &x509.Certificate{Subject: pkix.Name{CommonName: "verified-backchannel-client"}}

	state := tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{certificate},
	}
	if verified {
		state.VerifiedChains = [][]*x509.Certificate{{certificate}}
	}

	ctx := metadata.NewIncomingContext(context.Background(), md)

	return peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.45"), Port: 43123},
		AuthInfo: credentials.TLSInfo{
			State:          state,
			CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		},
	})
}

func TestHandlerAuthenticateLocalizesPolicyI18NStatusFromIncomingMetadata(t *testing.T) {
	service := &recordingService{
		authOutcome: &core.AuthOutcome{
			Decision:             core.AuthDecisionFail,
			Session:              "session-i18n-grpc",
			StatusMessage:        grpcI18NLockedText,
			StatusMessageI18NKey: grpcI18NLockedKey,
			HTTPStatus:           403,
		},
	}
	resolver := &recordingGRPCStatusResolver{
		t: t,
		wantSelection: localization.StatusMessage{
			Text:    grpcI18NLockedText,
			I18NKey: grpcI18NLockedKey,
		},
		wantPreference: localization.LanguagePreference{
			Header: "de-DE,de;q=0.9,en;q=0.8",
		},
		resolved: localization.ResolvedStatusMessage{
			Text:      grpcI18NLockedGerman,
			Language:  "de",
			Key:       grpcI18NLockedKey,
			Localized: true,
		},
	}
	handler := NewWithResolver(service, resolver)
	stream := &recordingServerTransportStream{}
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("accept-language", "de-DE,de;q=0.9,en;q=0.8"),
	)
	ctx = grpc.NewContextWithServerTransportStream(ctx, stream)

	response, err := handler.Authenticate(ctx, &authv1.AuthRequest{
		Username: "localized-user@example.test",
		Password: "secret",
		ClientIp: "203.0.113.20",
		Protocol: "imap",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls)
	}

	if got := response.GetStatusMessage(); got != grpcI18NLockedGerman {
		t.Fatalf("status message = %q, want localized message", got)
	}

	if got := stream.header.Get("content-language"); len(got) != 1 || got[0] != "de" {
		t.Fatalf("content-language metadata = %#v, want de", got)
	}
}

func TestHandlerAuthenticatePolicyLanguageOverridesIncomingMetadata(t *testing.T) {
	service := &recordingService{
		authOutcome: &core.AuthOutcome{
			Decision:             core.AuthDecisionFail,
			Session:              "session-i18n-grpc-policy-language",
			StatusMessage:        grpcI18NLockedText,
			StatusMessageI18NKey: grpcI18NLockedKey,
			ResponseLanguage:     "en",
			HTTPStatus:           403,
		},
	}
	resolver := &recordingGRPCStatusResolver{
		t: t,
		wantSelection: localization.StatusMessage{
			Text:    grpcI18NLockedText,
			I18NKey: grpcI18NLockedKey,
		},
		wantPreference: localization.LanguagePreference{
			Policy: "en",
			Header: "de",
		},
		resolved: localization.ResolvedStatusMessage{
			Text:      grpcI18NLockedEnglish,
			Language:  "en",
			Key:       grpcI18NLockedKey,
			Localized: true,
		},
	}
	handler := NewWithResolver(service, resolver)
	stream := &recordingServerTransportStream{}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("accept-language", "de"))
	ctx = grpc.NewContextWithServerTransportStream(ctx, stream)

	response, err := handler.Authenticate(ctx, &authv1.AuthRequest{
		Username: "policy-language-user@example.test",
		Password: "secret",
		ClientIp: "203.0.113.20",
		Protocol: "imap",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	if got := response.GetStatusMessage(); got != grpcI18NLockedEnglish {
		t.Fatalf("status message = %q, want policy-selected language message", got)
	}

	if got := stream.header.Get("content-language"); len(got) != 1 || got[0] != "en" {
		t.Fatalf("content-language metadata = %#v, want en", got)
	}
}

func TestHandlerAuthenticateKeepsPlainStatusMessageWithoutI18NKey(t *testing.T) {
	service := &recordingService{
		authOutcome: &core.AuthOutcome{
			Decision:      core.AuthDecisionFail,
			Session:       "session-plain-grpc",
			StatusMessage: "Plain policy denial",
			HTTPStatus:    403,
		},
	}
	resolver := &recordingGRPCStatusResolver{t: t, failOnCall: true}
	handler := NewWithResolver(service, resolver)
	stream := &recordingServerTransportStream{}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("accept-language", "de"))
	ctx = grpc.NewContextWithServerTransportStream(ctx, stream)

	response, err := handler.Authenticate(ctx, &authv1.AuthRequest{
		Username: "plain-user@example.test",
		Password: "secret",
		ClientIp: "203.0.113.20",
		Protocol: "imap",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	if got := response.GetStatusMessage(); got != "Plain policy denial" {
		t.Fatalf("status message = %q, want plain status message", got)
	}

	if got := stream.header.Get("content-language"); len(got) != 0 {
		t.Fatalf("content-language metadata = %#v, want empty metadata", got)
	}
}

func TestHandlerAuthenticateMapsInputValidationToInvalidArgument(t *testing.T) {
	handler := New(&recordingService{
		authErr: &core.AuthInputError{Field: "username", Reason: "required"},
	})

	_, err := handler.Authenticate(context.Background(), &authv1.AuthRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.InvalidArgument)
	}
}

func TestAllowedOperationsAfterAuthenticateIncludesResolveUser(t *testing.T) {
	operations := allowedOperationsAfterAuth(AuthorityOperationAuthenticate)
	if !authorityOperationSet(operations)[AuthorityOperationResolveUser] {
		t.Fatalf("authenticate backend reference operations = %v, want resolve_user", operations)
	}
}

func TestAuthOutcomeToProtoPreservesCanonicalIdentityMetadata(t *testing.T) {
	response := authOutcomeToProto(&core.AuthOutcome{
		TOTPRecoveryField:       "recovery",
		UniqueUserIDField:       "entryUUID",
		DisplayNameField:        "displayName",
		Groups:                  []string{"users", "operators"},
		GroupDistinguishedNames: []string{"cn=users,dc=example,dc=test"},
	})

	if response.GetTotpRecoveryField() != "recovery" ||
		response.GetUniqueUserIdField() != "entryUUID" ||
		response.GetDisplayNameField() != "displayName" ||
		len(response.GetGroups()) != 2 || len(response.GetGroupDns()) != 1 {
		t.Fatalf("auth response identity metadata = %#v", response)
	}
}

func TestHandlerAuthenticateBackendRefUsesResolvedAccount(t *testing.T) {
	refStore := newRecordingBackendRefStore()
	service := &recordingService{
		authOutcome: &core.AuthOutcome{
			Attributes: bktype.AttributeMapping{
				"uid": []any{grpcResolvedTarget},
			},
			Decision:     core.AuthDecisionOK,
			Session:      "session-master",
			AccountField: "uid",
			Backend:      definitions.BackendTest,
			HTTPStatus:   200,
		},
	}
	handler := NewWithServices(service, nil, nil, refStore)

	_, err := handler.Authenticate(context.Background(), &authv1.AuthRequest{
		Username: grpcResolvedTarget + "*master@example.test",
		Password: "secret",
		ClientIp: "203.0.113.20",
		Protocol: "idp",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	if refStore.payload.Username != grpcResolvedTarget {
		t.Fatalf("backend ref username = %q, want %s", refStore.payload.Username, grpcResolvedTarget)
	}
}

func TestHandlerLookupIdentityConsumesApplicationService(t *testing.T) {
	service := &recordingService{
		lookupOutcome: &core.AuthOutcome{
			Attributes: bktype.AttributeMapping{
				"uid": []any{"lookup-user@example.test"},
			},
			Decision:     core.AuthDecisionOK,
			Session:      "session-lookup",
			AccountField: "uid",
			Backend:      definitions.BackendTest,
			HTTPStatus:   200,
		},
	}
	handler := New(service)

	response, err := handler.LookupIdentity(context.Background(), &authv1.LookupIdentityRequest{
		Username: "lookup-user@example.test",
		ClientIp: "203.0.113.22",
		Protocol: "imap",
	})
	if err != nil {
		t.Fatalf("LookupIdentity returned error: %v", err)
	}

	if service.lookupInput.Mode != core.AuthModeLookupIdentity {
		t.Fatalf("mode = %q, want %q", service.lookupInput.Mode, core.AuthModeLookupIdentity)
	}

	if service.lookupInput.Credentials.Username != "lookup-user@example.test" {
		t.Fatalf("username = %q, want lookup-user@example.test", service.lookupInput.Credentials.Username)
	}

	if response.GetDecision() != authv1.AuthDecision_AUTH_DECISION_OK {
		t.Fatalf("decision = %v, want OK", response.GetDecision())
	}

	if response.GetSession() != "session-lookup" {
		t.Fatalf("session = %q, want session-lookup", response.GetSession())
	}
}

func authorityOperationSet(operations []AuthorityOperation) map[AuthorityOperation]bool {
	result := make(map[AuthorityOperation]bool, len(operations))
	for _, operation := range operations {
		result[operation] = true
	}

	return result
}

func TestHandlerListAccountsConsumesApplicationService(t *testing.T) {
	service := &recordingService{
		listOutcome: &core.ListAccountsOutcome{
			Accounts: core.AccountList{"alpha@example.test", "zeta@example.test"},
			Session:  "session-2",
		},
	}
	handler := New(service)

	response, err := handler.ListAccounts(context.Background(), &authv1.ListAccountsRequest{
		ClientIp: "203.0.113.21",
	})
	if err != nil {
		t.Fatalf("ListAccounts returned error: %v", err)
	}

	if service.listInput.Mode != core.AuthModeListAccounts {
		t.Fatalf("mode = %q, want %q", service.listInput.Mode, core.AuthModeListAccounts)
	}

	if response.GetSession() != "session-2" {
		t.Fatalf("session = %q, want session-2", response.GetSession())
	}

	if len(response.GetAccounts()) != 2 || response.GetAccounts()[0] != "alpha@example.test" {
		t.Fatalf("accounts = %#v", response.GetAccounts())
	}
}

type recordingService struct {
	authOutcome   *core.AuthOutcome
	lookupOutcome *core.AuthOutcome
	listOutcome   *core.ListAccountsOutcome
	authErr       error
	lookupErr     error
	listErr       error
	authInput     core.AuthInput
	lookupInput   core.AuthInput
	listInput     core.AuthInput
}

func (s *recordingService) Authenticate(ctx context.Context, input core.AuthInput) (*core.AuthOutcome, error) {
	_ = ctx
	s.authInput = input

	return s.authOutcome, s.authErr
}

func (s *recordingService) LookupIdentity(ctx context.Context, input core.AuthInput) (*core.AuthOutcome, error) {
	_ = ctx
	s.lookupInput = input

	return s.lookupOutcome, s.lookupErr
}

func (s *recordingService) ListAccounts(ctx context.Context, input core.AuthInput) (*core.ListAccountsOutcome, error) {
	_ = ctx
	s.listInput = input

	return s.listOutcome, s.listErr
}

type recordingGRPCStatusResolver struct {
	t              *testing.T
	wantSelection  localization.StatusMessage
	wantPreference localization.LanguagePreference
	resolved       localization.ResolvedStatusMessage
	calls          int
	failOnCall     bool
}

func (r *recordingGRPCStatusResolver) ResolveStatusMessage(
	_ context.Context,
	selection localization.StatusMessage,
	preference localization.LanguagePreference,
) localization.ResolvedStatusMessage {
	r.calls++

	if r.failOnCall {
		r.t.Fatal("resolver should not be called for plain status messages")
	}

	if selection != r.wantSelection {
		r.t.Fatalf("selection = %#v, want %#v", selection, r.wantSelection)
	}

	if preference.Policy != r.wantPreference.Policy ||
		preference.Header != r.wantPreference.Header ||
		preference.Default != r.wantPreference.Default {
		r.t.Fatalf("preference = %#v, want %#v", preference, r.wantPreference)
	}

	return r.resolved
}

type recordingServerTransportStream struct {
	header  metadata.MD
	trailer metadata.MD
}

func (s *recordingServerTransportStream) Method() string {
	return "/nauthilus.auth.v1.AuthService/Authenticate"
}

func (s *recordingServerTransportStream) SetHeader(md metadata.MD) error {
	s.header = metadata.Join(s.header, md)

	return nil
}

func (s *recordingServerTransportStream) SendHeader(md metadata.MD) error {
	return s.SetHeader(md)
}

func (s *recordingServerTransportStream) SetTrailer(md metadata.MD) error {
	s.trailer = metadata.Join(s.trailer, md)

	return nil
}

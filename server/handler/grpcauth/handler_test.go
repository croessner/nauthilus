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

package grpcauth

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/core/localization"
	"github.com/croessner/nauthilus/server/definitions"
	authv1 "github.com/croessner/nauthilus/server/grpcapi/auth/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	grpcI18NLockedKey     = "auth.policy.company.account_locked"
	grpcI18NLockedText    = "Login failed because the account is locked."
	grpcI18NLockedGerman  = "Anmeldung abgelehnt."
	grpcI18NLockedEnglish = "Login denied."
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

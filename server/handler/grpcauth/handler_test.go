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
	"github.com/croessner/nauthilus/server/definitions"
	authv1 "github.com/croessner/nauthilus/server/grpcapi/auth/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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

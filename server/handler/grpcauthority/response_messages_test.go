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
	"strings"
	"testing"

	authv1 "github.com/croessner/nauthilus/v4/api/auth/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	grpcResponseTestFailure  = "Login rejected by example.test"
	grpcResponseTestTempFail = "Service busy at example.test"
)

// TestHandlerAuthenticateAppliesOperatorResponseMessages presents auth.response texts for default deny and tempfail.
func TestHandlerAuthenticateAppliesOperatorResponseMessages(t *testing.T) {
	handlerCfg := &config.FileSettings{Server: &config.ServerSection{AuthResponse: config.AuthResponseSection{
		FailureMessage:  grpcResponseTestFailure,
		TempFailMessage: grpcResponseTestTempFail,
	}}}

	tests := []struct {
		name      string
		outcome   core.AuthOutcome
		wantText  string
		wantError string
	}{
		{name: "uncaptured deny uses the handler config", outcome: core.AuthOutcome{
			Decision: core.AuthDecisionFail, StatusMessage: definitions.PasswordFail, HTTPStatus: 403,
		}, wantText: grpcResponseTestFailure},
		{name: "uncaptured tempfail replaces status and error", outcome: core.AuthOutcome{
			Decision: core.AuthDecisionTempFail, StatusMessage: definitions.TempFailDefault,
			Error: definitions.TempFailDefault, HTTPStatus: 500,
		}, wantText: grpcResponseTestTempFail, wantError: grpcResponseTestTempFail},
		{name: "captured settings win over the handler config", outcome: core.AuthOutcome{
			Decision: core.AuthDecisionFail, StatusMessage: definitions.PasswordFail, HTTPStatus: 403,
			ResponseSettings: core.AuthResponseSettings{Captured: true, FailureMessage: "Captured rejection"},
		}, wantText: "Captured rejection"},
		{name: "captured built-in defaults stay unchanged", outcome: core.AuthOutcome{
			Decision: core.AuthDecisionFail, StatusMessage: definitions.PasswordFail, HTTPStatus: 403,
			ResponseSettings: core.NewAuthResponseSettings(&config.FileSettings{Server: &config.ServerSection{}}),
		}, wantText: definitions.PasswordFail},
		{name: "specific tempfail reason stays", outcome: core.AuthOutcome{
			Decision: core.AuthDecisionTempFail, StatusMessage: definitions.TempFailNoTLS, HTTPStatus: 500,
		}, wantText: definitions.TempFailNoTLS},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome := test.outcome
			handler := New(&recordingService{authOutcome: &outcome}).withResponseConfig(handlerCfg)

			response, err := handler.Authenticate(context.Background(), &authv1.AuthRequest{
				Username: "operator-text@example.test",
				Password: "secret",
				Protocol: "imap",
			})
			if err != nil {
				t.Fatalf("Authenticate() error = %v", err)
			}

			if got := response.GetStatusMessage(); got != test.wantText {
				t.Fatalf("status message = %q, want %q", got, test.wantText)
			}

			if test.wantError != "" && response.GetError() != test.wantError {
				t.Fatalf("error = %q, want %q", response.GetError(), test.wantError)
			}

			if outcome.StatusMessage != test.outcome.StatusMessage {
				t.Fatal("presentation mutated the application outcome")
			}
		})
	}
}

// validatingServerTransportStream rejects non-ASCII text metadata like grpc-go and records accepted headers.
type validatingServerTransportStream struct {
	recordingServerTransportStream
}

// SetHeader rejects the whole metadata set when one text key carries bytes outside printable ASCII.
func (s *validatingServerTransportStream) SetHeader(md metadata.MD) error {
	for key, values := range md {
		if strings.HasSuffix(key, grpcBinaryMetadataSuffix) {
			continue
		}

		for _, value := range values {
			if grpcTextMetadataKey(key, value) != key {
				return errors.New("non-ASCII text metadata")
			}
		}
	}

	return s.recordingServerTransportStream.SetHeader(md)
}

// TestHandlerListAccountsKeepsMetadataForNonASCIIStatusTexts keeps the session and status metadata when an operator
// or localized status text contains non-ASCII characters.
func TestHandlerListAccountsKeepsMetadataForNonASCIIStatusTexts(t *testing.T) {
	const operatorText = "Bitte später erneut versuchen"

	service := &recordingService{listOutcome: &core.ListAccountsOutcome{
		Decision: core.AuthDecisionTempFail, Session: "session-non-ascii", StatusMessage: operatorText,
		Error: definitions.TempFailDefault, HTTPStatus: 500,
	}}
	stream := &validatingServerTransportStream{}
	ctx := grpc.NewContextWithServerTransportStream(context.Background(), stream)

	_, _ = New(service).ListAccounts(ctx, &authv1.ListAccountsRequest{ClientIp: "203.0.113.22"})

	if got := stream.header.Get("x-nauthilus-session"); len(got) != 1 || got[0] != "session-non-ascii" {
		t.Fatalf("session metadata = %#v, want session-non-ascii", got)
	}

	if got := stream.header.Get("auth-status-bin"); len(got) != 1 || got[0] != operatorText {
		t.Fatalf("binary status metadata = %#v, want %q", got, operatorText)
	}

	if got := stream.header.Get("auth-error"); len(got) != 1 || got[0] != definitions.TempFailDefault {
		t.Fatalf("ASCII error metadata = %#v, want the text key", got)
	}
}

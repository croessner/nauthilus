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
	"testing"

	authv1 "github.com/croessner/nauthilus/v4/api/auth/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
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

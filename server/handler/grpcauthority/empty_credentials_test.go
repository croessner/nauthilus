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
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
)

// TestHandlerAuthenticatePassesEmptyCredentialsToTheAuthPipeline pins that the gRPC authority does not pre-reject
// empty credential values: proto3 cannot distinguish a missing from an empty field, so the application service
// answers both as an ordinary failed login.
func TestHandlerAuthenticatePassesEmptyCredentialsToTheAuthPipeline(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{name: "empty username", password: "secret"},
		{name: "empty password", username: "empty-password@example.test"},
		{name: "empty username and password"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &recordingService{authOutcome: &core.AuthOutcome{
				Decision:      core.AuthDecisionFail,
				StatusMessage: definitions.PasswordFail,
				HTTPStatus:    403,
			}}

			response, err := New(service).Authenticate(context.Background(), &authv1.AuthRequest{
				Username: test.username,
				Password: test.password,
				ClientIp: "203.0.113.30",
				Protocol: "imap",
			})
			if err != nil {
				t.Fatalf("Authenticate() error = %v, want the auth-fail outcome", err)
			}

			if service.authInput.Credentials.Username != test.username {
				t.Fatalf("service username = %q, want %q", service.authInput.Credentials.Username, test.username)
			}

			if response.GetStatusMessage() != definitions.PasswordFail {
				t.Fatalf("status message = %q, want %q", response.GetStatusMessage(), definitions.PasswordFail)
			}
		})
	}
}

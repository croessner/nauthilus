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

package config

import (
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
)

const authResponseTestStorage = `storage:
  redis:
    primary:
      address: 127.0.0.1:6379
    password_nonce: nonce-secret-1234
    encryption_secret: redis-secret-1234
`

// TestAuthResponseMessagesDefaultToBuiltInTexts keeps the built-in client texts when auth.response is absent.
func TestAuthResponseMessagesDefaultToBuiltInTexts(t *testing.T) {
	cfg := loadFileSettingsFromContent(t, authResponseTestStorage)

	response := cfg.GetServer().GetAuthResponse()
	if got := response.GetFailureMessage(); got != definitions.PasswordFail {
		t.Fatalf("failure message = %q, want %q", got, definitions.PasswordFail)
	}

	if got := response.GetTempFailMessage(); got != definitions.TempFailDefault {
		t.Fatalf("tempfail message = %q, want %q", got, definitions.TempFailDefault)
	}

	var missing *AuthResponseSection
	if missing.GetFailureMessage() != definitions.PasswordFail || missing.GetTempFailMessage() != definitions.TempFailDefault {
		t.Fatal("nil auth.response section did not fall back to the built-in texts")
	}
}

// TestAuthResponseMessagesLoadOperatorOverrides maps auth.response onto the server getters.
func TestAuthResponseMessagesLoadOperatorOverrides(t *testing.T) {
	cfg := loadFileSettingsFromContent(t, authResponseTestStorage+`auth:
  response:
    failure_message: "Anmeldung fehlgeschlagen"
    tempfail_message: "Bitte später erneut versuchen"
`)

	response := cfg.GetServer().GetAuthResponse()
	if got := response.GetFailureMessage(); got != "Anmeldung fehlgeschlagen" {
		t.Fatalf("failure message = %q, want the operator override", got)
	}

	if got := response.GetTempFailMessage(); got != "Bitte später erneut versuchen" {
		t.Fatalf("tempfail message = %q, want the operator override", got)
	}
}

// TestAuthResponseMessagesRejectUnsafeTexts rejects texts that cannot travel in response headers.
func TestAuthResponseMessagesRejectUnsafeTexts(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{name: "failure newline", field: "failure_message", value: `"Invalid\nlogin"`},
		{name: "tempfail carriage return", field: "tempfail_message", value: `"Try\rlater"`},
		{name: "failure too long", field: "failure_message", value: strings.Repeat("x", 257)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := handleFileFromContent(t, authResponseTestStorage+"auth:\n  response:\n    "+test.field+": "+test.value+"\n")
			if err == nil {
				t.Fatalf("auth.response.%s = %s loaded, want a validation error", test.field, test.value)
			}

			if !strings.Contains(err.Error(), "auth.response."+test.field) {
				t.Fatalf("validation error = %v, want it to name %s", err, test.field)
			}
		})
	}
}

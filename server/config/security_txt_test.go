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

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateSecurityTxt_RejectsIncompleteConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SecurityTxt
		wantErr string
	}{
		{
			name: "missing contact",
			cfg: SecurityTxt{
				Enabled: true,
				Expires: "2026-12-31T23:59:00Z",
			},
			wantErr: "contacts must contain at least one URI",
		},
		{
			name: "missing expires",
			cfg: SecurityTxt{
				Enabled:  true,
				Contacts: []string{"mailto:security@example.test"},
			},
			wantErr: "expires or runtime.servers.http.security_txt.expires_after must be set",
		},
		{
			name: "invalid expires",
			cfg: SecurityTxt{
				Enabled:  true,
				Contacts: []string{"mailto:security@example.test"},
				Expires:  "2026-12-31",
			},
			wantErr: "RFC3339",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &FileSettings{Server: &ServerSection{SecurityTxt: tt.cfg}}

			err := settings.validateSecurityTxt()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateSecurityTxt() error = %v, want nil", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateSecurityTxt() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSecurityTxt_RejectsConflictingExpiration(t *testing.T) {
	settings := &FileSettings{
		Server: &ServerSection{
			SecurityTxt: SecurityTxt{
				Enabled:      true,
				Contacts:     []string{"mailto:security@example.test"},
				Expires:      "2026-12-31T23:59:00Z",
				ExpiresAfter: time.Hour,
			},
		},
	}

	err := settings.validateSecurityTxt()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("validateSecurityTxt() error = %v, want mutual exclusion error", err)
	}
}

func TestValidateSecurityTxt_RejectsHTTPWebURI(t *testing.T) {
	settings := &FileSettings{
		Server: &ServerSection{
			SecurityTxt: SecurityTxt{
				Enabled:  true,
				Contacts: []string{"http://example.test/security"},
				Expires:  "2026-12-31T23:59:00Z",
			},
		},
	}

	err := settings.validateSecurityTxt()
	if err == nil || !strings.Contains(err.Error(), "web URI must use https") {
		t.Fatalf("validateSecurityTxt() error = %v, want https URI error", err)
	}
}

func TestValidateSecurityTxt_AcceptsDynamicExpirationAndServedFiles(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "security-policy.md")
	keyPath := filepath.Join(dir, "security.asc")

	writeSecurityTxtTestFile(t, policyPath, []byte("# Policy\n"))
	writeSecurityTxtTestFile(t, keyPath, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"))

	settings := &FileSettings{
		Server: &ServerSection{
			SecurityTxt: SecurityTxt{
				Enabled:        true,
				Contacts:       []string{"mailto:security@example.test"},
				ExpiresAfter:   720 * time.Hour,
				EncryptionFile: keyPath,
				EncryptionURI:  "https://example.test/.well-known/security.asc",
				PolicyFile:     policyPath,
				PolicyURI:      "https://example.test/.well-known/security-policy",
			},
		},
	}

	if err := settings.validateSecurityTxt(); err != nil {
		t.Fatalf("validateSecurityTxt() error = %v, want nil", err)
	}
}

func TestValidateSecurityTxt_RejectsIncompleteServedFile(t *testing.T) {
	settings := &FileSettings{
		Server: &ServerSection{
			SecurityTxt: SecurityTxt{
				Enabled:      true,
				Contacts:     []string{"mailto:security@example.test"},
				ExpiresAfter: time.Hour,
				PolicyFile:   "/tmp/security-policy.md",
			},
		},
	}

	err := settings.validateSecurityTxt()
	if err == nil || !strings.Contains(err.Error(), "policy_file and runtime.servers.http.security_txt.policy_uri") {
		t.Fatalf("validateSecurityTxt() error = %v, want paired file and URI error", err)
	}
}

func TestValidateSecurityTxt_AcceptsRFC9116Minimum(t *testing.T) {
	settings := &FileSettings{
		Server: &ServerSection{
			SecurityTxt: SecurityTxt{
				Enabled:  true,
				Contacts: []string{"mailto:security@example.test"},
				Expires:  "2026-12-31T23:59:00Z",
			},
		},
	}

	if err := settings.validateSecurityTxt(); err != nil {
		t.Fatalf("validateSecurityTxt() error = %v, want nil", err)
	}
}

func TestApplyRuntimeSection_MaterializesSecurityTxt(t *testing.T) {
	settings := &FileSettings{
		Runtime: &RuntimeSection{
			Servers: RuntimeServersSection{
				HTTP: RuntimeHTTPServerSection{
					SecurityTxt: SecurityTxt{
						Enabled:  true,
						Contacts: []string{"mailto:security@example.test"},
						Expires:  "2026-12-31T23:59:00Z",
					},
				},
			},
		},
	}

	server := settings.materializeServerSection()

	if !server.GetSecurityTxt().IsEnabled() {
		t.Fatal("materializeServerSection() did not enable security_txt")
	}

	if got := server.GetSecurityTxt().GetContacts(); len(got) != 1 || got[0] != "mailto:security@example.test" {
		t.Fatalf("materialized contacts = %v, want mailto:security@example.test", got)
	}
}

func writeSecurityTxtTestFile(t *testing.T, path string, content []byte) {
	t.Helper()

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}

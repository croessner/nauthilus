// Package config contains tests for admin UI configuration validation.
package config

import "testing"

const (
	adminUIBasePath   = "/admin"
	adminUILocalAdmin = "local_admin"
	adminRoleValue    = "nauthilus.admin"
)

type adminUIValidationTestCase struct {
	name    string
	adminUI AdminUI
	wantErr bool
}

func TestSetDefaultAdminUISettings(t *testing.T) {
	t.Parallel()

	file := &FileSettings{
		Server: &ServerSection{},
	}

	if err := file.setDefaultAdminUISettings(); err != nil {
		t.Fatalf("setDefaultAdminUISettings() error = %v", err)
	}

	adminUI := file.GetServer().GetAdminUI()

	if got := adminUI.GetBasePath(); got != adminUIBasePath {
		t.Fatalf("GetBasePath() = %q, want %q", got, adminUIBasePath)
	}

	if got := adminUI.GetAuthMode(); got != adminUIAuthModeIDPSession {
		t.Fatalf("GetAuthMode() = %q, want %q", got, adminUIAuthModeIDPSession)
	}
}

func TestValidateAdminUI_IDPSessionAndAPIOIDC(t *testing.T) {
	t.Parallel()

	runAdminUIValidationTests(t, idpSessionAndAPIOIDCTestCases())
}

func TestValidateAdminUI_LocalAdmin(t *testing.T) {
	t.Parallel()

	tests := []adminUIValidationTestCase{
		{
			name: "local_admin without enforcement",
			adminUI: AdminUI{
				Enabled:  true,
				AuthMode: adminUILocalAdmin,
				Network: AdminUINetwork{
					EnforceForLocalAdmin: false,
					SourceIPAllowlist:    []string{"127.0.0.1/32"},
				},
			},
			wantErr: true,
		},
		{
			name: "local_admin without allowlist",
			adminUI: AdminUI{
				Enabled:  true,
				AuthMode: adminUILocalAdmin,
				Network: AdminUINetwork{
					EnforceForLocalAdmin: true,
				},
			},
			wantErr: true,
		},
		{
			name: "local_admin valid",
			adminUI: AdminUI{
				Enabled:  true,
				AuthMode: adminUILocalAdmin,
				Network: AdminUINetwork{
					EnforceForLocalAdmin: true,
					SourceIPAllowlist:    []string{"127.0.0.1/32", "::1/128"},
				},
			},
			wantErr: false,
		},
	}

	runAdminUIValidationTests(t, tests)
}

func runAdminUIValidationTests(t *testing.T, tests []adminUIValidationTestCase) {
	t.Helper()

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			file := &FileSettings{
				Server: &ServerSection{
					AdminUI: tt.adminUI,
				},
			}

			err := file.validateAdminUI()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAdminUI() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func idpSessionAndAPIOIDCTestCases() []adminUIValidationTestCase {
	return []adminUIValidationTestCase{
		{
			name: "disabled",
			adminUI: AdminUI{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "idp_session missing required_role_values",
			adminUI: AdminUI{
				Enabled:  true,
				AuthMode: adminUIAuthModeIDPSession,
			},
			wantErr: true,
		},
		{
			name: "idp_session with required_role_values",
			adminUI: AdminUI{
				Enabled:  true,
				AuthMode: adminUIAuthModeIDPSession,
				Authorization: AdminUIAuthorization{
					RequiredRoleValues: []string{adminRoleValue},
				},
			},
			wantErr: false,
		},
		{
			name: "api oidc enabled without scopes",
			adminUI: AdminUI{
				Enabled:  true,
				AuthMode: adminUIAuthModeIDPSession,
				Authorization: AdminUIAuthorization{
					RequiredRoleValues: []string{adminRoleValue},
				},
				APIOIDC: AdminUIAPIOIDC{
					Enabled: true,
				},
			},
			wantErr: true,
		},
		{
			name: "idp_session plus api oidc valid",
			adminUI: AdminUI{
				Enabled:  true,
				AuthMode: adminUIAuthModeIDPSession,
				Authorization: AdminUIAuthorization{
					RequiredRoleValues: []string{adminRoleValue},
					RequiredScopes:     []string{adminRoleValue},
				},
				APIOIDC: AdminUIAPIOIDC{
					Enabled: true,
				},
			},
			wantErr: false,
		},
	}
}

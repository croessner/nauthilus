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

package config_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
)

const supportMCPExamplePath = "server/docs/examples/support_mcp.yml"

// setSupportMCPExampleSecrets provides synthetic secrets for the example's environment references.
func setSupportMCPExampleSecrets(t *testing.T) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("OIDC_SIGNING_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	t.Setenv("LOKI_READ_TOKEN", "example-loki-token")
	t.Setenv("PROMETHEUS_READ_TOKEN", "example-prometheus-token")
	t.Setenv("REDIS_ENCRYPTION_SECRET", "example-redis-encryption-secret-2026")
	t.Setenv("REDIS_PASSWORD_NONCE", "example-redis-password-nonce-2026")
	t.Setenv("CLICKHOUSE_HISTORY_PASSWORD", "example-history-reader")
	t.Setenv("FRONTEND_ENCRYPTION_SECRET", "example-frontend-encryption-secret-2026")
	t.Setenv("DCR_SOURCE_HMAC_KEY", "example-dcr-source-hmac-key-2026-0123456789")
}

// loadSupportMCPExample writes the example with an optional edit and loads it through the production loader.
func loadSupportMCPExample(t *testing.T, edit func(string) string) (config.File, error) {
	t.Helper()

	root := policyMigrationRepositoryRoot(t)

	source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(supportMCPExamplePath)))
	if err != nil {
		t.Fatal(err)
	}

	// The default frontend resource paths are relative to the working directory of a server started from the
	// repository root.
	t.Chdir(root)

	content := string(source)
	if edit != nil {
		content = edit(content)
	}

	path := filepath.Join(t.TempDir(), "support_mcp.yml")
	if err = os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return prepareProductionPolicyPathResult(t, "yaml", path)
}

// TestSupportMCPExamplePassesProductionConfigCheck loads the documented example through the real schema and
// validators and checks the materialized MCP, hosted resource, and diagnostics settings.
func TestSupportMCPExamplePassesProductionConfigCheck(t *testing.T) {
	setSupportMCPExampleSecrets(t)

	candidate, err := loadSupportMCPExample(t, nil)
	if err != nil {
		t.Fatalf("load support MCP example: %v", err)
	}

	settings, ok := candidate.(*config.FileSettings)
	if !ok {
		t.Fatalf("candidate type = %T", candidate)
	}

	assertExampleMCPAndHostedResource(t, settings)
	assertExampleDiagnostics(t, settings)
}

// assertExampleMCPAndHostedResource checks the materialized MCP listener and hosted resource of the example.
func assertExampleMCPAndHostedResource(t *testing.T, settings *config.FileSettings) {
	t.Helper()

	mcp := settings.GetMCPServer()
	if !mcp.Enabled || mcp.HostedResource != "support-mcp" || mcp.GetAddress() != "127.0.0.1:9097" {
		t.Fatalf("mcp = %+v", mcp)
	}

	hosted, found := settings.GetIDP().OIDC.FindHostedResource("support-mcp")
	if !found || hosted.Resource != "https://login.example.org/mcp" || !hosted.AdmitsClientID("support-cli") ||
		hosted.UserRight.From != config.HostedResourceUserRightFromGroups {
		t.Fatalf("hosted resource = %+v", hosted)
	}

	if !settings.GetIDP().OIDC.DynamicClientRegistration.Enabled {
		t.Fatal("the example keeps DCR for mail clients")
	}
}

// assertExampleDiagnostics checks the materialized diagnostics sources of the example.
func assertExampleDiagnostics(t *testing.T, settings *config.FileSettings) {
	t.Helper()

	operations := settings.GetOperationsDiagnostics()
	if !operations.Enabled {
		t.Fatalf("operations = %+v", operations)
	}

	for name, source := range map[string]*config.HistoricalDiagnosticsSource{"loki": &operations.Sources.Loki,
		"prometheus": &operations.Sources.Prometheus} {
		if !source.Enabled || source.BearerToken.IsZero() || source.GetQueryProfile() != config.DiagnosticsQueryProfileNauthilus {
			t.Fatalf("%s source = %+v", name, source)
		}
	}
}

// TestSupportMCPExampleRejectsUnsafeVariants pins that the documented boundaries are enforced at load time.
func TestSupportMCPExampleRejectsUnsafeVariants(t *testing.T) {
	setSupportMCPExampleSecrets(t)

	for name, tc := range map[string]struct {
		edit string
		with string
		want string
	}{
		"dcr admission block":     {"        static_clients: [support-cli]", "        static_clients: [support-cli]\n        dynamic_clients:\n          enabled: true", "dynamic_clients"},
		"dynamic client listed":   {"static_clients: [support-cli]", "static_clients: [dcr_abc]", "configured static client"},
		"attribute user right":    {"from: groups", "from: attribute", "user_right.from"},
		"device grant":            {"grant_types: [authorization_code, refresh_token]", "grant_types: [authorization_code, " + definitions.OIDCFlowDeviceCode + "]", "grant_types"},
		"no mfa":                  {"require_mfa: [totp, webauthn]", "require_mfa: []", "require MFA"},
		"https without proxies":   {`trusted_proxies: ["127.0.0.1/32"]`, "trusted_proxies: []", "trusted_proxies"},
		"unknown hosted resource": {"hosted_resource: support-mcp", "hosted_resource: other", "hosted_resource"},
		"caller supplied logql":   {"query_profile: nauthilus_diagnostics", "query_profile: custom", "query_profile"},
		"selector with quotes":    {"app: nauthilus", `app: 'nauth"ilus'`, "selector"},
		"window above 24 hours":   {"max_time_window: 1h", "max_time_window: 48h", "max_time_window"},
		"two loki credentials":    {`bearer_token: "${LOKI_READ_TOKEN}"`, "bearer_token: \"${LOKI_READ_TOKEN}\"\n          basic_auth:\n            username: u\n            password: p", "mutually exclusive"},
		"oversized mcp requests":  {"max_request_bytes: 65536", "max_request_bytes: 4194304", "max_request_bytes"},
		"prometheus url query":    {`url: "https://prometheus.example.org"`, `url: "https://prometheus.example.org?q=1"`, "sources.prometheus.url"},
		"prometheus selector":     {"job: nauthilus", `job: 'nauth"ilus'`, "sources.prometheus.selector"},
		"prometheus two secrets":  {`bearer_token: "${PROMETHEUS_READ_TOKEN}"`, "bearer_token: \"${PROMETHEUS_READ_TOKEN}\"\n          basic_auth:\n            username: u\n            password: p", "sources.prometheus"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadSupportMCPExample(t, func(content string) string {
				if !strings.Contains(content, tc.edit) {
					t.Fatalf("example lost fragment %q", tc.edit)
				}

				return strings.Replace(content, tc.edit, tc.with, 1)
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("load = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

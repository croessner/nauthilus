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

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	stdlog "log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/app/bootfx"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/spf13/viper"
)

const liveConfigDumpSource = `policy:
  api:
    enabled: true
    http:
      enabled: true
    clients:
      - principal: dump-client
        authentication_kinds: [basic]
        authentication:
          basic:
            username: dump-user
            password: policy-basic-secret
        targets:
          - namespace: mail
            actions: [submit]
        allowed_schemas: [mail/submit/v1]
  namespaces:
    mail:
      providers:
        signer:
          kind: native
          module: signer
          failure: indeterminate
          secrets:
            token: provider-secret
      effects:
        notify:
          kind: obligation
          execution: return_only
          secrets:
            webhook: effect-secret
`

func TestRunConfigDumpDefaults(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := runConfigDumpDefaults(stdout, stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}

	if !strings.Contains(stdout.String(), `runtime.servers.http.middlewares.logging = true`) {
		t.Fatalf("unexpected stdout output: %q", stdout.String())
	}
}

func TestRunConfigDumpNonDefaultsNilSetup(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := runConfigDumpNonDefaults(nil, stdout, stderr)
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "configuration dump failed: setup function is nil") {
		t.Fatalf("unexpected stderr output: %q", stderr.String())
	}
}

func TestRunConfigDumpNonDefaultsSetupError(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := runConfigDumpNonDefaults(func() (config.File, error) {
		return nil, errors.New("broken config")
	}, stdout, stderr)
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "configuration dump failed: broken config") {
		t.Fatalf("unexpected stderr output: %q", stderr.String())
	}
}

func TestRunConfigDumpNonDefaultsRejectsNilSnapshot(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := runConfigDumpNonDefaults(func() (config.File, error) {
		return nil, nil
	}, stdout, stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "configuration dump failed: configuration snapshot is nil") {
		t.Fatalf("unexpected stderr output: %q", stderr.String())
	}
}

func TestRunConfigDumpNonDefaultsUsesPreparedConfigurationSnapshot(t *testing.T) {
	installLiveConfigDumpFixture(t)

	tests := []struct {
		assert func(*testing.T, string)
		format config.DumpFormat
		name   string
	}{
		{name: "canonical", format: config.DumpFormatCanonical, assert: assertCanonicalPolicyDumpRedactions},
		{name: "json", format: config.DumpFormatJSON, assert: assertStructuredPolicyDumpRedactions},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dump := runPreparedConfigDump(t, test.format)
			assertConfigDumpOmitsSecrets(t, dump)
			test.assert(t, dump)
		})
	}
}

// installLiveConfigDumpFixture points command preparation at one valid unified policy file.
func installLiveConfigDumpFixture(t *testing.T) {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), "nauthilus.yml")

	if err := os.WriteFile(configPath, []byte(liveConfigDumpSource), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	previousPath := config.ConfigFilePath
	previousType := config.ConfigFileType
	previousLogWriter := stdlog.Writer()
	config.ConfigFilePath = configPath
	config.ConfigFileType = "yaml"

	config.SetConfigDumpPrintSensitiveValues(false)
	viper.Reset()
	t.Cleanup(func() {
		config.ConfigFilePath = previousPath
		config.ConfigFileType = previousType

		stdlog.SetOutput(previousLogWriter)
		viper.Reset()
	})
}

// runPreparedConfigDump executes the live command loader for one dump format.
func runPreparedConfigDump(t *testing.T, format config.DumpFormat) string {
	t.Helper()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	var exitCode int

	if format == config.DumpFormatCanonical {
		exitCode = runConfigDumpNonDefaults(bootfx.SetupConfiguration, stdout, stderr)
	} else {
		exitCode = runConfigDumpNonDefaultsWithFormat(bootfx.SetupConfiguration, format, stdout, stderr)
	}

	if exitCode != 0 {
		t.Fatalf("configuration dump exit code = %d, stderr = %q", exitCode, stderr.String())
	}

	if ambient := viper.AllSettings(); ambient["policy"] != nil {
		t.Fatalf("command preparation published policy into ambient Viper settings: %#v", ambient)
	}

	return stdout.String()
}

// assertCanonicalPolicyDumpRedactions verifies exact canonical live dump paths.
func assertCanonicalPolicyDumpRedactions(t *testing.T, dump string) {
	t.Helper()

	if got := requireCanonicalConfigDumpValue(t, dump, "policy.api.enabled"); got != "true" {
		t.Fatalf("policy.api.enabled = %s, want true", got)
	}

	passwordPath := "policy.api.clients[0].authentication.basic.password"
	if got := requireCanonicalConfigDumpValue(t, dump, passwordPath); got != `"***REDACTED***"` {
		t.Fatalf("%s = %s, want quoted redaction", passwordPath, got)
	}

	secretPaths := map[string]string{
		"policy.namespaces.mail.providers.signer.secrets": `{"token": "***REDACTED***"}`,
		"policy.namespaces.mail.effects.notify.secrets":   `{"webhook": "***REDACTED***"}`,
	}

	for path, want := range secretPaths {
		if got := requireCanonicalConfigDumpValue(t, dump, path); got != want {
			t.Fatalf("%s = %s, want %s", path, got, want)
		}
	}
}

// requireCanonicalConfigDumpValue returns one exact path-owned canonical value.
func requireCanonicalConfigDumpValue(t *testing.T, dump string, path string) string {
	t.Helper()

	prefix := path + " = "

	for _, line := range strings.Split(dump, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}

	t.Fatalf("configuration dump is missing exact path %q in %q", path, dump)

	return ""
}

// assertConfigDumpOmitsSecrets verifies that no source secret reaches command output.
func assertConfigDumpOmitsSecrets(t *testing.T, dump string) {
	t.Helper()

	for _, secretValue := range []string{"policy-basic-secret", "provider-secret", "effect-secret"} {
		if strings.Contains(dump, secretValue) {
			t.Fatalf("configuration dump exposed %q in %q", secretValue, dump)
		}
	}
}

// assertStructuredPolicyDumpRedactions verifies exact JSON paths from the live dump path.
func assertStructuredPolicyDumpRedactions(t *testing.T, dump string) {
	t.Helper()

	root := make(map[string]any)

	if err := json.Unmarshal([]byte(dump), &root); err != nil {
		t.Fatalf("json.Unmarshal() error = %v for %q", err, dump)
	}

	policy := requireConfigDumpMap(t, root, "policy")
	api := requireConfigDumpMap(t, policy, "api")

	if got := api["enabled"]; got != true {
		t.Fatalf("policy.api.enabled = %#v, want true", got)
	}

	clients := requireConfigDumpSlice(t, api, "clients")

	if got := requireConfigDumpBasicPassword(t, clients); got != "***REDACTED***" {
		t.Fatalf("policy.api.clients[0].authentication.basic.password = %#v, want redaction", got)
	}

	namespaces := requireConfigDumpMap(t, policy, "namespaces")
	mail := requireConfigDumpMap(t, namespaces, "mail")
	providers := requireConfigDumpMap(t, mail, "providers")
	signer := requireConfigDumpMap(t, providers, "signer")
	providerSecrets := requireConfigDumpMap(t, signer, "secrets")

	if got := providerSecrets["token"]; got != "***REDACTED***" {
		t.Fatalf("policy.namespaces.mail.providers.signer.secrets.token = %#v, want redaction", got)
	}

	effects := requireConfigDumpMap(t, mail, "effects")
	notify := requireConfigDumpMap(t, effects, "notify")
	effectSecrets := requireConfigDumpMap(t, notify, "secrets")

	if got := effectSecrets["webhook"]; got != "***REDACTED***" {
		t.Fatalf("policy.namespaces.mail.effects.notify.secrets.webhook = %#v, want redaction", got)
	}
}

// requireConfigDumpBasicPassword resolves the exact first Policy-Basic password path.
func requireConfigDumpBasicPassword(t *testing.T, clients []any) any {
	t.Helper()

	if len(clients) != 1 {
		t.Fatalf("policy.api.clients length = %d, want 1", len(clients))
	}

	client, ok := clients[0].(map[string]any)

	if !ok {
		t.Fatalf("policy.api.clients[0] = %T, want map[string]any", clients[0])
	}

	authentication := requireConfigDumpMap(t, client, "authentication")
	basic := requireConfigDumpMap(t, authentication, "basic")

	return basic["password"]
}

// requireConfigDumpMap returns one required structured dump object.
func requireConfigDumpMap(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()

	value, ok := parent[key].(map[string]any)

	if !ok {
		t.Fatalf("configuration dump key %q = %T, want map[string]any", key, parent[key])
	}

	return value
}

// requireConfigDumpSlice returns one required structured dump list.
func requireConfigDumpSlice(t *testing.T, parent map[string]any, key string) []any {
	t.Helper()

	value, ok := parent[key].([]any)

	if !ok {
		t.Fatalf("configuration dump key %q = %T, want []any", key, parent[key])
	}

	return value
}

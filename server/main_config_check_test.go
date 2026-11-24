package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
)

func TestRunConfigCheck(t *testing.T) {
	t.Run("valid configuration returns zero", func(t *testing.T) {
		stderr := &bytes.Buffer{}

		exitCode := runConfigCheck(func() error {
			return nil
		}, stderr)

		if exitCode != 0 {
			t.Fatalf("expected exit code 0, got %d", exitCode)
		}

		if stderr.Len() != 0 {
			t.Fatalf("expected no stderr output, got %q", stderr.String())
		}
	})

	t.Run("invalid configuration returns one", func(t *testing.T) {
		stderr := &bytes.Buffer{}

		exitCode := runConfigCheck(func() error {
			return errors.New("invalid config")
		}, stderr)

		if exitCode != 1 {
			t.Fatalf("expected exit code 1, got %d", exitCode)
		}

		if !strings.Contains(stderr.String(), "configuration check failed: invalid config") {
			t.Fatalf("unexpected stderr output: %q", stderr.String())
		}
	})

	t.Run("nil setup function returns one", func(t *testing.T) {
		stderr := &bytes.Buffer{}

		exitCode := runConfigCheck(nil, stderr)

		if exitCode != 1 {
			t.Fatalf("expected exit code 1, got %d", exitCode)
		}

		if !strings.Contains(stderr.String(), "configuration check failed: setup function is nil") {
			t.Fatalf("unexpected stderr output: %q", stderr.String())
		}
	})
}

// TestCheckConfigurationCompilesPolicyCatalog reproduces a configuration check that returned success for a
// configuration whose policy catalog the server start then rejected.
func TestCheckConfigurationCompilesPolicyCatalog(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		wantError string
	}{
		{name: "valid catalog", condition: "{always: true}"},
		{name: "rule fact mismatch", condition: "{attribute: mail.unknown_flag, is: true}", wantError: "policy rule fact mismatch"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := checkConfiguration(func() (config.File, error) {
				return configCheckPolicyFile(t, test.condition), nil
			})

			if test.wantError == "" {
				if err != nil {
					t.Fatalf("checkConfiguration() error = %v", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("checkConfiguration() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

// configCheckPolicyFile decodes a minimal non-auth Policy configuration with one configured rule condition.
func configCheckPolicyFile(t *testing.T, condition string) config.File {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(`policy:
  namespaces:
    mail:
      schema_contributions:
        static:
          submit:
            versions:
              v1: {facts: []}
      policy_sets:
        default:
          rules:
            - name: configured_permit
              checkpoint: final_decision
              if: `+condition+`
              then: {decision: permit}
  targets:
    - namespace: mail
      action: submit
      schema: mail/submit/v1
      default_policy: mail/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision: {policy_sets: [mail/default]}
`))
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	return &config.FileSettings{Policy: document.Policy}
}

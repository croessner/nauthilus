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

//nolint:goconst,wsl_v5 // Config-map literals mirror public configuration keys.
package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestHandleFileBackendHealthChecksAuthMechanismTargetDefaultsAndNormalizes(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setBackendHealthChecksAuthMechanismTestConfig([]any{
		map[string]any{
			"protocol":   "imap",
			"host":       "127.0.0.1",
			"port":       993,
			"deep_check": true,
		},
		map[string]any{
			"protocol":       "smtp",
			"host":           "127.0.0.1",
			"port":           465,
			"deep_check":     true,
			"auth_mechanism": "plain",
		},
		map[string]any{
			"protocol":       "pop3",
			"host":           "127.0.0.1",
			"port":           995,
			"deep_check":     true,
			"auth_mechanism": "UserPass",
		},
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("handle file failed: %v", err)
	}

	targets := cfg.GetBackendServerMonitoring().GetBackendServers()
	if len(targets) != 3 {
		t.Fatalf("expected three targets, got %d", len(targets))
	}

	if got := targets[0].GetAuthMechanism(); got != BackendAuthMechanismAuto {
		t.Fatalf("expected missing target auth mechanism to default to %q, got %q", BackendAuthMechanismAuto, got)
	}

	if got := targets[1].GetAuthMechanism(); got != BackendAuthMechanismPlain {
		t.Fatalf("expected lowercase auth mechanism to normalize to %q, got %q", BackendAuthMechanismPlain, got)
	}

	if got := targets[2].GetAuthMechanism(); got != BackendAuthMechanismUserPass {
		t.Fatalf("expected mixed-case auth mechanism to normalize to %q, got %q", BackendAuthMechanismUserPass, got)
	}
}

func TestHandleFileBackendHealthChecksRejectsServiceLevelAuthMechanism(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setBackendHealthChecksAuthMechanismTestConfig([]any{
		map[string]any{
			"protocol":   "imap",
			"host":       "127.0.0.1",
			"port":       993,
			"deep_check": true,
		},
	})
	viper.Set("auth.services.backend_health_checks.auth_mechanism", "PLAIN")

	cfg := &FileSettings{}
	err := cfg.HandleFile()
	if err == nil {
		t.Fatal("expected service-level auth_mechanism to be rejected")
	}

	if !strings.Contains(err.Error(), "auth.services.backend_health_checks") || !strings.Contains(err.Error(), "auth_mechanism") {
		t.Fatalf("expected error to mention service-level auth_mechanism, got %v", err)
	}
}

func TestHandleFileBackendHealthChecksRejectsUnsupportedAuthMechanisms(t *testing.T) {
	unsupportedMechanisms := []string{
		"SCRAM-SHA-256",
		"OAUTHBEARER",
		"XOAUTH2",
		"EXTERNAL",
		"CRAM-MD5",
		"DIGEST-MD5",
	}

	for _, mechanism := range unsupportedMechanisms {
		t.Run(mechanism, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)

			setBackendHealthChecksAuthMechanismTestConfig([]any{
				map[string]any{
					"protocol":       "imap",
					"host":           "127.0.0.1",
					"port":           993,
					"deep_check":     true,
					"auth_mechanism": mechanism,
				},
			})

			cfg := &FileSettings{}
			err := cfg.HandleFile()
			if err == nil {
				t.Fatalf("expected unsupported auth mechanism %q to be rejected", mechanism)
			}

			if !strings.Contains(err.Error(), "auth_mechanism") {
				t.Fatalf("expected error to mention auth_mechanism, got %v", err)
			}
		})
	}
}

func TestKnownConfigSyntaxKeysIncludesBackendHealthCheckTargetAuthMechanism(t *testing.T) {
	_, _, level3, err := KnownConfigSyntaxKeys()
	if err != nil {
		t.Fatalf("known syntax keys failed: %v", err)
	}

	if !containsString(level3, "auth_mechanism") {
		t.Fatal("expected generated config syntax keys to include target auth_mechanism")
	}
}

// setBackendHealthChecksAuthMechanismTestConfig installs a minimal viper config for target auth tests.
func setBackendHealthChecksAuthMechanismTestConfig(targets []any) {
	viper.Set("auth", map[string]any{
		"services": map[string]any{
			"enabled": []any{"backend_health_checks"},
			"backend_health_checks": map[string]any{
				"targets": targets,
			},
		},
	})
	viper.Set("storage", map[string]any{
		"redis": map[string]any{
			"primary": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})
}

// containsString reports whether a generated syntax-key slice includes the expected key.
func containsString(values []string, want string) bool {
	return slices.Contains(values, want)
}

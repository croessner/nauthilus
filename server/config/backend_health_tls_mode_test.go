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

//nolint:goconst,wsl_v5 // Config-map literals mirror the public configuration contract.
package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestHandleFileBackendHealthChecksAcceptsTLSMode(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setBackendHealthChecksTLSModeTestConfig(map[string]any{
		"protocol":   "imap",
		"host":       "127.0.0.1",
		"port":       143,
		"deep_check": true,
		"tls_mode":   "StArTtLs",
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("expected mixed-case tls_mode to load and normalize: %v", err)
	}

	targets := cfg.GetBackendServers()
	if len(targets) != 1 || targets[0].TLSMode != BackendTLSModeStartTLS || targets[0].GetTLSMode() != BackendTLSModeStartTLS {
		t.Fatalf("normalized TLS mode = %#v, want %q", targets, BackendTLSModeStartTLS)
	}
}

func TestBackendServerTLSModePreservesLegacyDefaults(t *testing.T) {
	testCases := []struct {
		name   string
		server *BackendServer
		want   BackendTLSMode
	}{
		{name: "plain-default", server: &BackendServer{Protocol: "imap"}, want: BackendTLSModePlain},
		{name: "legacy-implicit", server: &BackendServer{Protocol: "imap", TLS: true}, want: BackendTLSModeImplicit},
		{name: "legacy-sieve-starttls", server: &BackendServer{Protocol: "sieve"}, want: BackendTLSModeStartTLS},
		{name: "explicit-implicit", server: &BackendServer{Protocol: "sieve", TLSMode: BackendTLSModeImplicit}, want: BackendTLSModeImplicit},
		{name: "explicit-plain", server: &BackendServer{Protocol: "sieve", TLSMode: BackendTLSModePlain}, want: BackendTLSModePlain},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := testCase.server.GetTLSMode(); got != testCase.want {
				t.Fatalf("TLS mode = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestHandleFileBackendHealthChecksRejectsInvalidTLSModeCombinations(t *testing.T) {
	for _, testCase := range invalidBackendTLSModeTestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)

			setBackendHealthChecksTLSModeTestConfig(testCase.target)

			cfg := &FileSettings{}
			err := cfg.HandleFile()
			if err == nil {
				t.Fatal("expected invalid tls_mode configuration to fail")
			}

			if !strings.Contains(strings.ToLower(err.Error()), "tls_mode") {
				t.Fatalf("expected error to mention tls_mode, got %v", err)
			}
		})
	}
}

// invalidBackendTLSModeTestCases defines rejected public configuration combinations.
func invalidBackendTLSModeTestCases() []struct {
	name   string
	target map[string]any
} {
	return []struct {
		name   string
		target map[string]any
	}{
		{
			name: "unknown-mode",
			target: map[string]any{
				"protocol": "imap",
				"host":     "127.0.0.1",
				"port":     143,
				"tls_mode": "opportunistic",
			},
		},
		{
			name: "legacy-conflict",
			target: map[string]any{
				"protocol":   "imap",
				"host":       "127.0.0.1",
				"port":       143,
				"deep_check": true,
				"tls":        true,
				"tls_mode":   "starttls",
			},
		},
		{
			name: "http-starttls",
			target: map[string]any{
				"protocol":   "http",
				"host":       "127.0.0.1",
				"port":       80,
				"deep_check": true,
				"tls_mode":   "starttls",
			},
		},
		{
			name: "starttls-without-deep-check",
			target: map[string]any{
				"protocol": "pop3",
				"host":     "127.0.0.1",
				"port":     110,
				"tls_mode": "starttls",
			},
		},
	}
}

func TestKnownConfigSyntaxKeysIncludesBackendHealthCheckTLSMode(t *testing.T) {
	_, _, level3, err := KnownConfigSyntaxKeys()
	if err != nil {
		t.Fatalf("known syntax keys failed: %v", err)
	}

	if !containsString(level3, "tls_mode") {
		t.Fatal("expected generated config syntax keys to include target tls_mode")
	}
}

// setBackendHealthChecksTLSModeTestConfig installs one minimal backend-health target.
func setBackendHealthChecksTLSModeTestConfig(target map[string]any) {
	viper.Set("auth", map[string]any{
		"services": map[string]any{
			"enabled": []any{"backend_health_checks"},
			"backend_health_checks": map[string]any{
				"targets": []any{target},
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

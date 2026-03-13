package main

import (
	"strings"
	"testing"
)

func TestValidateDeveloperModeBindAddress(t *testing.T) {
	tests := []struct {
		name         string
		devMode      bool
		listen       string
		expectErr    bool
		errorContain string
	}{
		{
			name:      "non-dev-mode-allows-any-bind",
			devMode:   false,
			listen:    "0.0.0.0:9080",
			expectErr: false,
		},
		{
			name:      "dev-mode-allows-ipv4-loopback",
			devMode:   true,
			listen:    "127.0.0.1:9080",
			expectErr: false,
		},
		{
			name:      "dev-mode-allows-ipv6-loopback",
			devMode:   true,
			listen:    "[::1]:9080",
			expectErr: false,
		},
		{
			name:         "dev-mode-rejects-wildcard-bind",
			devMode:      true,
			listen:       "0.0.0.0:9080",
			expectErr:    true,
			errorContain: "requires loopback listen address",
		},
		{
			name:         "dev-mode-rejects-empty-host-bind",
			devMode:      true,
			listen:       ":9080",
			expectErr:    true,
			errorContain: "requires loopback listen address",
		},
		{
			name:         "dev-mode-rejects-localhost-hostname",
			devMode:      true,
			listen:       "localhost:9080",
			expectErr:    true,
			errorContain: "requires loopback listen address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDeveloperModeBindAddress(tt.devMode, tt.listen)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errorContain != "" && !strings.Contains(err.Error(), tt.errorContain) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errorContain)
				}

				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

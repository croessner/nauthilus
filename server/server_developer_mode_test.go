package main

import (
	"strings"
	"testing"
)

type developerModeBindCase struct {
	name         string
	listen       string
	errorContain string
	devMode      bool
	expectErr    bool
}

func TestValidateDeveloperModeBindAddress(t *testing.T) {
	for _, tt := range developerModeBindCases() {
		t.Run(tt.name, func(t *testing.T) {
			assertDeveloperModeBindCase(t, tt)
		})
	}
}

// developerModeBindCases returns the developer-mode bind validation matrix.
func developerModeBindCases() []developerModeBindCase {
	return []developerModeBindCase{
		{name: "non-dev-mode-allows-any-bind", listen: "0.0.0.0:9080"},
		{name: "dev-mode-allows-ipv4-loopback", devMode: true, listen: "127.0.0.1:9080"},
		{name: "dev-mode-allows-ipv6-loopback", devMode: true, listen: "[::1]:9080"},
		rejectedDeveloperModeBind("dev-mode-rejects-wildcard-bind", "0.0.0.0:9080"),
		rejectedDeveloperModeBind("dev-mode-rejects-empty-host-bind", ":9080"),
		rejectedDeveloperModeBind("dev-mode-rejects-localhost-hostname", "localhost:9080"),
	}
}

// rejectedDeveloperModeBind builds a rejected developer-mode bind case.
func rejectedDeveloperModeBind(name string, listen string) developerModeBindCase {
	return developerModeBindCase{
		name:         name,
		devMode:      true,
		listen:       listen,
		expectErr:    true,
		errorContain: "requires loopback listen address",
	}
}

// assertDeveloperModeBindCase verifies one developer-mode bind validation case.
func assertDeveloperModeBindCase(t *testing.T, tt developerModeBindCase) {
	t.Helper()

	err := validateDeveloperModeBindAddress(tt.devMode, tt.listen)
	if tt.expectErr {
		assertDeveloperModeBindError(t, err, tt.errorContain)

		return
	}

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// assertDeveloperModeBindError verifies the expected validation error text.
func assertDeveloperModeBindError(t *testing.T, err error, errorContain string) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if errorContain != "" && !strings.Contains(err.Error(), errorContain) {
		t.Fatalf("error %q does not contain %q", err.Error(), errorContain)
	}
}

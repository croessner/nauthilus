// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIdentityCompletionPathsDoNotDispatchEffectsOutsideDecisionSessions(t *testing.T) {
	t.Parallel()

	targets := identityCompletionSourcePaths(t)
	forbidden := []string{
		"QueueLuaPostAction",
		"QueueCompletedIDPMFAPostAction",
		"PostActionRequestChan",
		"effectsupervisor",
	}

	for _, target := range targets {
		source, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read %s: %v", target, err)
		}

		for _, fragment := range forbidden {
			if strings.Contains(string(source), fragment) {
				t.Errorf("%s contains direct effect bypass %q", target, fragment)
			}
		}
	}
}

// identityCompletionSourcePaths returns the production completion paths whose
// protocol success must not dispatch effects without an admitted target.
func identityCompletionSourcePaths(t *testing.T) []string {
	t.Helper()

	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve identity completion boundary test path")
	}

	packageDir := filepath.Dir(testFile)

	return []string{
		filepath.Join(packageDir, "canonical_webauthn.go"),
		filepath.Join(packageDir, "oidc.go"),
		filepath.Join(packageDir, "oidc_authorization_code.go"),
		filepath.Join(packageDir, "oidc_device_code.go"),
		filepath.Clean(filepath.Join(packageDir, "..", "..", "..", "core", "idp_mfa.go")),
	}
}

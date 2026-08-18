// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"strings"
	"testing"
)

func TestIDPCompositionRootUsesOnlyCanonicalBrowserRuntime(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server composition root: %v", err)
	}

	setup := sourceFunctionText(t, string(source), "func buildIDPSetupCallback(", "func frontendHandlerDeps(")
	registrar := sourceFunctionText(t, string(source), "func registerIDPRoutes(", "func buildBackchannelSetupCallback(")

	for _, required := range []string{
		"handleridp.NewCanonicalBrowserRuntime(deps)",
		"handleridp.NewCanonicalFrontendHandler(deps, canonicalRuntime)",
		"frontendHandler.Register(e)",
		"NewOIDCHandler(deps, nauthilusIDP, frontendHandler).Register(e, canonicalRuntime)",
		"NewSAMLHandler(deps, nauthilusIDP).Register(e, canonicalRuntime)",
	} {
		if !strings.Contains(setup+registrar, required) {
			t.Fatalf("canonical IDP composition missing %q", required)
		}
	}

	if strings.Contains(registrar, "handleridp.NewFrontendHandler(deps)") ||
		strings.Contains(registrar, ".RegisterCanonical(") ||
		strings.Contains(registrar, "handlerapiv1.NewMFAAPI") || strings.Count(registrar, ".Register(") != 3 {
		t.Fatalf("IDP registrar retained parallel browser worlds:\n%s", registrar)
	}
}

func sourceFunctionText(t *testing.T, source string, startMarker string, endMarker string) string {
	t.Helper()

	start := strings.Index(source, startMarker)

	end := strings.Index(source, endMarker)
	if start < 0 || end <= start {
		t.Fatalf("source function markers missing: %q..%q", startMarker, endMarker)
	}

	return source[start:end]
}

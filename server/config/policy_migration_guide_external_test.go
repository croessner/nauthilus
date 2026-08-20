// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
)

const policyMigrationGuideHeading = "### New standalone `policy` input"

type policyMigrationGuideAcceptance struct{}

// Accept supplies the capability needed to compile builtin post-action effects.
func (policyMigrationGuideAcceptance) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

func TestPolicyMigrationGuideStandaloneExampleCompiles(t *testing.T) {
	source := policyMigrationGuideStandaloneYAML(t)

	document, err := policyconfig.Decode("yaml", strings.NewReader(source))
	if err != nil {
		t.Fatalf("decode documented standalone policy: %v", err)
	}

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("normalize documented standalone policy: %v", err)
	}

	if _, err = input.Compile(context.Background(), policyMigrationGuideAcceptance{}); err != nil {
		t.Fatalf("compile documented standalone policy: %v", err)
	}
}

// policyMigrationGuideStandaloneYAML extracts the fenced example owned by the migration guide.
func policyMigrationGuideStandaloneYAML(t *testing.T) string {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve migration guide test path")
	}

	guidePath := filepath.Join(filepath.Dir(currentFile), "..", "docs", "policy_configuration_migration.md")

	guide, err := os.ReadFile(guidePath)
	if err != nil {
		t.Fatalf("read migration guide: %v", err)
	}

	_, afterHeading, found := strings.Cut(string(guide), policyMigrationGuideHeading)
	if !found || strings.Contains(afterHeading, policyMigrationGuideHeading) {
		t.Fatalf("migration guide must contain exactly one %q heading", policyMigrationGuideHeading)
	}

	const fenceStart = "\n\n```yaml\n"
	if !strings.HasPrefix(afterHeading, fenceStart) {
		t.Fatalf("migration guide heading %q has no YAML fence", policyMigrationGuideHeading)
	}

	afterFence := strings.TrimPrefix(afterHeading, fenceStart)

	source, _, found := strings.Cut(afterFence, "\n```\n")
	if !found {
		t.Fatalf("migration guide heading %q has no closing fence", policyMigrationGuideHeading)
	}

	return source
}

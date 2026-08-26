// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
)

// capturePolicyLuaTestArtifacts seals every script path declared by one test policy.
func capturePolicyLuaTestArtifacts(
	t *testing.T,
	policy policyconfig.PolicyConfig,
	patterns ...string,
) *config.ArtifactSnapshot {
	t.Helper()

	paths := make([]string, 0)

	for _, namespace := range policy.Namespaces {
		for _, provider := range namespace.Providers {
			if provider.ScriptPath != "" {
				paths = append(paths, provider.ScriptPath)
			}
		}

		for _, effect := range namespace.Effects {
			if effect.ScriptPath != "" {
				paths = append(paths, effect.ScriptPath)
			}
		}

		paths = append(paths, namespace.SchemaContributions.Lua.RegistryScripts...)
	}

	snapshot, err := config.CaptureArtifactSnapshot(config.ArtifactSnapshotSpec{
		Paths: paths, LuaPackagePatterns: patterns,
	})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	t.Cleanup(snapshot.Release)

	return snapshot
}

// captureEmptyLuaTestArtifacts returns a valid snapshot with no declared script paths.
func captureEmptyLuaTestArtifacts(t *testing.T) *config.ArtifactSnapshot {
	t.Helper()

	snapshot, err := config.CaptureArtifactSnapshot(config.ArtifactSnapshotSpec{})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	t.Cleanup(snapshot.Release)

	return snapshot
}

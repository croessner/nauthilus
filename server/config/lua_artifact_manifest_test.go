// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
)

func TestEffectiveLuaPackagePatternsPreserveLegacyFirstMatchOrder(t *testing.T) {
	customRoot := filepath.Join(t.TempDir(), "custom")
	configured := &FileSettings{Lua: &LuaSection{Config: &LuaConf{
		PackagePath: filepath.Join(customRoot, "?.lua") + ";/usr/local/share/nauthilus/lua/?.lua;" + filepath.Join(customRoot, "?/init.lua"),
	}}}
	want := []string{
		"/usr/local/share/nauthilus/lua/?.lua",
		"/usr/share/nauthilus/lua/?.lua",
		"/usr/app/lua-plugins.d/share/?.lua",
		filepath.Join(customRoot, "?.lua"),
		filepath.Join(customRoot, "?/init.lua"),
	}

	if got := EffectiveLuaPackagePatterns(configured); !reflect.DeepEqual(got, want) {
		t.Fatalf("EffectiveLuaPackagePatterns() = %#v, want legacy first-match order %#v", got, want)
	}
}

func TestProductionArtifactManifestIncludesLuaTreesAndPolicyPrograms(t *testing.T) {
	customRoot := filepath.Join(t.TempDir(), "modules")
	registryPath := filepath.Join(t.TempDir(), "registry.lua")
	providerPath := filepath.Join(t.TempDir(), "provider.lua")
	effectPath := filepath.Join(t.TempDir(), "effect.lua")
	configured := &FileSettings{
		Lua: &LuaSection{Config: &LuaConf{PackagePath: filepath.Join(customRoot, "?.lua")}},
		Policy: policyconfig.PolicyConfig{Namespaces: map[string]policyconfig.NamespaceConfig{
			"mail": {
				SchemaContributions: policyconfig.SchemaContributionsConfig{Lua: policyconfig.LuaSchemaContributionsConfig{
					RegistryScripts: []string{registryPath},
				}},
				Providers: map[string]policyconfig.ProviderConfig{"risk": {ScriptPath: providerPath}},
				Effects:   map[string]policyconfig.EffectConfig{"notify": {ScriptPath: effectPath}},
			},
		}},
	}

	manifest := ProductionArtifactManifestFor(configured)
	if got, want := manifest.LuaPackagePatterns, EffectiveLuaPackagePatterns(configured); !reflect.DeepEqual(got, want) {
		t.Fatalf("LuaPackagePatterns = %#v, want %#v", got, want)
	}

	if got, want := manifest.PolicyLua, []string{registryPath, providerPath, effectPath}; !reflect.DeepEqual(got, want) {
		t.Fatalf("PolicyLua = %#v, want %#v", got, want)
	}

	spec := manifest.SnapshotSpec()
	if !containsExactString(spec.Paths, registryPath) || !containsExactString(spec.Paths, providerPath) || !containsExactString(spec.Paths, effectPath) {
		t.Fatalf("SnapshotSpec.Paths = %#v, want every Policy Lua program", spec.Paths)
	}

	if !containsExactString(spec.LuaPackagePatterns, filepath.Join(customRoot, "?.lua")) {
		t.Fatalf("SnapshotSpec.LuaPackagePatterns = %#v, want custom pattern", spec.LuaPackagePatterns)
	}

	if containsExactString(spec.Trees, customRoot) {
		t.Fatalf("SnapshotSpec.Trees = %#v, must not broadly capture custom Lua root %q", spec.Trees, customRoot)
	}
}

// containsExactString reports whether one exact value appears in a test projection.
func containsExactString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}

	return false
}

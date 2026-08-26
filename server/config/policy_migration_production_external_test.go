// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	lua "github.com/yuin/gopher-lua"
)

type productionPolicyFormatFixture struct {
	valid string
	old   string
	mixed string
}

var productionPolicyFormatFixtures = map[string]productionPolicyFormatFixture{
	"json": {
		valid: `{"policy":{"api":{"enabled":true}}}`,
		old:   `{"auth":{"policy":{"mode":"observe"}}}`,
		mixed: `{"policy":{"api":{"enabled":true}},"auth":{"policy":{"mode":"observe"}}}`,
	},
	"toml": {
		valid: "[policy.api]\nenabled = true\n",
		old:   "[auth.policy]\nmode = \"observe\"\n",
		mixed: "[policy.api]\nenabled = true\n[auth.policy]\nmode = \"observe\"\n",
	},
	"yaml": {
		valid: "policy:\n  api:\n    enabled: true\n",
		old:   "auth:\n  policy:\n    mode: observe\n",
		mixed: "policy:\n  api:\n    enabled: true\nauth:\n  policy:\n    mode: observe\n",
	},
	"yml": {
		valid: "policy:\n  api:\n    enabled: true\n",
		old:   "auth:\n  policy:\n    mode: observe\n",
		mixed: "policy:\n  api:\n    enabled: true\nauth:\n  policy:\n    mode: observe\n",
	},
	"properties": {
		valid: "policy.api.enabled=true\n",
		old:   "auth.policy.mode=observe\n",
		mixed: "policy.api.enabled=true\nauth.policy.mode=observe\n",
	},
	"props": {
		valid: "policy.api.enabled=true\n",
		old:   "auth.policy.mode=observe\n",
		mixed: "policy.api.enabled=true\nauth.policy.mode=observe\n",
	},
	"prop": {
		valid: "policy.api.enabled=true\n",
		old:   "auth.policy.mode=observe\n",
		mixed: "policy.api.enabled=true\nauth.policy.mode=observe\n",
	},
	"hcl": {
		valid: "policy { api { enabled = true } }\n",
		old:   "auth { policy { mode = \"observe\" } }\n",
		mixed: "policy { api { enabled = true } }\nauth { policy { mode = \"observe\" } }\n",
	},
	"tfvars": {
		valid: "policy = { api = { enabled = true } }\n",
		old:   "auth = { policy = { mode = \"observe\" } }\n",
		mixed: "policy = { api = { enabled = true } }\nauth = { policy = { mode = \"observe\" } }\n",
	},
	"dotenv": {
		valid: "policy.api.enabled=true\n",
		old:   "auth.policy.mode=observe\n",
		mixed: "policy.api.enabled=true\nauth.policy.mode=observe\n",
	},
	"env": {
		valid: "policy.api.enabled=true\n",
		old:   "auth.policy.mode=observe\n",
		mixed: "policy.api.enabled=true\nauth.policy.mode=observe\n",
	},
	"ini": {
		valid: "[policy.api]\nenabled=true\n",
		old:   "[auth.policy]\nmode=observe\n",
		mixed: "[policy.api]\nenabled=true\n[auth.policy]\nmode=observe\n",
	},
}

func TestProductionPolicyRootLoadsEverySupportedViperFormat(t *testing.T) {
	formats := policyconfig.SupportedFormats()
	if len(productionPolicyFormatFixtures) != len(formats) {
		t.Fatalf("production format fixtures = %d, want %d", len(productionPolicyFormatFixtures), len(formats))
	}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			fixture, exists := productionPolicyFormatFixtures[format]
			if !exists {
				t.Fatalf("missing production source for %s", format)
			}

			active := &config.FileSettings{}
			config.SetTestFile(active)
			t.Cleanup(func() { config.SetTestFile(nil) })

			candidate := prepareProductionPolicySource(t, format, fixture.valid)
			if config.GetFile() != active {
				t.Fatal("production policy preparation published the candidate")
			}

			if !candidate.GetPolicy().API.Enabled {
				t.Fatalf("%s production load did not preserve policy.api.enabled", format)
			}
		})
	}
}

func TestProductionPolicyRootRejectsOldAndMixedRootsEverySupportedViperFormat(t *testing.T) {
	for _, format := range policyconfig.SupportedFormats() {
		fixture, exists := productionPolicyFormatFixtures[format]
		if !exists {
			t.Fatalf("missing production source for %s", format)
		}

		for name, source := range map[string]string{"old": fixture.old, "mixed": fixture.mixed} {
			t.Run(format+"/"+name, func(t *testing.T) {
				active := &config.FileSettings{}
				config.SetTestFile(active)
				t.Cleanup(func() { config.SetTestFile(nil) })

				_, err := prepareProductionPolicySourceResult(t, format, source)
				if err == nil {
					t.Fatal("PrepareFile() error = nil, want removed auth.policy rejection")
				}

				if !strings.Contains(err.Error(), "auth.policy") && !strings.Contains(err.Error(), "auth") {
					t.Fatalf("PrepareFile() error = %q, want removed root path", err)
				}

				if config.GetFile() != active {
					t.Fatal("rejected format candidate replaced the active production config")
				}
			})
		}
	}
}

func TestProductionPolicyMigrationFixtureLoadsAndBuildsUnifiedCatalog(t *testing.T) {
	candidate := prepareResolvedProductionMigrationFixture(t)
	document := policyconfig.Document{Policy: candidate.GetPolicy()}

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("normalize production-loaded migration fixture: %v", err)
	}

	catalog := compileUnifiedMigrationFixture(t, input)

	targetID, err := decision.NewTarget("authn", "authenticate")
	if err != nil {
		t.Fatalf("construct authn target: %v", err)
	}

	target, exists := catalog.Lookup(targetID)
	if !exists {
		t.Fatal("production catalog has no authn/authenticate target")
	}

	if got := target.DefaultPolicySet().String(); got != registry.BuiltinStandardAuthPolicySet {
		t.Fatalf("production default policy = %q, want %q", got, registry.BuiltinStandardAuthPolicySet)
	}

	if got := string(target.AuthorityMode()); got != "observe" {
		t.Fatalf("production authn authority mode = %q, want observe", got)
	}

	if _, exists := target.LookupProvider("authn/lua_environment_shared"); !exists {
		t.Fatal("production catalog has no qualified Lua environment provider")
	}

	if _, exists := target.LookupProvider("authn/lua_subject_shared"); !exists {
		t.Fatal("production catalog has no qualified Lua subject provider")
	}
}

func TestProductionPolicyMigrationFixtureLuaExtensionsCompileAndRegisterCallbacks(t *testing.T) {
	candidate := prepareResolvedProductionMigrationFixture(t)
	authn := candidate.GetPolicy().Namespaces["authn"]
	cases := []struct {
		name     string
		path     string
		callback string
	}{
		{
			name: "environment", path: authn.Providers["lua_environment_shared"].ScriptPath,
			callback: "nauthilus_call_environment",
		},
		{
			name: "subject", path: authn.Providers["lua_subject_shared"].ScriptPath,
			callback: "nauthilus_call_subject",
		},
		{
			name: "action", path: authn.Effects["lua_action_notify"].ScriptPath,
			callback: "nauthilus_call_action",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if !filepath.IsAbs(test.path) {
				t.Fatalf("resolved production script path = %q, want absolute", test.path)
			}

			prototype, err := compilePolicyMigrationLuaFile(test.path)
			if err != nil {
				t.Fatalf("compile production %s extension: %v", test.name, err)
			}

			state := lua.NewState()
			t.Cleanup(state.Close)
			state.PreloadModule(definitions.LuaModHTTPResponse, lualib.LoaderHTTPResponseStateless())

			if err = lualib.DoCompiledFile(state, prototype); err != nil {
				t.Fatalf("load production %s extension: %v", test.name, err)
			}

			if got := state.GetGlobal(test.callback).Type(); got != lua.LTFunction {
				t.Fatalf("production %s callback %q type = %s, want function", test.name, test.callback, got)
			}
		})
	}

	registryPath := authn.SchemaContributions.Lua.RegistryScripts[0]
	if !filepath.IsAbs(registryPath) {
		t.Fatalf("resolved production registry path = %q, want absolute", registryPath)
	}

	if _, err := compilePolicyMigrationLuaFile(registryPath); err != nil {
		t.Fatalf("compile production registry extension: %v", err)
	}
}

// compilePolicyMigrationLuaFile compiles one test-owned fixture after an explicit filesystem read.
func compilePolicyMigrationLuaFile(path string) (*lua.FunctionProto, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return lualib.CompileLuaSource(path, source)
}

func TestProductionPolicyMigrationRejectsOldAndMixedFixturesBeforePublication(t *testing.T) {
	oldSource, err := os.ReadFile(legacyMigrationFixture)
	if err != nil {
		t.Fatalf("read old migration fixture: %v", err)
	}

	newSource, err := os.ReadFile(unifiedMigrationFixture)
	if err != nil {
		t.Fatalf("read new migration fixture: %v", err)
	}

	cases := []struct {
		name   string
		source string
	}{
		{name: "old root", source: string(oldSource)},
		{name: "mixed roots", source: string(newSource) + "\n" + string(oldSource)},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			active := &config.FileSettings{}
			config.SetTestFile(active)
			t.Cleanup(func() { config.SetTestFile(nil) })

			_, err := prepareProductionPolicySourceResult(t, "yaml", test.source)
			if err == nil {
				t.Fatal("PrepareFile() error = nil, want removed auth.policy rejection")
			}

			if !strings.Contains(err.Error(), "auth.policy") {
				t.Fatalf("PrepareFile() error = %q, want exact removed root path", err)
			}

			if config.GetFile() != active {
				t.Fatal("rejected legacy fixture replaced the active production config")
			}
		})
	}
}

func TestProductionPolicyRootRejectsEveryRemovedShape(t *testing.T) {
	for _, test := range policyCutoverRemovedShapeCases() {
		t.Run(test.name, func(t *testing.T) {
			_, err := prepareProductionPolicySourceResult(t, "yaml", test.source)
			if err == nil {
				t.Fatalf("PrepareFile() error = nil, want rejection at %s", test.path)
			}

			var pathError *policyconfig.PathError
			if errors.As(err, &pathError) {
				if pathError.Path != test.path {
					t.Fatalf("production rejection path = %q, want %q", pathError.Path, test.path)
				}

				return
			}

			if !strings.Contains(err.Error(), test.path) {
				t.Fatalf("production rejection error = %q, want path %q", err, test.path)
			}
		})
	}
}

func TestProductionPolicyRootRejectsCaseVariantStaleShapesBeforePatches(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		wantPath string
	}{
		{
			name: "unqualified fallback under case variant root",
			source: `Policy:
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      default_policy: standard_auth
patch:
  - op: replace
    path: policy.targets
    value: []
`,
			wantPath: "policy.targets[0].default_policy",
		},
		{
			name: "provider alias under case variant root",
			source: `Policy:
  namespaces:
    authn:
      providers:
        risk:
          kind: lua
          stage: pre_auth
patch:
  - op: replace
    path: policy
    value: {}
`,
			wantPath: "policy.namespaces.authn.providers.risk.stage",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := prepareProductionPolicySourceResult(t, "yaml", test.source)
			if err == nil {
				t.Fatal("PrepareFile() error = nil, want case-variant pre-patch rejection")
			}

			if !strings.Contains(err.Error(), test.wantPath) {
				t.Fatalf("PrepareFile() error = %q, want path %q", err, test.wantPath)
			}
		})
	}
}

func TestProductionPolicyRootRejectsCaseVariantStaleShapeInIncludeBeforeOverride(t *testing.T) {
	directory := t.TempDir()

	includePath := filepath.Join(directory, "legacy.yaml")
	if err := os.WriteFile(includePath, []byte(`Policy:
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      default_policy: standard_auth
`), 0o600); err != nil {
		t.Fatalf("write case-variant include: %v", err)
	}

	rootPath := filepath.Join(directory, "root.yaml")
	if err := os.WriteFile(rootPath, []byte(`includes:
  required:
    - legacy.yaml
policy:
  targets: []
patch:
  - op: replace
    path: policy.targets
    value: []
`), 0o600); err != nil {
		t.Fatalf("write root override: %v", err)
	}

	_, err := prepareProductionPolicyPathResult(t, "yaml", rootPath)
	if err == nil {
		t.Fatal("PrepareFile() error = nil, want included case-variant rejection")
	}

	for _, expected := range []string{"legacy.yaml", "policy.targets[0].default_policy"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("PrepareFile() error = %q, want %q", err, expected)
		}
	}
}

// prepareProductionPolicySource writes and loads one complete production candidate.
func prepareProductionPolicySource(t *testing.T, format string, source string) config.File {
	t.Helper()

	candidate, err := prepareProductionPolicySourceResult(t, format, source)
	if err != nil {
		t.Fatalf("prepare %s production policy: %v", format, err)
	}

	return candidate
}

// prepareProductionPolicySourceResult writes and loads one production candidate while retaining expected errors.
func prepareProductionPolicySourceResult(t *testing.T, format string, source string) (config.File, error) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "candidate."+format)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatalf("write production policy candidate: %v", err)
	}

	return prepareProductionPolicyPathResult(t, format, path)
}

// prepareResolvedProductionMigrationFixture rewrites repository-local extensions to absolute test paths.
func prepareResolvedProductionMigrationFixture(t *testing.T) config.File {
	t.Helper()

	source, err := os.ReadFile(unifiedMigrationFixture)
	if err != nil {
		t.Fatalf("read production migration fixture: %v", err)
	}

	resolved := string(source)

	for _, relative := range []string{
		"testdata/policy_migration/environment.lua",
		"testdata/policy_migration/subject.lua",
		"testdata/policy_migration/action.lua",
		"testdata/policy_migration/registry.lua",
	} {
		absolute, absoluteErr := filepath.Abs(relative)
		if absoluteErr != nil {
			t.Fatalf("resolve production extension %s: %v", relative, absoluteErr)
		}

		resolved = strings.ReplaceAll(resolved, relative, strconv.Quote(absolute))
	}

	return prepareProductionPolicySource(t, "yaml", resolved)
}

// prepareProductionPolicyPath loads one existing fixture through FileSettings preparation.
func prepareProductionPolicyPath(t *testing.T, format string, path string) config.File {
	t.Helper()

	candidate, err := prepareProductionPolicyPathResult(t, format, path)
	if err != nil {
		t.Fatalf("prepare production policy fixture %s: %v", path, err)
	}

	return candidate
}

// prepareProductionPolicyPathResult installs one temporary production loader location.
func prepareProductionPolicyPathResult(t *testing.T, format string, path string) (config.File, error) {
	t.Helper()

	previousPath := config.ConfigFilePath
	previousType := config.ConfigFileType
	config.ConfigFilePath = path
	config.ConfigFileType = format

	defer func() {
		config.ConfigFilePath = previousPath
		config.ConfigFileType = previousType
	}()

	return config.PrepareFile()
}

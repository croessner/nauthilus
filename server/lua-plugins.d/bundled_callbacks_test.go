// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package luaplugins_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v4/server/policy/configinput"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

// TestBundledAuthnCallbacksPrepareAsPolicyProvidersAndEffects proves every shipped environment source, subject
// source, and action passes production candidate preparation. Authentication callbacks run with the complete Lua
// API, so no bundled callback may be rejected for a capability it uses.
func TestBundledAuthnCallbacksPrepareAsPolicyProvidersAndEffects(t *testing.T) {
	callbacks := shippedAuthnCallbacks(t)
	if len(callbacks) == 0 {
		t.Fatal("no bundled authn callbacks were found")
	}

	for index, callback := range callbacks {
		t.Run(callback, func(t *testing.T) {
			generation := uint64(index + 1)

			if filepath.Dir(callback) == "actions" {
				prepareBundledAction(t, callback, generation)

				return
			}

			prepareBundledSource(t, callback, generation)
		})
	}
}

// TestBundledPolicyExamplesDecodeValidateAndPrepare proves the checked-in operator examples stay loadable.
func TestBundledPolicyExamplesDecodeValidateAndPrepare(t *testing.T) {
	t.Run("policy-safe-idp.yml", func(t *testing.T) {
		document := readPolicyExample(t, "policy-safe-idp.yml")
		prepared := prepareExampleSources(t, document.Policy, 1)

		provider, exists := prepared["authn/lua_subject_idp_policy"]
		if !exists || provider.ID() != "authn/lua_subject_idp_policy" {
			t.Fatalf("prepared provider = %#v, want authn/lua_subject_idp_policy", provider)
		}
	})

	t.Run("policy-safe-bruteforce-header.yml", func(t *testing.T) {
		prepareExampleActions(t, readPolicyExample(t, "policy-safe-bruteforce-header.yml").Policy, 2)
	})
}

// prepareBundledSource selects one shipped source in its stage checkpoint and runs candidate preparation.
func prepareBundledSource(t *testing.T, callback string, generation uint64) {
	t.Helper()

	kind := policyconfig.ProviderKindLuaSubject
	checkpoint := "subject_analysis"
	stage := "subject"

	if filepath.Dir(callback) == "environment" {
		kind = policyconfig.ProviderKindLuaEnvironment
		checkpoint = "pre_auth"
		stage = "environment"
	}

	name := strings.TrimSuffix(filepath.Base(callback), filepath.Ext(callback))
	providerName := "lua_" + stage + "_" + name

	document := readPolicyExample(t, "policy-safe-idp.yml")
	authn := document.Policy.Namespaces["authn"]
	authn.Providers = map[string]policyconfig.ProviderConfig{
		providerName: {
			Kind:       kind,
			ScriptPath: callback,
			Targets:    []policyconfig.TargetReferenceConfig{{Action: "authenticate"}},
			Executions: []string{"host_sync"},
		},
	}
	authn.DomainPlans = map[string]policyconfig.DomainPlanConfig{
		"safe_idp": {
			Checkpoints: map[string]policyconfig.CheckpointConfig{
				checkpoint: {
					Providers: []policyconfig.ProviderInstanceConfig{{
						Name:    name,
						Use:     "authn/" + providerName,
						Actions: []string{"authenticate"},
					}},
				},
				"auth_decision": {},
			},
		},
	}
	document.Policy.Namespaces["authn"] = authn

	if prepared := prepareExampleSources(t, document.Policy, generation); len(prepared) != 1 {
		t.Fatalf("prepared sources = %d, want the bundled callback", len(prepared))
	}
}

// prepareBundledAction selects one shipped action as the example effect and runs candidate preparation.
func prepareBundledAction(t *testing.T, callback string, generation uint64) {
	t.Helper()

	document := readPolicyExample(t, "policy-safe-bruteforce-header.yml")
	authn := document.Policy.Namespaces["authn"]

	effect, exists := authn.Effects["lua_action_bruteforce_header"]
	if !exists {
		t.Fatal("action example lost its lua_action_bruteforce_header effect")
	}

	effect.ScriptPath = callback
	authn.Effects["lua_action_bruteforce_header"] = effect
	document.Policy.Namespaces["authn"] = authn

	prepareExampleActions(t, document.Policy, generation)
}

// prepareExampleSources runs production source preparation against the sealed checked-in bytes.
func prepareExampleSources(
	t *testing.T,
	configured policyconfig.PolicyConfig,
	generation uint64,
) map[string]policyruntime.AuthnHostProvider {
	t.Helper()

	snapshot, modules := capturePolicyExampleArtifacts(t, configured)

	prepared, err := configinput.PrepareConfiguredAuthnLuaSources(
		t.Context(),
		generation,
		configured,
		snapshot,
		modules,
		vmpool.NewManager(),
	)
	if err != nil {
		t.Fatalf("PrepareConfiguredAuthnLuaSources() error = %v", err)
	}

	return prepared
}

// prepareExampleActions runs production action preparation against the sealed checked-in bytes.
func prepareExampleActions(t *testing.T, configured policyconfig.PolicyConfig, generation uint64) {
	t.Helper()

	snapshot, modules := capturePolicyExampleArtifacts(t, configured)

	_, err := configinput.PrepareConfiguredAuthnLuaActions(
		t.Context(),
		configinput.ConfiguredAuthnLuaActionInput{
			PostActionAcceptance: policyExampleAcceptor{},
			Artifacts:            snapshot,
			Modules:              modules,
			Pools:                vmpool.NewManager(),
			Policy:               configured,
			Generation:           generation,
		},
	)
	if err != nil {
		t.Fatalf("PrepareConfiguredAuthnLuaActions() error = %v", err)
	}
}

// TestOperatorDocsUseOnlyCanonicalNativeEffectIDs prevents component-local names from becoming Policy examples.
func TestOperatorDocsUseOnlyCanonicalNativeEffectIDs(t *testing.T) {
	paths := []string{
		"POLICY_VM_COMPATIBILITY.md",
		filepath.Join("actions", "README.md"),
		filepath.Join("..", "docs", "examples", "go_plugin_clickhouse.yml"),
		filepath.Join("..", "docs", "examples", "go_plugin_haveibeenpwnd.yml"),
		filepath.Join("..", "..", "contrib", "clickhouse-kubernetes", "README.md"),
		filepath.Join("..", "..", "contrib", "plugins", "clickhouse", "README.md"),
		filepath.Join("..", "..", "contrib", "plugins", "haveibeenpwnd", "README.md"),
	}

	for _, path := range paths {
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read operator document: %v", err)
			}

			text := string(contents)
			text = strings.ReplaceAll(text, "authn/plugin.clickhouse.post_action", "")

			text = strings.ReplaceAll(text, "authn/plugin.haveibeenpwnd.post_action", "")
			for _, forbidden := range []string{"clickhouse.post_action", "haveibeenpwnd.post_action"} {
				if strings.Contains(text, forbidden) {
					t.Errorf("operator document retains unqualified Policy effect ID %q", forbidden)
				}
			}
		})
	}
}

// shippedAuthnCallbacks lists only callbacks that can be selected by authn Policy configuration.
func shippedAuthnCallbacks(t *testing.T) []string {
	t.Helper()

	return shippedLuaFiles(t, []string{"environment", "subject", "actions"})
}

// shippedLuaFiles returns a stable inventory for the requested plugin directories.
func shippedLuaFiles(t *testing.T, directories []string) []string {
	t.Helper()

	paths := make([]string, 0)

	for _, directory := range directories {
		matches, err := filepath.Glob(filepath.Join(directory, "*.lua"))
		if err != nil {
			t.Fatalf("glob %s callbacks: %v", directory, err)
		}

		for _, path := range matches {
			paths = append(paths, filepath.ToSlash(path))
		}
	}

	sort.Strings(paths)

	return paths
}

// readPolicyExample decodes and validates one checked-in top-level Policy example.
func readPolicyExample(t *testing.T, name string) policyconfig.Document {
	t.Helper()

	contents, err := os.ReadFile(filepath.Join("examples", name))
	if err != nil {
		t.Fatalf("read supported Policy example: %v", err)
	}

	document, err := policyconfig.Decode("yaml", bytes.NewReader(contents))
	if err != nil {
		t.Fatalf("decode supported Policy example: %v", err)
	}

	if err = policyconfig.Validate(document); err != nil {
		t.Fatalf("validate supported Policy example: %v", err)
	}

	return document
}

type policyExampleAcceptor struct{}

// Accept satisfies the mandatory candidate-owned post-action acceptance dependency.
func (policyExampleAcceptor) Accept(
	context.Context,
	effectsupervisor.Plan,
) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

// capturePolicyExampleArtifacts seals scripts and shared modules exactly as candidate preparation expects.
func capturePolicyExampleArtifacts(
	t *testing.T,
	configured policyconfig.PolicyConfig,
) (*config.ArtifactSnapshot, *luaseal.Modules) {
	t.Helper()

	paths := make([]string, 0)
	for _, namespace := range configured.Namespaces {
		paths = append(paths, namespace.SchemaContributions.Lua.RegistryScripts...)
		for _, provider := range namespace.Providers {
			paths = append(paths, provider.ScriptPath)
		}

		for _, effect := range namespace.Effects {
			paths = append(paths, effect.ScriptPath)
		}
	}

	modulePattern := filepath.Join("share", "?.lua")

	snapshot, err := config.CaptureArtifactSnapshot(config.ArtifactSnapshotSpec{
		Paths:              paths,
		LuaPackagePatterns: []string{modulePattern},
	})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	t.Cleanup(snapshot.Release)

	modules, err := luaseal.CaptureSnapshot([]string{modulePattern}, snapshot)
	if err != nil {
		t.Fatalf("CaptureSnapshot() error = %v", err)
	}

	return snapshot, modules
}

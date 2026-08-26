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
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v3/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
)

var (
	compatibilityRowPattern = regexp.MustCompile(`^\| \x60([^\x60]+\.lua)\x60 \| (supported|test-only|reference-only) \|`)
	otherSurfaceRowPattern  = regexp.MustCompile(`^\| \x60([^\x60]+\.lua)\x60 \| (backend-runtime|process-owned|candidate-schema|captured-library|standalone-example) \|`)
	policyIDLinePattern     = regexp.MustCompile(`(?:^|[\s{])-?\s*id:\s*["']?([^"'\s,}#]+)`)
)

// TestPolicyVMCompatibilityCatalogClassifiesEveryAuthnCallback keeps the operator boundary exhaustive.
func TestPolicyVMCompatibilityCatalogClassifiesEveryAuthnCallback(t *testing.T) {
	classified := readCompatibilityCatalog(t)
	shipped := shippedAuthnCallbacks(t)

	if len(classified) != len(shipped) {
		t.Fatalf("classified callbacks = %d, shipped callbacks = %d", len(classified), len(shipped))
	}

	for _, path := range shipped {
		if _, exists := classified[path]; !exists {
			t.Errorf("shipped authn callback %q has no Policy VM classification", path)
		}
	}
}

// TestPolicyVMCompatibilityCatalogClassifiesEveryOtherLuaSurface keeps non-Policy runtimes explicit.
func TestPolicyVMCompatibilityCatalogClassifiesEveryOtherLuaSurface(t *testing.T) {
	classified := readOtherLuaSurfaceCatalog(t)
	shipped := shippedLuaFiles(t, []string{"backend", "hooks", "init", "examples", "policy", "share"})

	if len(classified) != len(shipped) {
		t.Fatalf("classified other Lua surfaces = %d, shipped surfaces = %d", len(classified), len(shipped))
	}

	for _, path := range shipped {
		if _, exists := classified[path]; !exists {
			t.Errorf("shipped Lua surface %q has no explicit authority classification", path)
		}
	}
}

// TestSupportedIdPPolicyExampleDecodesValidatesAndPrepares proves the claimed source fits production preparation.
func TestSupportedIdPPolicyExampleDecodesValidatesAndPrepares(t *testing.T) {
	document := readPolicyExample(t, "policy-safe-idp.yml")
	snapshot, modules := capturePolicyExampleArtifacts(t, document.Policy)
	validateCapturedPolicyScript(t, snapshot, modules, filepath.Join("subject", "idp_policy.lua"), luaseal.PolicyProfileSubject)

	prepared, err := configinput.PrepareConfiguredAuthnLuaSources(
		t.Context(),
		1,
		document.Policy,
		snapshot,
		modules,
		vmpool.NewManager(),
	)
	if err != nil {
		t.Fatalf("PrepareConfiguredAuthnLuaSources() error = %v", err)
	}

	provider, exists := prepared["authn/lua_subject_idp_policy"]
	if !exists || provider.ID() != "authn/lua_subject_idp_policy" {
		t.Fatalf("prepared provider = %#v, want authn/lua_subject_idp_policy", provider)
	}
}

// TestReferenceOnlyOutboundSourceIsRejectedByPolicyProfile proves the catalog does not mask a forbidden capability.
func TestReferenceOnlyOutboundSourceIsRejectedByPolicyProfile(t *testing.T) {
	document := readPolicyExample(t, "policy-safe-idp.yml")
	authn := document.Policy.Namespaces["authn"]
	authn.Providers = map[string]policyconfig.ProviderConfig{
		"lua_environment_blocklist": {
			Kind:       policyconfig.ProviderKindLuaEnvironment,
			ScriptPath: filepath.Join("environment", "blocklist.lua"),
			Targets:    []policyconfig.TargetReferenceConfig{{Action: "authenticate"}},
			Executions: []string{"host_sync"},
		},
	}
	authn.DomainPlans = map[string]policyconfig.DomainPlanConfig{
		"safe_idp": {
			Checkpoints: map[string]policyconfig.CheckpointConfig{
				"pre_auth": {
					Providers: []policyconfig.ProviderInstanceConfig{{
						Name:    "blocklist",
						Use:     "authn/lua_environment_blocklist",
						Actions: []string{"authenticate"},
					}},
				},
				"auth_decision": {},
			},
		},
	}
	document.Policy.Namespaces["authn"] = authn

	snapshot, modules := capturePolicyExampleArtifacts(t, document.Policy)

	profileErr := capturedPolicyValidationError(
		t,
		snapshot,
		modules,
		filepath.Join("environment", "blocklist.lua"),
		luaseal.PolicyProfileEnvironment,
	)
	if profileErr == nil || !strings.Contains(profileErr.Error(), "policy Lua profile rejects") {
		t.Fatalf("reference-only profile validation error = %v, want an explicit policy profile rejection", profileErr)
	}

	_, err := configinput.PrepareConfiguredAuthnLuaSources(
		t.Context(),
		2,
		document.Policy,
		snapshot,
		modules,
		vmpool.NewManager(),
	)
	if err == nil {
		t.Fatal("PrepareConfiguredAuthnLuaSources() accepted the reference-only outbound HTTP source")
	}
}

// TestSupportedBruteforceHeaderExampleDecodesValidatesAndPrepares proves the response profile accepts its exact script.
func TestSupportedBruteforceHeaderExampleDecodesValidatesAndPrepares(t *testing.T) {
	document := readPolicyExample(t, "policy-safe-bruteforce-header.yml")
	snapshot, modules := capturePolicyExampleArtifacts(t, document.Policy)
	validateCapturedPolicyScript(
		t,
		snapshot,
		modules,
		filepath.Join("actions", "bruteforce_header.lua"),
		luaseal.PolicyProfileResponseAction,
	)

	_, err := configinput.PrepareConfiguredAuthnLuaActions(
		t.Context(),
		configinput.ConfiguredAuthnLuaActionInput{
			PostActionAcceptance: policyExampleAcceptor{},
			Artifacts:            snapshot,
			Modules:              modules,
			Pools:                vmpool.NewManager(),
			Policy:               document.Policy,
			Generation:           3,
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

// TestOperatorDocsDoNotActivateReferenceOnlyPolicyCallbacks prevents unsupported examples from returning.
func TestOperatorDocsDoNotActivateReferenceOnlyPolicyCallbacks(t *testing.T) {
	referenceOnly := make([]string, 0)

	for callback, status := range readCompatibilityCatalog(t) {
		if status == "reference-only" {
			referenceOnly = append(referenceOnly, callback)
		}
	}

	sort.Strings(referenceOnly)

	paths := []string{
		"README.md",
		filepath.Join("actions", "README.md"),
		filepath.Join("environment", "README.md"),
		filepath.Join("subject", "README.md"),
		filepath.Join("examples", "policy-safe-bruteforce-header.yml"),
		filepath.Join("examples", "policy-safe-idp.yml"),
		filepath.Join("..", "docs", "distributed_brute_force_detection.md"),
		filepath.Join("..", "docs", "go_plugins.md"),
		filepath.Join("..", "docs", "examples", "go_plugin_clickhouse.yml"),
		filepath.Join("..", "docs", "examples", "go_plugin_haveibeenpwnd.yml"),
		filepath.Join("..", "..", "client", "nauthilus-testing.yml"),
		filepath.Join("..", "..", "contrib", "clickhouse-kubernetes", "README.md"),
	}

	for _, path := range paths {
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read operator document: %v", err)
			}

			for lineNumber, line := range strings.Split(string(contents), "\n") {
				trimmed := strings.TrimSpace(line)
				if !strings.Contains(trimmed, "script_path:") && !strings.Contains(trimmed, "id:") {
					continue
				}

				for _, callback := range referenceOnly {
					if lineActivatesCallback(trimmed, callback) {
						t.Errorf("line %d activates reference-only callback %q: %s", lineNumber+1, callback, trimmed)
					}
				}
			}
		})
	}
}

// readCompatibilityCatalog parses the single operator-owned callback classification.
func readCompatibilityCatalog(t *testing.T) map[string]string {
	t.Helper()

	return readLuaSurfaceCatalog(t, compatibilityRowPattern, "compatibility catalog")
}

// readOtherLuaSurfaceCatalog parses the authority status for non-authn-callback Lua files.
func readOtherLuaSurfaceCatalog(t *testing.T) map[string]string {
	t.Helper()

	return readLuaSurfaceCatalog(t, otherSurfaceRowPattern, "other Lua surface catalog")
}

// readLuaSurfaceCatalog parses one table section from the shared compatibility document.
func readLuaSurfaceCatalog(t *testing.T, pattern *regexp.Regexp, catalogName string) map[string]string {
	t.Helper()

	contents, err := os.ReadFile("POLICY_VM_COMPATIBILITY.md")
	if err != nil {
		t.Fatalf("read compatibility catalog: %v", err)
	}

	classified := make(map[string]string)

	for _, line := range bytes.Split(contents, []byte{'\n'}) {
		match := pattern.FindSubmatch(line)
		if len(match) == 0 {
			continue
		}

		path := filepath.ToSlash(string(match[1]))
		if _, duplicate := classified[path]; duplicate {
			t.Fatalf("%s classifies %q more than once", catalogName, path)
		}

		classified[path] = string(match[2])
	}

	return classified
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

// policyIdentity returns the conventional qualified Policy identity for a checked-in authn callback.
func policyIdentity(callback string) string {
	name := strings.TrimSuffix(filepath.Base(callback), filepath.Ext(callback))

	switch filepath.Dir(callback) {
	case "environment":
		return "authn/lua_environment_" + name
	case "subject":
		return "authn/lua_subject_" + name
	case "actions":
		return "authn/lua_action_" + name
	default:
		return ""
	}
}

// lineActivatesCallback recognizes only exact script-path or qualified-ID configuration values.
func lineActivatesCallback(line string, callback string) bool {
	if strings.Contains(line, "script_path:") && strings.Contains(line, filepath.Base(callback)) {
		return true
	}

	match := policyIDLinePattern.FindStringSubmatch(line)

	return len(match) == 2 && match[1] == policyIdentity(callback)
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

// validateCapturedPolicyScript reports the exact profile violation before production wraps candidate diagnostics.
func validateCapturedPolicyScript(
	t *testing.T,
	snapshot *config.ArtifactSnapshot,
	modules *luaseal.Modules,
	path string,
	profile luaseal.PolicyProfile,
) {
	t.Helper()

	if err := capturedPolicyValidationError(t, snapshot, modules, path, profile); err != nil {
		t.Fatalf("validate captured Policy script %q: %v", path, err)
	}
}

// capturedPolicyValidationError validates immutable bytes against one exact stage profile.
func capturedPolicyValidationError(
	t *testing.T,
	snapshot *config.ArtifactSnapshot,
	modules *luaseal.Modules,
	path string,
	profile luaseal.PolicyProfile,
) error {
	t.Helper()

	source, err := snapshot.ReadFile(path)
	if err != nil {
		t.Fatalf("read captured Policy script %q: %v", path, err)
	}
	defer clear(source)

	return modules.ValidateSource(path, source, profile)
}

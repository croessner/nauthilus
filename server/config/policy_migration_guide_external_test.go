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
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	policyMigrationGuideHeading             = "### New production `policy` input"
	policyMigrationGuideOldHeading          = "### Old `auth.policy` input"
	policyMigrationGuideNativeHeading       = "## Generic native provider configuration"
	policyMigrationGuidePluginSourceHeading = "### Plugin environment and subject provider declarations"
	policyAPIExamplePath                    = "server/docs/examples/policy_api.yml"
	policyLocalizationAllowlistExamplePath  = "server/docs/examples/policy_localization_and_allowlists.yml"
	removedPolicyConverterReferencePhrase   = "legacy config converter"
)

var removedPolicyConverterPaths = []string{
	"scripts/convert-config-v1-to-v2.py",
	"scripts/read_yaml_as_json.go",
	"scripts/test_convert_config_v1_to_v2.py",
	"scripts/testdata/legacy-monolithic-config.yml",
	"server/docs/config_v2_converter.md",
}

type policyMigrationGuideAcceptance struct{}

// Accept supplies the capability needed to compile builtin post-action effects.
func (policyMigrationGuideAcceptance) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

func TestPolicyMigrationConverterSurfaceIsRemoved(t *testing.T) {
	repositoryRoot := policyMigrationRepositoryRoot(t)

	for _, relativePath := range removedPolicyConverterPaths {
		path := filepath.Join(repositoryRoot, filepath.FromSlash(relativePath))

		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("removed converter path %q remains: %v", relativePath, err)
		}
	}

	assertRemovedPolicyConverterNamesAbsent(t, repositoryRoot)
}

func TestPolicyMigrationConverterOracleScansNestedSupportedReferences(t *testing.T) {
	repositoryRoot := t.TempDir()
	fixtures := map[string]string{
		"server/docs/current.md":                 "Use scripts/convert-config-v1-to-v2.py.\n",
		"server/config/converter_oracle_test.go": "const removed = `scripts/convert-config-v1-to-v2.py`\n",
		"server/docs/policy-layer/historical.md": "Use scripts/convert-config-v1-to-v2.py.\n",
		"temp/planning.md":                       "Use scripts/convert-config-v1-to-v2.py.\n",
		"vendor/example.test/dependency.md":      "Use scripts/convert-config-v1-to-v2.py.\n",
		"scripts/migrate-config.py": "import sys, yaml\n" +
			"document = yaml.safe_load(sys.stdin)\n" +
			"legacy = document.get(\"auth\", {}).get(\"policy\", {})\n" +
			"yaml.safe_dump({\"policy\": legacy}, sys.stdout)\n",
		"scripts/migrate-config.sh":          "#!/bin/sh\nyq '.policy = .auth.policy | del(.auth.policy)' \"$1\"\n",
		"scripts/migrate-bracket.bash":       "#!/usr/bin/env bash\nyq '.policy = .auth[\"policy\"] | del(.auth[\"policy\"])' \"$1\"\n",
		"scripts/migrate-getpath.zsh":        "#!/usr/bin/env zsh\nyq '.policy = getpath([\"auth\",\"policy\"])' \"$1\"\n",
		"scripts/migrate-single-quotes.fish": "#!/usr/bin/env fish\nyq \".policy = .auth['policy']\" $argv[1]\n",
		"scripts/policy-parenthesized.sh":    "#!/bin/sh\nyq '.policy = ((.auth).policy)' \"$1\"\n",
		"scripts/policy-pipe-bracket.sh":     "#!/bin/sh\nyq '.policy = (.auth | .[\"policy\"])' \"$1\"\n",
		"scripts/policy-pipe-getpath.sh":     "#!/bin/sh\nyq '.policy = (.auth | getpath([\"policy\"]))' \"$1\"\n",
		"scripts/policy-pipe.sh":             "#!/bin/sh\nyq '.policy = (.auth | .policy)' \"$1\"\n",
		"scripts/policy-rewrite":             "#!/bin/sh\nyq '.policy = .auth.policy' \"$1\"\n",
		"scripts/policy-variable.sh":         "#!/bin/sh\nyq '.auth as $a | .policy = $a.policy' \"$1\"\n",
		"scripts/yq-policy-notes.sh": "#!/bin/sh\n" +
			"# yq '.policy = (.auth | .policy)' is a rejected migration example.\n" +
			"printf '%s\\n' \"Do not run yq '.policy = (.auth | .policy)'\"\n",
		"tools/policy-migration.mk": "rewrite:\n\tyq '.policy = getpath([\"auth\",\"policy\"])' input.yml\n",
		"Makefile":                  "migrate-policy:\n\tyq '.policy = getpath([\"auth\",\"policy\"])' legacy.yml\n",
		"tools/config-rewrite/main.go": "package main\n" +
			"func main() { legacy := input[\"auth\"].(map[string]any)[\"policy\"]; " +
			"yaml.NewEncoder(os.Stdout).Encode(map[string]any{\"policy\": legacy}) }\n",
		"scripts/config-lint.py": "if \"auth.policy\" in source: raise ValueError(\"removed root\")\n",
	}

	writePolicyRepositoryTextFixtures(t, repositoryRoot, fixtures)

	violations, err := policyRemovedConverterSurfaceViolations(repositoryRoot)
	if err != nil {
		t.Fatalf("scan converter fixtures: %v", err)
	}

	want := []string{
		"implementation: Makefile",
		"implementation: scripts/migrate-bracket.bash",
		"implementation: scripts/migrate-config.py",
		"implementation: scripts/migrate-config.sh",
		"implementation: scripts/migrate-getpath.zsh",
		"implementation: scripts/migrate-single-quotes.fish",
		"implementation: scripts/policy-parenthesized.sh",
		"implementation: scripts/policy-pipe-bracket.sh",
		"implementation: scripts/policy-pipe-getpath.sh",
		"implementation: scripts/policy-pipe.sh",
		"implementation: scripts/policy-rewrite",
		"implementation: scripts/policy-variable.sh",
		"implementation: tools/config-rewrite/main.go",
		"implementation: tools/policy-migration.mk",
		"reference: server/docs/current.md",
	}
	if !slices.Equal(violations, want) {
		t.Fatalf("converter violations = %v, want %v", violations, want)
	}
}

// assertRemovedPolicyConverterNamesAbsent rejects artifacts and references across supported repository files.
func assertRemovedPolicyConverterNamesAbsent(t *testing.T, repositoryRoot string) {
	t.Helper()

	violations, err := policyRemovedConverterSurfaceViolations(repositoryRoot)
	if err != nil {
		t.Fatalf("scan supported files for removed converter artifacts: %v", err)
	}

	if len(violations) != 0 {
		t.Fatalf("removed converter surface remains:\n%s", strings.Join(violations, "\n"))
	}
}

// policyRemovedConverterSurfaceViolations finds removed converter filenames and live references.
func policyRemovedConverterSurfaceViolations(repositoryRoot string) ([]string, error) {
	markers := policyRemovedConverterReferenceMarkers()
	violations := make([]string, 0)

	err := walkPolicyRepositoryTextFiles(repositoryRoot, func(relativePath string) bool {
		return isPolicyConverterReferenceCandidate(relativePath, markers)
	}, func(relativePath string, source []byte) {
		name := strings.ToLower(filepath.Base(relativePath))
		content := strings.ToLower(string(source))

		for _, marker := range markers {
			if strings.Contains(name, marker) {
				violations = append(violations, "artifact: "+relativePath)
			}

			if strings.Contains(content, marker) {
				violations = append(violations, "reference: "+relativePath)
			}
		}

		if isPolicyConverterImplementationCandidate(relativePath, source) &&
			containsPolicyConverterImplementation(relativePath, source) {
			violations = append(violations, "implementation: "+relativePath)
		}
	})
	if err != nil {
		return nil, err
	}

	slices.Sort(violations)

	return slices.Compact(violations), nil
}

// policyRemovedConverterReferenceMarkers derives every stale marker from the authoritative path list.
func policyRemovedConverterReferenceMarkers() []string {
	markers := make([]string, 0, len(removedPolicyConverterPaths)+1)

	for _, relativePath := range removedPolicyConverterPaths {
		baseName := strings.ToLower(filepath.Base(relativePath))
		markers = append(markers, strings.TrimSuffix(baseName, filepath.Ext(baseName)))
	}

	markers = append(markers, removedPolicyConverterReferencePhrase)
	slices.Sort(markers)

	return slices.Compact(markers)
}

// isPolicyConverterReferenceCandidate selects supported files and any artifact named after the converter.
func isPolicyConverterReferenceCandidate(relativePath string, markers []string) bool {
	name := strings.ToLower(filepath.Base(relativePath))

	for _, marker := range markers {
		if strings.Contains(name, marker) {
			return true
		}
	}

	return isPolicySupportedReferenceFile(relativePath) || isPolicyExtensionlessToolPath(relativePath)
}

// isPolicyConverterImplementationCandidate limits structural translation scans to executable repository tooling.
func isPolicyConverterImplementationCandidate(relativePath string, source []byte) bool {
	normalized := strings.ToLower(filepath.ToSlash(relativePath))

	baseName := filepath.Base(normalized)
	if baseName == "makefile" {
		return true
	}

	if isPolicyExtensionlessToolPath(relativePath) {
		return strings.HasPrefix(strings.TrimSpace(string(source)), "#!")
	}

	if !isPolicySupportedReferenceFile(relativePath) || isPolicySupportedSurfaceFile(relativePath) {
		return false
	}

	if strings.HasPrefix(normalized, "scripts/") || strings.HasPrefix(normalized, "tools/") ||
		strings.Contains(normalized, "/cmd/") {
		return true
	}

	return strings.Contains(baseName, "convert") || strings.Contains(baseName, "migrat") ||
		strings.Contains(baseName, "translat")
}

// isPolicyExtensionlessToolPath selects executable-looking locations before their shebang can be inspected.
func isPolicyExtensionlessToolPath(relativePath string) bool {
	normalized := strings.ToLower(filepath.ToSlash(relativePath))

	return filepath.Ext(normalized) == "" &&
		(strings.HasPrefix(normalized, "scripts/") || strings.HasPrefix(normalized, "tools/"))
}

// containsPolicyConverterImplementation recognizes structural old-root reads coupled to configuration serialization.
func containsPolicyConverterImplementation(relativePath string, source []byte) bool {
	if isPolicyShellConverterSource(relativePath) && containsShellPolicyConverterImplementation(string(source)) {
		return true
	}

	compact := compactPolicyConverterSource(string(source))

	if !containsPolicyOldRootAccess(compact) {
		return false
	}

	for _, marker := range []string{
		"safe_dump(",
		"yaml.dump(",
		"json.dump(",
		"toml.dump(",
		"json.marshal(",
		"yaml.marshal(",
		"toml.marshal(",
	} {
		if strings.Contains(compact, marker) {
			return true
		}
	}

	return strings.Contains(compact, "newencoder(") && strings.Contains(compact, ".encode(")
}

// isPolicyShellConverterSource limits yq parsing to shell and Make tooling.
func isPolicyShellConverterSource(relativePath string) bool {
	baseName := strings.ToLower(filepath.Base(relativePath))

	if baseName == "makefile" || isPolicyExtensionlessToolPath(relativePath) {
		return true
	}

	return slices.Contains([]string{".bash", ".fish", ".mk", ".sh", ".zsh"},
		strings.ToLower(filepath.Ext(relativePath)))
}

// compactPolicyConverterSource removes formatting that is insignificant to structural selectors.
func compactPolicyConverterSource(source string) string {
	return strings.NewReplacer(
		" ", "",
		"\t", "",
		"\r", "",
		"\n", "",
	).Replace(strings.ToLower(source))
}

// containsShellPolicyConverterImplementation detects structural rewrites in actual yq commands.
func containsShellPolicyConverterImplementation(source string) bool {
	for _, line := range strings.Split(strings.ReplaceAll(source, "\r\n", "\n"), "\n") {
		command, isYQ := policyYQShellCommand(line)

		if !isYQ {
			continue
		}

		compact := compactPolicyConverterSource(command)

		if containsShellPolicyOldRootAccess(compact) && containsShellPolicyWrite(compact) {
			return true
		}
	}

	return false
}

// policyYQShellCommand returns one uncommented command only when yq is the invoked executable.
func policyYQShellCommand(line string) (string, bool) {
	command := strings.TrimSpace(policyShellLineWithoutComment(line))
	command = strings.TrimLeft(command, "@+-")
	fields := strings.Fields(command)

	if len(fields) == 0 {
		return "", false
	}

	return command, strings.EqualFold(filepath.Base(fields[0]), "yq")
}

// policyShellLineWithoutComment removes unquoted shell comments while preserving yq expressions.
func policyShellLineWithoutComment(line string) string {
	var quote byte

	escaped := false

	for index := 0; index < len(line); index++ {
		character := line[index]

		if escaped {
			escaped = false

			continue
		}

		if quote == '\'' {
			if character == quote {
				quote = 0
			}

			continue
		}

		if quote == '"' {
			switch character {
			case '\\':
				escaped = true
			case quote:
				quote = 0
			}

			continue
		}

		switch character {
		case '\\':
			escaped = true
		case '\'', '"':
			quote = character
		case '#':
			return line[:index]
		}
	}

	return line
}

// containsShellPolicyWrite recognizes writes that emit the standalone top-level policy root.
func containsShellPolicyWrite(compact string) bool {
	canonical := canonicalShellPolicySelectors(compact)

	return containsAnyPolicyConverterMarker(canonical, []string{
		`.policy=`,
	}) || containsAnyPolicyConverterMarker(compact, []string{
		`setpath(["policy"]`,
		`setpath(['policy']`,
		`{"policy":`,
		`{policy:`,
	})
}

// containsShellPolicyOldRootAccess recognizes direct, piped, and variable-bound yq selectors.
func containsShellPolicyOldRootAccess(compact string) bool {
	canonical := canonicalShellPolicySelectors(compact)

	return strings.Contains(canonical, `.auth.policy`) ||
		strings.Contains(canonical, `.auth|.policy`) ||
		containsShellPolicyVariableOldRootAccess(canonical)
}

// canonicalShellPolicySelectors normalizes equivalent yq selectors without flattening arbitrary prose.
func canonicalShellPolicySelectors(compact string) string {
	return strings.NewReplacer(
		`getpath(["auth","policy"])`, `.auth.policy`,
		`getpath(['auth','policy'])`, `.auth.policy`,
		`getpath(["auth"])`, `.auth`,
		`getpath(['auth'])`, `.auth`,
		`getpath(["policy"])`, `.policy`,
		`getpath(['policy'])`, `.policy`,
		`.auth["policy"]`, `.auth.policy`,
		`.auth['policy']`, `.auth.policy`,
		`.["auth"]["policy"]`, `.auth.policy`,
		`.['auth']['policy']`, `.auth.policy`,
		`.["auth"]`, `.auth`,
		`.['auth']`, `.auth`,
		`.["policy"]`, `.policy`,
		`.['policy']`, `.policy`,
		`(`, ``,
		`)`, ``,
	).Replace(compact)
}

// containsShellPolicyVariableOldRootAccess validates same-variable auth-to-policy traversal.
func containsShellPolicyVariableOldRootAccess(canonical string) bool {
	const bindingPrefix = `.authas$`

	for searchFrom := 0; searchFrom < len(canonical); {
		bindingIndex := strings.Index(canonical[searchFrom:], bindingPrefix)

		if bindingIndex < 0 {
			return false
		}

		bindingIndex += searchFrom + len(`.authas`)
		pipeIndex := strings.IndexByte(canonical[bindingIndex:], '|')

		if pipeIndex < 0 {
			return false
		}

		variable := canonical[bindingIndex : bindingIndex+pipeIndex]
		afterPipe := canonical[bindingIndex+pipeIndex+1:]

		if validPolicyYQVariable(variable) && strings.Contains(afterPipe, variable+`.policy`) {
			return true
		}

		searchFrom = bindingIndex + pipeIndex + 1
	}

	return false
}

// validPolicyYQVariable accepts ordinary yq variable identifiers only.
func validPolicyYQVariable(variable string) bool {
	if len(variable) < 2 || variable[0] != '$' {
		return false
	}

	for index := 1; index < len(variable); index++ {
		character := variable[index]

		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}

	return variable[1] < '0' || variable[1] > '9'
}

// containsPolicyOldRootAccess distinguishes executable tree access from prose or rejection-only dotted markers.
func containsPolicyOldRootAccess(compact string) bool {
	authAccess := containsAnyPolicyConverterMarker(compact, []string{
		`["auth"]`,
		`['auth']`,
		`.get("auth"`,
		`.get('auth'`,
		`{"auth":`,
		`{'auth':`,
	})
	policyAccess := containsAnyPolicyConverterMarker(compact, []string{
		`["policy"]`,
		`['policy']`,
		`.get("policy"`,
		`.get('policy'`,
		`{"policy":`,
		`{'policy':`,
	})

	return authAccess && policyAccess
}

// containsAnyPolicyConverterMarker reports whether one structural source token is present.
func containsAnyPolicyConverterMarker(source string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(source, marker) {
			return true
		}
	}

	return false
}

func TestPolicyAPIExampleCompilesCompleteCallerAdmission(t *testing.T) {
	repositoryRoot := policyMigrationRepositoryRoot(t)
	examplePath := filepath.Join(repositoryRoot, filepath.FromSlash(policyAPIExamplePath))

	source, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatalf("read Policy API example: %v", err)
	}

	assertDocumentedFragments(t, "Policy API example", string(source), []string{
		"nauthilus:policy",
		"nauthilus:backchannel",
		"${POLICY_BASIC_PASSWORD}",
	})
	t.Setenv("POLICY_BASIC_PASSWORD", "production-example-basic-secret")

	candidate := prepareProductionPolicyPath(t, "yaml", examplePath)
	document := policyconfig.Document{Policy: candidate.GetPolicy()}

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("normalize Policy API example: %v", err)
	}

	if _, err = input.Compile(context.Background(), policyMigrationGuideAcceptance{}); err != nil {
		t.Fatalf("compile Policy API example: %v", err)
	}

	assertPolicyAPIExampleContract(t, document)
}

func TestPolicyLocalizationAndAllowlistsExamplePassesProductionConfigCheck(t *testing.T) {
	repositoryRoot := policyMigrationRepositoryRoot(t)
	examplePath := filepath.Join(repositoryRoot, filepath.FromSlash(policyLocalizationAllowlistExamplePath))
	guidePath := filepath.Join(repositoryRoot, "server/docs/go_plugins.md")

	source, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatalf("read Policy localization and allowlists example: %v", err)
	}

	sourceText := string(source)

	assertDocumentedFragments(t, "Policy localization and allowlists example", sourceText, []string{
		"--config /path/to/policy_localization_and_allowlists.yml",
		"policy:",
		"rns.account_disabled",
		"auth:",
		"name: documentation-window",
		"monitoring-account:",
	})

	if strings.Contains(sourceText, "${") {
		t.Fatal("Policy localization and allowlists example must not require secret or environment interpolation")
	}

	guide, err := os.ReadFile(guidePath)
	if err != nil {
		t.Fatalf("read Go plugin guide: %v", err)
	}

	assertDocumentedFragments(t, "Go plugin guide", string(guide), []string{
		"[complete non-secret production config-check example](examples/policy_localization_and_allowlists.yml)",
	})

	candidate := prepareProductionPolicyPath(t, "yaml", examplePath)

	if got := len(candidate.GetPolicy().Namespaces["authn"].Localization.Catalogs); got != 2 {
		t.Fatalf("Policy localization catalogs = %d, want 2", got)
	}

	bruteForceAllowlist := candidate.GetBruteForce().GetSoftWhitelist()

	if got := bruteForceAllowlist.Get("monitoring-account"); len(got) != 1 || got[0] != "192.0.2.0/24" {
		t.Fatalf("brute-force example allowlist = %#v, want one canonical network", got)
	}

	if got := candidate.GetBruteForceRules(); len(got) != 1 || got[0].GetName() != "documentation-window" {
		t.Fatalf("brute-force example buckets = %#v, want one valid documentation window", got)
	}

	relayDomainAllowlist := candidate.GetRelayDomains().GetSoftWhitelist()

	if got := relayDomainAllowlist.Get("monitoring-account"); len(got) != 1 || got[0] != "192.0.2.0/24" {
		t.Fatalf("relay-domain example allowlist = %#v, want one canonical network", got)
	}
}

// assertPolicyAPIExampleContract verifies transport, credential, and admission ownership.
func assertPolicyAPIExampleContract(t *testing.T, document policyconfig.Document) {
	t.Helper()

	api := document.Policy.API
	assertPolicyAPITransportAndLimits(t, api)
	assertPolicyAPIBearerProfile(t, api.Clients[0])
	assertPolicyAPIBasicProfile(t, api.Clients[1])
	assertPolicyAPITargetGrants(t, api.Clients)
}

// assertPolicyAPITransportAndLimits verifies endpoint activation and bounded admission settings.
func assertPolicyAPITransportAndLimits(t *testing.T, api policyconfig.APIConfig) {
	t.Helper()

	if !api.Enabled || !api.HTTP.Enabled || !api.GRPC.Enabled || !api.GRPC.RequireMTLS {
		t.Fatal("Policy API example must enable HTTP and mTLS-required gRPC")
	}

	if api.Limits.MaxRequestBytes != 1048576 || api.Limits.MaxFacts != 512 ||
		api.Limits.PerClientConcurrency != 8 || api.Limits.PerClientRequestsPerSecond != 25 {
		t.Fatal("Policy API example must retain explicit bounded global admission limits")
	}

	if len(api.Clients) != 2 {
		t.Fatalf("Policy API clients = %d, want separate Bearer and Basic profiles", len(api.Clients))
	}
}

// assertPolicyAPIBearerProfile verifies mTLS-bound Bearer admission and diagnostic grants.
func assertPolicyAPIBearerProfile(t *testing.T, bearer policyconfig.ClientProfileConfig) {
	t.Helper()

	if len(bearer.AuthenticationKinds) != 1 || bearer.AuthenticationKinds[0] != "oidc_bearer" || !bearer.RequireMTLS {
		t.Fatal("Policy Bearer profile must be an mTLS-bound oidc_bearer")
	}

	if !bearer.Diagnostics || len(bearer.AllowedSchemas) != 1 || len(bearer.AllowedSubjectAttributes) == 0 ||
		len(bearer.AllowedResourceAttributes) == 0 || len(bearer.AllowedEnvironmentAttributes) == 0 ||
		len(bearer.AllowedInputAttributes) == 0 {
		t.Fatal("Policy Bearer profile must document schema, fact, and diagnostics admission")
	}
}

// assertPolicyAPIBasicProfile verifies the dedicated non-empty Basic credential owner.
func assertPolicyAPIBasicProfile(t *testing.T, basic policyconfig.ClientProfileConfig) {
	t.Helper()

	if len(basic.AuthenticationKinds) != 1 || basic.AuthenticationKinds[0] != "basic" ||
		basic.Authentication.Basic == nil || basic.Authentication.Basic.Password.IsZero() {
		t.Fatal("Policy Basic profile must own dedicated non-empty credentials")
	}

	if basic.Authentication.Basic.Username != "policy-automation" {
		t.Fatal("Policy Basic profile must retain its dedicated username")
	}
}

// assertPolicyAPITargetGrants verifies both callers have only the documented target action.
func assertPolicyAPITargetGrants(t *testing.T, clients []policyconfig.ClientProfileConfig) {
	t.Helper()

	for index, client := range clients {
		if len(client.Targets) != 1 || client.Targets[0].Namespace != "dkim2" ||
			len(client.Targets[0].Actions) != 1 || client.Targets[0].Actions[0] != "sign-message" {
			t.Fatalf("Policy API client %d target grants = %+v, want exact dkim2/sign-message", index, client.Targets)
		}
	}
}

func TestPolicyMigrationGuidePairedExamplePreservesRBLMeaning(t *testing.T) {
	oldSource := policyMigrationGuideFencedYAML(t, policyMigrationGuideOldHeading)
	newSource := policyMigrationGuideProductionYAML(t)

	assertDocumentedFragments(t, "old paired policy", oldSource, []string{
		"name: rbl",
		"type: builtin.rbl",
		"config_ref: auth.controls.rbl",
		"attribute: auth.rbl.threshold_reached",
		"is: true",
	})
	assertDocumentedFragments(t, "new paired policy", newSource, []string{
		"name: rbl",
		"use: authn/builtin/rbl",
		"output: nauthilus.auth.rbl.threshold_reached",
		"attribute: nauthilus.auth.rbl.threshold_reached",
		"is: true",
	})
}

func TestPolicyMigrationGuidePluginProviderExampleValidates(t *testing.T) {
	source := policyMigrationGuideFencedYAML(t, policyMigrationGuidePluginSourceHeading)

	document, err := policyconfig.Decode("yaml", strings.NewReader(source))
	if err != nil {
		t.Fatalf("decode plugin source provider example: %v", err)
	}

	document = policyconfig.Normalize(document)
	if err = policyconfig.Validate(document); err != nil {
		t.Fatalf("validate plugin source provider example: %v", err)
	}

	authn := document.Policy.Namespaces["authn"]
	for _, identity := range []string{"plugin.acme.environment", "plugin.acme.subject.risk"} {
		provider, exists := authn.Providers[identity]
		if !exists || provider.Kind != "plugin" || provider.Module != "acme" ||
			provider.CanonicalID("authn", identity) != "authn/"+identity {
			t.Fatalf("documented plugin provider %q = %+v, exists %t", identity, provider, exists)
		}
	}
}

func TestPolicyDocsUseGenerationTerminology(t *testing.T) {
	repositoryRoot := policyMigrationRepositoryRoot(t)

	for _, relativePath := range []string{
		"server/docs/go_plugins.md",
		"server/docs/go_plugin_developer_api.md",
		"server/docs/go_plugin_api_working_draft.md",
	} {
		source, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(relativePath)))
		if err != nil {
			t.Fatalf("read %s: %v", relativePath, err)
		}

		if strings.Contains(strings.ToLower(string(source)), "policy snapshot") {
			t.Errorf("%s retains removed policy snapshot terminology", relativePath)
		}
	}
}

// assertDocumentedFragments verifies exact contract fragments in one fenced example.
func assertDocumentedFragments(t *testing.T, name string, source string, fragments []string) {
	t.Helper()

	for _, fragment := range fragments {
		if !strings.Contains(source, fragment) {
			t.Errorf("%s is missing %q", name, fragment)
		}
	}
}

func TestPolicyMigrationGuideProductionExampleCompiles(t *testing.T) {
	source := policyMigrationGuideProductionYAML(t)

	document, err := policyconfig.Decode("yaml", strings.NewReader(source))
	if err != nil {
		t.Fatalf("decode documented production policy: %v", err)
	}

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("normalize documented production policy: %v", err)
	}

	if _, err = input.Compile(context.Background(), policyMigrationGuideAcceptance{}); err != nil {
		t.Fatalf("compile documented production policy: %v", err)
	}
}

func TestPolicyMigrationGuideGenericNativeExampleValidates(t *testing.T) {
	source := policyMigrationGuideFencedYAML(t, policyMigrationGuideNativeHeading)

	document, err := policyconfig.Decode("yaml", strings.NewReader(source))
	if err != nil {
		t.Fatalf("decode documented generic native policy: %v", err)
	}

	if err = policyconfig.Validate(document); err != nil {
		t.Fatalf("validate documented generic native policy: %v", err)
	}

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("normalize documented generic native policy: %v", err)
	}

	catalog, err := input.Compile(context.Background(), policyMigrationGuideAcceptance{})
	if err != nil {
		t.Fatalf("compile documented generic native policy: %v", err)
	}

	assertPolicyMigrationGuideNativeCatalog(t, catalog)
	assertPolicyMigrationGuideNativeDocument(t, document)
}

// assertPolicyMigrationGuideNativeDocument checks the documented source-owned native contract.
func assertPolicyMigrationGuideNativeDocument(t *testing.T, document policyconfig.Document) {
	t.Helper()

	namespace := document.Policy.Namespaces["dkim2"]

	assertPolicyMigrationGuideNativeFactProvider(t, namespace)
	assertPolicyMigrationGuideNativeFactSchema(t, namespace)
	assertPolicyMigrationGuideNativeEffectProvider(t, namespace)
	assertPolicyMigrationGuideNativeEffectSelection(t, namespace)
}

// assertPolicyMigrationGuideNativeFactProvider checks the documented fact-provider identity and scope.
func assertPolicyMigrationGuideNativeFactProvider(t *testing.T, namespace policyconfig.NamespaceConfig) {
	t.Helper()

	provider := namespace.Providers["risk"]

	if got := provider.CanonicalID("dkim2", "risk"); got != "dkim2/plugin.reputation.risk" {
		t.Fatalf("documented native provider identity = %q, want dkim2/plugin.reputation.risk", got)
	}

	if provider.Module != "reputation" || len(provider.Targets) != 1 || provider.Targets[0].Action != "sign-message" {
		t.Fatalf("documented native module/targets = %q/%v", provider.Module, provider.Targets)
	}

	if got := provider.ProducedFacts; len(got) != 1 || got[0] != "plugin.reputation.risk_score" {
		t.Fatalf("documented native provider outputs = %v, want plugin.reputation.risk_score", got)
	}
}

// assertPolicyMigrationGuideNativeFactSchema checks the documented source authority.
func assertPolicyMigrationGuideNativeFactSchema(t *testing.T, namespace policyconfig.NamespaceConfig) {
	t.Helper()

	facts := namespace.SchemaContributions.Static["sign-message"].Versions["v1"].Facts

	if len(facts) != 1 || len(facts[0].AllowedSources) != 1 || facts[0].AllowedSources[0] != "plugin" {
		t.Fatalf("documented native fact schema = %v, want one plugin-sourced fact", facts)
	}
}

// assertPolicyMigrationGuideNativeEffectProvider checks the documented effect-provider binding and execution modes.
func assertPolicyMigrationGuideNativeEffectProvider(t *testing.T, namespace policyconfig.NamespaceConfig) {
	t.Helper()

	provider := namespace.Providers["risk"]
	notifier := namespace.Providers["notifier"]
	effect := namespace.Effects["record-audit"]

	if effect.Provider != "dkim2/plugin.reputation.notifier" ||
		effect.Provider != notifier.CanonicalID("dkim2", "notifier") ||
		effect.Execution != "host_sync" {
		t.Fatalf("documented native effect binding = %q/%q", effect.Provider, effect.Execution)
	}

	if len(provider.Executions) != 0 || len(notifier.Executions) != 1 || notifier.Executions[0] != "host_sync" {
		t.Fatalf("documented native fact/effect executions = %v/%v", provider.Executions, notifier.Executions)
	}
}

// assertPolicyMigrationGuideNativeEffectSelection checks the documented obligation selection and parameters.
func assertPolicyMigrationGuideNativeEffectSelection(t *testing.T, namespace policyconfig.NamespaceConfig) {
	t.Helper()

	rules := namespace.PolicySets["default"].Rules

	if len(rules) != 1 || len(rules[0].Then.Obligations) != 1 {
		t.Fatalf("documented native effect rules = %v, want one selected obligation", rules)
	}

	selection := rules[0].Then.Obligations[0]

	if selection.ID != "dkim2/record-audit" || selection.Parameters["channel"] != "security" {
		t.Fatalf("documented native effect selection = %q/%v", selection.ID, selection.Parameters)
	}
}

// assertPolicyMigrationGuideNativeCatalog checks exact native identities at the compiled target boundary.
func assertPolicyMigrationGuideNativeCatalog(t *testing.T, catalog *policyruntime.TargetCatalog) {
	t.Helper()

	target, err := decision.NewTarget("dkim2", "sign-message")
	if err != nil {
		t.Fatalf("construct documented generic native target: %v", err)
	}

	compiled, exists := catalog.Lookup(target)
	if !exists {
		t.Fatal("documented generic native target is absent from compiled catalog")
	}

	if got := compiled.Schema().Identity().String(); got != "dkim2/sign-message/v1" {
		t.Fatalf("documented generic native schema = %q, want dkim2/sign-message/v1", got)
	}

	factProvider, exists := compiled.LookupProvider("dkim2/plugin.reputation.risk")
	if !exists || factProvider.ID() != "dkim2/plugin.reputation.risk" {
		t.Fatalf("documented native fact provider = %q, exists %t", factProvider.ID(), exists)
	}

	effectProvider, exists := compiled.LookupProvider("dkim2/plugin.reputation.notifier")
	if !exists || effectProvider.ID() != "dkim2/plugin.reputation.notifier" {
		t.Fatalf("documented native effect provider = %q, exists %t", effectProvider.ID(), exists)
	}

	effect, exists := compiled.LookupEffect("dkim2/record-audit")
	if !exists || effect.Provider() != effectProvider.ID() {
		t.Fatalf("documented selected effect provider = %q, exists %t", effect.Provider(), exists)
	}
}

// policyMigrationGuideProductionYAML extracts the fenced example owned by the migration guide.
func policyMigrationGuideProductionYAML(t *testing.T) string {
	t.Helper()

	return policyMigrationGuideFencedYAML(t, policyMigrationGuideHeading)
}

// policyMigrationGuideFencedYAML extracts the first fenced YAML example after one exact heading.
func policyMigrationGuideFencedYAML(t *testing.T, heading string) string {
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

	_, afterHeading, found := strings.Cut(string(guide), heading)
	if !found || strings.Contains(afterHeading, heading) {
		t.Fatalf("migration guide must contain exactly one %q heading", heading)
	}

	const fenceStart = "\n\n```yaml\n"
	if !strings.HasPrefix(afterHeading, fenceStart) {
		t.Fatalf("migration guide heading %q has no YAML fence", heading)
	}

	afterFence := strings.TrimPrefix(afterHeading, fenceStart)

	source, _, found := strings.Cut(afterFence, "\n```\n")
	if !found {
		t.Fatalf("migration guide heading %q has no closing fence", heading)
	}

	return source
}

// policyMigrationRepositoryRoot resolves the checkout root from this test file.
func policyMigrationRepositoryRoot(t *testing.T) string {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve migration guide test path")
	}

	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}

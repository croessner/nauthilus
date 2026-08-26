// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package config_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

// policyCutoverPathCase binds one standalone source to its authoritative error path.
type policyCutoverPathCase struct {
	name     string
	source   string
	path     string
	validate bool
}

type removedPolicyRootCase struct {
	name   string
	source string
	want   bool
}

var removedPolicyRootCases = []removedPolicyRootCase{
	{
		name:   "policy is first auth child",
		source: "auth:\n  policy: {}\n",
		want:   true,
	},
	{
		name: "policy follows another auth child",
		source: `auth:
  controls:
    brute_force: {}
  policy: {}
`,
		want: true,
	},
	{
		name: "nested policy is not auth policy",
		source: `auth:
  controls:
    policy: {}
`,
	},
	{
		name:   "top level policy is supported",
		source: "auth: {}\npolicy: {}\n",
	},
	{
		name:   "json sibling",
		source: `{"auth":{"controls":{},"policy":{}}}`,
		want:   true,
	},
	{
		name:   "yaml case variant empty",
		source: "Auth:\n  Policy: {}\n",
		want:   true,
	},
	{
		name:   "yaml mixed case null",
		source: "auth:\n  Policy: null\npolicy: {}\n",
		want:   true,
	},
	{
		name:   "yaml quoted literal dotted empty",
		source: "\"auth.policy\": {}\n",
		want:   true,
	},
	{
		name:   "json case variant null",
		source: `{"policy":{},"Auth":{"Policy":null}}`,
		want:   true,
	},
	{
		name:   "json literal dotted empty",
		source: `{"policy":{},"auth.policy":{}}`,
		want:   true,
	},
	{
		name:   "toml section",
		source: "[auth.controls]\nenabled = true\n[auth.policy]\nmode = \"observe\"\n",
		want:   true,
	},
	{
		name:   "toml case variant section",
		source: "[Auth.Policy]\nmode = \"observe\"\n",
		want:   true,
	},
	{
		name:   "toml quoted literal dotted empty",
		source: "\"auth.policy\" = {}\n",
		want:   true,
	},
	{
		name:   "flat property",
		source: "auth.controls.enabled=true\nauth.policy.mode=observe\n",
		want:   true,
	},
	{
		name:   "flat case variant property",
		source: "Auth.Policy.mode=observe\n",
		want:   true,
	},
	{
		name:   "tfvars inline object",
		source: `auth = { controls = {}, policy = { mode = "observe" } }`,
		want:   true,
	},
	{
		name:   "prose is not a structural root",
		source: "The removed auth.policy owner is documented elsewhere.\n",
	},
	{
		name:   "namespace identity is not a structural root",
		source: "auth.policy.contract\n",
	},
}

// policyRepositoryTextFilter selects repository files for one supported-surface scan.
type policyRepositoryTextFilter func(relativePath string) bool

// policyRepositoryTextVisitor inspects one selected repository text file.
type policyRepositoryTextVisitor func(relativePath string, source []byte)

func TestPolicyCutoverStandaloneDecoderRejectsRemovedShapes(t *testing.T) {
	for _, test := range policyCutoverRemovedShapeCases() {
		t.Run(test.name, func(t *testing.T) {
			requirePolicyCutoverPathError(t, test)
		})
	}
}

// policyCutoverRemovedShapeCases owns every legacy spelling exercised by the required package lane.
func policyCutoverRemovedShapeCases() []policyCutoverPathCase {
	cases := []policyCutoverPathCase{
		{name: "old root", source: "auth:\n  policy: {}\n", path: "auth"},
		{name: "mixed roots", source: "policy: {}\nauth:\n  policy: {}\n", path: "auth"},
		{name: "global policy sets", source: "policy:\n  policy_sets: {}\n", path: "policy.policy_sets"},
		{
			name:   "target inline sets",
			source: "policy:\n  targets:\n    - namespace: dkim2\n      action: sign-message-instance\n      policy_sets: {}\n",
			path:   "policy.targets[0].policy_sets",
		},
		{
			name: "unqualified standard auth",
			source: `policy:
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      default_policy: standard_auth
`,
			path:     "policy.targets[0].default_policy",
			validate: true,
		},
	}

	for _, alias := range []struct {
		name  string
		field string
		value string
	}{
		{name: "provider type alias", field: "type", value: "builtin.brute_force"},
		{name: "provider operations alias", field: "operations", value: "[authenticate]"},
		{name: "provider stage alias", field: "stage", value: "pre_auth"},
		{name: "provider config ref alias", field: "config_ref", value: "auth.controls.brute_force"},
	} {
		cases = append(cases, policyCutoverPathCase{
			name:   alias.name,
			source: policyCutoverProviderAliasSource(alias.field, alias.value),
			path:   "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[0]." + alias.field,
		})
	}

	for _, alias := range []struct {
		name  string
		field string
		value string
	}{
		{name: "rule stage alias", field: "stage", value: "pre_auth"},
		{name: "rule operations alias", field: "operations", value: "[authenticate]"},
		{name: "rule require checks alias", field: "require_checks", value: "[brute_force]"},
	} {
		cases = append(cases, policyCutoverPathCase{
			name:   alias.name,
			source: policyCutoverRuleAliasSource(alias.field, alias.value),
			path:   "policy.namespaces.authn.policy_sets.configured.rules[0]." + alias.field,
		})
	}

	return append(cases, policyCutoverNestedRuleAliasCases()...)
}

// policyCutoverProviderAliasSource places one removed provider field at its natural location.
func policyCutoverProviderAliasSource(field string, value string) string {
	return fmt.Sprintf(`policy:
  namespaces:
    authn:
      domain_plans:
        password:
          checkpoints:
            pre_auth:
              providers:
                - name: brute_force
                  use: authn/builtin/brute_force
                  %s: %s
`, field, value)
}

// policyCutoverRuleAliasSource places one removed rule selector at its natural location.
func policyCutoverRuleAliasSource(field string, value string) string {
	return fmt.Sprintf(`policy:
  namespaces:
    authn:
      policy_sets:
        configured:
          rules:
            - name: deny
              %s: %s
`, field, value)
}

// policyCutoverNestedRuleAliasCases returns the removed control and effect-argument spellings.
func policyCutoverNestedRuleAliasCases() []policyCutoverPathCase {
	return []policyCutoverPathCase{
		{
			name: "stage control alias",
			source: `policy:
  namespaces:
    authn:
      policy_sets:
        configured:
          rules:
            - name: deny
              then:
                control:
                  skip_remaining_stage_checks: true
`,
			path: "policy.namespaces.authn.policy_sets.configured.rules[0].then.control.skip_remaining_stage_checks",
		},
		{
			name: "effect args alias",
			source: `policy:
  namespaces:
    authn:
      policy_sets:
        configured:
          rules:
            - name: deny
              then:
                obligations:
                  - id: authn/audit
                    args: {}
`,
			path: "policy.namespaces.authn.policy_sets.configured.rules[0].then.obligations[0].args",
		},
	}
}

func TestPolicyCutoverAcceptsQualifiedLuaCollisionAndHostOwnedEffect(t *testing.T) {
	document := requireValidPolicyCutoverSource(t, policyCutoverLuaCollisionSource)
	authn := document.Policy.Namespaces["authn"]
	providers := authn.DomainPlans["password"].Checkpoints["pre_auth"].Providers

	if len(providers) != 2 {
		t.Fatalf("checkpoint providers = %d, want 2", len(providers))
	}

	if providers[0].Use != "authn/lua_environment_shared" || providers[1].Use != "authn/lua_subject_shared" {
		t.Fatalf("qualified Lua identities = %q, %q", providers[0].Use, providers[1].Use)
	}

	if providers[0].Use == providers[1].Use {
		t.Fatalf("Lua environment and subject identities collide at %q", providers[0].Use)
	}

	environmentName, environmentQualified := strings.CutPrefix(providers[0].Name, "lua_environment_")
	subjectName, subjectQualified := strings.CutPrefix(providers[1].Name, "lua_subject_")

	if !environmentQualified || !subjectQualified || environmentName != subjectName || environmentName != "shared" {
		t.Fatalf("old Lua names = %q, %q, want equal shared names", environmentName, subjectName)
	}
}

func TestPolicyCutoverImplicitBuiltinRequirementsUseExactPaths(t *testing.T) {
	tests := []struct {
		name        string
		requirement string
		path        string
	}{
		{name: "available pre-auth builtin", requirement: "brute_force"},
		{
			name:        "unavailable pre-auth builtin",
			requirement: "tls_encryption",
			path:        "policy.namespaces.authn.policy_sets.configured.rules[0].require_providers[0]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := policyCutoverImplicitBuiltinSource(test.requirement)
			if test.path == "" {
				requireValidPolicyCutoverSource(t, source)

				return
			}

			requirePolicyCutoverPathError(t, policyCutoverPathCase{
				name:     test.name,
				source:   source,
				path:     test.path,
				validate: true,
			})
		})
	}
}

// requirePolicyCutoverPathError checks strict decoding and optional semantic validation at one exact path.
func requirePolicyCutoverPathError(t *testing.T, test policyCutoverPathCase) {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(test.source))
	if test.validate && err == nil {
		err = policyconfig.Validate(document)
	}

	var pathError *policyconfig.PathError

	if !errors.As(err, &pathError) {
		t.Fatalf("%s error = %v, want path error at %s", test.name, err, test.path)
	}

	if pathError.Path != test.path {
		t.Fatalf("%s error path = %q, want %q", test.name, pathError.Path, test.path)
	}
}

// requireValidPolicyCutoverSource decodes and validates one standalone YAML fixture.
func requireValidPolicyCutoverSource(t *testing.T, source string) policyconfig.Document {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(source))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if err := policyconfig.Validate(document); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	return document
}

// policyCutoverImplicitBuiltinSource selects one host-owned builtin without a replacement domain plan.
func policyCutoverImplicitBuiltinSource(requirement string) string {
	return fmt.Sprintf(`policy:
  namespaces:
    authn:
      policy_sets:
        configured:
          rules:
            - name: require_builtin
              checkpoint: pre_auth
              actions: [authenticate]
              require_providers: [%s]
              if:
                always: true
              then:
                decision: deny
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      default_policy: authn/standard_auth
      plans:
        pre_auth:
          policy_sets: [authn/configured]
`, requirement)
}

const policyCutoverLuaCollisionSource = `policy:
  namespaces:
    authn:
      providers:
        lua_environment_shared:
          kind: lua_environment
          script_path: /etc/nauthilus/lua/environment/shared.lua
        lua_subject_shared:
          kind: lua_subject
          script_path: /etc/nauthilus/lua/subject/shared.lua
      effects:
        lua_action_security:
          kind: lua_action
          action_type: lua
          script_path: /etc/nauthilus/lua/action/security.lua
          execution: host_sync
      domain_plans:
        password:
          checkpoints:
            pre_auth:
              providers:
                - name: lua_environment_shared
                  use: authn/lua_environment_shared
                  actions: [authenticate]
                - name: lua_subject_shared
                  use: authn/lua_subject_shared
                  actions: [authenticate]
                  after: [lua_environment_shared]
      policy_sets:
        configured:
          rules:
            - name: deny_shared
              checkpoint: pre_auth
              actions: [authenticate]
              require_providers: [lua_environment_shared]
              if:
                always: true
              then:
                decision: deny
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/password
      default_policy: authn/standard_auth
      plans:
        pre_auth:
          policy_sets: [authn/configured]
`

func TestPolicyCutoverRequiredCheckExercisesContract(t *testing.T) {
	document, err := policyconfig.Decode("yaml", strings.NewReader("policy: {}\n"))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if err := policyconfig.Validate(document); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	canonical, err := policyconfig.Canonical(document)
	if err != nil {
		t.Fatalf("Canonical() error = %v", err)
	}

	if got := canonical.Value("policy.api.enabled"); got != false {
		t.Fatalf("canonical policy.api.enabled = %#v, want false", got)
	}

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if len(input.Definitions) != 1 {
		t.Fatalf("definition contributions = %d, want builtin contribution only", len(input.Definitions))
	}

	if got := input.Definitions[0].Ownership().Owner(); got != "builtin.authn" {
		t.Fatalf("builtin definition owner = %q, want builtin.authn", got)
	}

	if got := input.Definitions[0].PolicySets(); len(got) != 1 || got[0].ID().String() != registry.BuiltinStandardAuthPolicySet {
		t.Fatalf("builtin policy sets = %v, want only %s", got, registry.BuiltinStandardAuthPolicySet)
	}

	if len(input.Activations) != 3 {
		t.Fatalf("builtin target activations = %d, want 3", len(input.Activations))
	}
}

func TestPolicyCutoverProductionFileSettingsOwnsUnifiedPolicy(t *testing.T) {
	settingsType := reflect.TypeFor[config.FileSettings]()

	field, ok := settingsType.FieldByName("Policy")
	if !ok {
		t.Fatal("FileSettings.Policy is missing")
	}

	if field.Type != reflect.TypeFor[policyconfig.PolicyConfig]() {
		t.Fatalf("FileSettings.Policy type = %s, want policyconfig.PolicyConfig", field.Type)
	}
}

func TestPolicyCutoverProductionContainsNoRemovedAuthority(t *testing.T) {
	root := policyContractRepositoryRoot(t)

	violations, err := policyProductionAuthorityViolations(root)
	if err != nil {
		t.Fatalf("scan production policy authority: %v", err)
	}

	if len(violations) != 0 {
		t.Fatalf("removed production policy authority remains:\n%s", strings.Join(violations, "\n"))
	}
}

func TestPolicyCutoverProductionAbsenceOracleClassifiesEveryAuthorityFamily(t *testing.T) {
	const source = `package fixture
import (
    "github.com/croessner/nauthilus/v3/server/policy/compiler"
    "github.com/croessner/nauthilus/v3/server/policy/evaluation"
)
type AuthPolicySection struct{}
type SnapshotStore struct{}
type CompiledStagePlan struct{}
type closedAdmissionAuthority struct{}
type authPolicyConfigProvider interface { GetAuthPolicy() AuthPolicySection }
func build() { _ = compiler.NewCompiler; _ = evaluation.NewEvaluator }
`

	file, err := parser.ParseFile(token.NewFileSet(), "authority_fixture.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse production authority fixture: %v", err)
	}

	violations := policyProductionFileAuthorityViolations("server/core/authority_fixture.go", file)
	for _, category := range []string{
		"config-root", "old-compiler", "old-plan", "second-generation", "closed-authority",
		"ambient-config", "direct-evaluator",
	} {
		if !slices.ContainsFunc(violations, func(violation string) bool {
			return strings.HasPrefix(violation, category+":")
		}) {
			t.Fatalf("classified production violations = %v, want category %q", violations, category)
		}
	}
}

func TestPolicyCutoverHistoricalRootExamplesAreExplicitlyAllowlisted(t *testing.T) {
	root := policyContractRepositoryRoot(t)
	allowlist := map[string]string{
		"server/config/testdata/policy_migration/old.yaml": "frozen rejected old fixture",
		"server/docs/policy_configuration_migration.md":    "paired manual old/new guide",
	}
	archiveIndexPath := filepath.Join(root, "server", "docs", "policy-layer", "README.md")

	archiveIndex, err := os.ReadFile(archiveIndexPath)
	if err != nil {
		t.Fatalf("read historical Policy archive index: %v", err)
	}

	for _, required := range []string{"historical", "not operator documentation", "top-level `policy` root"} {
		if !strings.Contains(string(archiveIndex), required) {
			t.Fatalf("historical Policy archive index is missing classification %q", required)
		}
	}

	for relative, purpose := range allowlist {
		source, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if readErr != nil {
			t.Fatalf("read %s %s: %v", purpose, relative, readErr)
		}

		if !containsRemovedPolicyRoot(source) {
			t.Fatalf("allowlisted %s %q has no structural auth.policy example", purpose, relative)
		}
	}

	unexpected, err := policyRemovedRootSurfaceViolations(root, allowlist)
	if err != nil {
		t.Fatalf("scan supported policy surfaces: %v", err)
	}

	if len(unexpected) != 0 {
		t.Fatalf("unclassified structural auth.policy examples remain: %v", unexpected)
	}
}

func TestPolicyCutoverRemovedRootDetectorHandlesAuthSiblings(t *testing.T) {
	for _, test := range removedPolicyRootCases {
		t.Run(test.name, func(t *testing.T) {
			if got := containsRemovedPolicyRoot([]byte(test.source)); got != test.want {
				t.Fatalf("containsRemovedPolicyRoot() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestPolicyCutoverSupportedSurfaceScanHonorsClassifications(t *testing.T) {
	root := t.TempDir()
	allowlist := map[string]string{
		"server/config/testdata/policy_migration/old.yaml": "frozen rejected old fixture",
		"server/docs/policy_configuration_migration.md":    "paired manual old/new guide",
	}
	fixtures := map[string]string{
		"contrib/examples/current.yml": `auth:
  controls: {}
  policy: {}
`,
		"server/config/testdata/policy_migration/old.yaml": "auth:\n  policy: {}\n",
		"server/docs/policy_configuration_migration.md":    "auth:\n  policy: {}\n",
		"server/docs/policy-layer/historical.md":           "auth:\n  policy: {}\n",
		"temp/planning.md":                                 "auth:\n  policy: {}\n",
		"vendor/example.test/dependency.yml":               "auth:\n  policy: {}\n",
	}

	writePolicyRepositoryTextFixtures(t, root, fixtures)

	violations, err := policyRemovedRootSurfaceViolations(root, allowlist)
	if err != nil {
		t.Fatalf("scan supported surface fixtures: %v", err)
	}

	want := []string{"contrib/examples/current.yml"}

	if !slices.Equal(violations, want) {
		t.Fatalf("supported surface violations = %v, want %v", violations, want)
	}
}

// writePolicyRepositoryTextFixtures writes hermetic repository-scan fixtures.
func writePolicyRepositoryTextFixtures(t *testing.T, root string, fixtures map[string]string) {
	t.Helper()

	for relativePath, source := range fixtures {
		path := filepath.Join(root, filepath.FromSlash(relativePath))

		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("create fixture directory for %s: %v", relativePath, err)
		}

		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", relativePath, err)
		}
	}
}

// policyRemovedRootSurfaceViolations scans supported configuration and documentation surfaces.
func policyRemovedRootSurfaceViolations(root string, allowlist map[string]string) ([]string, error) {
	violations := make([]string, 0)

	err := walkPolicyRepositoryTextFiles(root, isPolicySupportedSurfaceFile, func(relativePath string, source []byte) {
		if _, allowed := allowlist[relativePath]; allowed {
			return
		}

		if containsRemovedPolicyRoot(source) {
			violations = append(violations, relativePath)
		}
	})
	if err != nil {
		return nil, err
	}

	slices.Sort(violations)

	return slices.Compact(violations), nil
}

// walkPolicyRepositoryTextFiles visits repository-owned text files after shared exclusions.
func walkPolicyRepositoryTextFiles(
	root string,
	include policyRepositoryTextFilter,
	visit policyRepositoryTextVisitor,
) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		relative = filepath.ToSlash(relative)

		if entry.IsDir() {
			if policyRepositoryDirectoryExcluded(relative) {
				return filepath.SkipDir
			}

			return nil
		}

		if !include(relative) {
			return nil
		}

		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		visit(relative, source)

		return nil
	})
}

// policyRepositoryDirectoryExcluded classifies non-production and historical trees.
func policyRepositoryDirectoryExcluded(relativePath string) bool {
	if relativePath == "server/docs/policy-layer" {
		return true
	}

	return slices.Contains([]string{
		".agents",
		".codex",
		".git",
		"node_modules",
		"temp",
		"vendor",
	}, filepath.Base(relativePath))
}

// isPolicySupportedSurfaceFile selects configuration, template, example, and documentation text.
func isPolicySupportedSurfaceFile(relativePath string) bool {
	if policyRepositoryTestOracle(relativePath) {
		return false
	}

	extension := strings.ToLower(filepath.Ext(relativePath))

	return slices.Contains([]string{
		".adoc",
		".cfg",
		".conf",
		".env",
		".gohtml",
		".gotmpl",
		".hcl",
		".html",
		".ini",
		".json",
		".md",
		".markdown",
		".prop",
		".properties",
		".props",
		".rst",
		".tfvars",
		".toml",
		".tpl",
		".tmpl",
		".txt",
		".vim",
		".yaml",
		".yml",
	}, extension)
}

// isPolicySupportedReferenceFile extends surface files with production source and scripts.
func isPolicySupportedReferenceFile(relativePath string) bool {
	if isPolicySupportedSurfaceFile(relativePath) {
		return true
	}

	if policyRepositoryTestOracle(relativePath) {
		return false
	}

	baseName := strings.ToLower(filepath.Base(relativePath))

	if slices.Contains([]string{".dockerignore", ".gitignore", "dockerfile", "makefile"}, baseName) {
		return true
	}

	extension := strings.ToLower(filepath.Ext(relativePath))

	return slices.Contains([]string{
		".bash",
		".fish",
		".go",
		".mk",
		".py",
		".sh",
		".zsh",
	}, extension)
}

// policyRepositoryTestOracle excludes source files whose strings intentionally describe rejection cases.
func policyRepositoryTestOracle(relativePath string) bool {
	baseName := strings.ToLower(filepath.Base(relativePath))

	return strings.HasSuffix(baseName, "_test.go") ||
		(strings.HasPrefix(baseName, "test_") && strings.HasSuffix(baseName, ".py"))
}

// containsRemovedPolicyRoot recognizes structural old roots without matching identifiers or prose.
func containsRemovedPolicyRoot(source []byte) bool {
	if containsJSONRemovedPolicyRoot(source) {
		return true
	}

	lines := strings.Split(strings.ReplaceAll(string(source), "\r\n", "\n"), "\n")
	for index, line := range lines {
		if containsFlatRemovedPolicyRoot(line) {
			return true
		}

		if policyRootObjectLine(line, "auth") && authObjectContainsPolicy(lines, index) {
			return true
		}
	}

	return false
}

// authObjectContainsPolicy reports whether one textual auth object owns a direct policy child.
func authObjectContainsPolicy(lines []string, authIndex int) bool {
	authIndent := policyLineIndent(lines[authIndex])
	childIndent := -1

	for next := authIndex + 1; next < len(lines); next++ {
		trimmed := strings.TrimSpace(lines[next])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := policyLineIndent(lines[next])
		if indent <= authIndent {
			return false
		}

		if childIndent == -1 || indent < childIndent {
			childIndent = indent
		}

		if indent == childIndent && policyRootObjectLine(lines[next], "policy") {
			return true
		}
	}

	return false
}

// containsJSONRemovedPolicyRoot detects the removed nested owner in complete JSON documents.
func containsJSONRemovedPolicyRoot(source []byte) bool {
	document := make(map[string]any)

	if err := json.Unmarshal(source, &document); err != nil {
		return false
	}

	for rawKey, value := range document {
		key := strings.TrimSpace(rawKey)
		if strings.EqualFold(key, "auth.policy") {
			return true
		}

		if !strings.EqualFold(key, "auth") {
			continue
		}

		auth, ok := value.(map[string]any)
		if !ok {
			continue
		}

		for authKey := range auth {
			if strings.EqualFold(strings.TrimSpace(authKey), "policy") {
				return true
			}
		}
	}

	return false
}

// containsFlatRemovedPolicyRoot detects exact flat-format roots and inline mappings.
func containsFlatRemovedPolicyRoot(line string) bool {
	trimmed := strings.TrimSpace(line)
	compact := strings.ToLower(strings.NewReplacer(" ", "", "\t", "").Replace(trimmed))
	structural := strings.NewReplacer(`"`, "", `'`, "").Replace(compact)

	if structural == "[auth.policy]" || hasPolicyPrefix(structural, []string{
		"[auth.policy.", "auth.policy=", "auth.policy:",
	}) {
		return true
	}

	if strings.HasPrefix(structural, "auth.policy.") {
		return strings.Contains(structural, "=") || strings.Contains(structural, ":")
	}

	return containsInlineRemovedPolicyRoot(structural)
}

// hasPolicyPrefix reports whether a structural config line has any exact prefix.
func hasPolicyPrefix(structural string, prefixes []string) bool {
	return slices.ContainsFunc(prefixes, func(prefix string) bool {
		return strings.HasPrefix(structural, prefix)
	})
}

// containsInlineRemovedPolicyRoot detects old inline auth mappings in bounded text formats.
func containsInlineRemovedPolicyRoot(structural string) bool {
	patterns := []struct {
		prefix string
		child  string
	}{
		{prefix: "auth:{", child: "policy:"},
		{prefix: "auth{", child: "policy{"},
		{prefix: "auth={", child: "policy="},
	}

	return slices.ContainsFunc(patterns, func(pattern struct {
		prefix string
		child  string
	}) bool {
		return strings.HasPrefix(structural, pattern.prefix) && strings.Contains(structural, pattern.child)
	})
}

// policyRootObjectLine reports whether a line starts one exact object key.
func policyRootObjectLine(line string, key string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(line))
	key = strings.ToLower(strings.TrimSpace(key))

	for _, prefix := range []string{
		key + ":",
		`"` + key + `":`,
		`'` + key + `':`,
		key + " {",
		key + "{",
		key + " = {",
		key + "={",
	} {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}

	return false
}

// policyLineIndent counts leading horizontal whitespace for structural sibling detection.
func policyLineIndent(line string) int {
	indent := 0

	for _, character := range line {
		if character != ' ' && character != '\t' {
			break
		}

		indent++
	}

	return indent
}

// policyProductionAuthorityViolations scans non-test server code for removed authority families.
func policyProductionAuthorityViolations(root string) ([]string, error) {
	return policyGoSourceViolations(
		root,
		[]string{filepath.Join(root, "server")},
		parser.SkipObjectResolution,
		policyProductionFileAuthorityViolations,
	)
}

// policyProductionFileAuthorityViolations classifies exact legacy symbols and imports.
func policyProductionFileAuthorityViolations(path string, file *ast.File) []string {
	classified := map[string]string{
		"AuthPolicySection":              "config-root",
		"GetAuthPolicy":                  "config-root",
		"NewCompiler":                    "old-compiler",
		"CompileAndActivate":             "old-compiler",
		"CompiledStagePlan":              "old-plan",
		"CompiledCheck":                  "old-plan",
		"CompiledPolicy":                 "old-plan",
		"SnapshotStore":                  "second-generation",
		"NewSnapshotStore":               "second-generation",
		"DefaultStore":                   "second-generation",
		"BindDefaultStoreToGeneration":   "second-generation",
		"PolicySnapshot":                 "second-generation",
		"PolicySnapshotFromContext":      "second-generation",
		"ContextWithPolicySnapshot":      "second-generation",
		"closedCallerAuthenticationSlot": "closed-authority",
		"closedAdmissionSlot":            "closed-authority",
		"closedCallerAuthenticator":      "closed-authority",
		"closedAdmissionAuthority":       "closed-authority",
		"authPolicyConfigProvider":       "ambient-config",
		"policyConfigProvider":           "ambient-config",
	}
	violations := make([]string, 0)

	for _, importSpec := range file.Imports {
		importPath, err := strconv.Unquote(importSpec.Path.Value)
		if err == nil && importPath == "github.com/croessner/nauthilus/v3/server/policy/evaluation" {
			violations = append(violations, "direct-evaluator:"+path+" imports "+importPath)
		}
	}

	ast.Inspect(file, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok {
			return true
		}

		category, forbidden := classified[identifier.Name]
		if !forbidden {
			return true
		}

		violations = append(violations, category+":"+path+" references "+identifier.Name)

		return true
	})

	slices.Sort(violations)

	return slices.Compact(violations)
}

func TestPolicyMigrationStandaloneModelContainsNoLegacyRepresentation(t *testing.T) {
	violations := policyContractLegacyModelViolations(reflect.TypeFor[policyconfig.Document](), nil)
	if len(violations) != 0 {
		t.Fatalf("standalone policy model contains legacy representation: %s", strings.Join(violations, "; "))
	}

	root := policyContractRepositoryRoot(t)

	violations, err := policyContractStandaloneSourceViolations(root)
	if err != nil {
		t.Fatalf("scan standalone policy sources: %v", err)
	}

	if len(violations) != 0 {
		t.Fatalf("standalone policy sources contain a legacy decoder or translator: %s", strings.Join(violations, "; "))
	}
}

func TestPolicyMigrationAbsenceOracleRejectsLegacyTranslatorFixture(t *testing.T) {
	type legacyModelFixture struct {
		ConfigRef string `mapstructure:"config_ref"`
	}

	modelViolations := policyContractLegacyModelViolations(reflect.TypeFor[legacyModelFixture](), nil)
	if len(modelViolations) != 2 {
		t.Fatalf("legacy model fixture violations = %v, want ConfigRef field and tag", modelViolations)
	}

	const source = `package policyconfig
import "github.com/croessner/nauthilus/v3/server/config"
type LegacyPolicyDecoder struct{}
func migrateAuthPolicy(old config.AuthPolicySection) {}
var oldRoot = "auth.policy"
`

	file, err := parser.ParseFile(token.NewFileSet(), "legacy_fixture.go", source, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse legacy source fixture: %v", err)
	}

	sourceViolations := policyContractFileSourceViolations("legacy_fixture.go", file)
	wantFragments := []string{
		"imports production server/config",
		"references AuthPolicySection",
		"declares legacy type LegacyPolicyDecoder",
		"declares migration helper migrateAuthPolicy",
		"contains old auth.policy path",
	}

	for _, fragment := range wantFragments {
		if !slices.ContainsFunc(sourceViolations, func(violation string) bool {
			return strings.Contains(violation, fragment)
		}) {
			t.Fatalf("source fixture violations = %v, want fragment %q", sourceViolations, fragment)
		}
	}
}

// policyContractLegacyModelViolations walks the public standalone model without relying on source layout.
func policyContractLegacyModelViolations(model reflect.Type, visited map[reflect.Type]bool) []string {
	if visited == nil {
		visited = make(map[reflect.Type]bool)
	}

	for model.Kind() == reflect.Pointer || model.Kind() == reflect.Slice || model.Kind() == reflect.Array {
		model = model.Elem()
	}

	if model.Kind() == reflect.Map {
		model = model.Elem()
	}

	if model.Kind() != reflect.Struct || visited[model] {
		return nil
	}

	visited[model] = true
	violations := make([]string, 0)

	for field := range model.Fields() {
		path := model.Name() + "." + field.Name
		mapstructureName, _, _ := strings.Cut(field.Tag.Get("mapstructure"), ",")

		if field.Name == "ConfigRef" {
			violations = append(violations, path+" is a ConfigRef field")
		}

		if mapstructureName == "config_ref" {
			violations = append(violations, path+" owns mapstructure config_ref")
		}

		violations = append(violations, policyContractLegacyModelViolations(field.Type, visited)...)
	}

	return violations
}

// policyContractStandaloneSourceViolations rejects old-config coupling and migration machinery inside the new boundary.
func policyContractStandaloneSourceViolations(root string) ([]string, error) {
	directories := []string{
		filepath.Join(root, "server", "config", "policyconfig"),
		filepath.Join(root, "server", "policy", "configinput"),
	}

	return policyGoSourceViolations(root, directories, parser.ParseComments, policyContractFileSourceViolations)
}

// policyGoSourceViolations parses production Go files and returns sorted unique classifications.
func policyGoSourceViolations(
	root string,
	directories []string,
	mode parser.Mode,
	classify func(string, *ast.File) []string,
) ([]string, error) {
	violations := make([]string, 0)

	for _, directory := range directories {
		directoryViolations, err := policyGoDirectoryViolations(root, directory, mode, classify)
		if err != nil {
			return nil, err
		}

		violations = append(violations, directoryViolations...)
	}

	slices.Sort(violations)

	return slices.Compact(violations), nil
}

// policyGoDirectoryViolations scans one directory without duplicating source-walk mechanics.
func policyGoDirectoryViolations(
	root string,
	directory string,
	mode parser.Mode,
	classify func(string, *ast.File) []string,
) ([]string, error) {
	violations := make([]string, 0)

	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}

		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, mode)
		if parseErr != nil {
			return parseErr
		}

		relative, relativeErr := filepath.Rel(root, path)
		if relativeErr != nil {
			return relativeErr
		}

		violations = append(violations, classify(relative, file)...)

		return nil
	})

	return violations, err
}

// policyContractFileSourceViolations identifies only forbidden old-policy coupling in one standalone source file.
func policyContractFileSourceViolations(path string, file *ast.File) []string {
	violations := make([]string, 0)

	for _, importSpec := range file.Imports {
		importPath, err := strconv.Unquote(importSpec.Path.Value)
		if err == nil && importPath == "github.com/croessner/nauthilus/v3/server/config" {
			violations = append(violations, path+" imports production server/config")
		}
	}

	ast.Inspect(file, func(node ast.Node) bool {
		if violation := policyContractNodeSourceViolation(path, node); violation != "" {
			violations = append(violations, violation)
		}

		return true
	})

	return violations
}

// policyContractNodeSourceViolation identifies forbidden legacy syntax in one AST node.
func policyContractNodeSourceViolation(path string, node ast.Node) string {
	switch typed := node.(type) {
	case *ast.Ident:
		if slices.Contains([]string{"AuthPolicySection", "ConfigRef", "GetAuthPolicy"}, typed.Name) {
			return path + " references " + typed.Name
		}
	case *ast.FuncDecl:
		if policyContractMigrationHelperName(typed.Name.Name) {
			return path + " declares migration helper " + typed.Name.Name
		}
	case *ast.TypeSpec:
		if policyContractLegacyTypeName(typed.Name.Name) {
			return path + " declares legacy type " + typed.Name.Name
		}
	case *ast.BasicLit:
		if policyContractContainsOldPath(typed) {
			return path + " contains old auth.policy path"
		}
	}

	return ""
}

// policyContractContainsOldPath reports whether one string literal names the removed source root.
func policyContractContainsOldPath(literal *ast.BasicLit) bool {
	if literal.Kind != token.STRING {
		return false
	}

	value, err := strconv.Unquote(literal.Value)

	return err == nil && strings.Contains(value, "auth.policy")
}

// policyContractMigrationHelperName recognizes migration entry points without matching translation catalog helpers.
func policyContractMigrationHelperName(name string) bool {
	lowerName := strings.ToLower(name)

	return strings.Contains(lowerName, "migrat") ||
		(strings.Contains(lowerName, "policy") &&
			(strings.Contains(lowerName, "translate") || strings.Contains(lowerName, "convert")))
}

// policyContractLegacyTypeName recognizes decoder and translator types reserved for removed old shapes.
func policyContractLegacyTypeName(name string) bool {
	lowerName := strings.ToLower(name)

	return (strings.Contains(lowerName, "legacy") && strings.Contains(lowerName, "decoder")) ||
		strings.Contains(lowerName, "migrator") || strings.Contains(lowerName, "translator")
}

// policyContractRepositoryRoot resolves the checkout independently from the test working directory.
func policyContractRepositoryRoot(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() did not resolve the contract test path")
	}

	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

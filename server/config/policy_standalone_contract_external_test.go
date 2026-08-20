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
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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

func TestPolicyCutoverStandalonePackagesRemainIsolatedFromProduction(t *testing.T) {
	settingsType := reflect.TypeFor[config.FileSettings]()
	if _, ok := settingsType.FieldByName("Policy"); ok {
		t.Fatal("FileSettings.Policy exists, want standalone contract isolation")
	}

	root := policyContractRepositoryRoot(t)

	violations, err := policyContractIsolationViolations(root)
	if err != nil {
		t.Fatalf("scan production imports: %v", err)
	}

	if len(violations) != 0 {
		t.Fatalf("standalone policy packages escaped their boundary: %s", strings.Join(violations, "; "))
	}
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

// policyContractIsolationViolations finds production imports that escape the standalone package boundary.
func policyContractIsolationViolations(root string) ([]string, error) {
	standaloneDirectories := []string{
		filepath.Join(root, "server", "config", "policyconfig"),
		filepath.Join(root, "server", "policy", "configinput"),
	}
	forbiddenImports := []string{
		"github.com/croessner/nauthilus/v3/server/config/policyconfig",
		"github.com/croessner/nauthilus/v3/server/policy/configinput",
	}
	violations := make([]string, 0)

	err := filepath.WalkDir(filepath.Join(root, "server"), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}

		for _, directory := range standaloneDirectories {
			if pathInsideDirectory(path, directory) {
				return nil
			}
		}

		imports, parseErr := policyContractImports(path)
		if parseErr != nil {
			return parseErr
		}

		for _, importPath := range imports {
			if slices.Contains(forbiddenImports, importPath) {
				relative, relativeErr := filepath.Rel(root, path)
				if relativeErr != nil {
					return relativeErr
				}

				violations = append(violations, relative+" imports "+importPath)
			}
		}

		return nil
	})

	return violations, err
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
	violations := make([]string, 0)

	for _, directory := range directories {
		err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}

			file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
			if parseErr != nil {
				return parseErr
			}

			relative, relativeErr := filepath.Rel(root, path)
			if relativeErr != nil {
				return relativeErr
			}

			violations = append(violations, policyContractFileSourceViolations(relative, file)...)

			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	slices.Sort(violations)

	return violations, nil
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

// pathInsideDirectory reports whether path belongs to one standalone package directory.
func pathInsideDirectory(path string, directory string) bool {
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return false
	}

	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// policyContractImports parses only imports from one production Go source file.
func policyContractImports(path string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}

	imports := make([]string, 0, len(file.Imports))
	for _, importSpec := range file.Imports {
		importPath, unquoteErr := strconv.Unquote(importSpec.Path.Value)
		if unquoteErr != nil {
			return nil, unquoteErr
		}

		imports = append(imports, importPath)
	}

	return imports, nil
}

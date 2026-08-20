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

func TestPolicyStandaloneRequiredCheckExercisesContract(t *testing.T) {
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

func TestPolicyStandalonePackagesRemainIsolatedFromProduction(t *testing.T) {
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

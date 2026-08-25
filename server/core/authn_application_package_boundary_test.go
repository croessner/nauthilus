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

package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAuthnApplicationAdapterImportsOnlyDecisionServiceBoundary(t *testing.T) {
	for _, filename := range []string{
		"authn_application_adapter.go",
		"authn_application_facts.go",
		"authn_candidate_runtime.go",
		"authn_policy_facts.go",
		"authn_policy_effects.go",
	} {
		parsed := parseAuthnBoundaryFile(t, filename)
		for _, imported := range parsed.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", filename, err)
			}

			forbiddenImports := []string{
				"/server/policy/compiler",
				"/server/policy/evaluation",
			}
			if filename != "authn_policy_effects.go" {
				forbiddenImports = append(forbiddenImports, "/server/policy/runtime")
			}

			if filename != "authn_policy_effects.go" && filename != "authn_policy_facts.go" {
				forbiddenImports = append(forbiddenImports, "/server/policy/registry")
			}

			for _, forbidden := range forbiddenImports {
				if strings.HasPrefix(path, "github.com/croessner/nauthilus/v3"+forbidden) {
					t.Fatalf("%s imports forbidden policy implementation %q", filename, path)
				}
			}
		}
	}
}

func TestAuthnCandidateConstructorsHaveNoProductionWiringCallSite(t *testing.T) {
	constructorNames := map[string]struct{}{
		"NewAuthnCandidateApplicationService":                     {},
		"NewAuthnCandidateApplicationServiceWithInternalProfiles": {},
	}
	callSites := make(map[string][]string, len(constructorNames))

	err := filepath.WalkDir("..", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		if filepath.Base(path) == "authn_application_adapter.go" {
			return nil
		}

		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return parseErr
		}

		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}

			name := authnCandidateCallName(call.Fun)
			if _, candidate := constructorNames[name]; candidate {
				callSites[name] = append(callSites[name], path)
			}

			return true
		})

		return nil
	})
	if err != nil {
		t.Fatalf("scan production Go files: %v", err)
	}

	if len(callSites) != 0 {
		t.Fatalf("candidate adapters have production wiring call sites: %v", callSites)
	}
}

func TestAuthApplicationServiceIsolatesGinCompatibilityImports(t *testing.T) {
	serviceImports := authnBoundaryImportPaths(t, "auth_application_service.go")
	for _, forbidden := range []string{"github.com/gin-gonic/gin", "net/http/httptest"} {
		if _, found := serviceImports[forbidden]; found {
			t.Fatalf("auth application service imports compatibility dependency %q", forbidden)
		}
	}

	legacyImports := authnBoundaryImportPaths(t, "auth_application_legacy_executor.go")
	for _, required := range []string{"github.com/gin-gonic/gin", "net/http/httptest"} {
		if _, found := legacyImports[required]; !found {
			t.Fatalf("legacy auth executor does not own expected compatibility dependency %q", required)
		}
	}

	const legacyCallSite = "server/core/auth_application_legacy_executor.go|NewAuthStateFromContextWithDeps"

	entry, classified := authStateCallSiteInventory[legacyCallSite]
	if !classified || entry.owner != "isolated legacy FSM compatibility executor" {
		t.Fatalf("legacy auth executor lacks explicit global classification: %#v", entry)
	}

	for _, disposition := range backchannelAuthStateDispositions {
		if disposition.callSite == legacyCallSite && disposition.disposition == authStateDispositionRetained {
			return
		}
	}

	t.Fatalf("legacy auth executor lacks an explicit retained backchannel disposition")
}

// authnCandidateCallName returns the invoked identifier for direct and qualified calls.
func authnCandidateCallName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	default:
		return ""
	}
}

// authnBoundaryImportPaths returns the unquoted imports owned by one boundary file.
func authnBoundaryImportPaths(t *testing.T, filename string) map[string]struct{} {
	t.Helper()

	parsed := parseAuthnBoundaryFile(t, filename)
	paths := make(map[string]struct{}, len(parsed.Imports))

	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote import in %s: %v", filename, err)
		}

		paths[path] = struct{}{}
	}

	return paths
}

// parseAuthnBoundaryFile parses one adapter-owned source file for structural assertions.
func parseAuthnBoundaryFile(t *testing.T, filename string) *ast.File {
	t.Helper()

	parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	return parsed
}

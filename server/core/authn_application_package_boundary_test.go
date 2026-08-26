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
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
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

func TestProductionCompositionUsesAuthnDecisionServiceAdapter(t *testing.T) {
	const constructorName = "NewProductionAuthApplicationService"

	callSites := make([]string, 0, 1)

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

			if authnCandidateCallName(call.Fun) == constructorName {
				callSites = append(callSites, path)
			}

			return true
		})

		return nil
	})
	if err != nil {
		t.Fatalf("scan production Go files: %v", err)
	}

	if len(callSites) != 1 || filepath.Clean(callSites[0]) != filepath.Clean("../server.go") {
		t.Fatalf("production authn Decision Service adapter call sites = %v, want only ../server.go", callSites)
	}
}

func TestAuthApplicationServiceIsolatesGinCompatibilityImports(t *testing.T) {
	serviceImports := authnBoundaryImportPaths(t, "auth_application_service.go")
	for _, forbidden := range []string{"github.com/gin-gonic/gin", "net/http/httptest"} {
		if _, found := serviceImports[forbidden]; found {
			t.Fatalf("auth application service imports compatibility dependency %q", forbidden)
		}
	}

	hostImports := authnBoundaryImportPaths(t, "auth_application_host.go")
	for _, required := range []string{"github.com/gin-gonic/gin", "net/http/httptest"} {
		if _, found := hostImports[required]; !found {
			t.Fatalf("captured auth host does not own expected compatibility dependency %q", required)
		}
	}

	if _, err := fs.Stat(os.DirFS("."), "auth_application_legacy_executor.go"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("legacy auth executor source remains present: %v", err)
	}

	const hostCallSite = "server/core/auth_application_host.go|NewAuthStateFromContextWithDeps"

	entry, classified := authStateCallSiteInventory[hostCallSite]
	if !classified || entry.owner != "captured auth FSM host" {
		t.Fatalf("captured auth host lacks explicit global classification: %#v", entry)
	}

	for _, disposition := range backchannelAuthStateDispositions {
		if disposition.callSite == hostCallSite && disposition.disposition == authStateDispositionRetained {
			return
		}
	}

	t.Fatalf("captured auth host lacks an explicit retained backchannel disposition")
}

func TestAuthApplicationHostHasNoExportedRawAuthority(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "auth_application_service.go", nil, 0)
	if err != nil {
		t.Fatalf("parse auth application service: %v", err)
	}

	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}

		if function.Recv == nil && function.Name.Name == "NewAuthApplicationService" {
			t.Fatal("exported raw auth application constructor remains")
		}

		if authnMethodReceiverName(function) != "authApplicationService" {
			continue
		}

		switch function.Name.Name {
		case "Authenticate", "LookupIdentity", "ListAccounts":
			t.Fatalf("raw auth application host retains selectable %s authority", function.Name.Name)
		}
	}
}

func TestProductionAuthnHasNoMutableHostServiceRegistry(t *testing.T) {
	if _, err := os.Stat("services_registry.go"); !os.IsNotExist(err) {
		t.Fatalf("production service registry remains present: %v", err)
	}

	forbidden := []string{
		"RegisterLuaSubject(",
		"RegisterRBLService(",
		"RegisterBruteForceService(",
		"RegisterCacheService(",
		"RegisterPasswordVerifier(",
		"registeredAuthnHostServices(",
		"withRegisteredAuthnHostServices(",
	}

	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		source, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}

		for _, symbol := range forbidden {
			if strings.Contains(string(source), symbol) {
				t.Errorf("production authn source %s retains mutable host-service registry symbol %q", path, symbol)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("scan production core sources: %v", err)
	}
}

// authnMethodReceiverName returns the concrete receiver name for one method declaration.
func authnMethodReceiverName(function *ast.FuncDecl) string {
	if function == nil || function.Recv == nil || len(function.Recv.List) != 1 {
		return ""
	}

	typeExpression := function.Recv.List[0].Type
	if pointer, ok := typeExpression.(*ast.StarExpr); ok {
		typeExpression = pointer.X
	}

	if identifier, ok := typeExpression.(*ast.Ident); ok {
		return identifier.Name
	}

	return ""
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

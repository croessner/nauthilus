// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFrontendIDPPackageConsumesAuthApplicationWithoutOwningPolicyEvaluation(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read frontend IDP package: %v", err)
	}

	for _, entry := range entries {
		name := entry.Name()

		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		assertFrontendIDPFileBoundary(t, name)
	}
}

func TestFrontendIDPSpecializedStateRequiresAdmittedLookup(t *testing.T) {
	fileSet := token.NewFileSet()

	parsed, err := parser.ParseFile(fileSet, "backend_data.go", nil, 0)
	if err != nil {
		t.Fatalf("parse backend_data.go: %v", err)
	}

	lookups := 0

	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || frontendIDPBoundaryFunctionOwner(function) != "FrontendHandler.getUserBackendDataForIdentity" {
			continue
		}

		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if ok && frontendIDPBoundaryCallName(call.Fun) == "LookupMFAIdentity" {
				lookups++
			}

			return true
		})
	}

	if lookups != 1 {
		t.Fatalf("frontend specialized identity admissions = %d, want one exact LookupMFAIdentity call", lookups)
	}
}

// assertFrontendIDPFileBoundary rejects direct policy ownership in one frontend adapter source.
func assertFrontendIDPFileBoundary(t *testing.T, file string) {
	t.Helper()

	fileSet := token.NewFileSet()

	parsed, err := parser.ParseFile(fileSet, filepath.Clean(file), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	assertFrontendIDPImports(t, file, parsed)
	assertFrontendIDPCalls(t, file, fileSet, parsed)
}

// assertFrontendIDPImports rejects direct policy implementation dependencies.
func assertFrontendIDPImports(t *testing.T, file string, parsed *ast.File) {
	t.Helper()

	forbidden := []string{
		"/server/policy/collection",
		"/server/policy/compiler",
		"/server/policy/decision/service",
		"/server/policy/evaluation",
		"/server/policy/registry",
		"/server/policy/runtime",
	}

	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote import in %s: %v", file, err)
		}

		for _, fragment := range forbidden {
			if strings.Contains(path, fragment) {
				t.Errorf("%s imports forbidden policy implementation %q", file, path)
			}
		}
	}
}

// assertFrontendIDPCalls rejects direct authentication-state and policy ownership.
func assertFrontendIDPCalls(t *testing.T, file string, fileSet *token.FileSet, parsed *ast.File) {
	t.Helper()

	forbidden := frontendIDPForbiddenPolicyCalls()

	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}

		owner := frontendIDPBoundaryFunctionOwner(function)

		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}

			name := frontendIDPBoundaryCallName(call.Fun)
			if _, rejected := forbidden[name]; rejected {
				position := fileSet.Position(call.Pos())
				t.Errorf("%s:%d function %s directly calls forbidden auth authority %s", file, position.Line, owner, name)
			}

			if frontendIDPAuthStateConstructor(name) {
				position := fileSet.Position(call.Pos())
				t.Errorf("%s:%d function %s constructs AuthState outside an exact specialized owner", file, position.Line, owner)
			}

			return true
		})
	}
}

// frontendIDPForbiddenPolicyCalls returns evaluation and local-authority constructors forbidden in frontend adapters.
func frontendIDPForbiddenPolicyCalls() map[string]struct{} {
	return map[string]struct{}{
		"ApplyConfiguredPreAuthControl":                           {},
		"ApplyConfiguredPreAuthDecision":                          {},
		"ApplyDefaultPreAuthDecision":                             {},
		"AuthFail":                                                {},
		"CheckBruteForce":                                         {},
		"ConfiguredPolicyAllowsIDPDelayedResponse":                {},
		"ConfiguredPolicyTerminalDecision":                        {},
		"HandleAuthentication":                                    {},
		"HandleEnvironment":                                       {},
		"HandlePassword":                                          {},
		"HasConfiguredPreAuthPolicyAuthority":                     {},
		"NewAuthApplicationService":                               {},
		"NewAuthnCandidateApplicationService":                     {},
		"NewAuthnCandidateApplicationServiceWithInternalProfiles": {},
		"NewDecisionService":                                      {},
		"PreproccessAuthRequest":                                  {},
		"UpdateBruteForceBucketsCounter":                          {},
	}
}

// frontendIDPBoundaryCallName resolves direct and selector-based call names.
func frontendIDPBoundaryCallName(expression ast.Expr) string {
	switch function := expression.(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		return function.Sel.Name
	case *ast.StarExpr:
		return frontendIDPBoundaryCallName(function.X)
	default:
		return ""
	}
}

// frontendIDPBoundaryFunctionOwner returns the receiver-qualified owner of one adapter call.
func frontendIDPBoundaryFunctionOwner(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return function.Name.Name
	}

	return frontendIDPBoundaryCallName(function.Recv.List[0].Type) + "." + function.Name.Name
}

// frontendIDPAuthStateConstructor identifies direct and centralized state constructors.
func frontendIDPAuthStateConstructor(name string) bool {
	switch name {
	case "NewAuthState", "NewAuthStateFromContextWithDeps", "NewAuthStateWithSetup", "NewAuthStateWithSetupWithDeps",
		"NewIDPSpecializedAuthState":
		return true
	default:
		return false
	}
}

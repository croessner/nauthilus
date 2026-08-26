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

func TestIDPPackageConsumesAuthApplicationWithoutOwningPolicyEvaluation(t *testing.T) {
	files := idpProductionGoFiles(t)
	forbiddenCalls := idpForbiddenPolicyCalls()

	for _, file := range files {
		parsed, fileSet := parseIDPBoundaryFile(t, file)
		assertIDPBoundaryImports(t, file, parsed)
		assertIDPBoundaryCalls(t, file, fileSet, parsed, forbiddenCalls)
	}
}

func TestIDPAuthApplicationBridgeDoesNotOwnBrowserState(t *testing.T) {
	parsed, _ := parseIDPBoundaryFile(t, "auth_application.go")
	forbidden := []string{
		"/server/core/cookie",
		"/server/idp/flow",
		"/server/idp/mfastate",
		"/server/sessionstate",
	}

	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote auth application import: %v", err)
		}

		for _, fragment := range forbidden {
			if strings.Contains(path, fragment) {
				t.Errorf("auth_application.go imports browser-state owner %q", path)
			}
		}
	}
}

// idpProductionGoFiles returns every production source owned by the IDP package.
func idpProductionGoFiles(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read IDP package: %v", err)
	}

	files := make([]string, 0, len(entries))

	for _, entry := range entries {
		name := entry.Name()

		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		files = append(files, name)
	}

	return files
}

// parseIDPBoundaryFile parses one IDP production source with position evidence.
func parseIDPBoundaryFile(t *testing.T, file string) (*ast.File, *token.FileSet) {
	t.Helper()

	fileSet := token.NewFileSet()

	parsed, err := parser.ParseFile(fileSet, filepath.Clean(file), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	return parsed, fileSet
}

// assertIDPBoundaryImports rejects direct policy implementation ownership in IDP adapters.
func assertIDPBoundaryImports(t *testing.T, file string, parsed *ast.File) {
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

// assertIDPBoundaryCalls permits only exact post-admission owners to materialize AuthState.
func assertIDPBoundaryCalls(
	t *testing.T,
	file string,
	fileSet *token.FileSet,
	parsed *ast.File,
	forbiddenCalls map[string]struct{},
) {
	t.Helper()

	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}

		owner := idpBoundaryFunctionOwner(function)

		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}

			name := idpBoundaryCallName(call.Fun)
			if _, forbidden := forbiddenCalls[name]; forbidden {
				position := fileSet.Position(call.Pos())
				t.Errorf("%s:%d function %s directly calls forbidden auth authority %s", file, position.Line, owner, name)
			}

			if idpAuthStateConstructor(name) && !idpAllowedStateMaterializer(file, owner, name) {
				position := fileSet.Position(call.Pos())
				t.Errorf("%s:%d function %s constructs AuthState outside an exact post-admission materializer", file, position.Line, owner)
			}

			return true
		})
	}
}

// idpForbiddenPolicyCalls returns evaluation and local-authority constructors forbidden in IDP adapters.
func idpForbiddenPolicyCalls() map[string]struct{} {
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

// idpBoundaryCallName resolves direct and selector-based call names.
func idpBoundaryCallName(expression ast.Expr) string {
	switch function := expression.(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		return function.Sel.Name
	case *ast.StarExpr:
		return idpBoundaryCallName(function.X)
	default:
		return ""
	}
}

// idpBoundaryFunctionOwner returns the receiver-qualified owner of one adapter call.
func idpBoundaryFunctionOwner(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return function.Name.Name
	}

	return idpBoundaryCallName(function.Recv.List[0].Type) + "." + function.Name.Name
}

// idpAuthStateConstructor identifies direct and centralized state construction entries.
func idpAuthStateConstructor(name string) bool {
	switch name {
	case "NewAuthState", "NewAuthStateFromContextWithDeps", "NewAuthStateWithSetup", "NewAuthStateWithSetupWithDeps",
		"NewIDPSpecializedAuthState":
		return true
	default:
		return false
	}
}

// idpAllowedStateMaterializer keeps exact post-admission state owners separate from evaluation.
func idpAllowedStateMaterializer(file string, function string, call string) bool {
	key := file + "|" + function + "|" + call

	switch key {
	case "auth_application.go|NauthilusIDP.LookupMFAIdentity|NewIDPSpecializedAuthState",
		"nauthilus_idp.go|NauthilusIDP.GetClaims|NewAuthStateFromContextWithDeps":
		return true
	default:
		return false
	}
}

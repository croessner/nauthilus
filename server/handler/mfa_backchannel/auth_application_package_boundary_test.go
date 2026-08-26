// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package mfa_backchannel

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestMFABackchannelConsumesAdmittedSpecializedIdentity(t *testing.T) {
	fileSet := token.NewFileSet()

	parsed, err := parser.ParseFile(fileSet, "handler.go", nil, 0)
	if err != nil {
		t.Fatalf("parse MFA backchannel handler: %v", err)
	}

	assertMFABackchannelImports(t, parsed)
	assertMFABackchannelCalls(t, fileSet, parsed)
}

// assertMFABackchannelImports rejects direct policy implementation ownership.
func assertMFABackchannelImports(t *testing.T, parsed *ast.File) {
	t.Helper()

	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote MFA backchannel import: %v", err)
		}

		for _, fragment := range []string{
			"/server/policy/compiler",
			"/server/policy/decision/service",
			"/server/policy/evaluation",
			"/server/policy/registry",
			"/server/policy/runtime",
		} {
			if strings.Contains(path, fragment) {
				t.Errorf("handler.go imports forbidden policy implementation %q", path)
			}
		}
	}
}

// assertMFABackchannelCalls requires the shared IdP admission seam and forbids local state construction.
func assertMFABackchannelCalls(t *testing.T, fileSet *token.FileSet, parsed *ast.File) {
	t.Helper()

	lookups := 0

	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}

		owner := mfaBackchannelBoundaryFunctionOwner(function)

		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}

			name := mfaBackchannelBoundaryCallName(call.Fun)
			if mfaBackchannelForbiddenAuthorityCall(name) {
				position := fileSet.Position(call.Pos())
				t.Errorf("handler.go:%d function %s directly calls forbidden auth authority %s", position.Line, owner, name)
			}

			if name == "NewAuthStateFromContextWithDeps" || name == "NewIDPSpecializedAuthState" {
				position := fileSet.Position(call.Pos())
				t.Errorf("handler.go:%d function %s constructs AuthState outside the central specialized materializer", position.Line, owner)
			}

			if name == "LookupMFAIdentity" {
				lookups++

				if owner != "Handler.buildAuthState" {
					position := fileSet.Position(call.Pos())
					t.Errorf("handler.go:%d admits MFA identity in %s outside the exact adapter owner", position.Line, owner)
				}
			}

			return true
		})
	}

	if lookups != 1 {
		t.Fatalf("MFA backchannel application identity lookups = %d, want 1 exact owner", lookups)
	}
}

// mfaBackchannelBoundaryCallName resolves direct and selector-based calls.
func mfaBackchannelBoundaryCallName(expression ast.Expr) string {
	switch function := expression.(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		return function.Sel.Name
	case *ast.StarExpr:
		return mfaBackchannelBoundaryCallName(function.X)
	default:
		return ""
	}
}

// mfaBackchannelBoundaryFunctionOwner returns the receiver-qualified owner of one adapter call.
func mfaBackchannelBoundaryFunctionOwner(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return function.Name.Name
	}

	return mfaBackchannelBoundaryCallName(function.Recv.List[0].Type) + "." + function.Name.Name
}

// mfaBackchannelForbiddenAuthorityCall identifies generic auth evaluation and local authority construction.
func mfaBackchannelForbiddenAuthorityCall(name string) bool {
	switch name {
	case "HandleAuthentication", "HandleEnvironment", "HandlePassword", "NewAuthApplicationService",
		"NewAuthnCandidateApplicationService", "NewAuthnCandidateApplicationServiceWithInternalProfiles",
		"NewDecisionService", "PreproccessAuthRequest":
		return true
	default:
		return false
	}
}

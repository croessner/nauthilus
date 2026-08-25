// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package auth

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

func TestBackchannelHTTPPackageBoundaryForbidsAuthStateAndPolicyRuntimeOwnership(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read auth handler package: %v", err)
	}

	forbiddenCalls := map[string]struct{}{
		"HandleAuthentication":            {},
		"NewAuthState":                    {},
		"NewAuthStateFromContextWithDeps": {},
		"NewAuthStateWithSetup":           {},
		"NewAuthStateWithSetupWithDeps":   {},
		"PreproccessAuthRequest":          {},
	}
	forbiddenImports := []string{
		"/server/policy/collection",
		"/server/policy/compiler",
		"/server/policy/evaluation",
		"/server/policy/registry",
		"/server/policy/runtime",
	}

	for _, name := range productionHTTPAuthFiles(entries) {
		assertHTTPAuthFileBoundary(t, name, forbiddenCalls, forbiddenImports)
	}
}

// productionHTTPAuthFiles returns non-test Go sources owned by the handler package.
func productionHTTPAuthFiles(entries []os.DirEntry) []string {
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

// assertHTTPAuthFileBoundary checks imports and direct runtime calls in one source file.
func assertHTTPAuthFileBoundary(
	t *testing.T,
	name string,
	forbiddenCalls map[string]struct{},
	forbiddenImports []string,
) {
	t.Helper()

	fileSet := token.NewFileSet()
	assertHTTPAuthImportsAllowed(t, fileSet, name, forbiddenImports)

	if name == "basic_endpoint_enabled.go" {
		return
	}

	assertHTTPAuthCallsAllowed(t, fileSet, name, forbiddenCalls)
}

// assertHTTPAuthImportsAllowed rejects direct policy implementation imports.
func assertHTTPAuthImportsAllowed(t *testing.T, fileSet *token.FileSet, name string, forbiddenImports []string) {
	t.Helper()

	parsed, err := parser.ParseFile(fileSet, filepath.Clean(name), nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse imports from %s: %v", name, err)
	}

	for _, imported := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil {
			t.Fatalf("unquote import in %s: %v", name, unquoteErr)
		}

		for _, forbidden := range forbiddenImports {
			if strings.Contains(path, forbidden) {
				t.Fatalf("%s imports forbidden policy implementation %q", name, path)
			}
		}
	}
}

// assertHTTPAuthCallsAllowed rejects handler-owned evaluator and AuthState calls.
func assertHTTPAuthCallsAllowed(
	t *testing.T,
	fileSet *token.FileSet,
	name string,
	forbiddenCalls map[string]struct{},
) {
	t.Helper()

	parsed, err := parser.ParseFile(fileSet, filepath.Clean(name), nil, 0)
	if err != nil {
		t.Fatalf("parse calls from %s: %v", name, err)
	}

	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}

		callName := httpAuthCallName(call.Fun)
		if _, forbidden := forbiddenCalls[callName]; forbidden {
			position := fileSet.Position(call.Pos())
			t.Errorf("%s:%d calls forbidden auth runtime entry %s", name, position.Line, callName)
		}

		return true
	})
}

// httpAuthCallName resolves direct and selector call names for boundary checks.
func httpAuthCallName(expression ast.Expr) string {
	switch function := expression.(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		return function.Sel.Name
	default:
		return ""
	}
}

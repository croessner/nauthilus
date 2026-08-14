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
	for _, filename := range []string{"authn_application_adapter.go", "authn_application_facts.go"} {
		parsed := parseAuthnBoundaryFile(t, filename)
		for _, imported := range parsed.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", filename, err)
			}

			for _, forbidden := range []string{
				"/server/policy/compiler",
				"/server/policy/evaluation",
				"/server/policy/registry",
				"/server/policy/runtime",
			} {
				if strings.HasPrefix(path, "github.com/croessner/nauthilus/v3"+forbidden) {
					t.Fatalf("%s imports forbidden policy implementation %q", filename, path)
				}
			}
		}
	}
}

func TestAuthnCandidateConstructorHasNoProductionCallSite(t *testing.T) {
	var callSites []string

	err := filepath.WalkDir("..", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
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

			if authnCandidateCallName(call.Fun) == "NewAuthnCandidateApplicationService" {
				callSites = append(callSites, path)
			}

			return true
		})

		return nil
	})
	if err != nil {
		t.Fatalf("scan production Go files: %v", err)
	}

	if len(callSites) != 0 {
		t.Fatalf("candidate adapter has production call sites: %v", callSites)
	}
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

// parseAuthnBoundaryFile parses one adapter-owned source file for structural assertions.
func parseAuthnBoundaryFile(t *testing.T, filename string) *ast.File {
	t.Helper()

	parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	return parsed
}

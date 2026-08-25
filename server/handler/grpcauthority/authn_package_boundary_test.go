// Copyright (C) 2026 Christian Roessner
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

package grpcauthority

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestGRPCBackchannelAuthHandlerOwnsOnlyTransportConversion(t *testing.T) {
	fileSet := token.NewFileSet()

	parsed, err := parser.ParseFile(fileSet, "handler.go", nil, 0)
	if err != nil {
		t.Fatalf("parse gRPC auth handler: %v", err)
	}

	forbiddenImports := []string{
		"/server/policy/compiler",
		"/server/policy/evaluation",
		"/server/policy/registry",
		"/server/policy/runtime",
	}

	for _, imported := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil {
			t.Fatalf("unquote handler import: %v", unquoteErr)
		}

		for _, forbidden := range forbiddenImports {
			if strings.Contains(path, forbidden) {
				t.Fatalf("gRPC auth handler imports forbidden policy implementation %q", path)
			}
		}
	}

	forbiddenCalls := map[string]struct{}{
		"HandleAuthentication":            {},
		"NewAuthState":                    {},
		"NewAuthStateFromContextWithDeps": {},
		"NewAuthStateWithSetup":           {},
		"NewAuthStateWithSetupWithDeps":   {},
		"PreproccessAuthRequest":          {},
	}

	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}

		name := grpcAuthBoundaryCallName(call.Fun)
		if _, forbidden := forbiddenCalls[name]; forbidden {
			position := fileSet.Position(call.Pos())
			t.Errorf("handler.go:%d calls forbidden auth runtime entry %s", position.Line, name)
		}

		return true
	})
}

// grpcAuthBoundaryCallName returns the invoked identifier for direct and qualified calls.
func grpcAuthBoundaryCallName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	default:
		return ""
	}
}

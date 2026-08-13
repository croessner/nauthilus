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

package bootfx

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

type setupConfigurationCalls struct {
	foundSetup       bool
	foundPrepare     bool
	foundPublication bool
}

// TestSetupConfigurationUsesOffSideConfigPreparation prevents pre-generation config publication.
func TestSetupConfigurationUsesOffSideConfigPreparation(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "boot.go", nil, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile(boot.go): %v", err)
	}

	calls := inspectSetupConfigurationCalls(parsed)

	if !calls.foundSetup {
		t.Fatal("SetupConfiguration declaration was not found")
	}

	if calls.foundPublication {
		t.Error("SetupConfiguration publishes config before the runtime generation commit")
	}

	if !calls.foundPrepare {
		t.Fatal("SetupConfiguration does not prepare config off-side")
	}
}

// inspectSetupConfigurationCalls records config constructor calls in the boot owner.
func inspectSetupConfigurationCalls(parsed *ast.File) setupConfigurationCalls {
	var result setupConfigurationCalls

	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "SetupConfiguration" {
			continue
		}

		result.foundSetup = true

		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch configCallName(node) {
			case "NewFile":
				result.foundPublication = true
			case "PrepareFile":
				result.foundPrepare = true
			}

			return true
		})
	}

	return result
}

// configCallName returns the selected config package function for one AST node.
func configCallName(node ast.Node) string {
	call, ok := node.(*ast.CallExpr)
	if !ok {
		return ""
	}

	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}

	owner, ok := selector.X.(*ast.Ident)
	if !ok || owner.Name != "config" {
		return ""
	}

	return selector.Sel.Name
}

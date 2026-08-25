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
	"path/filepath"
	"testing"
)

func TestBackchannelRuntimeTimersUseSharedRequestResource(t *testing.T) {
	productionFiles := []string{
		"workflow.go",
		"environment.go",
		"bruteforce.go",
		"policy_obligations.go",
		filepath.Join("auth", "lua_service.go"),
	}

	for _, filename := range productionFiles {
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}

		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}

			selector, ok := call.Fun.(*ast.SelectorExpr)
			if ok && selector.Sel.Name == "FullPath" {
				t.Errorf("%s calls Gin FullPath directly; use util.RequestResource", filename)
			}

			return true
		})
	}
}

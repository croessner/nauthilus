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

package service_test

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

func TestDecisionServicePackageBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("os.ReadDir(): %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		assertApplicationFileBoundary(t, entry.Name())
	}
}

func TestDecisionServiceEvaluatorAndGenerationConstructionRemainPrivate(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "generation.go", nil, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile(generation.go): %v", err)
	}

	assertNoEvaluatorConstructionExports(t, parsed)
	assertSealedGenerationBoundary(t, parsed)
}

// assertNoEvaluatorConstructionExports rejects public evaluator and generation internals.
func assertNoEvaluatorConstructionExports(t *testing.T, parsed *ast.File) {
	t.Helper()

	forbiddenExports := map[string]struct{}{
		"CheckpointEvaluator":           {},
		"InternalDecisionReport":        {},
		"RuntimeEvaluation":             {},
		"RuntimeGeneration":             {},
		"RuntimeGenerationDependencies": {},
	}

	for _, declaration := range parsed.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}

		for _, spec := range general.Specs {
			typeSpec := spec.(*ast.TypeSpec)
			if _, forbidden := forbiddenExports[typeSpec.Name.Name]; forbidden {
				t.Fatalf("generation.go exports forbidden evaluator construction type %s", typeSpec.Name.Name)
			}
		}
	}
}

// assertSealedGenerationBoundary verifies that external packages cannot implement Generation.
func assertSealedGenerationBoundary(t *testing.T, parsed *ast.File) {
	t.Helper()

	foundGeneration := false

	for _, declaration := range parsed.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}

		for _, spec := range general.Specs {
			typeSpec := spec.(*ast.TypeSpec)

			if typeSpec.Name.Name != "Generation" {
				continue
			}

			foundGeneration = true

			interfaceType, ok := typeSpec.Type.(*ast.InterfaceType)
			if !ok || len(interfaceType.Methods.List) != 1 {
				t.Fatal("Generation must remain a single-method sealed interface")
			}

			method := interfaceType.Methods.List[0]
			if len(method.Names) != 1 || method.Names[0].IsExported() {
				t.Fatal("Generation sealing method must remain package-private")
			}
		}
	}

	if !foundGeneration {
		t.Fatal("generation.go no longer defines the sealed Generation boundary")
	}
}

// assertApplicationFileBoundary rejects transport, generated DTO, auth-state, and protobuf coupling.
func assertApplicationFileBoundary(t *testing.T, path string) {
	t.Helper()

	source, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("os.ReadFile(%s): %v", path, err)
	}

	if strings.Contains(string(source), "AuthState") {
		t.Fatalf("%s contains forbidden AuthState dependency", path)
	}

	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(path), source, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parser.ParseFile(%s): %v", path, err)
	}

	forbidden := []string{
		"github.com/gin-gonic/gin",
		"/api/",
		"/server/core",
		"/server/grpcapi",
		"/server/openapi",
		"google.golang.org/grpc",
		"google.golang.org/protobuf",
	}

	for _, imported := range parsed.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("strconv.Unquote(%s): %v", imported.Path.Value, err)
		}

		for _, fragment := range forbidden {
			if strings.Contains(importPath, fragment) {
				t.Fatalf("%s imports forbidden application dependency %q", path, importPath)
			}
		}
	}
}

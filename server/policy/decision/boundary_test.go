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

package decision_test

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

func TestDecisionPackageHasNoTransportOrAuthStateDependencies(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("os.ReadDir(): %v", err)
	}

	forbidden := []string{
		"encoding/json",
		"github.com/gin-gonic/gin",
		"/api/",
		"/server/core",
		"/server/grpcapi",
		"/server/openapi",
		"google.golang.org/grpc",
		"google.golang.org/protobuf",
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		assertFileImportsExclude(t, entry.Name(), forbidden)
	}
}

func TestDecisionPackageExportsNoForbiddenContractTypes(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("os.ReadDir(): %v", err)
	}

	forbidden := []string{"batch", "cache", "outcomereport", "retry", "replay", "idempotency", "deduplication"}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		assertFileTypesExclude(t, entry.Name(), forbidden)
	}
}

// assertFileImportsExclude parses one production file and rejects forbidden dependencies.
func assertFileImportsExclude(t *testing.T, path string, forbidden []string) {
	t.Helper()

	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(path), nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parser.ParseFile(%s): %v", path, err)
	}

	for _, declaration := range parsed.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.IMPORT {
			continue
		}

		for _, spec := range general.Specs {
			importSpec := spec.(*ast.ImportSpec)

			importPath, err := strconv.Unquote(importSpec.Path.Value)
			if err != nil {
				t.Fatalf("strconv.Unquote(%s): %v", importSpec.Path.Value, err)
			}

			for _, fragment := range forbidden {
				if strings.Contains(importPath, fragment) {
					t.Fatalf("%s imports forbidden dependency %q", path, importPath)
				}
			}
		}
	}
}

// assertFileTypesExclude rejects forbidden exported contract type families.
func assertFileTypesExclude(t *testing.T, path string, forbidden []string) {
	t.Helper()

	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(path), nil, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile(%s): %v", path, err)
	}

	for _, declaration := range parsed.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}

		for _, spec := range general.Specs {
			typeSpec := spec.(*ast.TypeSpec)
			if !typeSpec.Name.IsExported() {
				continue
			}

			normalized := strings.ToLower(typeSpec.Name.Name)
			for _, fragment := range forbidden {
				if strings.Contains(normalized, fragment) {
					t.Fatalf("%s exports forbidden contract type %s", path, typeSpec.Name.Name)
				}
			}
		}
	}
}

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

package runtime

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestGenerationCoordinatorHasNoTransportOrPublicExtensionDependencies protects the internal boundary.
func TestGenerationCoordinatorHasNoTransportOrPublicExtensionDependencies(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("os.ReadDir(): %v", err)
	}

	forbidden := []string{
		"/api/",
		"/pluginapi/",
		"/server/grpcapi",
		"/server/handler",
		"/server/lualib",
		"/server/openapi",
		"/server/pluginloader",
		"/server/pluginruntime",
		"google.golang.org/grpc",
		"google.golang.org/protobuf",
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		assertFileExcludesImports(t, entry.Name(), forbidden, "generation")
	}
}

// TestTargetCatalogImportBoundaryExcludesPublicExtensionAPIs protects catalog ownership from adapter dependencies.
func TestTargetCatalogImportBoundaryExcludesPublicExtensionAPIs(t *testing.T) {
	files := []string{
		"../compiler/target_catalog.go",
		"../registry/effect_catalog.go",
		"../registry/target_contribution.go",
		"target_catalog.go",
	}
	forbidden := []string{
		"/pluginapi/",
		"/server/lualib",
		"/server/pluginloader",
		"/server/pluginregistry",
		"/server/pluginruntime",
	}

	for _, name := range files {
		assertFileExcludesImports(t, name, forbidden, "target catalog")
	}
}

// assertFileExcludesImports rejects one production file that crosses an internal dependency boundary.
func assertFileExcludesImports(t *testing.T, name string, forbidden []string, boundary string) {
	t.Helper()

	parsed, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parser.ParseFile(%s): %v", name, err)
	}

	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("strconv.Unquote(%s): %v", imported.Path.Value, err)
		}

		for _, fragment := range forbidden {
			if strings.Contains(path, fragment) {
				t.Fatalf("%s imports forbidden %s dependency %q", name, boundary, path)
			}
		}
	}
}

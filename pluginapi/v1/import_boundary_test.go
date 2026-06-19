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

package pluginapi

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPublicPackageDoesNotImportServerInternals(t *testing.T) {
	files, err := publicPackageGoFiles(".")
	if err != nil {
		t.Fatalf("read public package files: %v", err)
	}

	for _, name := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse imports for %s: %v", name, err)
		}

		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import path %s: %v", spec.Path.Value, err)
			}

			if isForbiddenPublicAPIImport(importPath) {
				t.Fatalf("%s imports forbidden public API package %q", name, importPath)
			}
		}
	}
}

// publicPackageGoFiles returns production Go files for pluginapi and public subpackages.
func publicPackageGoFiles(root string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.IsDir() {
			switch entry.Name() {
			case "testdata", ".git":
				return filepath.SkipDir
			default:
				return nil
			}
		}

		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

// isForbiddenPublicAPIImport reports whether importPath binds pluginapi to host internals.
func isForbiddenPublicAPIImport(importPath string) bool {
	return importPath == "github.com/croessner/nauthilus/v3/server" ||
		strings.HasPrefix(importPath, "github.com/croessner/nauthilus/v3/server/") ||
		importPath == "github.com/gin-gonic/gin"
}

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
	"strconv"
	"strings"
	"testing"
)

func TestPublicPackageDoesNotImportServerInternals(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

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

// isForbiddenPublicAPIImport reports whether importPath binds pluginapi to host internals.
func isForbiddenPublicAPIImport(importPath string) bool {
	return importPath == "github.com/croessner/nauthilus/server" ||
		strings.HasPrefix(importPath, "github.com/croessner/nauthilus/server/") ||
		importPath == "github.com/gin-gonic/gin"
}

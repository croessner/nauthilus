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

package nativebinding

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestNativeBindingImportBoundary protects the inward candidate-preparation seam.
func TestNativeBindingImportBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("os.ReadDir(): %v", err)
	}

	forbidden := []string{
		"/pluginapi/",
		"/server/core",
		"/server/pluginloader",
		"/server/pluginregistry",
		"/server/pluginruntime",
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		parsed, parseErr := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Fatalf("parser.ParseFile(%s): %v", entry.Name(), parseErr)
		}

		for _, imported := range parsed.Imports {
			path, unquoteErr := strconv.Unquote(imported.Path.Value)
			if unquoteErr != nil {
				t.Fatalf("strconv.Unquote(%s): %v", imported.Path.Value, unquoteErr)
			}

			for _, fragment := range forbidden {
				if strings.Contains(path, fragment) {
					t.Fatalf("%s imports forbidden native binding dependency %q", entry.Name(), path)
				}
			}
		}
	}
}

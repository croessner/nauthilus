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

package configinput

import (
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// TestNativeGenerationUsesInwardBindingSeam prevents plugin runtime cycles through policy input preparation.
func TestNativeGenerationUsesInwardBindingSeam(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "native_generation.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parser.ParseFile(native_generation.go): %v", err)
	}

	required := "/server/policy/nativebinding"
	forbidden := []string{
		"/pluginapi/",
		"/server/core",
		"/server/pluginloader",
		"/server/pluginregistry",
		"/server/pluginruntime",
	}
	foundRequired := false

	for _, imported := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil {
			t.Fatalf("strconv.Unquote(%s): %v", imported.Path.Value, unquoteErr)
		}

		if strings.Contains(path, required) {
			foundRequired = true
		}

		for _, fragment := range forbidden {
			if strings.Contains(path, fragment) {
				t.Fatalf("native_generation.go imports forbidden outward dependency %q", path)
			}
		}
	}

	if !foundRequired {
		t.Fatalf("native_generation.go must import inward binding seam containing %q", required)
	}
}

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

package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestConfigStructFieldsHaveExplicitMapstructureTags(t *testing.T) {
	t.Helper()

	fset := token.NewFileSet()
	files, err := configSourceFiles()
	if err != nil {
		t.Fatalf("list config package files: %v", err)
	}

	var missing []string

	for _, fileName := range files {
		file, err := parseConfigSourceFile(fset, fileName)
		if err != nil {
			t.Fatalf("parse config source file %s: %v", fileName, err)
		}

		baseName := filepath.Base(fileName)

		ast.Inspect(file, func(node ast.Node) bool {
			typeSpec, ok := node.(*ast.TypeSpec)
			if !ok {
				return true
			}

			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				return true
			}

			for _, field := range structType.Fields.List {
				fieldLabel := configFieldLabel(field)
				if fieldLabel == "" {
					continue
				}

				if field.Tag == nil {
					missing = append(missing, baseName+":"+typeSpec.Name.Name+"."+fieldLabel)

					continue
				}

				tagValue := strings.Trim(field.Tag.Value, "`")
				if reflect.StructTag(tagValue).Get("mapstructure") == "" {
					missing = append(missing, baseName+":"+typeSpec.Name.Name+"."+fieldLabel)
				}
			}

			return true
		})
	}

	if len(missing) == 0 {
		return
	}

	sort.Strings(missing)
	t.Fatalf("missing explicit mapstructure tags:\n%s", strings.Join(missing, "\n"))
}

func configSourceFiles() ([]string, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		files = append(files, filepath.Join(".", name))
	}

	sort.Strings(files)

	return files, nil
}

func parseConfigSourceFile(fset *token.FileSet, fileName string) (*ast.File, error) {
	return parser.ParseFile(fset, fileName, nil, parser.ParseComments)
}

func configFieldLabel(field *ast.Field) string {
	if len(field.Names) > 0 {
		labels := make([]string, 0, len(field.Names))

		for _, name := range field.Names {
			labels = append(labels, name.Name)
		}

		return strings.Join(labels, ",")
	}

	switch expr := field.Type.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.SelectorExpr:
		return expr.Sel.Name
	default:
		return ""
	}
}

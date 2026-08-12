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

package api_test

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const serverImportSegment = "github.com/croessner/nauthilus/v3/server/"

func TestPublicProtobufLayout(t *testing.T) {
	t.Parallel()

	repositoryRoot := findRepositoryRoot(t)
	expectedFiles := []string{
		"api/common/v1/common.proto",
		"api/common/v1/common.pb.go",
		"api/auth/v1/auth.proto",
		"api/auth/v1/auth.pb.go",
		"api/auth/v1/auth_grpc.pb.go",
		"api/identity/v1/identity_backend.proto",
		"api/identity/v1/identity_backend.pb.go",
		"api/identity/v1/identity_backend_grpc.pb.go",
		"api/policy/v1/README.md",
	}

	for _, relativePath := range expectedFiles {
		assertRegularFile(t, filepath.Join(repositoryRoot, relativePath))
	}
}

func TestRemovedPublicProtobufPathsAreAbsent(t *testing.T) {
	t.Parallel()

	repositoryRoot := findRepositoryRoot(t)
	removedPaths := []string{
		"server/grpcapi/common/v1",
		"server/grpcapi/auth/v1",
		"server/grpcapi/identity/v1",
	}

	for _, relativePath := range removedPaths {
		path := filepath.Join(repositoryRoot, relativePath)
		if _, err := os.Stat(path); err == nil {
			t.Errorf("removed public protobuf path still exists: %s", relativePath)
		} else if !os.IsNotExist(err) {
			t.Errorf("stat removed public protobuf path %s: %v", relativePath, err)
		}
	}
}

func TestPolicyProtobufOwnershipIsReservedWithoutRPC(t *testing.T) {
	t.Parallel()

	repositoryRoot := findRepositoryRoot(t)
	for _, pattern := range []string{"*.proto", "*.pb.go"} {
		matches, err := filepath.Glob(filepath.Join(repositoryRoot, "api/policy/v1", pattern))
		if err != nil {
			t.Fatalf("resolve reserved Policy API pattern %q: %v", pattern, err)
		}

		if len(matches) != 0 {
			t.Errorf("Policy RPC is outside this layout change, found generated contract artifacts: %v", matches)
		}
	}
}

func TestPublicAPIPackagesDoNotImportServer(t *testing.T) {
	t.Parallel()

	repositoryRoot := findRepositoryRoot(t)
	apiRoot := filepath.Join(repositoryRoot, "api")

	err := filepath.WalkDir(apiRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}

		return assertFileDoesNotImportServer(t, repositoryRoot, path)
	})
	if err != nil {
		t.Fatalf("walk public API tree: %v", err)
	}
}

// findRepositoryRoot resolves the checkout root from this test file.
func findRepositoryRoot(t *testing.T) string {
	t.Helper()

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve public layout test source path")
	}

	return filepath.Dir(filepath.Dir(sourceFile))
}

// assertRegularFile verifies that a required public API artifact exists.
func assertRegularFile(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Errorf("required public API artifact %s: %v", path, err)

		return
	}

	if !info.Mode().IsRegular() {
		t.Errorf("required public API artifact is not a regular file: %s", path)
	}
}

// assertFileDoesNotImportServer rejects private server dependencies in public packages.
func assertFileDoesNotImportServer(t *testing.T, repositoryRoot, path string) error {
	t.Helper()

	parsedFile, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	for _, importSpec := range parsedFile.Imports {
		importPath, unquoteErr := strconv.Unquote(importSpec.Path.Value)
		if unquoteErr != nil {
			return fmt.Errorf("unquote import in %s: %w", path, unquoteErr)
		}

		if strings.HasPrefix(importPath, serverImportSegment) {
			relativePath, relErr := filepath.Rel(repositoryRoot, path)
			if relErr != nil {
				return fmt.Errorf("resolve relative path for %s: %w", path, relErr)
			}

			t.Errorf("public API file %s imports private server package %s", relativePath, importPath)
		}
	}

	return nil
}

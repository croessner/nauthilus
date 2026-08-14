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
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const (
	authStateConstructorFromContext = "NewAuthStateFromContextWithDeps"
	authStateConstructorWithSetup   = "NewAuthStateWithSetupWithDeps"
	authStateConstructorLiteral     = "AuthState literal"
)

type authStateInventoryEntry struct {
	owner string
	count int
}

var authStateCallSiteInventory = map[string]authStateInventoryEntry{
	"server/core/auth_application_service.go|NewAuthStateFromContextWithDeps":                          {owner: "candidate application seam", count: 1},
	"server/core/auth.go|AuthState literal":                                                            {owner: "constructor implementation", count: 1},
	"server/core/auth.go|NewAuthStateFromContextWithDeps":                                              {owner: "constructor implementation", count: 1},
	"server/core/idp_mfa.go|NewAuthStateFromContextWithDeps":                                           {owner: "IdP and MFA convergence", count: 2},
	"server/core/protect_impl.go|AuthState literal":                                                    {owner: "protected endpoint compatibility", count: 1},
	"server/core/webauthn.go|NewAuthStateFromContextWithDeps":                                          {owner: "IdP and WebAuthn convergence", count: 4},
	"server/handler/api/v1/mfa.go|NewAuthStateWithSetupWithDeps":                                       {owner: "MFA route convergence", count: 1},
	"server/handler/auth/handler.go|NewAuthStateWithSetupWithDeps":                                     {owner: "auth route convergence", count: 1},
	"server/handler/frontend/idp/backend_data.go|NewAuthStateWithSetupWithDeps":                        {owner: "IdP convergence", count: 1},
	"server/handler/frontend/idp/frontend.go|NewAuthStateFromContextWithDeps":                          {owner: "IdP convergence", count: 1},
	"server/handler/frontend/idp/frontend.go|NewAuthStateWithSetupWithDeps":                            {owner: "IdP convergence", count: 4},
	"server/handler/frontend/idp/oidc.go|NewAuthStateFromContextWithDeps":                              {owner: "IdP convergence", count: 1},
	"server/handler/frontend/idp/require_mfa.go|NewAuthStateWithSetupWithDeps":                         {owner: "IdP and MFA convergence", count: 1},
	"server/handler/grpcauthority/backend_manager_identity_service.go|NewAuthStateFromContextWithDeps": {owner: "identity backend compatibility", count: 1},
	"server/handler/health/healthz.go|NewAuthStateFromContextWithDeps":                                 {owner: "health compatibility", count: 1},
	"server/handler/mfa_backchannel/handler.go|NewAuthStateFromContextWithDeps":                        {owner: "MFA backchannel convergence", count: 1},
	"server/idp/mfa.go|NewAuthStateFromContextWithDeps":                                                {owner: "IdP and MFA convergence", count: 1},
	"server/idp/nauthilus_idp.go|NewAuthStateFromContextWithDeps":                                      {owner: "IdP convergence", count: 3},
}

func TestAuthnAuthStateConstructionCallSiteInventoryIsComplete(t *testing.T) {
	actual, err := scanAuthStateConstructionCallSites("..")
	if err != nil {
		t.Fatalf("scan auth-state call sites: %v", err)
	}

	expected := make(map[string]int, len(authStateCallSiteInventory))
	for key, entry := range authStateCallSiteInventory {
		if strings.TrimSpace(entry.owner) == "" || entry.count <= 0 {
			t.Fatalf("inventory entry %q has invalid owner/count: %#v", key, entry)
		}

		expected[key] = entry.count
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("auth-state inventory drift\nactual:   %s\nexpected: %s", formatAuthStateInventory(actual), formatAuthStateInventory(expected))
	}
}

// scanAuthStateConstructionCallSites finds constructor calls and direct literals in production Go files.
func scanAuthStateConstructionCallSites(root string) (map[string]int, error) {
	result := make(map[string]int)

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}

		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		filename := filepath.ToSlash(filepath.Join("server", relative))

		ast.Inspect(parsed, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.CallExpr:
				name := authnCandidateCallName(typed.Fun)
				if name == authStateConstructorFromContext || name == authStateConstructorWithSetup {
					result[filename+"|"+name]++
				}
			case *ast.CompositeLit:
				if authStateTypeName(typed.Type) == "AuthState" {
					result[filename+"|"+authStateConstructorLiteral]++
				}
			}

			return true
		})

		return nil
	})

	return result, err
}

// authStateTypeName returns the terminal type name for direct and qualified literals.
func authStateTypeName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	default:
		return ""
	}
}

// formatAuthStateInventory returns a deterministic compact inventory for drift failures.
func formatAuthStateInventory(input map[string]int) string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	var output strings.Builder

	for index, key := range keys {
		if index > 0 {
			output.WriteString(", ")
		}

		_, _ = fmt.Fprintf(&output, "%s=%d", key, input[key])
	}

	return output.String()
}

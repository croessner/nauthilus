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
	authStateConstructorBuiltinNew  = "new(AuthState)"
)

type authStateDisposition string

const (
	authStateDispositionMigrated authStateDisposition = "migrated"
	authStateDispositionRetained authStateDisposition = "retained"
	authStateDispositionBlocking authStateDisposition = "blocking"
)

type authStateInventoryEntry struct {
	owner string
	count int
}

var authStateCallSiteInventory = map[string]authStateInventoryEntry{
	"server/core/auth_application_legacy_executor.go|NewAuthStateFromContextWithDeps":                  {owner: "isolated legacy FSM compatibility executor", count: 1},
	"server/core/auth.go|AuthState literal":                                                            {owner: "constructor implementation", count: 1},
	"server/core/auth.go|NewAuthStateFromContextWithDeps":                                              {owner: "constructor implementation", count: 1},
	"server/core/idp_mfa.go|NewAuthStateFromContextWithDeps":                                           {owner: "IdP and MFA convergence", count: 2},
	"server/core/protect_impl.go|AuthState literal":                                                    {owner: "protected endpoint compatibility", count: 1},
	"server/handler/auth/basic_endpoint_enabled.go|NewAuthStateWithSetupWithDeps":                      {owner: "optional Basic endpoint compatibility", count: 1},
	"server/handler/frontend/idp/backend_data.go|NewAuthStateWithSetupWithDeps":                        {owner: "IdP convergence", count: 1},
	"server/handler/frontend/idp/oidc.go|NewAuthStateFromContextWithDeps":                              {owner: "IdP convergence", count: 1},
	"server/handler/grpcauthority/backend_manager_identity_service.go|NewAuthStateFromContextWithDeps": {owner: "identity backend compatibility", count: 1},
	"server/handler/health/healthz.go|NewAuthStateFromContextWithDeps":                                 {owner: "health compatibility", count: 1},
	"server/handler/mfa_backchannel/handler.go|NewAuthStateFromContextWithDeps":                        {owner: "MFA backchannel convergence", count: 1},
	"server/idp/nauthilus_idp.go|NewAuthStateFromContextWithDeps":                                      {owner: "IdP convergence", count: 5},
}

type authStateDispositionEntry struct {
	routeFamily string
	callSite    string
	rationale   string
	disposition authStateDisposition
}

var backchannelAuthStateDispositions = []authStateDispositionEntry{
	{
		routeFamily: "HTTP JSON, CBOR, header, and nginx auth",
		callSite:    "server/handler/auth/handler.go|NewAuthStateWithSetupWithDeps",
		disposition: authStateDispositionMigrated,
		rationale:   "The HTTP handlers now convert transport input and invoke the shared auth application service.",
	},
	{
		routeFamily: "Shared HTTP and gRPC auth application execution",
		callSite:    "server/core/auth_application_legacy_executor.go|NewAuthStateFromContextWithDeps",
		disposition: authStateDispositionRetained,
		rationale:   "The isolated non-policy compatibility executor owns the existing FSM until the later atomic runtime cutover.",
	},
	{
		routeFamily: "Optional build-tagged HTTP Basic auth",
		callSite:    "server/handler/auth/basic_endpoint_enabled.go|NewAuthStateWithSetupWithDeps",
		disposition: authStateDispositionRetained,
		rationale:   "The separately gated Basic credential handshake is outside the listed JSON, CBOR, header, and nginx response surfaces.",
	},
	{
		routeFamily: "HTTP MFA backchannel",
		callSite:    "server/handler/mfa_backchannel/handler.go|NewAuthStateFromContextWithDeps",
		disposition: authStateDispositionRetained,
		rationale:   "The specialized MFA backend operation is deferred and remains a non-policy domain owner.",
	},
	{
		routeFamily: "gRPC identity backend MFA and WebAuthn",
		callSite:    "server/handler/grpcauthority/backend_manager_identity_service.go|NewAuthStateFromContextWithDeps",
		disposition: authStateDispositionRetained,
		rationale:   "The specialized identity-backend operation is not one of authenticate, lookup identity, or list accounts.",
	},
	{
		routeFamily: "IdP shared MFA helpers",
		callSite:    "server/core/idp_mfa.go|NewAuthStateFromContextWithDeps",
		disposition: authStateDispositionRetained,
		rationale:   "OIDC, device, SAML, and browser MFA convergence is explicitly deferred to the IdP convergence work.",
	},
	{
		routeFamily: "IdP frontend backend data",
		callSite:    "server/handler/frontend/idp/backend_data.go|NewAuthStateWithSetupWithDeps",
		disposition: authStateDispositionRetained,
		rationale:   "Browser-path backend data construction is explicitly deferred to the IdP convergence work.",
	},
	{
		routeFamily: "IdP frontend OIDC",
		callSite:    "server/handler/frontend/idp/oidc.go|NewAuthStateFromContextWithDeps",
		disposition: authStateDispositionRetained,
		rationale:   "OIDC browser-path construction is explicitly deferred to the IdP convergence work.",
	},
	{
		routeFamily: "IdP protocol implementation",
		callSite:    "server/idp/nauthilus_idp.go|NewAuthStateFromContextWithDeps",
		disposition: authStateDispositionRetained,
		rationale:   "OIDC, device, SAML, and client-credentials paths are explicitly deferred to the IdP convergence work.",
	},
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

func TestBackchannelAuthStateDispositionInventoryHasNoBlockingGap(t *testing.T) {
	actual, err := scanAuthStateConstructionCallSites("..")
	if err != nil {
		t.Fatalf("scan auth-state call sites: %v", err)
	}

	requiredCallSites := []string{
		"server/handler/auth/handler.go|NewAuthStateWithSetupWithDeps",
		"server/core/auth_application_legacy_executor.go|NewAuthStateFromContextWithDeps",
		"server/handler/auth/basic_endpoint_enabled.go|NewAuthStateWithSetupWithDeps",
		"server/handler/mfa_backchannel/handler.go|NewAuthStateFromContextWithDeps",
		"server/handler/grpcauthority/backend_manager_identity_service.go|NewAuthStateFromContextWithDeps",
		"server/core/idp_mfa.go|NewAuthStateFromContextWithDeps",
		"server/handler/frontend/idp/backend_data.go|NewAuthStateWithSetupWithDeps",
		"server/handler/frontend/idp/oidc.go|NewAuthStateFromContextWithDeps",
		"server/idp/nauthilus_idp.go|NewAuthStateFromContextWithDeps",
	}
	seen := make(map[string]struct{}, len(backchannelAuthStateDispositions))

	for _, entry := range backchannelAuthStateDispositions {
		assertBackchannelAuthStateDisposition(t, actual, seen, entry)
	}

	for _, callSite := range requiredCallSites {
		if _, classified := seen[callSite]; !classified {
			t.Fatalf("required backchannel AuthState call site %q is not classified", callSite)
		}
	}
}

// assertBackchannelAuthStateDisposition validates one complete and unique inventory classification.
func assertBackchannelAuthStateDisposition(
	t *testing.T,
	actual map[string]int,
	seen map[string]struct{},
	entry authStateDispositionEntry,
) {
	t.Helper()

	if strings.TrimSpace(entry.routeFamily) == "" ||
		strings.TrimSpace(entry.callSite) == "" ||
		strings.TrimSpace(entry.rationale) == "" {
		t.Fatalf("incomplete backchannel disposition entry: %#v", entry)
	}

	if _, found := seen[entry.callSite]; found {
		t.Fatalf("duplicate backchannel disposition for %q", entry.callSite)
	}

	seen[entry.callSite] = struct{}{}
	count := actual[entry.callSite]

	switch entry.disposition {
	case authStateDispositionMigrated:
		if count != 0 {
			t.Fatalf("migrated call site %q still has %d construction calls", entry.callSite, count)
		}
	case authStateDispositionRetained:
		if count == 0 {
			t.Fatalf("retained call site %q is absent from the global inventory", entry.callSite)
		}
	case authStateDispositionBlocking:
		t.Fatalf("blocking backchannel AuthState gap remains: %#v", entry)
	default:
		t.Fatalf("unknown backchannel disposition %q for %q", entry.disposition, entry.callSite)
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
			recordAuthStateConstruction(result, filename, node)

			return true
		})

		return nil
	})

	return result, err
}

// recordAuthStateConstruction records one constructor call or direct literal from an AST node.
func recordAuthStateConstruction(result map[string]int, filename string, node ast.Node) {
	switch typed := node.(type) {
	case *ast.CallExpr:
		name := authnCandidateCallName(typed.Fun)

		if name == authStateConstructorFromContext || name == authStateConstructorWithSetup {
			result[filename+"|"+name]++

			return
		}

		if name == "new" && len(typed.Args) == 1 && authStateTypeName(typed.Args[0]) == "AuthState" {
			result[filename+"|"+authStateConstructorBuiltinNew]++
		}
	case *ast.CompositeLit:
		if authStateTypeName(typed.Type) == "AuthState" {
			result[filename+"|"+authStateConstructorLiteral]++
		}
	}
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

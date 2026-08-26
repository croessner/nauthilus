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

type authStateDispositionEntry struct {
	routeFamily string
	callSite    string
	owner       string
	rationale   string
	disposition authStateDisposition
	count       int
}

var authStateConstructionDispositions = []authStateDispositionEntry{
	{
		routeFamily: "HTTP JSON, CBOR, header, and nginx auth",
		callSite:    "server/handler/auth/handler.go|Handler.newAuthState|NewAuthStateWithSetupWithDeps",
		owner:       "shared HTTP auth application adapter",
		disposition: authStateDispositionMigrated,
		rationale:   "The HTTP handlers now convert transport input and invoke the shared auth application service.",
		count:       0,
	},
	{
		routeFamily: "Captured HTTP, IdP, backchannel, and gRPC auth execution",
		callSite:    "server/core/auth_application_host.go|authApplicationService.newAuthState|NewAuthStateFromContextWithDeps",
		owner:       "captured auth FSM host",
		disposition: authStateDispositionRetained,
		rationale:   "The host materializes the existing FSM only inside the admitted Decision Service session and uses its captured configuration.",
		count:       1,
	},
	{
		routeFamily: "AuthState setup constructor",
		callSite:    "server/core/auth.go|NewAuthStateWithSetupWithDeps|NewAuthStateFromContextWithDeps",
		owner:       "constructor implementation",
		disposition: authStateDispositionRetained,
		rationale:   "The setup constructor delegates to the single dependency-injected AuthState constructor.",
		count:       1,
	},
	{
		routeFamily: "AuthState base constructor",
		callSite:    "server/core/auth.go|NewAuthStateFromContextWithDeps|AuthState literal",
		owner:       "constructor implementation",
		disposition: authStateDispositionRetained,
		rationale:   "The canonical dependency-injected constructor remains the sole direct AuthState literal owner.",
		count:       1,
	},
	{
		routeFamily: "IdP MFA result audit logging",
		callSite:    "server/core/idp_mfa.go|LogIDPMFAuthResult|NewAuthStateFromContextWithDeps",
		owner:       "IdP MFA audit projection",
		disposition: authStateDispositionRetained,
		rationale:   "The helper projects completed MFA protocol facts into the existing audit logger and does not evaluate policy.",
		count:       1,
	},
	{
		routeFamily: "Admitted IdP specialized identity state",
		callSite:    "server/core/idp_specialized_auth_state.go|NewIDPSpecializedAuthState|NewAuthStateFromContextWithDeps",
		owner:       "IdP specialized outcome materializer",
		disposition: authStateDispositionRetained,
		rationale:   "The helper materializes an already admitted identity outcome for protocol-owned MFA and WebAuthn backend operations without evaluating policy.",
		count:       1,
	},
	{
		routeFamily: "Protected HTTP endpoint checks",
		callSite:    "server/core/protect_impl.go|newProtectedEndpointAuthState|AuthState literal",
		owner:       "protected endpoint compatibility",
		disposition: authStateDispositionRetained,
		rationale:   "Protected endpoint pre-auth checks remain outside the IdP and backchannel authentication entry-path convergence.",
		count:       1,
	},
	{
		routeFamily: "Optional build-tagged HTTP Basic auth",
		callSite:    "server/handler/auth/basic_endpoint_enabled.go|Handler.processLegacyBasic|NewAuthStateWithSetupWithDeps",
		owner:       "shared HTTP auth application adapter",
		disposition: authStateDispositionMigrated,
		rationale:   "The optional Basic surface decodes credentials and invokes the same admitted auth application service as every other HTTP surface.",
		count:       0,
	},
	{
		routeFamily: "IdP frontend MFA and WebAuthn backend data",
		callSite:    "server/handler/frontend/idp/backend_data.go|FrontendHandler.newBackendDataAuthState|NewAuthStateWithSetupWithDeps",
		owner:       "shared IdP identity application adapter",
		disposition: authStateDispositionMigrated,
		rationale:   "The browser package must materialize specialized MFA and WebAuthn state only from an admitted identity outcome through the central specialized-state owner.",
		count:       0,
	},
	{
		routeFamily: "gRPC identity backend MFA and WebAuthn",
		callSite:    "server/handler/grpcauthority/backend_manager_identity_service.go|backendManagerIdentityService.authAndManager|NewAuthStateFromContextWithDeps",
		owner:       "shared gRPC identity application adapter",
		disposition: authStateDispositionMigrated,
		rationale:   "Every factor-backend operation must materialize specialized state only from an admitted identity outcome through the central specialized-state owner.",
		count:       0,
	},
	{
		routeFamily: "Health test backend",
		callSite:    "server/handler/health/healthz.go|newHealthzTestBackend|NewAuthStateFromContextWithDeps",
		owner:       "health compatibility",
		disposition: authStateDispositionRetained,
		rationale:   "The synthetic health backend is an operational probe rather than an authentication or identity entry path.",
		count:       1,
	},
	{
		routeFamily: "HTTP MFA backchannel",
		callSite:    "server/handler/mfa_backchannel/handler.go|Handler.buildAuthState|NewAuthStateFromContextWithDeps",
		owner:       "shared MFA identity application adapter",
		disposition: authStateDispositionMigrated,
		rationale:   "The handler must materialize specialized backend state only from an admitted identity outcome through the central specialized-state owner.",
		count:       0,
	},
	{
		routeFamily: "IdP delayed-response identity lookup",
		callSite:    "server/idp/nauthilus_idp.go|NauthilusIDP.lookupPasswordIdentity|NewAuthStateFromContextWithDeps",
		owner:       "shared IdP identity application adapter",
		disposition: authStateDispositionMigrated,
		rationale:   "Delayed-response hydration must use the same admitted identity lookup application boundary as other IdP identity paths.",
		count:       0,
	},
	{
		routeFamily: "IdP password authentication",
		callSite:    "server/idp/nauthilus_idp.go|NauthilusIDP.newPasswordAuthState|NewAuthStateFromContextWithDeps",
		owner:       "shared IdP authentication application adapter",
		disposition: authStateDispositionMigrated,
		rationale:   "OIDC, device, and SAML password authentication must enter the shared application and Decision Service boundary.",
		count:       0,
	},
	{
		routeFamily: "OIDC claim identity lookup",
		callSite:    "server/idp/nauthilus_idp.go|NauthilusIDP.GetUserByUsernameForOIDCClaimsCanonical|NewAuthStateFromContextWithDeps",
		owner:       "shared OIDC identity application adapter",
		disposition: authStateDispositionMigrated,
		rationale:   "OIDC claim identity loading must consume the shared lookup outcome with exact client and requested-attribute facts.",
		count:       0,
	},
	{
		routeFamily: "SAML attribute identity lookup",
		callSite:    "server/idp/nauthilus_idp.go|NauthilusIDP.GetUserByUsernameForSAMLCanonical|NewAuthStateFromContextWithDeps",
		owner:       "shared SAML identity application adapter",
		disposition: authStateDispositionMigrated,
		rationale:   "SAML attribute loading must consume the shared lookup outcome with the exact service-provider facts.",
		count:       0,
	},
	{
		routeFamily: "OIDC claim mapping",
		callSite:    "server/idp/nauthilus_idp.go|NauthilusIDP.GetClaims|NewAuthStateFromContextWithDeps",
		owner:       "OIDC claim mapping compatibility",
		disposition: authStateDispositionRetained,
		rationale:   "The lightweight state maps an already resolved identity outcome into protocol claims and does not evaluate policy.",
		count:       1,
	},
}

var authStateCallSiteInventory = legacyAuthStateInventoryView(authStateConstructionDispositions)
var backchannelAuthStateDispositions = legacyAuthStateDispositionView(authStateConstructionDispositions)

// legacyAuthStateInventoryView preserves the file-level view consumed by an existing compatibility assertion.
func legacyAuthStateInventoryView(dispositions []authStateDispositionEntry) map[string]authStateInventoryEntry {
	result := make(map[string]authStateInventoryEntry)

	for _, disposition := range dispositions {
		if disposition.disposition != authStateDispositionRetained || disposition.count <= 0 {
			continue
		}

		key := legacyAuthStateCallSite(disposition.callSite)
		entry := result[key]

		if entry.owner == "" {
			entry.owner = disposition.owner
		} else if entry.owner != disposition.owner {
			entry.owner = "multiple function-qualified owners"
		}

		entry.count += disposition.count
		result[key] = entry
	}

	return result
}

// legacyAuthStateDispositionView preserves file-level compatibility for the isolated executor assertion.
func legacyAuthStateDispositionView(dispositions []authStateDispositionEntry) []authStateDispositionEntry {
	result := make([]authStateDispositionEntry, 0, len(dispositions))

	for _, disposition := range dispositions {
		disposition.callSite = legacyAuthStateCallSite(disposition.callSite)
		result = append(result, disposition)
	}

	return result
}

// legacyAuthStateCallSite removes the function owner from one canonical inventory key.
func legacyAuthStateCallSite(callSite string) string {
	parts := strings.Split(callSite, "|")
	if len(parts) != 3 {
		return callSite
	}

	return parts[0] + "|" + parts[2]
}

func TestAuthnAuthStateConstructionCallSiteInventoryIsComplete(t *testing.T) {
	actual, err := scanAuthStateConstructionCallSites("..")
	if err != nil {
		t.Fatalf("scan auth-state call sites: %v", err)
	}

	expected := expectedAuthStateConstructionInventory(authStateConstructionDispositions)

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("auth-state inventory drift\nactual:   %s\nexpected: %s", formatAuthStateInventory(actual), formatAuthStateInventory(expected))
	}
}

func TestAuthStateDispositionInventoryHasNoBlockingOrUnclassifiedGap(t *testing.T) {
	actual, err := scanAuthStateConstructionCallSites("..")
	if err != nil {
		t.Fatalf("scan auth-state call sites: %v", err)
	}

	seen := make(map[string]struct{}, len(authStateConstructionDispositions))

	for _, entry := range authStateConstructionDispositions {
		assertAuthStateDisposition(t, actual, seen, entry)
	}

	for callSite := range actual {
		if _, classified := seen[callSite]; !classified {
			t.Fatalf("production AuthState construction %q has no disposition", callSite)
		}
	}
}

func TestAuthStateConstructionInventorySeparatesFunctionOwners(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "fixture.go", `package fixture
type AuthState struct{}
type owner struct{}
var packageState = &AuthState{}
func first() { _ = NewAuthStateFromContextWithDeps() }
func (*owner) second() { _ = &AuthState{} }
`, 0)
	if err != nil {
		t.Fatalf("parse AuthState inventory fixture: %v", err)
	}

	actual := make(map[string]int)
	recordAuthStateFileConstructions(actual, "server/fixture.go", parsed)

	expected := map[string]int{
		"server/fixture.go|<package>|AuthState literal":           1,
		"server/fixture.go|first|NewAuthStateFromContextWithDeps": 1,
		"server/fixture.go|owner.second|AuthState literal":        1,
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("function-qualified inventory\nactual:   %s\nexpected: %s", formatAuthStateInventory(actual), formatAuthStateInventory(expected))
	}
}

// expectedAuthStateConstructionInventory derives the exact retained-site inventory from the disposition authority.
func expectedAuthStateConstructionInventory(dispositions []authStateDispositionEntry) map[string]int {
	expected := make(map[string]int)

	for _, disposition := range dispositions {
		if disposition.disposition == authStateDispositionRetained && disposition.count > 0 {
			expected[disposition.callSite] = disposition.count
		}
	}

	return expected
}

// assertAuthStateDisposition validates one complete and unique function-qualified classification.
func assertAuthStateDisposition(
	t *testing.T,
	actual map[string]int,
	seen map[string]struct{},
	entry authStateDispositionEntry,
) {
	t.Helper()
	validateAuthStateDispositionDefinition(t, entry)

	if _, found := seen[entry.callSite]; found {
		t.Fatalf("duplicate AuthState disposition for %q", entry.callSite)
	}

	seen[entry.callSite] = struct{}{}
	assertAuthStateDispositionCount(t, actual[entry.callSite], entry)
}

// validateAuthStateDispositionDefinition requires complete function-qualified disposition metadata.
func validateAuthStateDispositionDefinition(t *testing.T, entry authStateDispositionEntry) {
	t.Helper()

	if strings.TrimSpace(entry.routeFamily) == "" ||
		strings.TrimSpace(entry.callSite) == "" ||
		strings.TrimSpace(entry.owner) == "" ||
		strings.TrimSpace(entry.rationale) == "" {
		t.Fatalf("incomplete AuthState disposition entry: %#v", entry)
	}

	if parts := strings.Split(entry.callSite, "|"); len(parts) != 3 ||
		strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" || strings.TrimSpace(parts[2]) == "" {
		t.Fatalf("AuthState disposition key is not file|function|kind: %q", entry.callSite)
	}
}

// assertAuthStateDispositionCount enforces migrated absence or the exact retained count.
func assertAuthStateDispositionCount(t *testing.T, count int, entry authStateDispositionEntry) {
	t.Helper()

	switch entry.disposition {
	case authStateDispositionMigrated:
		if entry.count != 0 || count != 0 {
			t.Fatalf("migrated call site %q still has %d construction calls", entry.callSite, count)
		}
	case authStateDispositionRetained:
		if entry.count <= 0 || count != entry.count {
			t.Fatalf("retained call site %q has %d construction calls, want %d", entry.callSite, count, entry.count)
		}
	case authStateDispositionBlocking:
		t.Fatalf("blocking AuthState gap remains: %#v", entry)
	default:
		t.Fatalf("unknown AuthState disposition %q for %q", entry.disposition, entry.callSite)
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
		recordAuthStateFileConstructions(result, filename, parsed)

		return nil
	})

	return result, err
}

// recordAuthStateFileConstructions records package- and function-owned constructions in one parsed file.
func recordAuthStateFileConstructions(result map[string]int, filename string, parsed *ast.File) {
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			ast.Inspect(declaration, func(node ast.Node) bool {
				recordAuthStateConstruction(result, filename, "<package>", node)

				return true
			})

			continue
		}

		ast.Inspect(function.Body, func(node ast.Node) bool {
			recordAuthStateConstruction(result, filename, authStateFunctionOwner(function), node)

			return true
		})
	}
}

// recordAuthStateConstruction records one constructor call or direct literal from an AST node.
func recordAuthStateConstruction(result map[string]int, filename string, functionOwner string, node ast.Node) {
	switch typed := node.(type) {
	case *ast.CallExpr:
		name := authnCandidateCallName(typed.Fun)

		if name == authStateConstructorFromContext || name == authStateConstructorWithSetup {
			result[authStateInventoryKey(filename, functionOwner, name)]++

			return
		}

		if name == "new" && len(typed.Args) == 1 && authStateTypeName(typed.Args[0]) == "AuthState" {
			result[authStateInventoryKey(filename, functionOwner, authStateConstructorBuiltinNew)]++
		}
	case *ast.CompositeLit:
		if authStateTypeName(typed.Type) == "AuthState" {
			result[authStateInventoryKey(filename, functionOwner, authStateConstructorLiteral)]++
		}
	}
}

// authStateFunctionOwner returns a stable receiver-qualified function identity.
func authStateFunctionOwner(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return function.Name.Name
	}

	receiver := authStateTypeName(function.Recv.List[0].Type)
	if receiver == "" {
		receiver = "<receiver>"
	}

	return receiver + "." + function.Name.Name
}

// authStateInventoryKey joins the source, function owner, and construction kind.
func authStateInventoryKey(filename string, functionOwner string, constructionKind string) string {
	return strings.Join([]string{filename, functionOwner, constructionKind}, "|")
}

// authStateTypeName returns the terminal type name for direct and qualified literals.
func authStateTypeName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	case *ast.StarExpr:
		return authStateTypeName(typed.X)
	case *ast.ParenExpr:
		return authStateTypeName(typed.X)
	case *ast.IndexExpr:
		return authStateTypeName(typed.X)
	case *ast.IndexListExpr:
		return authStateTypeName(typed.X)
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

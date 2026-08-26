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

package grpcauthority

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestGRPCBackchannelAuthHandlerOwnsOnlyTransportConversion(t *testing.T) {
	fileSet := token.NewFileSet()

	parsed, err := parser.ParseFile(fileSet, "handler.go", nil, 0)
	if err != nil {
		t.Fatalf("parse gRPC auth handler: %v", err)
	}

	forbiddenImports := []string{
		"/server/policy/compiler",
		"/server/policy/evaluation",
		"/server/policy/registry",
		"/server/policy/runtime",
	}

	for _, imported := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil {
			t.Fatalf("unquote handler import: %v", unquoteErr)
		}

		for _, forbidden := range forbiddenImports {
			if strings.Contains(path, forbidden) {
				t.Fatalf("gRPC auth handler imports forbidden policy implementation %q", path)
			}
		}
	}

	forbiddenCalls := map[string]struct{}{
		"HandleAuthentication":            {},
		"NewAuthState":                    {},
		"NewAuthStateFromContextWithDeps": {},
		"NewAuthStateWithSetup":           {},
		"NewAuthStateWithSetupWithDeps":   {},
		"PreproccessAuthRequest":          {},
	}

	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}

		name := grpcAuthBoundaryCallName(call.Fun)
		if _, forbidden := forbiddenCalls[name]; forbidden {
			position := fileSet.Position(call.Pos())
			t.Errorf("handler.go:%d calls forbidden auth runtime entry %s", position.Line, name)
		}

		return true
	})
}

func TestGRPCIdentityBackendRetainsOnlySpecializedAuthStateMaterialization(t *testing.T) {
	fileSet := token.NewFileSet()

	parsed, err := parser.ParseFile(fileSet, "backend_manager_identity_service.go", nil, 0)
	if err != nil {
		t.Fatalf("parse gRPC identity backend service: %v", err)
	}

	counts := &grpcIdentityBoundaryCounts{}

	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}

		inspectGRPCIdentityBoundaryFunction(t, fileSet, function, counts)
	}

	if counts.specializedConstructors != 1 {
		t.Fatalf("gRPC identity specialized AuthState constructors = %d, want 1 exact owner", counts.specializedConstructors)
	}

	if counts.authAndManagerAdmissions != 1 || counts.applicationLookups != 1 {
		t.Fatalf(
			"gRPC specialized identity call chain has %d adapter admissions and %d application lookups, want 1 each",
			counts.authAndManagerAdmissions,
			counts.applicationLookups,
		)
	}

	if counts.admissionPosition >= counts.constructorPosition {
		t.Fatal("gRPC identity materializes specialized AuthState before application admission")
	}
}

type grpcIdentityBoundaryCounts struct {
	admissionPosition        token.Pos
	constructorPosition      token.Pos
	authAndManagerAdmissions int
	applicationLookups       int
	specializedConstructors  int
}

// inspectGRPCIdentityBoundaryFunction enforces the exact admission-to-materializer call chain.
func inspectGRPCIdentityBoundaryFunction(
	t *testing.T,
	fileSet *token.FileSet,
	function *ast.FuncDecl,
	counts *grpcIdentityBoundaryCounts,
) {
	t.Helper()

	owner := grpcAuthBoundaryFunctionOwner(function)

	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}

		name := grpcAuthBoundaryCallName(call.Fun)
		if name == "HandlePassword" || name == "HandleEnvironment" || name == "HandleAuthentication" {
			position := fileSet.Position(call.Pos())
			t.Errorf("backend_manager_identity_service.go:%d directly evaluates authentication through %s", position.Line, name)
		}

		if name == "NewAuthStateFromContextWithDeps" {
			position := fileSet.Position(call.Pos())
			t.Errorf("backend_manager_identity_service.go:%d function %s bypasses the specialized AuthState materializer", position.Line, owner)
		}

		if name == "lookupIdentity" && owner == "backendManagerIdentityService.authAndManager" {
			counts.authAndManagerAdmissions++
			counts.admissionPosition = call.Pos()
		}

		if name == "LookupIdentity" {
			counts.applicationLookups++

			if owner != "backendManagerIdentityService.lookupIdentity" {
				position := fileSet.Position(call.Pos())
				t.Errorf("backend_manager_identity_service.go:%d invokes the application lookup outside lookupIdentity", position.Line)
			}
		}

		if name == "NewIDPSpecializedAuthState" {
			counts.specializedConstructors++
			counts.constructorPosition = call.Pos()

			if owner != "backendManagerIdentityService.authAndManager" {
				position := fileSet.Position(call.Pos())
				t.Errorf("backend_manager_identity_service.go:%d constructs specialized AuthState in %s", position.Line, owner)
			}
		}

		return true
	})
}

// grpcAuthBoundaryCallName returns the invoked identifier for direct and qualified calls.
func grpcAuthBoundaryCallName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	case *ast.StarExpr:
		return grpcAuthBoundaryCallName(typed.X)
	default:
		return ""
	}
}

// grpcAuthBoundaryFunctionOwner returns the receiver-qualified owner of one boundary call.
func grpcAuthBoundaryFunctionOwner(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return function.Name.Name
	}

	return grpcAuthBoundaryCallName(function.Recv.List[0].Type) + "." + function.Name.Name
}

// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestIDPCompositionRootUsesOnlyCanonicalBrowserRuntime(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server composition root: %v", err)
	}

	setup := sourceFunctionText(t, string(source), "func buildIDPSetupCallback(", "func frontendHandlerDeps(")
	registrar := sourceFunctionText(t, string(source), "func registerIDPRoutes(", "func buildBackchannelSetupCallback(")

	for _, required := range []string{
		"handleridp.NewCanonicalBrowserRuntime(deps)",
		"handleridp.NewCanonicalFrontendHandler(deps, canonicalRuntime)",
		"frontendHandler.Register(e)",
		"oidcHandler := handleridp.NewOIDCHandler(deps, nauthilusIDP, frontendHandler)",
		"frontendHandler.SetCanonicalOIDCDeviceLoginContinuer(oidcHandler.ContinueDeviceLoginCanonical)",
		"oidcHandler.Register(e, canonicalRuntime)",
		"NewSAMLHandler(deps, nauthilusIDP).Register(e, canonicalRuntime)",
	} {
		if !strings.Contains(setup+registrar, required) {
			t.Fatalf("canonical IDP composition missing %q", required)
		}
	}

	if strings.Contains(registrar, "handleridp.NewFrontendHandler(deps)") ||
		strings.Contains(registrar, ".RegisterCanonical(") ||
		strings.Contains(registrar, "handlerapiv1.NewMFAAPI") || strings.Count(registrar, ".Register(") != 3 {
		t.Fatalf("IDP registrar retained parallel browser worlds:\n%s", registrar)
	}
}

func TestIDPCompositionRootSuppliesSharedAuthApplicationBeforeAdapters(t *testing.T) {
	t.Parallel()

	fileSet := token.NewFileSet()

	parsed, err := parser.ParseFile(fileSet, "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server composition root: %v", err)
	}

	functions := compositionFunctions(parsed)
	dependencyBuilder := requireCompositionFunction(t, functions, "frontendHandlerDeps")
	dependencyName, returnPosition := returnedCompositionDependency(t, dependencyBuilder)
	applicationPosition := requireRuntimeAuthApplicationAssignment(t, dependencyBuilder, dependencyName)

	if applicationPosition >= returnPosition {
		t.Fatal("frontend IDP dependencies return before AuthApplication initialization")
	}

	setup := requireCompositionFunction(t, functions, "buildIDPSetupCallback")
	setupDependency, setupDependencyPosition := requireAssignedCompositionCall(t, setup, "frontendHandlerDeps")

	for _, adapter := range []string{"NewCanonicalBrowserRuntime", "NewCanonicalFrontendHandler"} {
		call := requireSingleCompositionCall(t, setup, adapter)

		if call.Pos() <= setupDependencyPosition || !compositionCallArgumentIs(call, 0, setupDependency) {
			t.Fatalf("%s does not consume the initialized frontend dependency", adapter)
		}
	}

	registration := requireSingleCompositionCall(t, setup, "registerIDPRoutes")
	if !compositionCallArgumentIs(registration, 2, setupDependency) {
		t.Fatal("IDP route registration does not receive the initialized frontend dependency")
	}

	registrar := requireCompositionFunction(t, functions, "registerIDPRoutes")
	registrarDependency := requireCompositionParameter(t, registrar, "Deps")
	nauthilusIDP := requireSingleCompositionCall(t, registrar, "NewNauthilusIDP")

	if !compositionCallArgumentIs(nauthilusIDP, 0, registrarDependency) {
		t.Fatal("canonical OIDC and SAML adapters do not share the registered frontend dependency")
	}
}

// compositionFunctions indexes top-level functions by their declaration name.
func compositionFunctions(parsed *ast.File) map[string]*ast.FuncDecl {
	functions := make(map[string]*ast.FuncDecl)

	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok {
			functions[function.Name.Name] = function
		}
	}

	return functions
}

// requireCompositionFunction returns one required composition-root function.
func requireCompositionFunction(t *testing.T, functions map[string]*ast.FuncDecl, name string) *ast.FuncDecl {
	t.Helper()

	function := functions[name]
	if function == nil || function.Body == nil {
		t.Fatalf("server composition function %s is missing", name)
	}

	return function
}

// returnedCompositionDependency identifies the local dependency object returned by a builder.
func returnedCompositionDependency(t *testing.T, function *ast.FuncDecl) (string, token.Pos) {
	t.Helper()

	var (
		dependency string
		position   token.Pos
	)

	ast.Inspect(function.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}

		statement, ok := node.(*ast.ReturnStmt)
		if !ok || len(statement.Results) != 1 {
			return true
		}

		identifier, ok := statement.Results[0].(*ast.Ident)
		if !ok || dependency != "" && dependency != identifier.Name {
			t.Fatalf("%s does not return one stable dependency object", function.Name.Name)
		}

		dependency = identifier.Name

		if position == token.NoPos || statement.Pos() < position {
			position = statement.Pos()
		}

		return true
	})

	if dependency == "" {
		t.Fatalf("%s does not return a local dependency object", function.Name.Name)
	}

	return dependency, position
}

// requireRuntimeAuthApplicationAssignment proves the returned dependency receives the sole runtime-owned application.
func requireRuntimeAuthApplicationAssignment(t *testing.T, function *ast.FuncDecl, dependency string) token.Pos {
	t.Helper()

	var position token.Pos

	ast.Inspect(function.Body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}

		for index, target := range assignment.Lhs {
			selector, selected := target.(*ast.SelectorExpr)
			if !selected {
				continue
			}

			root, rooted := selectorRootIdentifier(selector)

			if !rooted || root != dependency || selector.Sel.Name != "AuthApplication" {
				continue
			}

			value := compositionAssignmentValue(assignment, index)

			selector, selected = value.(*ast.SelectorExpr)
			if !selected {
				t.Fatalf("%s assigns AuthApplication from %T, want runtime.authApplication", function.Name.Name, value)
			}

			root, rooted = selectorRootIdentifier(selector)
			if !rooted || root != "runtime" || selector.Sel.Name != "authApplication" {
				t.Fatalf("%s assigns AuthApplication from %T, want runtime.authApplication", function.Name.Name, value)
			}

			position = assignment.Pos()
		}

		return true
	})

	if position == token.NoPos {
		t.Fatalf("%s does not initialize AuthApplication on its returned dependency", function.Name.Name)
	}

	return position
}

// requireAssignedCompositionCall returns the identifier bound to one constructor result.
func requireAssignedCompositionCall(t *testing.T, function *ast.FuncDecl, callName string) (string, token.Pos) {
	t.Helper()

	var (
		result   string
		position token.Pos
	)

	ast.Inspect(function.Body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}

		for index, value := range assignment.Rhs {
			call, called := value.(*ast.CallExpr)
			if !called || compositionCallName(call.Fun) != callName || index >= len(assignment.Lhs) {
				continue
			}

			identifier, bound := assignment.Lhs[index].(*ast.Ident)
			if !bound || result != "" {
				t.Fatalf("%s must bind exactly one %s result", function.Name.Name, callName)
			}

			result = identifier.Name
			position = assignment.Pos()
		}

		return true
	})

	if result == "" {
		t.Fatalf("%s does not bind %s", function.Name.Name, callName)
	}

	return result, position
}

// requireSingleCompositionCall returns one exact function call from a composition owner.
func requireSingleCompositionCall(t *testing.T, function *ast.FuncDecl, name string) *ast.CallExpr {
	t.Helper()

	var calls []*ast.CallExpr

	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && compositionCallName(call.Fun) == name {
			calls = append(calls, call)
		}

		return true
	})

	if len(calls) != 1 {
		t.Fatalf("%s calls %s %d times, want exactly 1", function.Name.Name, name, len(calls))
	}

	return calls[0]
}

// requireCompositionParameter returns the parameter that carries the requested terminal type.
func requireCompositionParameter(t *testing.T, function *ast.FuncDecl, terminalType string) string {
	t.Helper()

	for _, field := range function.Type.Params.List {
		if compositionTypeName(field.Type) == terminalType && len(field.Names) == 1 {
			return field.Names[0].Name
		}
	}

	t.Fatalf("%s has no unique %s parameter", function.Name.Name, terminalType)

	return ""
}

// compositionAssignmentValue maps one assignment target to its corresponding value.
func compositionAssignmentValue(assignment *ast.AssignStmt, index int) ast.Expr {
	if len(assignment.Rhs) == len(assignment.Lhs) {
		return assignment.Rhs[index]
	}

	if len(assignment.Rhs) == 1 {
		return assignment.Rhs[0]
	}

	return nil
}

// selectorRootIdentifier resolves the root variable of a selector chain.
func selectorRootIdentifier(selector *ast.SelectorExpr) (string, bool) {
	switch expression := selector.X.(type) {
	case *ast.Ident:
		return expression.Name, true
	case *ast.SelectorExpr:
		return selectorRootIdentifier(expression)
	default:
		return "", false
	}
}

// compositionCallArgumentIs checks an exact identifier argument without depending on its spelling.
func compositionCallArgumentIs(call *ast.CallExpr, index int, identifier string) bool {
	if index >= len(call.Args) {
		return false
	}

	argument, ok := call.Args[index].(*ast.Ident)

	return ok && argument.Name == identifier
}

// compositionCallName resolves the terminal name of direct and qualified calls.
func compositionCallName(expression ast.Expr) string {
	switch function := expression.(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		return function.Sel.Name
	default:
		return ""
	}
}

// compositionTypeName resolves the terminal name of a qualified pointer type.
func compositionTypeName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	case *ast.StarExpr:
		return compositionTypeName(typed.X)
	default:
		return ""
	}
}

func sourceFunctionText(t *testing.T, source string, startMarker string, endMarker string) string {
	t.Helper()

	start := strings.Index(source, startMarker)

	end := strings.Index(source, endMarker)
	if start < 0 || end <= start {
		t.Fatalf("source function markers missing: %q..%q", startMarker, endMarker)
	}

	return source[start:end]
}

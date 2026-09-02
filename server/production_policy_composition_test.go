// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionCompositionOwnsOneDecisionAndAuthApplicationAuthority(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server composition root: %v", err)
	}

	functions := compositionFunctions(parsed)

	prepare := requireCompositionFunction(t, functions, "prepareHTTPServerRuntime")
	if got := countCompositionCalls(prepare, "newPolicyDecisionService"); got != 0 {
		t.Fatalf("prepareHTTPServerRuntime newPolicyDecisionService calls = %d, want 0", got)
	}

	if got := countSelectorReferences(prepare, "store", "policyDecision"); got != 2 {
		t.Fatalf("prepareHTTPServerRuntime store.policyDecision references = %d, want 2", got)
	}

	if got := countCompositionCalls(prepare, "NewProductionAuthApplicationService"); got != 1 {
		t.Fatalf("prepareHTTPServerRuntime NewProductionAuthApplicationService calls = %d, want 1", got)
	}

	if got := countParsedCalls(parsed, "NewAuthApplicationService"); got != 0 {
		t.Fatalf("server composition retains %d direct base auth application constructors", got)
	}

	for _, owner := range []string{"frontendHandlerDeps", "buildBackchannelSetupCallback", "startGRPCAuthorityForHTTP"} {
		function := requireCompositionFunction(t, functions, owner)
		if countSelectorReferences(function, "runtime", "authApplication") == 0 {
			t.Fatalf("%s does not consume runtime.authApplication", owner)
		}

		if countSelectorReferences(function, "runtime", "policyDecision") == 0 && owner != "frontendHandlerDeps" {
			t.Fatalf("%s does not consume runtime.policyDecision", owner)
		}
	}
}

func TestHTTPHandlerDependenciesCarryTheActiveConfigProvider(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server composition root: %v", err)
	}

	functions := compositionFunctions(parsed)
	for _, owner := range []string{"frontendHandlerDeps", "buildBackchannelSetupCallback"} {
		function := requireCompositionFunction(t, functions, owner)
		if got := countSelectorReferences(function, "runtime", "cfgProvider"); got != 1 {
			t.Errorf("%s active config provider references = %d, want 1", owner, got)
		}
	}
}

func TestProductionDecisionServiceConstructorHasOneCompositionOwner(t *testing.T) {
	owners := productionDecisionServiceConstructorOwners(t)

	want := filepath.Join("app", "policyfx", "module.go")
	if len(owners) != 1 || owners[0] != want {
		t.Fatalf("production NewDecisionService owners = %v, want [%s]", owners, want)
	}
}

func TestProductionAuthApplicationBindsTheExplicitPluginRunner(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server composition root: %v", err)
	}

	prepare := requireCompositionFunction(t, compositionFunctions(parsed), "prepareHTTPServerRuntime")
	if got := countCompositionCalls(prepare, "NewBackendManagerFactory"); got != 1 {
		t.Fatalf("prepareHTTPServerRuntime NewBackendManagerFactory calls = %d, want 1", got)
	}

	if got := countSelectorReferences(prepare, "store", "pluginRunner"); got != 1 {
		t.Fatalf("prepareHTTPServerRuntime store.pluginRunner references = %d, want 1", got)
	}
}

func TestProductionAuthApplicationBindsExplicitLDAPQueues(t *testing.T) {
	contents, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read production composition root: %v", err)
	}

	for _, required := range []string{
		"LDAPQueue:            priorityqueue.LDAPQueue",
		"LDAPAuthQueue:        priorityqueue.LDAPAuthQueue",
	} {
		if !strings.Contains(string(contents), required) {
			t.Errorf("production auth composition is missing explicit LDAP dependency %q", required)
		}
	}
}

func TestProductionCompositionHasNoGlobalPolicyLocalizationAuthority(t *testing.T) {
	for _, path := range []string{"main.go", "main_wiring.go"} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read production composition %s: %v", path, err)
		}

		for _, forbidden := range []string{"localizationfx", "ReloadOperatorOverlays", "CatalogOverlays"} {
			if strings.Contains(string(contents), forbidden) {
				t.Errorf("production composition %s retains global Policy localization authority %q", path, forbidden)
			}
		}
	}

	sources, err := filepath.Glob(filepath.Join("app", "localizationfx", "*.go"))
	if err != nil {
		t.Fatalf("scan retired localization package: %v", err)
	}

	if len(sources) != 0 {
		t.Fatalf("retired global Policy localization package still contains %v", sources)
	}
}

func TestProductionTransportCompositionDoesNotInjectAmbientPolicyResolver(t *testing.T) {
	for _, path := range []string{"server.go", filepath.Join("core", "localization", "resolver.go")} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read production resolver authority %s: %v", path, err)
		}

		for _, forbidden := range []string{
			"newDefaultPolicyMessageResolver",
			"NewRegistryResolver",
			"type RegistryResolver",
			"MessageResolver:",
			"DefaultI18NRuntime",
		} {
			if strings.Contains(string(contents), forbidden) {
				t.Errorf("production source %s retains ambient Policy resolver wiring %q", path, forbidden)
			}
		}
	}
}

func TestProductionCompositionHasNoUnusedRedisDefaultAuthority(t *testing.T) {
	for _, path := range []string{"main_wiring.go", "server.go"} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read production Redis composition %s: %v", path, err)
		}

		if strings.Contains(string(contents), "SetDefaultRedisClient(") {
			t.Errorf("production source %s retains the removed Redis default authority", path)
		}
	}

	for _, path := range []string{
		filepath.Join("backend", "redis_default.go"),
		filepath.Join("bruteforce", "redis_default.go"),
		filepath.Join("core", "redis_default.go"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("removed Redis default authority %s remains or cannot be checked: %v", path, err)
		}
	}
}

func TestProductionCompositionHasNoLegacyLuaActionWorkerAuthority(t *testing.T) {
	for _, path := range []string{
		"main_wiring.go",
		"server.go",
		"fx_ops_components.go",
		filepath.Join("core", "lua_post_action.go"),
		filepath.Join("core", "environment.go"),
		filepath.Join("core", "policy_obligations.go"),
		filepath.Join("policy", "decision", "service", "authn_selection_runtime.go"),
	} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read production action composition %s: %v", path, err)
		}

		for _, forbidden := range []string{
			"server/lualib/action",
			"action.RequestChan",
			"action.PostActionRequestChan",
			"action.NewWorker",
			"[]*action.Worker",
			"HaveLuaActions()",
			"GetLuaActionNumberOfWorkers()",
			"DefaultActionDispatcher",
			"executeLuaActionObligation",
			"performAction(",
			"WithBuiltinAuthPostAction",
			"authnImplicitPostActionRequired",
		} {
			if strings.Contains(string(contents), forbidden) {
				t.Errorf("production source %s retains legacy Lua action authority %q", path, forbidden)
			}
		}
	}

	if _, err := os.Stat(filepath.Join("core", "auth", "action_service.go")); !os.IsNotExist(err) {
		t.Fatalf("legacy action dispatcher source still exists or cannot be checked: %v", err)
	}

	sources, err := filepath.Glob(filepath.Join("lualib", "action", "*.go"))
	if err != nil {
		t.Fatalf("scan legacy Lua action package: %v", err)
	}

	for _, source := range sources {
		if !strings.HasSuffix(source, "_test.go") {
			t.Errorf("legacy Lua action production source still exists: %s", source)
		}
	}
}

func TestGenerationOwnedLuaPathsUseSealedModuleAuthority(t *testing.T) {
	for _, path := range []string{
		filepath.Join("core", "authn_lua_action.go"),
		filepath.Join("lualib", "environment", "environment.go"),
		filepath.Join("lualib", "subject", "subject.go"),
	} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read generation-owned Lua runtime %s: %v", path, err)
		}

		if strings.Contains(string(contents), "lualib.PackagePath(") {
			t.Errorf("generation-owned Lua runtime %s retains live package.path authority", path)
		}

		for _, forbidden := range []string{"BindAllDefault(", "LoaderModRedis(", "LoaderModPsnet("} {
			if strings.Contains(string(contents), forbidden) {
				t.Errorf("generation-owned Lua runtime %s retains mutable request module authority %s", path, forbidden)
			}
		}

		if !strings.Contains(string(contents), "luaseal.InstallPolicyProfile(") {
			t.Errorf("generation-owned Lua runtime %s does not install sealed module authority", path)
		}
	}
}

func TestGenerationOwnedLuaPreparationHasNoAmbientVMPoolLookup(t *testing.T) {
	for _, path := range []string{
		filepath.Join("app", "policyfx", "module.go"),
		filepath.Join("policy", "configinput", "authn_lua_action_generation.go"),
		filepath.Join("policy", "configinput", "authn_lua_source_generation.go"),
		filepath.Join("core", "authn_lua_action.go"),
		filepath.Join("lualib", "environment", "environment.go"),
		filepath.Join("lualib", "subject", "subject.go"),
	} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read generation-owned Lua owner %s: %v", path, err)
		}

		if strings.Contains(string(contents), "vmpool.GetManager(") {
			t.Errorf("generation-owned Lua owner %s retains ambient VM pool lookup", path)
		}
	}
}

func TestGenerationOwnedLuaCompilersHaveNoLiveFilesystemFallback(t *testing.T) {
	paths := []string{
		filepath.Join("lualib", "misc.go"),
		filepath.Join("lualib", "environment", "environment.go"),
		filepath.Join("lualib", "subject", "subject.go"),
		filepath.Join("lualib", "policyprovider", "script.go"),
	}
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read generation-owned Lua compiler %s: %v", path, err)
		}

		for _, forbidden := range []string{
			"CompileLua(",
			"NewLuaEnvironmentSource(",
			"NewLuaSubjectSource(",
			"CompileScriptFile(",
			"os.ReadFile(",
			"os.Open(",
		} {
			if strings.Contains(string(contents), forbidden) {
				t.Errorf("generation-owned Lua compiler %s retains live filesystem fallback %s", path, forbidden)
			}
		}
	}
}

func TestProductionConfigProjectionReadsTheActiveGeneration(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "main_wiring.go", nil, 0)
	if err != nil {
		t.Fatalf("parse runtime composition: %v", err)
	}

	constructor := requireCompositionFunction(t, compositionFunctions(parsed), "newConfigDeps")
	if got := countCompositionCalls(constructor, "BindActiveFileSource"); got != 1 {
		t.Fatalf("BindActiveFileSource calls = %d, want exactly 1", got)
	}

	if got := countSelectorReferences(constructor, "generations", "Active"); got != 1 {
		t.Fatalf("generations.Active references = %d, want exactly 1", got)
	}

	if got := countCompositionCalls(constructor, "Config"); got != 1 {
		t.Fatalf("active generation Config calls = %d, want exactly 1", got)
	}

	if !activeFileSourceReturnsBootstrapBeforeInitialGeneration(constructor) {
		t.Fatal("active config projection has no bootstrap fallback before initial generation commit")
	}
}

func TestRuntimeCompositionCapturesLuaInitBeforeGenerationAndHTTP(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "main_wiring.go", nil, 0)
	if err != nil {
		t.Fatalf("parse runtime composition: %v", err)
	}

	if got := countParsedCalls(parsed, "RunLuaInitScript"); got != 0 {
		t.Fatalf("best-effort RunLuaInitScript calls = %d, want 0", got)
	}

	start := requireCompositionFunction(t, compositionFunctions(parsed), "startRuntimeLifecycle")
	pluginPosition := firstCompositionCallPosition(start, "startRuntimePluginRunner")
	policyPosition := firstCompositionCallPosition(start, "prepareInitialPolicyGeneration")

	httpPosition := firstCompositionCallPosition(start, "startHTTPAndDropPrivileges")
	if pluginPosition == token.NoPos || policyPosition <= pluginPosition || httpPosition <= policyPosition {
		t.Fatalf(
			"startup positions plugin=%d policy=%d HTTP=%d, want plugin < policy < HTTP",
			pluginPosition,
			policyPosition,
			httpPosition,
		)
	}

	prepare := requireCompositionFunction(t, compositionFunctions(parsed), "prepareInitialPolicyGeneration")
	initPosition := firstCompositionCallPosition(prepare, "PrepareLuaInitCatalogs")
	capturePosition := firstCompositionCallPosition(prepare, "Capture")

	commitPosition := firstCompositionCallPosition(prepare, "Apply")
	if initPosition == token.NoPos || capturePosition <= initPosition || commitPosition <= capturePosition {
		t.Fatalf(
			"policy preparation positions init=%d capture=%d commit=%d, want init < capture < commit",
			initPosition,
			capturePosition,
			commitPosition,
		)
	}
}

// countCompositionCalls counts exact calls owned by one top-level function.
func countCompositionCalls(function *ast.FuncDecl, name string) int {
	if function == nil || function.Body == nil {
		return 0
	}

	return countCallsInNode(function.Body, name)
}

// countParsedCalls counts exact calls across one parsed composition source.
func countParsedCalls(parsed *ast.File, name string) int {
	return countCallsInNode(parsed, name)
}

// firstCompositionCallPosition returns the source position of one exact call inside a function.
func firstCompositionCallPosition(function *ast.FuncDecl, name string) token.Pos {
	position := token.NoPos
	if function == nil || function.Body == nil {
		return position
	}

	ast.Inspect(function.Body, func(current ast.Node) bool {
		call, ok := current.(*ast.CallExpr)
		if ok && compositionCallName(call.Fun) == name && position == token.NoPos {
			position = call.Pos()
		}

		return position == token.NoPos
	})

	return position
}

// countCallsInNode counts direct or qualified calls with one terminal identifier.
func countCallsInNode(node ast.Node, name string) int {
	count := 0

	ast.Inspect(node, func(current ast.Node) bool {
		call, ok := current.(*ast.CallExpr)
		if ok && compositionCallName(call.Fun) == name {
			count++
		}

		return true
	})

	return count
}

// countSelectorReferences counts exact selector reads rooted at one identifier.
func countSelectorReferences(function *ast.FuncDecl, root string, field string) int {
	count := 0

	ast.Inspect(function.Body, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != field {
			return true
		}

		resolved, rooted := selectorRootIdentifier(selector)
		if rooted && resolved == root {
			count++
		}

		return true
	})

	return count
}

// activeFileSourceReturnsBootstrapBeforeInitialGeneration finds the bootstrap-only return inside the bound closure.
func activeFileSourceReturnsBootstrapBeforeInitialGeneration(function *ast.FuncDecl) bool {
	found := false

	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || compositionCallName(call.Fun) != "BindActiveFileSource" || len(call.Args) != 1 {
			return true
		}

		closure, ok := call.Args[0].(*ast.FuncLit)
		if !ok {
			return false
		}

		ast.Inspect(closure.Body, func(closureNode ast.Node) bool {
			statement, ok := closureNode.(*ast.ReturnStmt)
			if !ok || len(statement.Results) != 1 {
				return true
			}

			selector, ok := statement.Results[0].(*ast.SelectorExpr)
			if !ok {
				return true
			}

			identifier, rooted := selector.X.(*ast.Ident)
			if rooted && identifier.Name == "bootstrap" && selector.Sel.Name == "file" {
				found = true
			}

			return !found
		})

		return false
	})

	return found
}

// productionDecisionServiceConstructorOwners returns every non-test production
// source that constructs a Decision Service.
func productionDecisionServiceConstructorOwners(t *testing.T) []string {
	t.Helper()

	owners := make([]string, 0, 1)

	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return parseErr
		}

		for range countParsedCalls(parsed, "NewDecisionService") {
			owners = append(owners, filepath.Clean(path))
		}

		return nil
	})
	if err != nil {
		t.Fatalf("scan production Decision Service constructors: %v", err)
	}

	return owners
}

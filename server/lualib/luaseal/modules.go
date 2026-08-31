// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package luaseal captures external Lua modules and installs immutable loaders.
package luaseal

import (
	"bytes"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/ast"
	"github.com/yuin/gopher-lua/parse"
)

const (
	maximumModuleCount                = 1024
	maximumModuleSize                 = 4 << 20
	maximumTotalSize                  = 32 << 20
	policyPreloadBaselineRegistryKey  = "_NAUTHILUS_SEALED_POLICY_PRELOADS"
	policyPreparedRegistryKey         = "_NAUTHILUS_SEALED_POLICY_PREPARED"
	policyProfileRegistryKey          = "_NAUTHILUS_SEALED_POLICY_PROFILE"
	processPreloadBaselineRegistryKey = "_NAUTHILUS_SEALED_PROCESS_PRELOADS"
	processPreparedRegistryKey        = "_NAUTHILUS_SEALED_PROCESS_PREPARED"
	policyBaseEnvironmentKey          = "__NAUTH_BASE_ENV"
	policyRequestEnvironmentKey       = "__NAUTH_REQ_ENV"
	policyRequestBindingPrefix        = "__NAUTH_REQ_"
	luaGlobalName                     = "_G"
	luaDoFileName                     = "dofile"
	luaLoadFileName                   = "loadfile"
	luaLoadStringName                 = "loadstring"
	luaDynamicLoaderName              = "dynamic_loader"
	luaRequireName                    = "require"
)

var processLoadedNames = map[string]struct{}{
	luaGlobalName:        {},
	lua.LoadLibName:      {},
	lua.TabLibName:       {},
	lua.StringLibName:    {},
	lua.MathLibName:      {},
	lua.CoroutineLibName: {},
	lua.IoLibName:        {},
	lua.OsLibName:        {},
	lua.DebugLibName:     {},
	lua.ChannelLibName:   {},
}

var disabledRuntimeGlobals = [...]string{
	"collectgarbage",
	luaDoFileName,
	"load",
	luaLoadFileName,
	luaLoadStringName,
	"print",
	"_printregs",
	"module",
	"newproxy",
	"getfenv",
	"setfenv",
	luaDynamicLoaderName,
	lua.IoLibName,
	lua.OsLibName,
	lua.DebugLibName,
	lua.ChannelLibName,
	lua.CoroutineLibName,
}

var generationPreloadNames = map[string]struct{}{
	definitions.LuaModPassword:           {},
	definitions.LuaModMisc:               {},
	definitions.LuaModCache:              {},
	definitions.LuaModPrometheus:         {},
	definitions.LuaModRedis:              {},
	definitions.LuaModContext:            {},
	definitions.LuaModHTTPRequest:        {},
	definitions.LuaModHTTPResponse:       {},
	definitions.LuaModCBOR:               {},
	definitions.LuaModBruteForce:         {},
	definitions.LuaModPsnet:              {},
	definitions.LuaModOpenTelemetry:      {},
	definitions.LuaModPolicy:             {},
	definitions.LuaModI18N:               {},
	definitions.LuaModBackend:            {},
	definitions.LuaBackendResultTypeName: {},
	"time":                               {},
	"json":                               {},
	"glua_crypto":                        {},
}

var generationLoadedNames = map[string]struct{}{
	luaGlobalName:     {},
	lua.LoadLibName:   {},
	lua.TabLibName:    {},
	lua.StringLibName: {},
	lua.MathLibName:   {},
}

var policyOwnedModuleNames = map[string]struct{}{
	definitions.LuaModMail:          {},
	definitions.LuaModLDAP:          {},
	definitions.LuaModSoftWhitelist: {},
	definitions.LuaModDNS:           {},
	"glua_http":                     {},
	"os":                            {},
	"io":                            {},
	"debug":                         {},
	"channel":                       {},
	"coroutine":                     {},
}

var policyForbiddenSymbols = map[string]struct{}{
	luaDynamicLoaderName:                       {},
	luaDoFileName:                              {},
	luaLoadFileName:                            {},
	luaLoadStringName:                          {},
	definitions.LuaFnRedisRegisterRedisPool:    {},
	definitions.LuaFnRedisSet:                  {},
	definitions.LuaFnRedisIncr:                 {},
	definitions.LuaFnRedisDel:                  {},
	definitions.LuaFnRedisRename:               {},
	definitions.LuaFnRedisExpire:               {},
	definitions.LuaFnRedisMSet:                 {},
	definitions.LuaFnRedisRunScript:            {},
	definitions.LuaFnRedisUploadScript:         {},
	definitions.LuaFnRedisPipeline:             {},
	definitions.LuaFnRedisHSet:                 {},
	definitions.LuaFnRedisHDel:                 {},
	definitions.LuaFnRedisHIncrBy:              {},
	definitions.LuaFnRedisHIncrByFloat:         {},
	definitions.LuaFnRedisZAdd:                 {},
	definitions.LuaFnRedisZRem:                 {},
	definitions.LuaFnRedisZRemRangeByScore:     {},
	definitions.LuaFnRedisRedisZRemRangeByRank: {},
	definitions.LuaFnRedisZIncrBy:              {},
	definitions.LuaFnRedisLPush:                {},
	definitions.LuaFnRedisRPush:                {},
	definitions.LuaFnRedisLPop:                 {},
	definitions.LuaFnRedisRPop:                 {},
	definitions.LuaFnRedisPFAdd:                {},
	definitions.LuaFnRedisPFMerge:              {},
	definitions.LuaFnRedisSAdd:                 {},
	definitions.LuaFnRedisSRem:                 {},
	definitions.LuaFnRegisterConnectionTarget:  {},
	definitions.LuaFnCreateSummaryVec:          {},
	definitions.LuaFnCreateCounterVec:          {},
	definitions.LuaFnCreateHistogramVec:        {},
	definitions.LuaFnCreateGaugeVec:            {},
	definitions.LuaFnBfSetCustomTolerations:    {},
	definitions.LuaFnBfSetCustomToleration:     {},
	definitions.LuaFnBfDeleteCustomToleration:  {},
	definitions.LuaFnI18NRegisterCatalog:       {},
	definitions.LuaFnGetBackendServers:         {},
	definitions.LuaFnSelectBackendServer:       {},
	definitions.LuaFnGetSelectedBackendServer:  {},
	definitions.LuaFnCheckBackendConnection:    {},
	definitions.LuaFnCacheSet:                  {},
	definitions.LuaFnCacheDelete:               {},
	definitions.LuaFnCacheUpdate:               {},
	definitions.LuaFnCacheFlush:                {},
	definitions.LuaFnCachePush:                 {},
	definitions.LuaFnCachePopAll:               {},
	definitions.LuaFnWaitRandom:                {},
}

type capturedModule struct {
	source []byte
	name   string
}

// Modules is an immutable snapshot of external Lua package membership and bytes.
type Modules struct {
	entries map[string]capturedModule
}

type sourceVocabulary struct {
	dependencies   map[string]struct{}
	tokens         map[string]struct{}
	dynamicRequire bool
}

// PolicyProfile selects the code-owned modules available to one authn Lua stage.
type PolicyProfile uint8

const (
	// PolicyProfileEnvironment exposes pre-auth facts without response or backend mutation.
	PolicyProfileEnvironment PolicyProfile = iota
	// PolicyProfileSubject additionally exposes request-local backend-result projection.
	PolicyProfileSubject
	// PolicyProfileAction exposes action facts without a live HTTP response.
	PolicyProfileAction
	// PolicyProfileResponseAction additionally exposes the selected synchronous response capability.
	PolicyProfileResponseAction
)

// CaptureSnapshot compiles every module from the candidate's single immutable artifact snapshot.
func CaptureSnapshot(patterns []string, snapshot *config.ArtifactSnapshot) (*Modules, error) {
	modules := &Modules{entries: make(map[string]capturedModule)}

	if snapshot == nil {
		return nil, fmt.Errorf("capture Lua modules: artifact snapshot is unavailable")
	}

	totalSize := 0

	for _, rawPattern := range patterns {
		pattern := strings.TrimSpace(rawPattern)
		if pattern == "" {
			continue
		}

		files, err := snapshot.FilesForLuaPackagePattern(pattern)
		if err != nil {
			return nil, fmt.Errorf("open captured Lua module pattern %q: %w", pattern, err)
		}

		if err = capturePattern(modules, filepath.Clean(pattern), files, &totalSize); err != nil {
			return nil, err
		}
	}

	return modules, nil
}

// ValidateSource rejects mutable APIs and unavailable modules before candidate compilation.
func (m *Modules) ValidateSource(name string, source []byte, profile PolicyProfile) error {
	return m.validateSource(name, source, profile, make(map[string]struct{}))
}

// validateSource validates one immutable source and its exact static captured dependency graph.
func (m *Modules) validateSource(
	name string,
	source []byte,
	profile PolicyProfile,
	visited map[string]struct{},
) error {
	vocabulary, err := parseSourceVocabulary(name, source)
	if err != nil {
		return err
	}

	if err = validateSourceTokens(vocabulary, profile); err != nil {
		return err
	}

	if vocabulary.dynamicRequire {
		return fmt.Errorf("policy Lua profile rejects dynamic module selection")
	}

	return m.validateSourceDependencies(vocabulary.dependencies, profile, visited)
}

// parseSourceVocabulary parses immutable Lua source into its static identifier and dependency vocabulary.
func parseSourceVocabulary(name string, source []byte) (*sourceVocabulary, error) {
	chunk, err := parse.Parse(bytes.NewReader(source), name)
	if err != nil {
		return nil, fmt.Errorf("parse Policy Lua source: %w", err)
	}

	vocabulary := newSourceVocabulary()
	if err = vocabulary.collectStatements(chunk); err != nil {
		return nil, err
	}

	return vocabulary, nil
}

// validateSourceTokens rejects mutable symbols and profile-ineligible generation modules.
func validateSourceTokens(vocabulary *sourceVocabulary, profile PolicyProfile) error {
	for token := range vocabulary.tokens {
		_, forbidden := policyForbiddenSymbols[token]
		if forbidden || policyRuntimeGlobalDisabled(token) {
			return fmt.Errorf("policy Lua profile rejects mutable API %q", token)
		}

		if _, known := policyOwnedModuleNames[token]; known && !generationModuleAllowed(token, profile) {
			return fmt.Errorf("policy Lua profile rejects module %q", token)
		}

		if _, known := generationPreloadNames[token]; known && !generationModuleAllowed(token, profile) {
			return fmt.Errorf("policy Lua profile rejects module %q", token)
		}
	}

	return nil
}

// validateSourceDependencies walks the exact captured dependency graph once per module identity.
func (m *Modules) validateSourceDependencies(
	dependencies map[string]struct{},
	profile PolicyProfile,
	visited map[string]struct{},
) error {
	for dependency := range dependencies {
		if generationModuleAllowed(dependency, profile) {
			continue
		}

		if err := m.validateSourceDependency(dependency, profile, visited); err != nil {
			return err
		}
	}

	return nil
}

// validateSourceDependency resolves and recursively validates one captured module identity.
func (m *Modules) validateSourceDependency(
	dependency string,
	profile PolicyProfile,
	visited map[string]struct{},
) error {
	if m == nil {
		return fmt.Errorf("policy Lua profile rejects unavailable module %q", dependency)
	}

	module, captured := m.entries[dependency]
	if !captured {
		return fmt.Errorf("policy Lua profile rejects unavailable module %q", dependency)
	}

	if _, seen := visited[dependency]; seen {
		return nil
	}

	visited[dependency] = struct{}{}
	if err := m.validateSource("@policy-module/"+module.name, module.source, profile, visited); err != nil {
		return fmt.Errorf("validate captured Lua module %q: %w", dependency, err)
	}

	return nil
}

// policyRuntimeGlobalDisabled keeps source validation aligned with the installed closed base library.
func policyRuntimeGlobalDisabled(name string) bool {
	return slices.Contains(disabledRuntimeGlobals[:], name)
}

// newSourceVocabulary allocates exact source identifiers, string literals, and imports.
func newSourceVocabulary() *sourceVocabulary {
	return &sourceVocabulary{
		dependencies: make(map[string]struct{}),
		tokens:       make(map[string]struct{}),
	}
}

// collectStatements visits all nested statements without evaluating candidate code.
func (v *sourceVocabulary) collectStatements(statements []ast.Stmt) error {
	for _, statement := range statements {
		if err := v.collectStatement(statement); err != nil {
			return err
		}
	}

	return nil
}

// collectStatement records identifiers and expressions from one Lua statement.
func (v *sourceVocabulary) collectStatement(statement ast.Stmt) error {
	switch typed := statement.(type) {
	case *ast.AssignStmt:
		expressions := append(append([]ast.Expr(nil), typed.Lhs...), typed.Rhs...)

		return v.collectExpressions(expressions)
	case *ast.LocalAssignStmt:
		v.collectNames(typed.Names)

		return v.collectExpressions(typed.Exprs)
	case *ast.FuncCallStmt:
		return v.collectExpression(typed.Expr, false)
	case *ast.DoBlockStmt:
		return v.collectStatements(typed.Stmts)
	case *ast.ReturnStmt:
		return v.collectExpressions(typed.Exprs)
	case *ast.LabelStmt:
		v.collectNames([]string{typed.Name})
	case *ast.GotoStmt:
		v.collectNames([]string{typed.Label})
	default:
		return v.collectControlStatement(statement)
	}

	return nil
}

// collectControlStatement records nested control flow and function definitions.
func (v *sourceVocabulary) collectControlStatement(statement ast.Stmt) error {
	switch typed := statement.(type) {
	case *ast.WhileStmt:
		return v.collectConditionThenStatements(typed.Condition, typed.Stmts)
	case *ast.RepeatStmt:
		return v.collectStatementsThenCondition(typed.Stmts, typed.Condition)
	case *ast.IfStmt:
		return v.collectIfStatement(typed)
	case *ast.NumberForStmt:
		return v.collectNumberForStatement(typed)
	case *ast.GenericForStmt:
		return v.collectGenericForStatement(typed)
	case *ast.FuncDefStmt:
		return v.collectFunctionDefinition(typed)
	default:
		return nil
	}
}

// collectConditionThenStatements visits a loop condition before its body.
func (v *sourceVocabulary) collectConditionThenStatements(condition ast.Expr, statements []ast.Stmt) error {
	if err := v.collectExpression(condition, false); err != nil {
		return err
	}

	return v.collectStatements(statements)
}

// collectStatementsThenCondition visits a repeat body before its terminating condition.
func (v *sourceVocabulary) collectStatementsThenCondition(statements []ast.Stmt, condition ast.Expr) error {
	if err := v.collectStatements(statements); err != nil {
		return err
	}

	return v.collectExpression(condition, false)
}

// collectIfStatement visits the condition and both deterministic branches.
func (v *sourceVocabulary) collectIfStatement(statement *ast.IfStmt) error {
	if err := v.collectExpression(statement.Condition, false); err != nil {
		return err
	}

	if err := v.collectStatements(statement.Then); err != nil {
		return err
	}

	return v.collectStatements(statement.Else)
}

// collectNumberForStatement records one numeric loop owner and body.
func (v *sourceVocabulary) collectNumberForStatement(statement *ast.NumberForStmt) error {
	v.collectNames([]string{statement.Name})

	if err := v.collectExpressions([]ast.Expr{statement.Init, statement.Limit, statement.Step}); err != nil {
		return err
	}

	return v.collectStatements(statement.Stmts)
}

// collectGenericForStatement records one generic loop owner and body.
func (v *sourceVocabulary) collectGenericForStatement(statement *ast.GenericForStmt) error {
	v.collectNames(statement.Names)

	if err := v.collectExpressions(statement.Exprs); err != nil {
		return err
	}

	return v.collectStatements(statement.Stmts)
}

// collectFunctionDefinition records the callable name and nested function body.
func (v *sourceVocabulary) collectFunctionDefinition(statement *ast.FuncDefStmt) error {
	if statement.Name != nil {
		v.collectNames([]string{statement.Name.Method})

		if err := v.collectExpressions([]ast.Expr{statement.Name.Func, statement.Name.Receiver}); err != nil {
			return err
		}
	}

	return v.collectExpression(statement.Func, false)
}

// collectExpressions visits a list of optional expressions.
func (v *sourceVocabulary) collectExpressions(expressions []ast.Expr) error {
	for _, expression := range expressions {
		if err := v.collectExpression(expression, false); err != nil {
			return err
		}
	}

	return nil
}

// collectExpression records one expression and rejects non-literal require selection.
func (v *sourceVocabulary) collectExpression(expression ast.Expr, exactRequire bool) error {
	if expression == nil {
		return nil
	}

	switch typed := expression.(type) {
	case *ast.NumberExpr:
		v.collectNames([]string{typed.Value})
	case *ast.StringExpr:
		v.collectNames([]string{typed.Value})
	case *ast.IdentExpr:
		v.collectNames([]string{typed.Value})

		if typed.Value == luaRequireName && !exactRequire {
			v.dynamicRequire = true
		}
	case *ast.AttrGetExpr:
		return v.collectExpressions([]ast.Expr{typed.Object, typed.Key})
	case *ast.TableExpr:
		return v.collectTableExpression(typed)
	case *ast.FuncCallExpr:
		return v.collectFunctionCall(typed)
	default:
		return v.collectCompoundExpression(expression)
	}

	return nil
}

// collectCompoundExpression records operators and nested anonymous function bodies.
func (v *sourceVocabulary) collectCompoundExpression(expression ast.Expr) error {
	switch typed := expression.(type) {
	case *ast.LogicalOpExpr:
		return v.collectExpressions([]ast.Expr{typed.Lhs, typed.Rhs})
	case *ast.RelationalOpExpr:
		return v.collectExpressions([]ast.Expr{typed.Lhs, typed.Rhs})
	case *ast.StringConcatOpExpr:
		return v.collectExpressions([]ast.Expr{typed.Lhs, typed.Rhs})
	case *ast.ArithmeticOpExpr:
		return v.collectExpressions([]ast.Expr{typed.Lhs, typed.Rhs})
	case *ast.UnaryMinusOpExpr:
		return v.collectExpression(typed.Expr, false)
	case *ast.UnaryNotOpExpr:
		return v.collectExpression(typed.Expr, false)
	case *ast.UnaryLenOpExpr:
		return v.collectExpression(typed.Expr, false)
	case *ast.FunctionExpr:
		if typed.ParList != nil {
			v.collectNames(typed.ParList.Names)
		}

		return v.collectStatements(typed.Stmts)
	default:
		return nil
	}
}

// collectTableExpression visits every explicit key and value expression.
func (v *sourceVocabulary) collectTableExpression(expression *ast.TableExpr) error {
	for _, field := range expression.Fields {
		if field == nil {
			continue
		}

		if err := v.collectExpressions([]ast.Expr{field.Key, field.Value}); err != nil {
			return err
		}
	}

	return nil
}

// collectFunctionCall recognizes exact static require calls and visits the remaining call graph.
func (v *sourceVocabulary) collectFunctionCall(expression *ast.FuncCallExpr) error {
	if identifier, ok := expression.Func.(*ast.IdentExpr); ok && identifier.Value == luaRequireName {
		v.collectStaticDependency(expression.Args)

		if err := v.collectExpression(expression.Func, true); err != nil {
			return err
		}
	} else if err := v.collectExpression(expression.Func, false); err != nil {
		return err
	}

	v.collectNames([]string{expression.Method})

	if err := v.collectExpression(expression.Receiver, false); err != nil {
		return err
	}

	return v.collectExpressions(expression.Args)
}

// collectStaticDependency accepts only a single literal module name.
func (v *sourceVocabulary) collectStaticDependency(arguments []ast.Expr) {
	if len(arguments) != 1 {
		v.dynamicRequire = true

		return
	}

	dependency, ok := arguments[0].(*ast.StringExpr)
	if !ok {
		v.dynamicRequire = true

		return
	}

	v.collectNames([]string{dependency.Value})
	v.dependencies[dependency.Value] = struct{}{}
}

// collectNames records identifiers while avoiding empty optional method names.
func (v *sourceVocabulary) collectNames(names []string) {
	for _, name := range names {
		if name != "" {
			v.tokens[name] = struct{}{}
		}
	}
}

// capturePattern adds first-match module entries from one captured deterministic path pattern.
func capturePattern(
	modules *Modules,
	pattern string,
	files []config.ArtifactFile,
	totalSize *int,
) error {
	defer clearArtifactFiles(files)

	if strings.Count(pattern, "?") != 1 {
		return fmt.Errorf("lua module pattern %q must contain exactly one placeholder", pattern)
	}

	marker := strings.IndexByte(pattern, '?')
	prefix := pattern[:marker]
	suffix := pattern[marker+1:]

	for _, file := range files {
		path := filepath.Clean(file.Path)
		if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
			return fmt.Errorf("captured Lua module %q does not match pattern %q", path, pattern)
		}

		middle := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)

		moduleName := moduleNameFromPath(middle)
		if moduleName == "" {
			continue
		}

		if _, exists := modules.entries[moduleName]; exists {
			continue
		}

		if len(modules.entries) >= maximumModuleCount {
			return fmt.Errorf("lua module snapshot exceeds %d entries", maximumModuleCount)
		}

		source := file.Content
		if len(source) == 0 || len(source) > maximumModuleSize || *totalSize+len(source) > maximumTotalSize {
			return fmt.Errorf("lua module %q has an invalid snapshot size", path)
		}

		if _, err := compileModule(path, source); err != nil {
			return fmt.Errorf("compile Lua module %q: %w", path, err)
		}

		*totalSize += len(source)
		modules.entries[moduleName] = capturedModule{
			name: moduleName, source: append([]byte(nil), source...),
		}
	}

	return nil
}

// clearArtifactFiles erases detached snapshot clones after module compilation.
func clearArtifactFiles(files []config.ArtifactFile) {
	for index := range files {
		clear(files[index].Content)
		files[index].Content = nil
	}
}

// moduleNameFromPath converts the package placeholder portion into require vocabulary.
func moduleNameFromPath(value string) string {
	value = strings.Trim(filepath.ToSlash(value), "/")
	if value == "" {
		return ""
	}

	return strings.ReplaceAll(value, "/", ".")
}

// InstallPolicy applies the closed Policy VM library and captured-module authority.
func InstallPolicy(state *lua.LState, modules *Modules) error {
	return InstallPolicyProfile(state, modules, PolicyProfileEnvironment)
}

// InstallPolicyProfile applies the closed Policy VM library for one exact authn stage.
func InstallPolicyProfile(state *lua.LState, modules *Modules, profile PolicyProfile) error {
	if state == nil {
		return fmt.Errorf("lua state is unavailable")
	}

	registry := state.Get(lua.RegistryIndex)
	if state.GetField(registry, policyPreparedRegistryKey) != lua.LTrue {
		return fmt.Errorf("policy Lua state was not prepared before request binding")
	}

	packageTable, loaded, err := installSealedSearchers(state, modules)
	if err != nil {
		return err
	}

	filterGenerationPreloads(state, packageTable, profile)
	filterPolicyRequestEnvironment(state, profile)

	for _, name := range disabledRuntimeGlobals {
		state.SetGlobal(name, lua.LNil)
	}

	state.SetGlobal(policyBaseEnvironmentKey, lua.LNil)
	state.SetField(registry, policyPreparedRegistryKey, lua.LNil)
	state.SetField(registry, policyProfileRegistryKey, lua.LNumber(profile))

	if loaded != nil {
		stale := make([]lua.LValue, 0)

		loaded.ForEach(func(key lua.LValue, _ lua.LValue) {
			name, isString := key.(lua.LString)
			if !isString || generationLoadedNameAllowed(string(name), modules, profile) {
				return
			}

			stale = append(stale, key)
		})

		for _, key := range stale {
			loaded.RawSet(key, lua.LNil)
		}
	}

	return nil
}

// PreparePolicy rebuilds the closed standard library and module caches before request bindings are installed.
func PreparePolicy(state *lua.LState, modules *Modules) error {
	return PreparePolicyProfile(state, modules, PolicyProfileEnvironment)
}

// PreparePolicyProfile rebuilds the exact stage library before request bindings are installed.
func PreparePolicyProfile(state *lua.LState, modules *Modules, profile PolicyProfile) error {
	baseline, err := policyPreloadBaseline(state)
	if err != nil {
		return err
	}

	state.SetTop(0)
	global := state.NewTable()
	state.Replace(lua.GlobalsIndex, global)
	state.Env = global
	openPolicyLibrary(state, lua.OpenPackage)
	openPolicyLibrary(state, lua.OpenBase)
	openPolicyLibrary(state, lua.OpenTable)
	openPolicyLibrary(state, lua.OpenString)
	openPolicyLibrary(state, lua.OpenMath)
	restorePolicyPreloads(state, baseline)
	state.SetGlobal(policyBaseEnvironmentKey, global)

	packageTable, _, err := installSealedSearchers(state, modules)
	if err != nil {
		return err
	}

	filterGenerationPreloads(state, packageTable, profile)
	registry := state.Get(lua.RegistryIndex)
	state.SetField(registry, policyPreparedRegistryKey, lua.LTrue)
	state.SetField(registry, policyProfileRegistryKey, lua.LNumber(profile))

	return nil
}

// policyPreloadBaseline captures the host-installed preload functions before scripts can mutate them.
func policyPreloadBaseline(state *lua.LState) (*lua.LTable, error) {
	if state == nil {
		return nil, fmt.Errorf("lua state is unavailable")
	}

	registry := state.Get(lua.RegistryIndex)
	if baseline, ok := state.GetField(registry, policyPreloadBaselineRegistryKey).(*lua.LTable); ok {
		return baseline, nil
	}

	packageTable, ok := state.GetGlobal(lua.LoadLibName).(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("lua package table is unavailable")
	}

	preloads, ok := state.GetField(packageTable, "preload").(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("lua package preload table is unavailable")
	}

	baseline := state.NewTable()

	preloads.ForEach(func(key lua.LValue, value lua.LValue) {
		name, isString := key.(lua.LString)
		if !isString {
			return
		}

		if _, allowed := generationPreloadNames[string(name)]; allowed {
			baseline.RawSet(key, value)
		}
	})
	state.SetField(registry, policyPreloadBaselineRegistryKey, baseline)

	return baseline, nil
}

// openPolicyLibrary opens one standard library into the newly detached global table.
func openPolicyLibrary(state *lua.LState, loader lua.LGFunction) {
	loader(state)
	state.Pop(1)
}

// restorePolicyPreloads projects the immutable host loader baseline into the new package authority.
func restorePolicyPreloads(state *lua.LState, baseline *lua.LTable) {
	preloads := cloneLuaTable(state, baseline)
	packageTable := state.GetGlobal(lua.LoadLibName)
	state.SetField(packageTable, "preload", preloads)
	state.SetField(state.Get(lua.RegistryIndex), "_PRELOAD", preloads)
}

// filterPolicyRequestEnvironment removes direct module bindings outside the exact Policy profile.
func filterPolicyRequestEnvironment(state *lua.LState, profile PolicyProfile) {
	requestEnv, ok := state.GetGlobal(policyRequestEnvironmentKey).(*lua.LTable)
	if !ok {
		return
	}

	stale := make([]lua.LValue, 0)

	requestEnv.ForEach(func(key lua.LValue, _ lua.LValue) {
		name, isString := key.(lua.LString)
		if !isString {
			stale = append(stale, key)

			return
		}

		if strings.HasPrefix(string(name), policyRequestBindingPrefix) {
			return
		}

		if generationModuleAllowed(string(name), profile) {
			return
		}

		stale = append(stale, key)
	})

	for _, key := range stale {
		requestEnv.RawSet(key, lua.LNil)
	}
}

// PrepareProcess restores the previous trusted host preload set before current host bindings are installed.
func PrepareProcess(state *lua.LState, modules *Modules) error {
	packageTable, loaded, err := installSealedSearchers(state, modules)
	if err != nil {
		return err
	}

	preloads, err := restoreProcessPreloads(state, packageTable)
	if err != nil {
		return err
	}

	clearStaleProcessModules(loaded, preloads, modules)
	disableProcessFilesystemLoaders(state)
	state.SetField(state.Get(lua.RegistryIndex), processPreparedRegistryKey, lua.LTrue)

	return nil
}

// InstallProcess captures current host bindings and seals process module authority for script execution.
func InstallProcess(state *lua.LState, modules *Modules) error {
	if state == nil {
		return fmt.Errorf("lua state is unavailable")
	}

	registry := state.Get(lua.RegistryIndex)
	if state.GetField(registry, processPreparedRegistryKey) != lua.LTrue {
		return fmt.Errorf("process Lua state was not prepared before host binding")
	}

	packageTable, _, err := installSealedSearchers(state, modules)
	if err != nil {
		return err
	}

	preloads, ok := state.GetField(packageTable, "preload").(*lua.LTable)
	if !ok {
		return fmt.Errorf("lua package preload table is unavailable")
	}

	state.SetField(registry, processPreloadBaselineRegistryKey, cloneLuaTable(state, preloads))
	state.SetField(registry, "_PRELOAD", preloads)
	disableProcessFilesystemLoaders(state)
	state.SetField(registry, processPreparedRegistryKey, lua.LNil)

	return nil
}

// disableProcessFilesystemLoaders removes direct filesystem code loading after host binding.
func disableProcessFilesystemLoaders(state *lua.LState) {
	state.SetGlobal(luaDoFileName, lua.LNil)
	state.SetGlobal(luaLoadFileName, lua.LNil)
}

// restoreProcessPreloads resets script mutations while retaining the VM's host-installed preload surface.
func restoreProcessPreloads(state *lua.LState, packageTable *lua.LTable) (*lua.LTable, error) {
	registry := state.Get(lua.RegistryIndex)

	baseline, hasBaseline := state.GetField(registry, processPreloadBaselineRegistryKey).(*lua.LTable)
	if !hasBaseline {
		current, ok := state.GetField(packageTable, "preload").(*lua.LTable)
		if !ok {
			return nil, fmt.Errorf("lua package preload table is unavailable")
		}

		baseline = cloneLuaTable(state, current)
		state.SetField(registry, processPreloadBaselineRegistryKey, baseline)

		return current, nil
	}

	restored := cloneLuaTable(state, baseline)
	state.SetField(packageTable, "preload", restored)
	state.SetField(registry, "_PRELOAD", restored)

	return restored, nil
}

// cloneLuaTable copies one flat host-owned loader table into a detached Lua table.
func cloneLuaTable(state *lua.LState, source *lua.LTable) *lua.LTable {
	cloned := state.NewTable()

	source.ForEach(func(key lua.LValue, value lua.LValue) {
		cloned.RawSet(key, value)
	})

	return cloned
}

// clearStaleProcessModules removes prior script state while preserving core and host preload names.
func clearStaleProcessModules(loaded *lua.LTable, preloads *lua.LTable, modules *Modules) {
	if loaded == nil {
		return
	}

	allowedPreloads := make(map[string]struct{})

	if preloads != nil {
		preloads.ForEach(func(key lua.LValue, _ lua.LValue) {
			if name, ok := key.(lua.LString); ok {
				allowedPreloads[string(name)] = struct{}{}
			}
		})
	}

	stale := make([]lua.LValue, 0)

	loaded.ForEach(func(key lua.LValue, _ lua.LValue) {
		name, ok := key.(lua.LString)
		if !ok {
			stale = append(stale, key)

			return
		}

		if _, allowed := processLoadedNames[string(name)]; allowed {
			return
		}

		stale = append(stale, key)
	})

	for _, key := range stale {
		loaded.RawSet(key, lua.LNil)
	}

	for name := range allowedPreloads {
		loaded.RawSetString(name, lua.LNil)
	}

	if modules != nil {
		for name := range modules.entries {
			loaded.RawSetString(name, lua.LNil)
		}
	}
}

// installSealedSearchers replaces every filesystem searcher with preload and snapshot owners.
func installSealedSearchers(
	state *lua.LState,
	modules *Modules,
) (*lua.LTable, *lua.LTable, error) {
	if state == nil {
		return nil, nil, fmt.Errorf("lua state is unavailable")
	}

	if modules == nil {
		modules = &Modules{entries: make(map[string]capturedModule)}
	}

	packageTable, ok := state.GetGlobal(lua.LoadLibName).(*lua.LTable)
	if !ok {
		return nil, nil, fmt.Errorf("lua package table is unavailable")
	}

	loaders, ok := state.GetField(state.Get(lua.RegistryIndex), "_LOADERS").(*lua.LTable)
	if !ok {
		return nil, nil, fmt.Errorf("lua package loaders are unavailable")
	}

	preload := loaders.RawGetInt(1)
	if preload.Type() != lua.LTFunction {
		return nil, nil, fmt.Errorf("lua preload searcher is unavailable")
	}

	sealedLoaders := state.NewTable()
	sealedLoaders.RawSetInt(1, preload)
	sealedLoaders.RawSetInt(2, state.NewFunction(modules.searcher))
	state.SetField(packageTable, "loaders", sealedLoaders)
	state.SetField(packageTable, "searchers", sealedLoaders)
	state.SetField(state.Get(lua.RegistryIndex), "_LOADERS", sealedLoaders)
	state.SetField(packageTable, "path", lua.LString(""))
	state.SetField(packageTable, "cpath", lua.LString(""))
	state.SetField(packageTable, "loadlib", lua.LNil)
	state.SetField(packageTable, "seeall", lua.LNil)

	loaded, _ := state.GetField(state.Get(lua.RegistryIndex), "_LOADED").(*lua.LTable)
	if loaded != nil {
		for name := range modules.entries {
			state.SetField(loaded, name, lua.LNil)
		}
	}

	return packageTable, loaded, nil
}

// filterGenerationPreloads retains only modules explicitly owned by production code.
func filterGenerationPreloads(state *lua.LState, packageTable *lua.LTable, profile PolicyProfile) {
	preloads, ok := state.GetField(packageTable, "preload").(*lua.LTable)
	if !ok {
		return
	}

	filtered := state.NewTable()

	preloads.ForEach(func(key lua.LValue, value lua.LValue) {
		name, isString := key.(lua.LString)
		if !isString {
			return
		}

		if generationModuleAllowed(string(name), profile) {
			filtered.RawSet(key, value)
		}
	})
	state.SetField(packageTable, "preload", filtered)
	state.SetField(state.Get(lua.RegistryIndex), "_PRELOAD", filtered)
}

// generationLoadedNameAllowed keeps only closed standard, code-owned, and captured modules.
func generationLoadedNameAllowed(name string, modules *Modules, profile PolicyProfile) bool {
	if _, allowed := generationLoadedNames[name]; allowed {
		return true
	}

	if generationModuleAllowed(name, profile) {
		return true
	}

	if modules != nil {
		_, allowed := modules.entries[name]

		return allowed
	}

	return false
}

// generationModuleAllowed applies stage-specific response and backend capabilities to the safe base profile.
func generationModuleAllowed(name string, profile PolicyProfile) bool {
	if _, allowed := generationPreloadNames[name]; !allowed {
		return false
	}

	switch name {
	case definitions.LuaModHTTPResponse:
		return profile == PolicyProfileResponseAction
	case definitions.LuaModBackend, definitions.LuaBackendResultTypeName:
		return profile == PolicyProfileSubject
	default:
		return true
	}
}

// searcher returns a loader compiled only from candidate-captured module bytes.
func (m *Modules) searcher(state *lua.LState) int {
	name := state.CheckString(1)

	module, exists := m.entries[name]
	if !exists {
		state.Push(lua.LString(fmt.Sprintf("no captured Lua module %q", name)))

		return 1
	}

	if profile, ok := activePolicyProfile(state); ok {
		if err := m.ValidateSource("@policy-module/"+module.name, module.source, profile); err != nil {
			state.RaiseError("captured Lua module %q is unavailable: %v", name, err)

			return 0
		}
	}

	prototype, err := compileModule("@policy-module/"+module.name, module.source)
	if err != nil {
		state.RaiseError("captured Lua module %q is invalid: %v", name, err)

		return 0
	}

	state.Push(state.NewFunctionFromProto(prototype))

	return 1
}

// activePolicyProfile returns the exact stage installed for the current request VM.
func activePolicyProfile(state *lua.LState) (PolicyProfile, bool) {
	value, ok := state.GetField(state.Get(lua.RegistryIndex), policyProfileRegistryKey).(lua.LNumber)
	if !ok {
		return 0, false
	}

	return PolicyProfile(value), true
}

// compileModule compiles one detached module copy without accessing the filesystem.
func compileModule(name string, source []byte) (*lua.FunctionProto, error) {
	chunk, err := parse.Parse(bytes.NewReader(source), name)
	if err != nil {
		return nil, err
	}

	return lua.Compile(chunk, name)
}

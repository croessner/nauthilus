// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/lualib"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

const authnLuaRegistryModule = "nauthilus_policy"

// PrepareConfiguredAuthnLuaFacts executes dedicated authn registry scripts in an isolated candidate VM.
func PrepareConfiguredAuthnLuaFacts(
	ctx context.Context,
	configured policyconfig.PolicyConfig,
	artifacts LuaArtifactReader,
) ([]registry.AuthnLuaFactDeclaration, error) {
	ctx = normalizeConfiguredPreparationContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	document := policyconfig.Normalize(policyconfig.Document{Policy: configured})
	if err := policyconfig.Validate(document); err != nil {
		return nil, configuredPreparationError(ctx, "authn Lua registry configuration was rejected")
	}

	configured = document.Policy
	for namespace, namespaceConfig := range configured.Namespaces {
		if namespace != policy.AuthnNamespace && len(namespaceConfig.SchemaContributions.Lua.RegistryScripts) > 0 {
			return nil, configuredPreparationError(ctx, "Lua registry scripts are restricted to authn")
		}
	}

	authn, exists := configured.Namespaces[policy.AuthnNamespace]
	if !exists || len(authn.SchemaContributions.Lua.RegistryScripts) == 0 {
		return []registry.AuthnLuaFactDeclaration{}, nil
	}

	collector := newAuthnLuaFactCollector()
	for _, scriptPath := range authn.SchemaContributions.Lua.RegistryScripts {
		if err := collector.execute(ctx, artifacts, scriptPath); err != nil {
			return nil, configuredPreparationError(ctx, "configured authn Lua registry script was rejected")
		}
	}

	return collector.declarations(), nil
}

type authnLuaFactCollector struct {
	values []registry.AuthnLuaFactDeclaration
	seen   map[string]struct{}
}

// newAuthnLuaFactCollector allocates one candidate-local declaration authority.
func newAuthnLuaFactCollector() *authnLuaFactCollector {
	return &authnLuaFactCollector{seen: make(map[string]struct{})}
}

// execute runs one registry script with only the declaration API exposed.
func (c *authnLuaFactCollector) execute(
	ctx context.Context,
	artifacts LuaArtifactReader,
	scriptPath string,
) error {
	source, err := readCapturedLuaArtifact(artifacts, scriptPath, maximumAuthnLuaSourceSize)
	if err != nil {
		return err
	}
	defer clear(source)

	chunk, err := parse.Parse(bytes.NewReader(source), scriptPath)
	if err != nil {
		return err
	}

	prototype, err := lua.Compile(chunk, scriptPath)
	if err != nil {
		return err
	}

	state := newAuthnLuaRegistryState()
	defer state.Close()

	state.SetContext(ctx)
	module := state.SetFuncs(state.NewTable(), map[string]lua.LGFunction{
		"register_attribute": c.register,
	})
	state.SetGlobal(authnLuaRegistryModule, module)

	return lualib.DoCompiledFile(state, prototype)
}

// newAuthnLuaRegistryState exposes only pure standard helpers and the dedicated declaration API.
func newAuthnLuaRegistryState() *lua.LState {
	state := lua.NewState(lua.Options{SkipOpenLibs: true})
	for _, open := range []lua.LGFunction{lua.OpenBase, lua.OpenTable, lua.OpenString, lua.OpenMath} {
		open(state)
		state.Pop(1)
	}

	for _, name := range []string{
		"collectgarbage", "dofile", "load", "loadfile", "loadstring", "print", "_printregs",
		"module", "newproxy", "getfenv", "setfenv",
	} {
		state.SetGlobal(name, lua.LNil)
	}

	state.SetGlobal("require", state.NewFunction(authnLuaRegistryRequire))

	return state
}

// authnLuaRegistryRequire resolves only pure code-owned standard libraries.
func authnLuaRegistryRequire(state *lua.LState) int {
	name := state.CheckString(1)
	switch name {
	case lua.TabLibName, lua.StringLibName, lua.MathLibName:
		state.Push(state.GetGlobal(name))

		return 1
	default:
		state.RaiseError("registry module %q is unavailable", name)

		return 0
	}
}

// register validates one Lua declaration before adding it to the candidate.
func (c *authnLuaFactCollector) register(state *lua.LState) int {
	declaration, err := parseAuthnLuaFactDeclaration(state.CheckTable(1))
	if err != nil {
		state.RaiseError("%s", err.Error())

		return 0
	}

	if _, exists := c.seen[declaration.ID()]; exists {
		state.RaiseError("duplicate authn Lua fact %q", declaration.ID())

		return 0
	}

	c.seen[declaration.ID()] = struct{}{}
	c.values = append(c.values, declaration)

	return 0
}

// declarations returns a deeply detached registration-order snapshot.
func (c *authnLuaFactCollector) declarations() []registry.AuthnLuaFactDeclaration {
	result := make([]registry.AuthnLuaFactDeclaration, len(c.values))
	for index, declaration := range c.values {
		result[index] = declaration.Clone()
	}

	return result
}

// parseAuthnLuaFactDeclaration converts one strict registry table into immutable candidate material.
func parseAuthnLuaFactDeclaration(table *lua.LTable) (registry.AuthnLuaFactDeclaration, error) {
	declaredType, kind, err := parseAuthnLuaFactType(luaRegistryRequiredString(table, "type"))
	if err != nil {
		return registry.AuthnLuaFactDeclaration{}, err
	}

	category, err := parseAuthnLuaFactCategory(luaRegistryRequiredString(table, "category"))
	if err != nil {
		return registry.AuthnLuaFactDeclaration{}, err
	}

	details, err := parseAuthnLuaFactDetails(table.RawGetString("details"))
	if err != nil {
		return registry.AuthnLuaFactDeclaration{}, err
	}

	return registry.NewAuthnLuaFactDeclaration(registry.AuthnLuaFactDeclarationInput{
		Details: details, ID: luaRegistryRequiredString(table, "id"),
		Description: luaRegistryOptionalString(table, "description"),
		Stage:       luaRegistryRequiredString(table, "stage"), Actions: luaRegistryStringList(table.RawGetString("operations")),
		Category: category, Kind: kind, DeclaredType: declaredType,
	})
}

// parseAuthnLuaFactType maps the closed registry vocabulary without coercion.
func parseAuthnLuaFactType(input string) (registry.AttributeType, decision.ValueKind, error) {
	declared := registry.AttributeType(input)

	switch declared {
	case registry.AttributeTypeBool:
		return declared, decision.ValueKindBoolean, nil
	case registry.AttributeTypeString, registry.AttributeTypeIP, registry.AttributeTypeCIDR:
		return declared, decision.ValueKindString, nil
	case registry.AttributeTypeStringList:
		return declared, decision.ValueKindStrings, nil
	case registry.AttributeTypeNumber:
		return declared, decision.ValueKindDouble, nil
	case registry.AttributeTypeDateTime:
		return declared, decision.ValueKindTimestamp, nil
	default:
		return "", "", fmt.Errorf("unsupported authn Lua fact type %q", input)
	}
}

// parseAuthnLuaFactCategory maps the closed XACML-style category vocabulary.
func parseAuthnLuaFactCategory(input string) (decision.FactCategory, error) {
	category := decision.FactCategory(input)
	if !category.IsValid() {
		return "", fmt.Errorf("unsupported authn Lua fact category %q", input)
	}

	return category, nil
}

// parseAuthnLuaFactDetails converts shorthand and expanded detail declarations.
func parseAuthnLuaFactDetails(value lua.LValue) (map[string]registry.DetailDefinition, error) {
	if value == lua.LNil {
		return nil, nil
	}

	table, ok := value.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("authn Lua fact details must be a table")
	}

	result := make(map[string]registry.DetailDefinition, table.Len())

	var parseErr error

	table.ForEach(func(key lua.LValue, item lua.LValue) {
		if parseErr != nil {
			return
		}

		name := strings.TrimSpace(key.String())
		if name == "" {
			parseErr = fmt.Errorf("authn Lua fact detail name is required")

			return
		}

		result[name], parseErr = parseAuthnLuaFactDetail(name, item)
	})

	return result, parseErr
}

// parseAuthnLuaFactDetail validates one detail's type and optional disclosure metadata.
func parseAuthnLuaFactDetail(name string, value lua.LValue) (registry.DetailDefinition, error) {
	if shorthand, ok := value.(lua.LString); ok {
		declared, _, err := parseAuthnLuaFactType(string(shorthand))

		return registry.DetailDefinition{Type: declared}, err
	}

	table, ok := value.(*lua.LTable)
	if !ok {
		return registry.DetailDefinition{}, fmt.Errorf("authn Lua fact detail %q must be a type or table", name)
	}

	declared, _, err := parseAuthnLuaFactType(luaRegistryRequiredString(table, "type"))
	if err != nil {
		return registry.DetailDefinition{}, err
	}

	detail := registry.DetailDefinition{
		Type: declared, Sensitivity: luaRegistryOptionalString(table, "sensitivity"),
		Purpose: luaRegistryOptionalString(table, "purpose"), MaxLength: luaRegistryOptionalInt(table, "max_length"),
	}
	if err = validateAuthnLuaFactDetail(name, detail); err != nil {
		return registry.DetailDefinition{}, err
	}

	return detail, nil
}

// validateAuthnLuaFactDetail keeps response disclosure metadata closed and bounded.
func validateAuthnLuaFactDetail(name string, detail registry.DetailDefinition) error {
	if detail.Sensitivity != "" && detail.Sensitivity != registry.DetailSensitivityPublic &&
		detail.Sensitivity != registry.DetailSensitivityInternal && detail.Sensitivity != registry.DetailSensitivitySecret {
		return fmt.Errorf("authn Lua fact detail %q has invalid sensitivity", name)
	}

	if detail.Purpose != "" && detail.Purpose != registry.DetailPurposeResponseMessage {
		return fmt.Errorf("authn Lua fact detail %q has invalid purpose", name)
	}

	if detail.Purpose == registry.DetailPurposeResponseMessage &&
		(detail.Type != registry.AttributeTypeString || detail.Sensitivity != registry.DetailSensitivityPublic) {
		return fmt.Errorf("authn Lua fact detail %q response_message must be a public string", name)
	}

	return nil
}

// luaRegistryRequiredString reads one nonblank exact string field.
func luaRegistryRequiredString(table *lua.LTable, name string) string {
	value := strings.TrimSpace(luaRegistryOptionalString(table, name))
	if value == "" {
		return ""
	}

	return value
}

// luaRegistryOptionalString reads one optional exact string without coercion.
func luaRegistryOptionalString(table *lua.LTable, name string) string {
	value := table.RawGetString(name)
	if value == lua.LNil {
		return ""
	}

	text, ok := value.(lua.LString)
	if !ok {
		return ""
	}

	return string(text)
}

// luaRegistryOptionalInt reads one optional finite integer field.
func luaRegistryOptionalInt(table *lua.LTable, name string) int {
	value := table.RawGetString(name)
	if number, ok := value.(lua.LNumber); ok {
		return int(number)
	}

	return 0
}

// luaRegistryStringList reads one dense ordered string table.
func luaRegistryStringList(value lua.LValue) []string {
	table, ok := value.(*lua.LTable)
	if !ok {
		return nil
	}

	result := make([]string, 0, table.Len())
	for index := 1; index <= table.Len(); index++ {
		item, ok := table.RawGetInt(index).(lua.LString)
		if !ok {
			return nil
		}

		result = append(result, strings.TrimSpace(string(item)))
	}

	return result
}

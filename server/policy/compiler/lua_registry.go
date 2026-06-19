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

package compiler

import (
	"context"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"

	lua "github.com/yuin/gopher-lua"
)

func runLuaRegistryScripts(
	ctx context.Context,
	scripts []string,
	registry *policyregistry.AttributeRegistry,
) error {
	for index, scriptPath := range scripts {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := runLuaRegistryScript(scriptPath, registry); err != nil {
			return configPathError(indexedPath("auth.policy.registry_scripts", index), err.Error())
		}
	}

	return nil
}

func runLuaRegistryScript(scriptPath string, registry *policyregistry.AttributeRegistry) error {
	L := lua.NewState()
	defer L.Close()

	module := L.NewTable()
	L.SetField(module, "register_attribute", L.NewFunction(func(L *lua.LState) int {
		table := L.CheckTable(1)

		definition, err := luaAttributeDefinition(table)
		if err != nil {
			L.RaiseError("%s", err.Error())

			return 0
		}

		if err := registry.Register(definition); err != nil {
			L.RaiseError("%s", err.Error())

			return 0
		}

		return 0
	}))
	L.SetGlobal("nauthilus_policy", module)

	if err := L.DoFile(scriptPath); err != nil {
		return err
	}

	return nil
}

func luaAttributeDefinition(table *lua.LTable) (policyregistry.AttributeDefinition, error) {
	id := strings.TrimSpace(luaStringField(table, "id"))
	if id == "" {
		return policyregistry.AttributeDefinition{}, fmt.Errorf("attribute id must not be empty")
	}

	stage := policy.Stage(luaStringField(table, "stage"))
	if !stageValid(stage) {
		return policyregistry.AttributeDefinition{}, fmt.Errorf("attribute %s has invalid stage", id)
	}

	operations, err := luaOperations(table.RawGetString("operations"))
	if err != nil {
		return policyregistry.AttributeDefinition{}, fmt.Errorf("attribute %s has invalid operations: %w", id, err)
	}

	valueType, err := luaAttributeType(table.RawGetString("type"))
	if err != nil {
		return policyregistry.AttributeDefinition{}, fmt.Errorf("attribute %s has invalid type: %w", id, err)
	}

	category, err := luaAttributeCategory(table.RawGetString("category"))
	if err != nil {
		return policyregistry.AttributeDefinition{}, fmt.Errorf("attribute %s has invalid category: %w", id, err)
	}

	details, err := luaDetails(table.RawGetString("details"))
	if err != nil {
		return policyregistry.AttributeDefinition{}, fmt.Errorf("attribute %s has invalid details: %w", id, err)
	}

	return policyregistry.AttributeDefinition{
		ID:          id,
		Description: luaStringField(table, "description"),
		Stage:       stage,
		Operations:  operations,
		Category:    category,
		Type:        valueType,
		Source:      policyregistry.SourceLua,
		Details:     details,
	}, nil
}

func luaStringField(table *lua.LTable, name string) string {
	value := table.RawGetString(name)
	if stringValue, ok := value.(lua.LString); ok {
		return string(stringValue)
	}

	return ""
}

func luaOperations(value lua.LValue) ([]policy.Operation, error) {
	if value == lua.LNil {
		return []policy.Operation{policy.OperationAuthenticate}, nil
	}

	table, ok := value.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("must be a table")
	}

	if table.Len() == 0 {
		return nil, fmt.Errorf("must not be empty")
	}

	operations := make([]policy.Operation, 0, table.Len())

	seen := make(map[policy.Operation]struct{}, table.Len())
	for index := 1; index <= table.Len(); index++ {
		operation := policy.Operation(table.RawGetInt(index).String())
		if !operationValid(operation) {
			return nil, fmt.Errorf("unknown operation %q", operation)
		}

		if _, exists := seen[operation]; exists {
			return nil, fmt.Errorf("duplicate operation %q", operation)
		}

		seen[operation] = struct{}{}
		operations = append(operations, operation)
	}

	return operations, nil
}

func luaAttributeType(value lua.LValue) (policyregistry.AttributeType, error) {
	if value == lua.LNil {
		return "", fmt.Errorf("must not be empty")
	}

	valueType := policyregistry.AttributeType(value.String())
	if !attributeTypeValid(valueType) {
		return "", fmt.Errorf("unknown type %q", valueType)
	}

	return valueType, nil
}

func luaAttributeCategory(value lua.LValue) (policyregistry.AttributeCategory, error) {
	if value == lua.LNil {
		return "", fmt.Errorf("must not be empty")
	}

	category := policyregistry.AttributeCategory(value.String())
	if !attributeCategoryValid(category) {
		return "", fmt.Errorf("unknown category %q", category)
	}

	return category, nil
}

func attributeCategoryValid(category policyregistry.AttributeCategory) bool {
	switch category {
	case policyregistry.AttributeCategoryEnvironment,
		policyregistry.AttributeCategorySubject,
		policyregistry.AttributeCategoryResource:
		return true
	default:
		return false
	}
}

func attributeTypeValid(valueType policyregistry.AttributeType) bool {
	switch valueType {
	case policyregistry.AttributeTypeBool,
		policyregistry.AttributeTypeString,
		policyregistry.AttributeTypeStringList,
		policyregistry.AttributeTypeNumber,
		policyregistry.AttributeTypeIP,
		policyregistry.AttributeTypeCIDR,
		policyregistry.AttributeTypeDateTime:
		return true
	default:
		return false
	}
}

func luaDetails(value lua.LValue) (map[string]policyregistry.DetailDefinition, error) {
	if value == lua.LNil {
		return nil, nil
	}

	table, ok := value.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("must be a table")
	}

	details := make(map[string]policyregistry.DetailDefinition)

	var parseErr error

	table.ForEach(func(key lua.LValue, value lua.LValue) {
		if parseErr != nil {
			return
		}

		name := key.String()

		detail, err := luaDetailDefinition(value)
		if err != nil {
			parseErr = fmt.Errorf("%s: %w", name, err)

			return
		}

		details[name] = detail
	})

	if parseErr != nil {
		return nil, parseErr
	}

	return details, nil
}

func luaDetailDefinition(value lua.LValue) (policyregistry.DetailDefinition, error) {
	if stringValue, ok := value.(lua.LString); ok {
		valueType := policyregistry.AttributeType(string(stringValue))
		if !attributeTypeValid(valueType) {
			return policyregistry.DetailDefinition{}, fmt.Errorf("unknown type %q", valueType)
		}

		return policyregistry.DetailDefinition{Type: valueType, Sensitivity: policyregistry.DetailSensitivityInternal}, nil
	}

	table, ok := value.(*lua.LTable)
	if !ok {
		return policyregistry.DetailDefinition{}, fmt.Errorf("must be a string or table")
	}

	valueType, err := luaAttributeType(table.RawGetString("type"))
	if err != nil {
		return policyregistry.DetailDefinition{}, err
	}

	return policyregistry.DetailDefinition{
		Type:        valueType,
		Sensitivity: defaultedLuaStringField(table, "sensitivity", policyregistry.DetailSensitivityInternal),
		Purpose:     luaStringField(table, "purpose"),
		MaxLength:   luaIntField(table, "max_length"),
	}, nil
}

func defaultedLuaStringField(table *lua.LTable, name string, fallback string) string {
	value := luaStringField(table, name)
	if value == "" {
		return fallback
	}

	return value
}

func luaIntField(table *lua.LTable, name string) int {
	value := table.RawGetString(name)
	if numberValue, ok := value.(lua.LNumber); ok {
		return int(numberValue)
	}

	return 0
}

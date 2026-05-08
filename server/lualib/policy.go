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

package lualib

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	policyregistry "github.com/croessner/nauthilus/server/policy/registry"
	"github.com/croessner/nauthilus/server/policy/report"

	lua "github.com/yuin/gopher-lua"
)

// PolicyEmitter records Lua-owned attributes into the request-local policy context.
type PolicyEmitter struct {
	ctx   *policycollection.DecisionContext
	stage policy.Stage
}

// LoaderModPolicy returns the request-bound nauthilus_policy module.
func LoaderModPolicy(ctx *policycollection.DecisionContext, stage policy.Stage) lua.LGFunction {
	return func(L *lua.LState) int {
		emitter := &PolicyEmitter{ctx: ctx, stage: stage}
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnPolicyEmitAttribute: emitter.emitAttribute,
		})
		L.Push(mod)

		return 1
	}
}

// LoaderPolicyStateless returns a placeholder for Lua runtimes without a policy context.
func LoaderPolicyStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnPolicyEmitAttribute: func(L *lua.LState) int {
				L.RaiseError("nauthilus_policy emitter is not available in this Lua runtime")

				return 0
			},
		})
		L.Push(mod)

		return 1
	}
}

func (e *PolicyEmitter) emitAttribute(L *lua.LState) int {
	if e == nil || e.ctx == nil {
		L.RaiseError("nauthilus_policy emitter is not available in this Lua runtime")

		return 0
	}

	table := L.CheckTable(1)
	id := strings.TrimSpace(luaPolicyStringField(table, "id"))
	if id == "" {
		L.ArgError(1, "id must be a non-empty string")

		return 0
	}

	definition, operation, ok := e.validateEmissionTarget(L, id)
	if !ok {
		return 0
	}

	value, err := luaPolicyTypedValue(table.RawGetString("value"), definition.Type, id)
	if err != nil {
		L.RaiseError("%s", err.Error())

		return 0
	}

	details, err := luaPolicyDetails(table.RawGetString("details"), definition.Details, id)
	if err != nil {
		L.RaiseError("%s", err.Error())

		return 0
	}

	e.ctx.RecordAttribute(policycollection.AttributeValue{
		ID:        id,
		Stage:     definition.Stage,
		Operation: operation,
		Value:     value,
		Details:   details,
	})

	return 0
}

func (e *PolicyEmitter) validateEmissionTarget(
	L *lua.LState,
	id string,
) (policyregistry.AttributeDefinition, policy.Operation, bool) {
	definition, ok := e.lookupAttribute(id)
	if !ok {
		L.RaiseError("policy attribute %q is not registered", id)

		return policyregistry.AttributeDefinition{}, "", false
	}

	if definition.Source != policyregistry.SourceLua {
		L.RaiseError("policy attribute %q is not Lua-owned", id)

		return policyregistry.AttributeDefinition{}, "", false
	}

	if definition.Stage != e.stage {
		L.RaiseError("policy attribute %q cannot be emitted from stage %q", id, e.stage)

		return policyregistry.AttributeDefinition{}, "", false
	}

	operation := e.ctx.Report().Operation
	if !policyOperationAllowed(operation, definition.Operations) {
		L.RaiseError("policy attribute %q cannot be emitted for operation %q", id, operation)

		return policyregistry.AttributeDefinition{}, "", false
	}

	return definition, operation, true
}

func (e *PolicyEmitter) lookupAttribute(id string) (policyregistry.AttributeDefinition, bool) {
	snapshot := e.ctx.Snapshot()
	if snapshot == nil || snapshot.AttributeRegistry == nil {
		return policyregistry.AttributeDefinition{}, false
	}

	definition, ok := snapshot.AttributeRegistry[id]

	return definition, ok
}

func policyOperationAllowed(operation policy.Operation, operations []policy.Operation) bool {
	if len(operations) == 0 {
		return true
	}

	return slices.Contains(operations, operation)
}

func luaPolicyStringField(table *lua.LTable, name string) string {
	if value, ok := table.RawGetString(name).(lua.LString); ok {
		return string(value)
	}

	return ""
}

func luaPolicyTypedValue(value lua.LValue, valueType policyregistry.AttributeType, id string) (any, error) {
	switch valueType {
	case policyregistry.AttributeTypeBool:
		boolValue, ok := value.(lua.LBool)
		if !ok {
			return nil, fmt.Errorf("policy attribute %q value must be a boolean", id)
		}

		return bool(boolValue), nil
	case policyregistry.AttributeTypeString:
		stringValue, ok := value.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("policy attribute %q value must be a string", id)
		}

		return string(stringValue), nil
	case policyregistry.AttributeTypeStringList:
		return luaPolicyStringList(value, id)
	case policyregistry.AttributeTypeNumber:
		numberValue, ok := value.(lua.LNumber)
		if !ok {
			return nil, fmt.Errorf("policy attribute %q value must be a number", id)
		}

		return float64(numberValue), nil
	case policyregistry.AttributeTypeIP:
		return luaPolicyIP(value, id)
	case policyregistry.AttributeTypeCIDR:
		return luaPolicyCIDR(value, id)
	case policyregistry.AttributeTypeDateTime:
		return luaPolicyDateTime(value, id)
	default:
		return nil, fmt.Errorf("policy attribute %q has unsupported type %q", id, valueType)
	}
}

func luaPolicyStringList(value lua.LValue, id string) ([]string, error) {
	table, ok := value.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("policy attribute %q value must be a string list", id)
	}

	result := make([]string, 0, table.Len())
	for index := 1; index <= table.Len(); index++ {
		item, ok := table.RawGetInt(index).(lua.LString)
		if !ok {
			return nil, fmt.Errorf("policy attribute %q value[%d] must be a string", id, index)
		}

		result = append(result, string(item))
	}

	return result, nil
}

func luaPolicyIP(value lua.LValue, id string) (netip.Addr, error) {
	stringValue, ok := value.(lua.LString)
	if !ok {
		return netip.Addr{}, fmt.Errorf("policy attribute %q value must be an IP address string", id)
	}

	addr, err := netip.ParseAddr(string(stringValue))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("policy attribute %q value must be an IP address", id)
	}

	return addr, nil
}

func luaPolicyCIDR(value lua.LValue, id string) (netip.Prefix, error) {
	stringValue, ok := value.(lua.LString)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("policy attribute %q value must be a CIDR string", id)
	}

	prefix, err := netip.ParsePrefix(string(stringValue))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("policy attribute %q value must be a CIDR", id)
	}

	return prefix, nil
}

func luaPolicyDateTime(value lua.LValue, id string) (time.Time, error) {
	stringValue, ok := value.(lua.LString)
	if !ok {
		return time.Time{}, fmt.Errorf("policy attribute %q value must be an RFC3339 timestamp string", id)
	}

	parsed, err := time.Parse(time.RFC3339, string(stringValue))
	if err != nil {
		return time.Time{}, fmt.Errorf("policy attribute %q value must be an RFC3339 timestamp", id)
	}

	return parsed, nil
}

func luaPolicyDetails(
	value lua.LValue,
	definitions map[string]policyregistry.DetailDefinition,
	id string,
) (map[string]policycollection.DetailValue, error) {
	if value == lua.LNil {
		return nil, nil
	}

	table, ok := value.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("policy attribute %q details must be a table", id)
	}

	details := make(map[string]policycollection.DetailValue)
	var parseErr error
	table.ForEach(func(key lua.LValue, detailValue lua.LValue) {
		if parseErr != nil {
			return
		}

		name := strings.TrimSpace(key.String())
		definition, ok := definitions[name]
		if !ok {
			parseErr = fmt.Errorf("policy attribute %q detail %q is not registered", id, name)

			return
		}

		converted, err := luaPolicyTypedValue(detailValue, definition.Type, id+"."+name)
		if err != nil {
			parseErr = err

			return
		}

		if err := luaPolicyValidateDetailLength(converted, definition, id, name); err != nil {
			parseErr = err

			return
		}

		details[name] = policycollection.DetailValue{
			Value:       converted,
			Sensitivity: report.Sensitivity(definition.Sensitivity),
			Purpose:     report.DetailPurpose(definition.Purpose),
		}
	})
	if parseErr != nil {
		return nil, parseErr
	}

	return details, nil
}

func luaPolicyValidateDetailLength(value any, definition policyregistry.DetailDefinition, id string, name string) error {
	if definition.MaxLength <= 0 {
		return nil
	}

	stringValue, ok := value.(string)
	if !ok {
		return nil
	}

	if len(stringValue) > definition.MaxLength {
		return fmt.Errorf("policy attribute %q detail %q exceeds max_length %d", id, name, definition.MaxLength)
	}

	return nil
}

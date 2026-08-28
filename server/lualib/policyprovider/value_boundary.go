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

package policyprovider

import (
	"encoding/base64"
	"sort"
	"strconv"
	"time"

	lua "github.com/yuin/gopher-lua"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

const maximumCallbackListItems = 4096

// buildFactRequestTable constructs the closed fact callback request shape.
func buildFactRequestTable(state *lua.LState, request FactRequest) lua.LValue {
	result := buildCommonRequestTable(state, request.Facts, request.Target, request.Caller)

	return result
}

// buildEffectRequestTable constructs the closed selected-effect callback request shape.
func buildEffectRequestTable(state *lua.LState, request EffectRequest) lua.LValue {
	result := buildCommonRequestTable(state, request.Facts, request.Target, request.Caller)
	result.RawSetString("effect", lua.LString(request.Effect))

	parameters := state.NewTable()
	for _, parameter := range request.Parameters {
		entry := state.NewTable()
		entry.RawSetString("name", lua.LString(parameter.Name))
		entry.RawSetString("value", buildTypedValueTable(state, parameter.Value))
		parameters.Append(entry)
	}

	result.RawSetString("parameters", parameters)

	return result
}

// buildCommonRequestTable constructs shared immutable-by-contract caller, target, and fact views.
func buildCommonRequestTable(
	state *lua.LState,
	facts []FactView,
	target TargetSelector,
	caller CallerView,
) *lua.LTable {
	result := state.NewTable()
	targetTable := state.NewTable()
	targetTable.RawSetString("namespace", lua.LString(target.Namespace))
	targetTable.RawSetString("action", lua.LString(target.Action))
	result.RawSetString("target", targetTable)

	callerTable := state.NewTable()
	callerTable.RawSetString("principal", lua.LString(caller.Principal))
	callerTable.RawSetString("client_id", lua.LString(caller.ClientID))
	callerTable.RawSetString("authentication_kind", lua.LString(caller.AuthenticationKind))

	scopes := state.NewTable()
	for _, scope := range caller.Scopes {
		scopes.Append(lua.LString(scope))
	}

	callerTable.RawSetString("scopes", scopes)
	result.RawSetString("caller", callerTable)

	factTable := state.NewTable()
	for _, fact := range facts {
		entry := state.NewTable()
		entry.RawSetString("id", lua.LString(fact.ID))
		entry.RawSetString("category", lua.LString(fact.Category))
		entry.RawSetString("value", buildTypedValueTable(state, fact.Value))
		factTable.Append(entry)
	}

	result.RawSetString("facts", factTable)

	return result
}

// buildTypedValueTable preserves exact strict kinds across Lua's number boundary.
func buildTypedValueTable(state *lua.LState, value decision.Value) *lua.LTable {
	result := state.NewTable()
	result.RawSetString("kind", lua.LString(value.Kind()))

	switch value.Kind() {
	case decision.ValueKindString:
		member, _ := value.StringValue()
		result.RawSetString("value", lua.LString(member))
	case decision.ValueKindBoolean:
		member, _ := value.Boolean()
		result.RawSetString("value", lua.LBool(member))
	case decision.ValueKindInteger:
		member, _ := value.Integer()
		result.RawSetString("value", lua.LString(strconv.FormatInt(member, 10)))
	case decision.ValueKindDouble:
		member, _ := value.Double()
		result.RawSetString("value", lua.LNumber(member))
	case decision.ValueKindStrings:
		members, _ := value.Strings()
		table := state.NewTable()

		for _, member := range members {
			table.Append(lua.LString(member))
		}

		result.RawSetString("value", table)
	case decision.ValueKindBytes:
		member, _ := value.Bytes()
		result.RawSetString("value", lua.LString(base64.StdEncoding.EncodeToString(member)))
	case decision.ValueKindTimestamp:
		member, _ := value.Timestamp()
		result.RawSetString("value", lua.LString(member.UTC().Format(time.RFC3339Nano)))
	case decision.ValueKindRecords:
		member, _ := value.Records()
		result.RawSetString("value", buildRecordListTable(state, member))
	}

	return result
}

// buildRecordListTable preserves record and field order through dense Lua arrays.
func buildRecordListTable(state *lua.LState, input decision.RecordList) *lua.LTable {
	result := state.NewTable()
	for _, record := range input.Records() {
		recordTable := state.NewTable()
		fields := state.NewTable()

		for _, field := range record.Fields() {
			fieldTable := state.NewTable()
			fieldTable.RawSetString("name", lua.LString(field.Name()))
			fieldTable.RawSetString("value", buildTypedValueTable(state, field.Value().Value()))
			fields.Append(fieldTable)
		}

		recordTable.RawSetString("fields", fields)
		result.Append(recordTable)
	}

	return result
}

// parseFactResult accepts only declared local values or one closed error class.
func parseFactResult(value lua.LValue, descriptor FactProviderDescriptor) (FactResult, error) {
	table, err := closedTable(value, "facts", "error_class")
	if err != nil {
		return FactResult{}, err
	}

	errorClass, err := parseOptionalErrorClass(table.RawGetString("error_class"))
	if err != nil {
		return FactResult{}, err
	}

	result := FactResult{ErrorClass: errorClass}

	result.Facts, err = parseFactValues(table.RawGetString("facts"), len(descriptor.Outputs))
	if err != nil {
		return FactResult{}, err
	}

	sort.Slice(result.Facts, func(left int, right int) bool {
		return result.Facts[left].Name < result.Facts[right].Name
	})

	if err = descriptor.ValidateResult(result); err != nil {
		return FactResult{}, ErrInvalidResult
	}

	return result, nil
}

// parseFactValues extracts a bounded dense list of local names and strict values.
func parseFactValues(value lua.LValue, maximum int) ([]FactValue, error) {
	if value == lua.LNil {
		return nil, nil
	}

	entries, err := luaArray(value, maximum)
	if err != nil {
		return nil, err
	}

	result := make([]FactValue, 0, len(entries))
	totalBytes := 0

	for _, entryValue := range entries {
		fact, valueBytes, entryErr := parseFactValue(entryValue)
		if entryErr != nil || len(fact.Name)+valueBytes > maximumCallbackInputBytes-totalBytes {
			return nil, ErrInvalidResult
		}

		result = append(result, fact)
		totalBytes += len(fact.Name) + valueBytes
	}

	return result, nil
}

// parseFactValue extracts one closed local-name and typed-value pair.
func parseFactValue(value lua.LValue) (FactValue, int, error) {
	entry, err := closedTable(value, "name", "value")
	if err != nil {
		return FactValue{}, 0, err
	}

	name, ok := entry.RawGetString("name").(lua.LString)
	if !ok || len(name) > maximumCallbackTextBytes {
		return FactValue{}, 0, ErrInvalidResult
	}

	factValue, err := parseTypedValue(entry.RawGetString("value"))
	if err != nil {
		return FactValue{}, 0, err
	}

	_, _, _, valueBytes, valid := strictValueBounds(factValue)
	if !valid {
		return FactValue{}, 0, ErrInvalidResult
	}

	return FactValue{Name: string(name), Value: factValue}, valueBytes, nil
}

// parseEffectResult accepts only the closed completion and error-class vocabulary.
func parseEffectResult(value lua.LValue) (EffectResult, error) {
	table, err := closedTable(value, "state", "error_class")
	if err != nil {
		return EffectResult{}, err
	}

	state, ok := table.RawGetString("state").(lua.LString)
	if !ok || len(state) > maximumCallbackTextBytes {
		return EffectResult{}, ErrInvalidResult
	}

	errorClass, err := parseOptionalErrorClass(table.RawGetString("error_class"))
	if err != nil {
		return EffectResult{}, err
	}

	result := EffectResult{State: EffectState(state), ErrorClass: errorClass}
	if err = result.Validate(); err != nil {
		return EffectResult{}, ErrInvalidResult
	}

	return result, nil
}

// parseTypedValue reconstructs one strict policy value through decision.NewValue.
func parseTypedValue(value lua.LValue) (decision.Value, error) {
	table, err := closedTable(value, "kind", "value")
	if err != nil {
		return decision.Value{}, err
	}

	kindValue, kindOK := table.RawGetString("kind").(lua.LString)
	if !kindOK {
		return decision.Value{}, ErrInvalidResult
	}

	kind := decision.ValueKind(kindValue)
	if !kind.IsValid() {
		return decision.Value{}, ErrInvalidResult
	}

	member := table.RawGetString("value")

	switch kind {
	case decision.ValueKindString:
		return parseStringValue(member)
	case decision.ValueKindBoolean:
		return parseBooleanValue(member)
	case decision.ValueKindInteger:
		return parseIntegerValue(member)
	case decision.ValueKindDouble:
		return parseDoubleValue(member)
	case decision.ValueKindStrings:
		return parseStringsValue(member)
	case decision.ValueKindBytes:
		return parseBytesValue(member)
	case decision.ValueKindTimestamp:
		return parseTimestampValue(member)
	case decision.ValueKindRecords:
		return parseRecordsValue(member)
	default:
		return decision.Value{}, ErrInvalidResult
	}
}

// parseRecordsValue reconstructs one bounded flat record collection from dense ordered arrays.
func parseRecordsValue(value lua.LValue) (decision.Value, error) {
	entries, err := luaArray(value, maximumCallbackListItems)
	if err != nil {
		return decision.Value{}, err
	}

	records := make([]decision.Record, 0, len(entries))
	for _, entry := range entries {
		recordTable, tableErr := closedTable(entry, "fields")
		if tableErr != nil {
			return decision.Value{}, tableErr
		}

		fieldEntries, arrayErr := luaArray(recordTable.RawGetString("fields"), maximumCallbackListItems)
		if arrayErr != nil || len(fieldEntries) == 0 {
			return decision.Value{}, ErrInvalidResult
		}

		fields := make([]decision.RecordField, 0, len(fieldEntries))
		for _, fieldEntry := range fieldEntries {
			field, fieldErr := parseRecordField(fieldEntry)
			if fieldErr != nil {
				return decision.Value{}, fieldErr
			}

			fields = append(fields, field)
		}

		record, recordErr := decision.NewRecord(fields)
		if recordErr != nil {
			return decision.Value{}, ErrInvalidResult
		}

		records = append(records, record)
	}

	owned, err := decision.NewRecordList(records)
	if err != nil {
		return decision.Value{}, ErrInvalidResult
	}

	return constructCallbackValue(decision.ValueInput{Records: &owned})
}

// parseRecordField rejects recursive value kinds before constructing one local field.
func parseRecordField(value lua.LValue) (decision.RecordField, error) {
	entry, err := closedTable(value, "name", "value")
	if err != nil {
		return decision.RecordField{}, err
	}

	name, ok := entry.RawGetString("name").(lua.LString)
	if !ok {
		return decision.RecordField{}, ErrInvalidResult
	}

	valueTable, err := closedTable(entry.RawGetString("value"), "kind", "value")
	if err != nil {
		return decision.RecordField{}, err
	}

	kind, ok := valueTable.RawGetString("kind").(lua.LString)
	if !ok || decision.ValueKind(kind) == decision.ValueKindRecords {
		return decision.RecordField{}, ErrInvalidResult
	}

	leaf, err := parseTypedValue(valueTable)
	if err != nil {
		return decision.RecordField{}, err
	}

	fieldValue, err := decision.NewRecordFieldValueFromValue(leaf)
	if err != nil {
		return decision.RecordField{}, ErrInvalidResult
	}

	field, err := decision.NewRecordField(string(name), fieldValue)
	if err != nil {
		return decision.RecordField{}, ErrInvalidResult
	}

	return field, nil
}

// parseStringValue constructs one bounded UTF-8 string member.
func parseStringValue(value lua.LValue) (decision.Value, error) {
	member, ok := value.(lua.LString)
	if !ok || len(member) > maximumCallbackInputBytes {
		return decision.Value{}, ErrInvalidResult
	}

	text := string(member)

	return constructCallbackValue(decision.ValueInput{String: &text})
}

// parseBooleanValue constructs one exact boolean member.
func parseBooleanValue(value lua.LValue) (decision.Value, error) {
	member, ok := value.(lua.LBool)
	if !ok {
		return decision.Value{}, ErrInvalidResult
	}

	boolean := bool(member)

	return constructCallbackValue(decision.ValueInput{Boolean: &boolean})
}

// parseIntegerValue range-checks one base-10 int64 encoded without Lua precision loss.
func parseIntegerValue(value lua.LValue) (decision.Value, error) {
	member, ok := value.(lua.LString)
	if !ok || len(member) > 32 {
		return decision.Value{}, ErrInvalidResult
	}

	result, err := decision.ParseIntegerValue(string(member))
	if err != nil {
		return decision.Value{}, ErrInvalidResult
	}

	return result, nil
}

// parseDoubleValue constructs one finite IEEE-754 double.
func parseDoubleValue(value lua.LValue) (decision.Value, error) {
	member, ok := value.(lua.LNumber)
	if !ok {
		return decision.Value{}, ErrInvalidResult
	}

	double := float64(member)

	return constructCallbackValue(decision.ValueInput{Double: &double})
}

// parseStringsValue constructs one bounded ordered UTF-8 string list.
func parseStringsValue(value lua.LValue) (decision.Value, error) {
	entries, err := luaArray(value, maximumCallbackListItems)
	if err != nil {
		return decision.Value{}, err
	}

	members := make([]string, 0, len(entries))
	totalBytes := 0

	for _, entry := range entries {
		member, ok := entry.(lua.LString)
		if !ok || len(member) > maximumCallbackInputBytes-totalBytes {
			return decision.Value{}, ErrInvalidResult
		}

		members = append(members, string(member))
		totalBytes += len(member)
	}

	return constructCallbackValue(decision.ValueInput{Strings: members})
}

// parseBytesValue decodes one bounded standard-base64 byte sequence.
func parseBytesValue(value lua.LValue) (decision.Value, error) {
	member, ok := value.(lua.LString)
	if !ok || len(member) > base64.StdEncoding.EncodedLen(maximumCallbackInputBytes) {
		return decision.Value{}, ErrInvalidResult
	}

	decoded, err := base64.StdEncoding.Strict().DecodeString(string(member))
	if err != nil || len(decoded) > maximumCallbackInputBytes {
		return decision.Value{}, ErrInvalidResult
	}

	return constructCallbackValue(decision.ValueInput{Bytes: decoded})
}

// parseTimestampValue parses and UTC-normalizes one RFC3339Nano instant.
func parseTimestampValue(value lua.LValue) (decision.Value, error) {
	member, ok := value.(lua.LString)
	if !ok || len(member) > 64 {
		return decision.Value{}, ErrInvalidResult
	}

	parsed, err := time.Parse(time.RFC3339Nano, string(member))
	if err != nil {
		return decision.Value{}, ErrInvalidResult
	}

	return constructCallbackValue(decision.ValueInput{Timestamp: &parsed})
}

// constructCallbackValue hides detailed rejected values behind the stable result class.
func constructCallbackValue(input decision.ValueInput) (decision.Value, error) {
	value, err := decision.NewValue(input)
	if err != nil {
		return decision.Value{}, ErrInvalidResult
	}

	return value, nil
}

// parseOptionalErrorClass validates an absent or registered secret-safe class.
func parseOptionalErrorClass(value lua.LValue) (ErrorClass, error) {
	if value == lua.LNil {
		return "", nil
	}

	member, ok := value.(lua.LString)
	if !ok || len(member) > 32 {
		return "", ErrInvalidResult
	}

	result := ErrorClass(member)
	if !result.IsValid() {
		return "", ErrInvalidResult
	}

	return result, nil
}

// closedTable rejects non-table values, non-string keys, and undeclared authority fields.
func closedTable(value lua.LValue, fields ...string) (*lua.LTable, error) {
	table, ok := value.(*lua.LTable)
	if !ok {
		return nil, ErrInvalidResult
	}

	allowed := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		allowed[field] = struct{}{}
	}

	invalid := false

	table.ForEach(func(key lua.LValue, _ lua.LValue) {
		name, isString := key.(lua.LString)
		if !isString {
			invalid = true

			return
		}

		if _, exists := allowed[string(name)]; !exists {
			invalid = true
		}
	})

	if invalid {
		return nil, ErrInvalidResult
	}

	return table, nil
}

// luaArray extracts one dense one-indexed array with an exact entry bound.
func luaArray(value lua.LValue, maximum int) ([]lua.LValue, error) {
	table, ok := value.(*lua.LTable)
	if !ok || table.Len() > maximum {
		return nil, ErrInvalidResult
	}

	length := table.Len()
	result := make([]lua.LValue, length)
	seen := make([]bool, length)
	invalid := false
	count := 0

	table.ForEach(func(key lua.LValue, member lua.LValue) {
		number, numberOK := key.(lua.LNumber)
		index := int(number)

		if !numberOK || float64(index) != float64(number) || index < 1 || index > length || seen[index-1] {
			invalid = true

			return
		}

		seen[index-1] = true
		result[index-1] = member
		count++
	})

	if invalid || count != length {
		return nil, ErrInvalidResult
	}

	return result, nil
}

// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyprovider

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	lua "github.com/yuin/gopher-lua"
)

func TestLuaRecordValueRoundTripIsOrderedFreshAndNonRecursive(t *testing.T) {
	state := lua.NewState()
	defer state.Close()

	value := luaRecordTestValue(t)
	table := buildTypedValueTable(state, value)

	parsed, err := parseTypedValue(table)
	if err != nil {
		t.Fatalf("parseTypedValue(records) error = %v", err)
	}

	records, _ := parsed.Records()
	fields := records.Records()[0].Fields()

	if len(fields) != 2 || fields[0].Name() != "sequence" || fields[1].Name() != "result" {
		t.Fatalf("Lua record order = %#v", fields)
	}

	valueTable := table.RawGetString("value").(*lua.LTable)
	recordTable := valueTable.RawGetInt(1).(*lua.LTable)
	fieldTable := recordTable.RawGetString("fields").(*lua.LTable).RawGetInt(1).(*lua.LTable)
	fieldTable.RawSetString("name", lua.LString("changed"))

	original, _ := value.Records()
	if got := original.Records()[0].Fields()[0].Name(); got != "sequence" {
		t.Fatalf("Lua table mutation leaked into source value: %q", got)
	}

	nested := state.NewTable()
	nested.RawSetString("kind", lua.LString(decision.ValueKindRecords))
	nested.RawSetString("value", state.NewTable())
	recursiveField := state.NewTable()
	recursiveField.RawSetString("name", lua.LString("nested"))
	recursiveField.RawSetString("value", nested)

	recursiveFields := state.NewTable()
	recursiveFields.Append(recursiveField)

	recursiveRecord := state.NewTable()
	recursiveRecord.RawSetString("fields", recursiveFields)

	recursiveRecords := state.NewTable()
	recursiveRecords.Append(recursiveRecord)

	recursive := state.NewTable()
	recursive.RawSetString("kind", lua.LString(decision.ValueKindRecords))
	recursive.RawSetString("value", recursiveRecords)

	if _, err = parseTypedValue(recursive); err == nil {
		t.Fatal("parseTypedValue() accepted recursive records")
	}
}

// luaRecordTestValue constructs one ordered record-list fixture.
func luaRecordTestValue(t *testing.T) decision.Value {
	t.Helper()

	sequence := int64(1)
	result := "pass"
	sequenceValue, _ := decision.NewValue(decision.ValueInput{Integer: &sequence})
	resultValue, _ := decision.NewValue(decision.ValueInput{String: &result})
	sequenceLeaf, _ := decision.NewRecordFieldValueFromValue(sequenceValue)
	resultLeaf, _ := decision.NewRecordFieldValueFromValue(resultValue)
	sequenceField, _ := decision.NewRecordField("sequence", sequenceLeaf)
	resultField, _ := decision.NewRecordField("result", resultLeaf)
	record, _ := decision.NewRecord([]decision.RecordField{sequenceField, resultField})
	records, _ := decision.NewRecordList([]decision.Record{record})

	value, err := decision.NewValue(decision.ValueInput{Records: &records})
	if err != nil {
		t.Fatalf("NewValue(records) error = %v", err)
	}

	return value
}

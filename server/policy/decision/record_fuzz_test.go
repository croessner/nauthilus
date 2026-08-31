// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package decision

import "testing"

func FuzzRecordListConstruction(f *testing.F) {
	f.Add("state", "ready")
	f.Add("sequence", "")

	f.Fuzz(func(t *testing.T, name string, text string) {
		if len(name) > maximumValueMapKeyLength || len(text) > 4096 {
			t.Skip()
		}

		value, err := NewValue(ValueInput{String: &text})
		if err != nil {
			return
		}

		fieldValue, err := NewRecordFieldValueFromValue(value)
		if err != nil {
			t.Fatalf("NewRecordFieldValueFromValue() error = %v", err)
		}

		field, err := NewRecordField(name, fieldValue)
		if err != nil {
			return
		}

		record, err := NewRecord([]RecordField{field})
		if err != nil {
			t.Fatalf("NewRecord() error = %v", err)
		}

		records, err := NewRecordList([]Record{record})
		if err != nil || len(records.Records()) != 1 {
			t.Fatalf("NewRecordList() = %d/%v", len(records.Records()), err)
		}
	})
}

// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginruntime

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

func TestNativeDecisionRecordConversionIsOrderedAndDeeplyOwned(t *testing.T) {
	labels := []string{"one"}
	leafValue, _ := decision.NewValue(decision.ValueInput{Strings: labels})
	fieldValue, _ := decision.NewRecordFieldValueFromValue(leafValue)
	field, _ := decision.NewRecordField("labels", fieldValue)
	record, _ := decision.NewRecord([]decision.RecordField{field})
	records, _ := decision.NewRecordList([]decision.Record{record})
	value, _ := decision.NewValue(decision.ValueInput{Records: &records})

	publicValue, err := pluginDecisionValue(value)
	if err != nil {
		t.Fatalf("pluginDecisionValue() error = %v", err)
	}

	labels[0] = "changed"
	publicRecords, ok := publicValue.Records()

	if !ok || publicRecords.Records()[0].Fields()[0].Name() != "labels" {
		t.Fatalf("public records = %#v, %t", publicRecords, ok)
	}

	internalValue, err := nativeDecisionValue(publicValue)
	if err != nil {
		t.Fatalf("nativeDecisionValue() error = %v", err)
	}

	internalRecords, _ := internalValue.Records()
	stringsValue, _ := internalRecords.Records()[0].Fields()[0].Value().Value().Strings()

	if len(stringsValue) != 1 || stringsValue[0] != "one" {
		t.Fatalf("native record strings = %#v, want one", stringsValue)
	}
}

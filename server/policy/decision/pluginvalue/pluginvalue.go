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

// Package pluginvalue converts strict Policy decision values between the internal decision vocabulary and the public
// plugin API. It is a leaf package so both the auth core and the plugin runtime can share one conversion.
package pluginvalue

import (
	"errors"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

// ErrContract reports a value outside the closed strict-value vocabulary.
var ErrContract = errors.New("decision value contract rejected")

type valueProjection struct {
	stringValue    *string
	booleanValue   *bool
	integerValue   *int64
	doubleValue    *float64
	timestampValue *time.Time
	stringsValue   []string
	bytesValue     []byte
}

// ToPlugin translates one internal strict value through the public constructor.
func ToPlugin(input decision.Value) (pluginapi.DecisionValue, error) {
	return convertValue(
		input.Records,
		RecordsToPlugin,
		func(records *pluginapi.DecisionRecordList) (pluginapi.DecisionValue, error) {
			return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Records: records})
		},
		input.Any,
		valueProjection.pluginValue,
	)
}

// FromPlugin translates one public strict value through the internal constructor.
func FromPlugin(input pluginapi.DecisionValue) (decision.Value, error) {
	return convertValue(
		input.Records,
		RecordsFromPlugin,
		func(records *decision.RecordList) (decision.Value, error) {
			return decision.NewValue(decision.ValueInput{Records: records})
		},
		input.Any,
		valueProjection.nativeValue,
	)
}

// convertValue shares the record-versus-scalar dispatch of both boundary directions.
func convertValue[SourceRecords any, TargetRecords any, Target any](
	records func() (SourceRecords, bool),
	convertRecords func(SourceRecords) (TargetRecords, error),
	wrapRecords func(*TargetRecords) (Target, error),
	member func() (any, bool),
	build func(valueProjection) (Target, error),
) (Target, error) {
	var zero Target

	if source, ok := records(); ok {
		converted, err := convertRecords(source)
		if err != nil {
			return zero, ErrContract
		}

		return wrapRecords(&converted)
	}

	projection, err := newValueProjection(member())
	if err != nil {
		return zero, ErrContract
	}

	return build(projection)
}

// RecordsToPlugin converts one internal record collection through public constructors.
func RecordsToPlugin(input decision.RecordList) (pluginapi.DecisionRecordList, error) {
	return convertRecordList(
		input.Records(),
		func(record decision.Record) []decision.RecordField { return record.Fields() },
		pluginRecordField,
		pluginapi.NewDecisionRecord,
		pluginapi.NewDecisionRecordList,
	)
}

// RecordsFromPlugin converts one public record collection through internal constructors.
func RecordsFromPlugin(input pluginapi.DecisionRecordList) (decision.RecordList, error) {
	return convertRecordList(
		input.Records(),
		func(record pluginapi.DecisionRecord) []pluginapi.DecisionRecordField { return record.Fields() },
		nativeRecordField,
		decision.NewRecord,
		decision.NewRecordList,
	)
}

// pluginRecordField converts one internal field through the public leaf constructors.
func pluginRecordField(input decision.RecordField) (pluginapi.DecisionRecordField, error) {
	leaf, err := ToPlugin(input.Value().Value())
	if err != nil {
		return pluginapi.DecisionRecordField{}, err
	}

	value, err := pluginapi.NewDecisionRecordFieldValue(leaf)
	if err != nil {
		return pluginapi.DecisionRecordField{}, err
	}

	return pluginapi.NewDecisionRecordField(input.Name(), value)
}

// nativeRecordField converts one public field through the internal leaf constructors.
func nativeRecordField(input pluginapi.DecisionRecordField) (decision.RecordField, error) {
	leaf, err := FromPlugin(input.Value().Value())
	if err != nil {
		return decision.RecordField{}, err
	}

	value, err := decision.NewRecordFieldValueFromValue(leaf)
	if err != nil {
		return decision.RecordField{}, err
	}

	return decision.NewRecordField(input.Name(), value)
}

// convertRecordList shares ordered record traversal across both native boundary directions.
func convertRecordList[
	SourceRecord any,
	SourceField any,
	TargetField any,
	TargetRecord any,
	TargetList any,
](
	sourceRecords []SourceRecord,
	fieldsFor func(SourceRecord) []SourceField,
	convertField func(SourceField) (TargetField, error),
	newRecord func([]TargetField) (TargetRecord, error),
	newList func([]TargetRecord) (TargetList, error),
) (TargetList, error) {
	records := make([]TargetRecord, 0, len(sourceRecords))

	for _, sourceRecord := range sourceRecords {
		sourceFields := fieldsFor(sourceRecord)
		fields := make([]TargetField, 0, len(sourceFields))

		for _, sourceField := range sourceFields {
			field, err := convertField(sourceField)
			if err != nil {
				var zero TargetList

				return zero, err
			}

			fields = append(fields, field)
		}

		record, err := newRecord(fields)
		if err != nil {
			var zero TargetList

			return zero, err
		}

		records = append(records, record)
	}

	return newList(records)
}

// newValueProjection normalizes one closed strict-value member for either boundary constructor.
func newValueProjection(member any, present bool) (valueProjection, error) {
	if !present {
		return valueProjection{}, ErrContract
	}

	projection := valueProjection{}

	switch value := member.(type) {
	case string:
		projection.stringValue = &value
	case bool:
		projection.booleanValue = &value
	case int64:
		projection.integerValue = &value
	case float64:
		projection.doubleValue = &value
	case []string:
		projection.stringsValue = value
	case []byte:
		projection.bytesValue = value
	case time.Time:
		projection.timestampValue = &value
	default:
		return valueProjection{}, ErrContract
	}

	return projection, nil
}

// pluginValue constructs one detached public strict value from the shared projection.
func (p valueProjection) pluginValue() (pluginapi.DecisionValue, error) {
	return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{
		String: p.stringValue, Boolean: p.booleanValue, Integer: p.integerValue,
		Double: p.doubleValue, Timestamp: p.timestampValue,
		Strings: p.stringsValue, Bytes: p.bytesValue,
	})
}

// nativeValue constructs one detached internal strict value from the shared projection.
func (p valueProjection) nativeValue() (decision.Value, error) {
	return decision.NewValue(decision.ValueInput{
		String: p.stringValue, Boolean: p.booleanValue, Integer: p.integerValue,
		Double: p.doubleValue, Timestamp: p.timestampValue,
		Strings: p.stringsValue, Bytes: p.bytesValue,
	})
}

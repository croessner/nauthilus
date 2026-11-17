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

package clickhousestore

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"
)

// nullLiteral is the JSON null token.
var nullLiteral = []byte("null")

// optInt decodes a nullable integer that ClickHouse may quote (64-bit quoting settings differ between servers).
type optInt struct {
	value *int64
}

// UnmarshalJSON accepts null, a number, or a quoted number.
func (o *optInt) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(raw, nullLiteral) {
		o.value = nil

		return nil
	}

	text := string(bytes.Trim(raw, `"`))

	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		unsigned, unsignedErr := strconv.ParseUint(text, 10, 64)
		if unsignedErr != nil {
			return err
		}

		value = int64(min(unsigned, uint64(1<<63-1)))
	}

	o.value = &value

	return nil
}

// int returns the value or zero.
func (o optInt) int() int64 {
	if o.value == nil {
		return 0
	}

	return *o.value
}

// optFloat decodes a nullable float that may be quoted.
type optFloat struct {
	value *float64
}

// UnmarshalJSON accepts null, a number, or a quoted number.
func (o *optFloat) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(raw, nullLiteral) {
		o.value = nil

		return nil
	}

	value, err := strconv.ParseFloat(string(bytes.Trim(raw, `"`)), 64)
	if err != nil {
		return err
	}

	o.value = &value

	return nil
}

// optBool decodes a nullable Bool, which ClickHouse renders as true/false.
type optBool struct {
	value *bool
}

// UnmarshalJSON accepts null, true, false, 0, or 1.
func (o *optBool) UnmarshalJSON(raw []byte) error {
	switch string(raw) {
	case "null":
		o.value = nil
	case "true", "1":
		value := true
		o.value = &value
	case "false", "0":
		value := false
		o.value = &value
	default:
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}

		o.value = &value
	}

	return nil
}

// bool returns the value or false.
func (o optBool) bool() bool {
	return o.value != nil && *o.value
}

// millis converts a decoded unix millisecond value to UTC time.
func millis(value optInt) time.Time {
	return time.UnixMilli(value.int()).UTC()
}

// optMillis converts a nullable unix millisecond value.
func optMillis(value optInt) *time.Time {
	if value.value == nil {
		return nil
	}

	at := time.UnixMilli(*value.value).UTC()

	return &at
}

// formatTime renders a parameter for {name:DateTime64(3, 'UTC')}.
func formatTime(at time.Time) string {
	return at.UTC().Format("2006-01-02 15:04:05.000")
}

// stringParam renders a parameter for {name:String}; ClickHouse interprets backslash escapes in parameter values.
func stringParam(value string) string {
	var buffer bytes.Buffer

	for _, char := range []byte(value) {
		if char == '\\' {
			buffer.WriteByte('\\')
		}

		buffer.WriteByte(char)
	}

	return buffer.String()
}

// formatStrings renders a parameter for {name:Array(String)} as a ClickHouse array literal.
func formatStrings(values []string) string {
	var buffer bytes.Buffer

	buffer.WriteByte('[')

	for index, value := range values {
		if index > 0 {
			buffer.WriteByte(',')
		}

		buffer.WriteString(quoteString(value))
	}

	buffer.WriteByte(']')

	return buffer.String()
}

// quoteString renders one single-quoted ClickHouse string literal with escaped quotes and backslashes.
func quoteString(value string) string {
	var buffer bytes.Buffer

	buffer.WriteByte('\'')

	for _, char := range []byte(value) {
		if char == '\'' || char == '\\' {
			buffer.WriteByte('\\')
		}

		buffer.WriteByte(char)
	}

	buffer.WriteByte('\'')

	return buffer.String()
}

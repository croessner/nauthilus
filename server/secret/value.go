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

// Package secret provides secret functionality.
package secret

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"

	rtsecret "runtime/secret"
)

// redactedFormat replaces a non-empty secret wherever fmt or slog render it.
const redactedFormat = "<hidden>"

// Value stores secret material and provides scoped access helpers. The bytes sit behind a pointer: when a Value
// is an unexported field, fmt cannot call its formatting methods and walks the struct by reflection instead, and a
// nested pointer is rendered only as an address, never as its content.
type Value struct {
	data *[]byte
}

// New wraps a string secret into a Value.
func New(value string) Value {
	if value == "" {
		return Value{}
	}

	data := []byte(value)

	return Value{data: &data}
}

// FromBytes wraps a byte slice secret into a Value.
func FromBytes(value []byte) Value {
	if len(value) == 0 {
		return Value{}
	}

	data := bytes.Clone(value)

	return Value{data: &data}
}

// bytes returns the stored secret bytes, or nil for an empty Value.
func (v Value) bytes() []byte {
	if v.data == nil {
		return nil
	}

	return *v.data
}

// IsZero reports whether the secret is empty.
func (v Value) IsZero() bool {
	return len(v.bytes()) == 0
}

// Len returns the secret length in bytes.
func (v Value) Len() int {
	return len(v.bytes())
}

// String returns the secret as a string.
// Use only for validation or when an API strictly requires a string.
func (v Value) String() string {
	if v.IsZero() {
		return ""
	}

	return string(v.bytes())
}

// Format redacts the secret for every fmt verb, including nested struct and slice formatting, so a value printed
// by accident never reveals its content. Callers that need the value use String or WithBytes explicitly.
func (v Value) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, v.redacted())
}

// GoString redacts the secret for the %#v verb.
func (v Value) GoString() string {
	return v.redacted()
}

// LogValue redacts the secret in structured logs.
func (v Value) LogValue() slog.Value {
	return slog.StringValue(v.redacted())
}

// redacted returns the placeholder shown instead of a non-empty secret; an empty secret stays empty.
func (v Value) redacted() string {
	if v.IsZero() {
		return ""
	}

	return redactedFormat
}

// WithBytes provides a temporary byte slice to the caller and clears it afterwards.
func (v Value) WithBytes(fn func([]byte)) {
	rtsecret.Do(func() {
		if v.IsZero() {
			fn(nil)
			return
		}

		buf := bytes.Clone(v.bytes())
		defer clear(buf)

		fn(buf)
	})
}

// WithString provides a temporary string to the caller.
// Avoid for long-lived strings; prefer WithBytes when possible.
func (v Value) WithString(fn func(string)) {
	v.WithBytes(func(buf []byte) {
		fn(string(buf))
	})
}

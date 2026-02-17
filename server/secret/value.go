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

package secret

import (
	"bytes"

	rtsecret "runtime/secret"
)

// Value stores secret material and provides scoped access helpers.
type Value struct {
	data []byte
}

// New wraps a string secret into a Value.
func New(value string) Value {
	if value == "" {
		return Value{}
	}

	return Value{data: []byte(value)}
}

// FromBytes wraps a byte slice secret into a Value.
func FromBytes(value []byte) Value {
	if len(value) == 0 {
		return Value{}
	}

	return Value{data: bytes.Clone(value)}
}

// IsZero reports whether the secret is empty.
func (v Value) IsZero() bool {
	return len(v.data) == 0
}

// Len returns the secret length in bytes.
func (v Value) Len() int {
	return len(v.data)
}

// String returns the secret as a string.
// Use only for validation or when an API strictly requires a string.
func (v Value) String() string {
	if len(v.data) == 0 {
		return ""
	}

	return string(v.data)
}

// WithBytes provides a temporary byte slice to the caller and clears it afterwards.
func (v Value) WithBytes(fn func([]byte)) {
	rtsecret.Do(func() {
		if len(v.data) == 0 {
			fn(nil)
			return
		}

		buf := bytes.Clone(v.data)
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

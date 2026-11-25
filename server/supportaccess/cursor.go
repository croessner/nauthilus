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

package supportaccess

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// MaxCursorLength bounds an opaque page cursor a caller sends back.
const MaxCursorLength = 512

// EncodeCursor renders a page state as an opaque, URL-safe cursor. It is not signed, so cursors stay valid across the
// instances of a deployment; a service binds it to its query with a digest and validates and bounds every field on
// the way back, so an edited cursor can only move its own pages.
func EncodeCursor(state any) string {
	raw, _ := json.Marshal(state)

	return base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeCursor parses an opaque cursor into state. It refuses an over-long, malformed, or non-object cursor and
// unknown fields, so a crafted cursor never carries more than the service reads.
func DecodeCursor(cursor string, state any) bool {
	if cursor == "" || len(cursor) > MaxCursorLength {
		return false
	}

	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return false
	}

	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()

	return decoder.Decode(state) == nil && !decoder.More()
}

// QueryDigest returns a short stable digest of the parts that define a query, so a cursor cannot be replayed against
// another query.
func QueryDigest(parts ...string) string {
	hash := sha256.New()

	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}

	return hex.EncodeToString(hash.Sum(nil)[:12])
}

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

// Package jsonstrict holds JSON checks for untrusted request bodies that the standard decoder does not perform.
// Duplicate object member names are accepted by encoding/json (last one wins) but may be read differently by
// another parser in the same request path; refusing them closes that parser differential.
package jsonstrict

import (
	"bytes"
	"encoding/json"
)

// maxDepth bounds the nesting the duplicate check walks; deeper bodies count as having duplicates.
const maxDepth = 64

// HasDuplicateNames reports whether any JSON object in body, at any depth, repeats a member name. Malformed JSON is
// reported as false; the caller's decoder rejects it.
func HasDuplicateNames(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()

	duplicate, _ := scanValue(decoder, 0)

	return duplicate
}

// scanValue walks one JSON value; it returns whether a duplicate was found and whether the walk stayed well-formed.
func scanValue(decoder *json.Decoder, depth int) (bool, bool) {
	if depth > maxDepth {
		return true, false
	}

	token, err := decoder.Token()
	if err != nil {
		return false, false
	}

	switch token {
	case json.Delim('{'):
		return scanObject(decoder, depth)
	case json.Delim('['):
		return scanArray(decoder, depth)
	default:
		return false, true
	}
}

// scanObject walks the members of one object after its opening delimiter.
func scanObject(decoder *json.Decoder, depth int) (bool, bool) {
	seen := make(map[string]struct{})

	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return false, false
		}

		name, ok := nameToken.(string)
		if !ok {
			return false, false
		}

		if _, exists := seen[name]; exists {
			return true, true
		}

		seen[name] = struct{}{}

		if duplicate, wellFormed := scanValue(decoder, depth+1); duplicate || !wellFormed {
			return duplicate, wellFormed
		}
	}

	_, err := decoder.Token()

	return false, err == nil
}

// scanArray walks the elements of one array after its opening delimiter.
func scanArray(decoder *json.Decoder, depth int) (bool, bool) {
	for decoder.More() {
		if duplicate, wellFormed := scanValue(decoder, depth+1); duplicate || !wellFormed {
			return duplicate, wellFormed
		}
	}

	_, err := decoder.Token()

	return false, err == nil
}

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

package supportops

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// errNotObject reports a JSON line that is not one object.
var errNotObject = errors.New("log line is not one JSON object")

// fieldSet collects the fields of one object. A repeated name keeps every value in line order as a list and is
// recorded with its path, so no stored value is lost when the line becomes a map.
type fieldSet struct {
	values   map[string]any
	repeated *[]string
	counts   map[string]int
	path     string
}

// newFieldSet starts the fields of the object at path; repeated names are appended to repeated.
func newFieldSet(path string, repeated *[]string) *fieldSet {
	return &fieldSet{values: map[string]any{}, counts: map[string]int{}, repeated: repeated, path: path}
}

// add records one field.
func (f *fieldSet) add(name string, value any) {
	f.counts[name]++

	switch f.counts[name] {
	case 1:
		f.values[name] = value
	case 2:
		f.values[name] = []any{f.values[name], value}
		*f.repeated = append(*f.repeated, fieldPathOf(f.path, name))
	default:
		f.values[name] = append(f.values[name].([]any), value)
	}
}

// fieldPathOf names a nested field as parent.child.
func fieldPathOf(path string, name string) string {
	if path == "" {
		return name
	}

	return path + "." + name
}

// parseJSONFields reads one JSON object line without losing repeated names at any depth.
func parseJSONFields(line string) (map[string]any, []string, error) {
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.UseNumber()

	repeated := []string{}

	value, err := decodeJSONValue(decoder, "", &repeated)
	if err != nil {
		return nil, nil, err
	}

	fields, ok := value.(map[string]any)
	if !ok {
		return nil, nil, errNotObject
	}

	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, errNotObject
	}

	return fields, repeated, nil
}

// decodeJSONValue reads one JSON value token by token; objects keep repeated names through fieldSet.
func decodeJSONValue(decoder *json.Decoder, path string, repeated *[]string) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}

	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}

	if delimiter == '[' {
		return decodeJSONArray(decoder, path, repeated)
	}

	set := newFieldSet(path, repeated)

	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}

		name, _ := key.(string)

		value, err := decodeJSONValue(decoder, fieldPathOf(path, name), repeated)
		if err != nil {
			return nil, err
		}

		set.add(name, value)
	}

	_, err = decoder.Token()

	return set.values, err
}

// decodeJSONArray reads the items of a JSON array after its opening bracket.
func decodeJSONArray(decoder *json.Decoder, path string, repeated *[]string) (any, error) {
	items := []any{}

	for decoder.More() {
		item, err := decodeJSONValue(decoder, path, repeated)
		if err != nil {
			return nil, err
		}

		items = append(items, item)
	}

	_, err := decoder.Token()

	return items, err
}

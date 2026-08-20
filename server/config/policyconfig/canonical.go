// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

// CanonicalEntry is one deterministic path/value projection.
type CanonicalEntry struct {
	Path  string
	Value any
}

// CanonicalDocument is a deterministic, secret-safe standalone projection.
type CanonicalDocument struct {
	entries []CanonicalEntry
}

// Canonical validates and projects one normalized standalone document.
func Canonical(document Document) (CanonicalDocument, error) {
	document = Normalize(document)
	if err := Validate(document); err != nil {
		return CanonicalDocument{}, err
	}

	entries := make([]CanonicalEntry, 0, 128)
	collectCanonical(reflect.ValueOf(document), "", &entries)
	sort.Slice(entries, func(left int, right int) bool {
		return entries[left].Path < entries[right].Path
	})

	return CanonicalDocument{entries: entries}, nil
}

// Entries returns a detached canonical entry list.
func (d CanonicalDocument) Entries() []CanonicalEntry {
	return append([]CanonicalEntry(nil), d.entries...)
}

// Value returns the value at one exact canonical path or nil when absent.
func (d CanonicalDocument) Value(path string) any {
	index := sort.Search(len(d.entries), func(index int) bool {
		return d.entries[index].Path >= path
	})

	if index >= len(d.entries) || d.entries[index].Path != path {
		return nil
	}

	return d.entries[index].Value
}

// String renders stable path/JSON-value lines without secret material.
func (d CanonicalDocument) String() string {
	var builder strings.Builder

	for _, entry := range d.entries {
		encoded, err := json.Marshal(entry.Value)
		if err != nil {
			encoded = []byte(fmt.Sprintf("%q", fmt.Sprint(entry.Value)))
		}

		builder.WriteString(entry.Path)
		builder.WriteByte('=')
		builder.Write(encoded)
		builder.WriteByte('\n')
	}

	return builder.String()
}

// collectCanonical projects values through the shared mapstructure field authority.
func collectCanonical(value reflect.Value, path string, entries *[]CanonicalEntry) {
	if !value.IsValid() {
		appendCanonical(entries, path, nil)

		return
	}

	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			appendCanonical(entries, path, nil)

			return
		}

		collectCanonical(value.Elem(), path, entries)

		return
	}

	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			appendCanonical(entries, path, nil)

			return
		}

		collectCanonical(value.Elem(), path, entries)

		return
	}

	if value.Type() == secretType {
		appendCanonical(entries, path, RedactedValue)

		return
	}

	if value.Type() == durationType {
		appendCanonical(entries, path, time.Duration(value.Int()).String())

		return
	}

	switch value.Kind() {
	case reflect.Struct:
		collectCanonicalStruct(value, path, entries)
	case reflect.Map:
		collectCanonicalMap(value, path, entries)
	case reflect.Slice, reflect.Array:
		collectCanonicalSlice(value, path, entries)
	default:
		appendCanonical(entries, path, value.Interface())
	}
}

// collectCanonicalStruct projects fields in tagged key order.
func collectCanonicalStruct(value reflect.Value, path string, entries *[]CanonicalEntry) {
	for _, field := range sortedTaggedFields(value.Type()) {
		collectCanonical(value.FieldByIndex(field.Index), joinPath(path, field.Tag.Get("mapstructure")), entries)
	}
}

// collectCanonicalMap projects dynamic keys in deterministic order.
func collectCanonicalMap(value reflect.Value, path string, entries *[]CanonicalEntry) {
	if value.IsNil() || value.Len() == 0 {
		appendCanonical(entries, path, map[string]any{})

		return
	}

	keys := value.MapKeys()
	sort.Slice(keys, func(left int, right int) bool {
		return fmt.Sprint(keys[left].Interface()) < fmt.Sprint(keys[right].Interface())
	})

	for _, key := range keys {
		collectCanonical(value.MapIndex(key), joinPath(path, fmt.Sprint(key.Interface())), entries)
	}
}

// collectCanonicalSlice projects indexed entries in source order.
func collectCanonicalSlice(value reflect.Value, path string, entries *[]CanonicalEntry) {
	if value.IsNil() || value.Len() == 0 {
		appendCanonical(entries, path, []any{})

		return
	}

	for index := range value.Len() {
		collectCanonical(value.Index(index), fmt.Sprintf("%s[%d]", path, index), entries)
	}
}

// appendCanonical appends one non-empty canonical path.
func appendCanonical(entries *[]CanonicalEntry, path string, value any) {
	if path == "" {
		return
	}

	*entries = append(*entries, CanonicalEntry{Path: path, Value: value})
}

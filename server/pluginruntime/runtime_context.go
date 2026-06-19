// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"sort"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

var (
	// ErrUnsupportedRuntimeValue is returned when runtime data is not JSON/CBOR-compatible.
	ErrUnsupportedRuntimeValue = errors.New("unsupported runtime value")

	// ErrInvalidRuntimeKey is returned when a runtime key is empty.
	ErrInvalidRuntimeKey = errors.New("invalid runtime key")
)

const (
	// RuntimeDeltaConflictLogLimit bounds per-merge conflict diagnostics.
	RuntimeDeltaConflictLogLimit = 8
)

var _ pluginapi.RuntimeContext = (*runtimeContext)(nil)

// NewRuntimeContext returns an immutable runtime context view.
func NewRuntimeContext(values map[string]any) (pluginapi.RuntimeContext, error) {
	cloned, err := cloneRuntimeMap(values)
	if err != nil {
		return nil, err
	}

	return runtimeContext{values: cloned}, nil
}

// ValidateRuntimeDelta checks all values in a returned runtime delta.
func ValidateRuntimeDelta(delta pluginapi.RuntimeDelta) error {
	for key, value := range delta.Set {
		if key == "" {
			return fmt.Errorf("%w: set key is empty", ErrInvalidRuntimeKey)
		}

		if _, err := normalizeRuntimeValue(key, value); err != nil {
			return err
		}
	}

	if slices.Contains(delta.Delete, "") {
		return fmt.Errorf("%w: delete key is empty", ErrInvalidRuntimeKey)
	}

	return nil
}

// MergeRuntimeDeltas applies plugin deltas in argument order with deterministic key ordering inside each delta.
func MergeRuntimeDeltas(
	ctx context.Context,
	base map[string]any,
	logger pluginapi.Logger,
	deltas ...pluginapi.RuntimeDelta,
) (map[string]any, error) {
	merged, err := cloneRuntimeMap(base)
	if err != nil {
		return nil, err
	}

	conflictsLogged := 0

	for _, delta := range deltas {
		if err := ValidateRuntimeDelta(delta); err != nil {
			return nil, err
		}

		for _, key := range sortedStrings(delta.Delete) {
			delete(merged, key)
		}

		for _, key := range sortedMapKeys(delta.Set) {
			value, err := normalizeRuntimeValue(key, delta.Set[key])
			if err != nil {
				return nil, err
			}

			if current, ok := merged[key]; ok && !reflect.DeepEqual(current, value) && conflictsLogged < RuntimeDeltaConflictLogLimit {
				logRuntimeConflict(ctx, logger, key)

				conflictsLogged++
			}

			merged[key] = value
		}
	}

	return merged, nil
}

type runtimeContext struct {
	values map[string]any
}

// Get returns a cloned runtime value for one key.
func (c runtimeContext) Get(key string) (any, bool) {
	value, ok := c.values[key]
	if !ok {
		return nil, false
	}

	return cloneNormalizedRuntimeValue(value), true
}

// Snapshot returns a cloned runtime value map.
func (c runtimeContext) Snapshot() map[string]any {
	return cloneNormalizedRuntimeMap(c.values)
}

// cloneRuntimeMap validates and clones an input map.
func cloneRuntimeMap(values map[string]any) (map[string]any, error) {
	if len(values) == 0 {
		return map[string]any{}, nil
	}

	cloned := make(map[string]any, len(values))
	for key, value := range values {
		if key == "" {
			return nil, fmt.Errorf("%w: key is empty", ErrInvalidRuntimeKey)
		}

		normalized, err := normalizeRuntimeValue(key, value)
		if err != nil {
			return nil, err
		}

		cloned[key] = normalized
	}

	return cloned, nil
}

// normalizeRuntimeValue converts supported containers to map[string]any and []any.
func normalizeRuntimeValue(path string, value any) (any, error) {
	if value == nil {
		return nil, nil
	}

	switch typed := value.(type) {
	case bool, string,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return normalizeScalar(path, typed)
	default:
		return normalizeRuntimeReflectValue(path, reflect.ValueOf(value))
	}
}

// normalizeScalar checks numeric edge cases and returns supported scalar values.
func normalizeScalar(path string, value any) (any, error) {
	switch typed := value.(type) {
	case float32:
		if math.IsNaN(float64(typed)) || math.IsInf(float64(typed), 0) {
			return nil, fmt.Errorf("%w at %s: non-finite float", ErrUnsupportedRuntimeValue, path)
		}
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil, fmt.Errorf("%w at %s: non-finite float", ErrUnsupportedRuntimeValue, path)
		}
	}

	return value, nil
}

// normalizeRuntimeReflectValue handles map and slice values without accepting arbitrary structs.
func normalizeRuntimeReflectValue(path string, value reflect.Value) (any, error) {
	if !value.IsValid() {
		return nil, nil
	}

	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return nil, nil
		}

		return normalizeRuntimeReflectValue(path, value.Elem())
	case reflect.Pointer:
		return nil, fmt.Errorf("%w at %s: %T", ErrUnsupportedRuntimeValue, path, value.Interface())
	case reflect.Map:
		return normalizeRuntimeMapValue(path, value)
	case reflect.Slice, reflect.Array:
		return normalizeRuntimeSliceValue(path, value)
	default:
		return nil, fmt.Errorf("%w at %s: %T", ErrUnsupportedRuntimeValue, path, value.Interface())
	}
}

// normalizeRuntimeMapValue converts maps with string keys to map[string]any.
func normalizeRuntimeMapValue(path string, value reflect.Value) (map[string]any, error) {
	if value.Type().Key().Kind() != reflect.String {
		return nil, fmt.Errorf("%w at %s: map keys must be strings", ErrUnsupportedRuntimeValue, path)
	}

	normalized := make(map[string]any, value.Len())
	iter := value.MapRange()

	for iter.Next() {
		key := iter.Key().String()
		if key == "" {
			return nil, fmt.Errorf("%w: key is empty", ErrInvalidRuntimeKey)
		}

		childPath := path + "." + key

		child, err := normalizeRuntimeValue(childPath, iter.Value().Interface())
		if err != nil {
			return nil, err
		}

		normalized[key] = child
	}

	return normalized, nil
}

// normalizeRuntimeSliceValue converts slices and arrays to []any.
func normalizeRuntimeSliceValue(path string, value reflect.Value) ([]any, error) {
	normalized := make([]any, value.Len())
	for index := 0; index < value.Len(); index++ {
		childPath := fmt.Sprintf("%s[%d]", path, index)

		child, err := normalizeRuntimeValue(childPath, value.Index(index).Interface())
		if err != nil {
			return nil, err
		}

		normalized[index] = child
	}

	return normalized, nil
}

// cloneNormalizedRuntimeMap clones a map known to contain normalized runtime values.
func cloneNormalizedRuntimeMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return map[string]any{}
	}

	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = cloneNormalizedRuntimeValue(value)
	}

	return cloned
}

// cloneNormalizedRuntimeValue clones normalized runtime container values.
func cloneNormalizedRuntimeValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneNormalizedRuntimeMap(typed)
	case []any:
		cloned := make([]any, len(typed))
		for index, item := range typed {
			cloned[index] = cloneNormalizedRuntimeValue(item)
		}

		return cloned
	default:
		return typed
	}
}

// sortedMapKeys returns map keys in lexical order for deterministic merges.
func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

// sortedStrings returns a sorted copy of input strings.
func sortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	cloned := append([]string(nil), values...)
	sort.Strings(cloned)

	return cloned
}

// logRuntimeConflict writes a bounded, value-free runtime conflict diagnostic.
func logRuntimeConflict(ctx context.Context, logger pluginapi.Logger, key string) {
	if logger == nil {
		return
	}

	logger.Debug(ctx, "plugin runtime value overwritten", pluginapi.LogField{Key: "runtime_key", Value: key})
}

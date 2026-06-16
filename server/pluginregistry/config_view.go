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

package pluginregistry

import (
	"strings"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"

	"github.com/go-viper/mapstructure/v2"
)

var (
	_ pluginapi.ConfigView = (*ConfigView)(nil)
	_ pluginapi.ArgsView   = (*ArgsView)(nil)
)

// ConfigView exposes one immutable-looking plugin configuration subtree.
type ConfigView struct {
	data map[string]any
}

// ArgsView exposes immutable policy effect arguments to native plugins.
type ArgsView struct {
	data map[string]any
}

// NewConfigView returns a read-only view over a defensive copy of data.
func NewConfigView(data map[string]any) *ConfigView {
	return &ConfigView{data: cloneMap(data)}
}

// NewArgsView returns a read-only view over policy effect arguments.
func NewArgsView(data map[string]any) *ArgsView {
	return &ArgsView{data: cloneMap(data)}
}

// Get resolves a dot-separated configuration path.
func (v *ConfigView) Get(path string) (any, bool) {
	return v.GetPath(splitConfigPath(path))
}

// GetPath resolves a segment-based configuration path.
func (v *ConfigView) GetPath(path []string) (any, bool) {
	value, ok := valueAtPath(v.data, path)
	if !ok {
		return nil, false
	}

	return cloneValue(value), true
}

// Sub returns a view rooted at a dot-separated configuration path.
func (v *ConfigView) Sub(path string) pluginapi.ConfigView {
	return v.SubPath(splitConfigPath(path))
}

// SubPath returns a view rooted at a segment-based configuration path.
func (v *ConfigView) SubPath(path []string) pluginapi.ConfigView {
	value, ok := valueAtPath(v.data, path)
	if !ok {
		return NewConfigView(nil)
	}

	subtree, ok := value.(map[string]any)
	if !ok {
		return NewConfigView(nil)
	}

	return NewConfigView(subtree)
}

// Decode strictly decodes the current subtree into target.
func (v *ConfigView) Decode(target any) error {
	return decodeStrictMap(v.data, target)
}

// IsZero reports whether the view has no keys.
func (v *ConfigView) IsZero() bool {
	return v == nil || len(v.data) == 0
}

// Get resolves a dot-separated argument path.
func (v *ArgsView) Get(path string) (any, bool) {
	return v.GetPath(splitConfigPath(path))
}

// GetPath resolves a segment-based argument path.
func (v *ArgsView) GetPath(path []string) (any, bool) {
	value, ok := valueAtPath(v.data, path)
	if !ok {
		return nil, false
	}

	return cloneValue(value), true
}

// Sub returns an argument view rooted at a dot-separated path.
func (v *ArgsView) Sub(path string) pluginapi.ArgsView {
	return v.SubPath(splitConfigPath(path))
}

// SubPath returns an argument view rooted at a segment-based path.
func (v *ArgsView) SubPath(path []string) pluginapi.ArgsView {
	value, ok := valueAtPath(v.data, path)
	if !ok {
		return NewArgsView(nil)
	}

	subtree, ok := value.(map[string]any)
	if !ok {
		return NewArgsView(nil)
	}

	return NewArgsView(subtree)
}

// Decode strictly decodes the current argument subtree into target.
func (v *ArgsView) Decode(target any) error {
	return decodeStrictMap(v.data, target)
}

// decodeStrictMap applies the same strict mapstructure rules to all host-owned views.
func decodeStrictMap(data map[string]any, target any) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		ErrorUnused: true,
		Result:      target,
		TagName:     "mapstructure",
	})
	if err != nil {
		return err
	}

	return decoder.Decode(data)
}

// IsZero reports whether the argument view has no keys.
func (v *ArgsView) IsZero() bool {
	return v == nil || len(v.data) == 0
}

// splitConfigPath turns dot paths into path segments.
func splitConfigPath(path string) []string {
	if path == "" {
		return nil
	}

	return strings.Split(path, ".")
}

// valueAtPath resolves a map value without exposing missing intermediate paths.
func valueAtPath(data map[string]any, path []string) (any, bool) {
	if len(path) == 0 {
		return data, data != nil
	}

	var current any = data

	for _, segment := range path {
		if segment == "" {
			return nil, false
		}

		currentMap, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}

		current, ok = currentMap[segment]
		if !ok {
			return nil, false
		}
	}

	return current, true
}

// cloneMap recursively copies map data owned by the host.
func cloneMap(data map[string]any) map[string]any {
	if len(data) == 0 {
		return map[string]any{}
	}

	cloned := make(map[string]any, len(data))
	for key, value := range data {
		cloned[key] = cloneValue(value)
	}

	return cloned
}

// cloneValue copies the container types that plugin config may expose.
func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		cloned := make([]any, len(typed))
		for index, item := range typed {
			cloned[index] = cloneValue(item)
		}

		return cloned
	default:
		return value
	}
}

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

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

const (
	includeKey = "includes"
	patchKey   = "patch"
	envKey     = "env"

	patchOpAdd     = "add"
	patchOpReplace = "replace"
	patchOpRemove  = "remove"
)

// ConfigReader loads configuration settings from a path.
type ConfigReader interface {
	Read(path string) (map[string]any, error)
}

// IncludeResolver resolves include files from a root configuration tree.
type IncludeResolver interface {
	Resolve(root map[string]any) ([]IncludeFile, error)
}

// PatchEngine applies patch operations to a settings tree.
type PatchEngine interface {
	Apply(target map[string]any, patches []PatchOperation) error
}

// SettingsMerger merges source settings into a target map.
type SettingsMerger interface {
	Merge(target map[string]any, source map[string]any)
}

// ConfigLoader loads a config tree, resolves includes, and applies patches.
type ConfigLoader struct {
	reader          ConfigReader
	includeResolver IncludeResolver
	patchEngine     PatchEngine
	merger          SettingsMerger
}

// NewConfigLoader returns a ConfigLoader configured for the given config type.
func NewConfigLoader(configType string) *ConfigLoader {
	return &ConfigLoader{
		reader:          &ViperConfigReader{configType: configType},
		includeResolver: IncludeResolverFromConfig{},
		patchEngine:     DefaultPatchEngine{},
		merger:          MapMerger{},
	}
}

// LoadFromFile reads the config file and applies includes and patches.
func (l *ConfigLoader) LoadFromFile(path string) (map[string]any, error) {
	settings, err := l.reader.Read(path)
	if err != nil {
		return nil, err
	}

	return l.Load(path, settings)
}

// Load applies includes and patches starting from a settings map.
func (l *ConfigLoader) Load(path string, settings map[string]any) (map[string]any, error) {
	merged, patches, err := l.loadWithSettings(path, settings, map[string]struct{}{})
	if err != nil {
		return nil, err
	}

	if err := l.patchEngine.Apply(merged, patches); err != nil {
		return nil, err
	}

	return merged, nil
}

func (l *ConfigLoader) loadWithSettings(path string, settings map[string]any, visited map[string]struct{}) (map[string]any, []PatchOperation, error) {
	cleanPath := filepath.Clean(path)
	if _, ok := visited[cleanPath]; ok {
		return nil, nil, fmt.Errorf("include cycle detected at %q", cleanPath)
	}

	visited[cleanPath] = struct{}{}
	defer delete(visited, cleanPath)

	includes, err := l.includeResolver.Resolve(settings)
	if err != nil {
		return nil, nil, err
	}

	merged := map[string]any{}
	var patches []PatchOperation
	baseDir := filepath.Dir(cleanPath)

	for _, include := range includes {
		includePath := resolveIncludePath(baseDir, include.Path)
		includeSettings, includePatches, err := l.loadFromFile(includePath, visited)
		if err != nil {
			if include.Required || !isConfigNotFound(err) {
				return nil, nil, fmt.Errorf("include %q failed: %w", includePath, err)
			}

			continue
		}

		patches = append(patches, includePatches...)
		l.merger.Merge(merged, includeSettings)
	}

	filePatches, hasPatches, err := parsePatchOperations(settings)
	if err != nil {
		return nil, nil, err
	}
	if hasPatches {
		patches = append(patches, filePatches...)
	}

	stripLoaderKeys(settings)
	l.merger.Merge(merged, settings)

	return merged, patches, nil
}

func (l *ConfigLoader) loadFromFile(path string, visited map[string]struct{}) (map[string]any, []PatchOperation, error) {
	settings, err := l.reader.Read(path)
	if err != nil {
		return nil, nil, err
	}

	return l.loadWithSettings(path, settings, visited)
}

func resolveIncludePath(baseDir string, includePath string) string {
	if filepath.IsAbs(includePath) {
		return includePath
	}

	return filepath.Join(baseDir, includePath)
}

func stripLoaderKeys(settings map[string]any) {
	delete(settings, includeKey)
	delete(settings, patchKey)
	delete(settings, envKey)
}

func parsePatchOperations(settings map[string]any) ([]PatchOperation, bool, error) {
	raw, ok := settings[patchKey]
	if !ok {
		return nil, false, nil
	}

	var patches []PatchOperation
	if err := decodeConfigValue(raw, &patches); err != nil {
		return nil, false, fmt.Errorf("decode patch operations: %w", err)
	}

	return patches, true, nil
}

func decodeConfigValue(input any, output any) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:          "mapstructure",
		WeaklyTypedInput: true,
		Result:           output,
	})
	if err != nil {
		return err
	}

	return decoder.Decode(input)
}

func isConfigNotFound(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, fs.ErrNotExist) {
		return true
	}

	if pathErr, ok := errors.AsType[*os.PathError](err); ok {
		return errors.Is(pathErr.Err, fs.ErrNotExist)
	}

	if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); ok {
		return true
	}

	return false
}

// IncludeFile describes a resolved include path and whether it is required.
type IncludeFile struct {
	Path     string
	Required bool
}

// IncludeGroup groups required and optional include paths.
type IncludeGroup struct {
	Required []string `mapstructure:"required"`
	Optional []string `mapstructure:"optional"`
}

// IncludeSpec describes include groups and environment-specific overrides.
type IncludeSpec struct {
	Required []string                `mapstructure:"required"`
	Optional []string                `mapstructure:"optional"`
	Env      map[string]IncludeGroup `mapstructure:"env"`
}

// IncludeResolverFromConfig resolves include files from the config tree.
type IncludeResolverFromConfig struct{}

// Resolve returns the include file list from the root settings.
func (IncludeResolverFromConfig) Resolve(root map[string]any) ([]IncludeFile, error) {
	raw, ok := root[includeKey]
	if !ok {
		return nil, nil
	}

	var spec IncludeSpec
	if err := decodeConfigValue(raw, &spec); err != nil {
		return nil, fmt.Errorf("decode includes: %w", err)
	}

	var includeFiles []IncludeFile
	includeFiles = append(includeFiles, toIncludeFiles(spec.Required, true)...)
	includeFiles = append(includeFiles, toIncludeFiles(spec.Optional, false)...)

	envName, err := resolveEnvName(root)
	if err != nil {
		return nil, err
	}

	if envName != "" {
		if envSpec, ok := spec.Env[envName]; ok {
			includeFiles = append(includeFiles, toIncludeFiles(envSpec.Required, true)...)
			includeFiles = append(includeFiles, toIncludeFiles(envSpec.Optional, false)...)
		}
	}

	return includeFiles, nil
}

func resolveEnvName(root map[string]any) (string, error) {
	raw, ok := root[envKey]
	if !ok {
		return strings.TrimSpace(viper.GetString(envKey)), nil
	}

	envName, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string, got %T", envKey, raw)
	}

	return strings.TrimSpace(envName), nil
}

func toIncludeFiles(paths []string, required bool) []IncludeFile {
	if len(paths) == 0 {
		return nil
	}

	files := make([]IncludeFile, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}

		files = append(files, IncludeFile{Path: path, Required: required})
	}

	return files
}

// PatchOperation describes a single patch operation.
type PatchOperation struct {
	Op    string `mapstructure:"op"`
	Path  string `mapstructure:"path"`
	Value any    `mapstructure:"value"`
}

// DefaultPatchEngine applies patch operations to settings.
type DefaultPatchEngine struct{}

// Apply runs each patch operation against the target map.
func (DefaultPatchEngine) Apply(target map[string]any, patches []PatchOperation) error {
	for _, patch := range patches {
		if err := applyPatch(target, patch); err != nil {
			return err
		}
	}

	return nil
}

func applyPatch(target map[string]any, patch PatchOperation) error {
	path := strings.TrimSpace(patch.Path)
	if path == "" {
		return errors.New("patch path must not be empty")
	}

	parts := strings.Split(path, ".")
	parent, key, err := resolveParentMap(target, parts, patch.Op != patchOpRemove)
	if err != nil {
		return fmt.Errorf("invalid patch path %q: %w", path, err)
	}

	switch patch.Op {
	case patchOpAdd:
		return applyAdd(parent, key, patch.Value, path)
	case patchOpReplace:
		parent[key] = patch.Value
		return nil
	case patchOpRemove:
		return applyRemove(parent, key, patch.Value, path)
	default:
		return fmt.Errorf("unsupported patch operation %q", patch.Op)
	}
}

func resolveParentMap(root map[string]any, parts []string, create bool) (map[string]any, string, error) {
	if len(parts) == 0 {
		return nil, "", errors.New("path is empty")
	}

	current := root
	for _, part := range parts[:len(parts)-1] {
		if part == "" {
			return nil, "", errors.New("path segment is empty")
		}

		next, ok := current[part]
		if !ok {
			if !create {
				return nil, "", fmt.Errorf("path %q not found", strings.Join(parts, "."))
			}

			nextMap := map[string]any{}
			current[part] = nextMap
			current = nextMap
			continue
		}

		nextMap, ok := next.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("path %q is not a map", strings.Join(parts, "."))
		}

		current = nextMap
	}

	key := parts[len(parts)-1]
	if key == "" {
		return nil, "", errors.New("path segment is empty")
	}

	return current, key, nil
}

func applyAdd(parent map[string]any, key string, value any, fullPath string) error {
	current, ok := parent[key]
	if !ok {
		parent[key] = []any{value}
		return nil
	}

	switch typed := current.(type) {
	case []any:
		parent[key] = append(typed, value)
		return nil
	case map[string]any:
		valueMap, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("add to map at %q requires map value, got %T", fullPath, value)
		}

		for mapKey, mapValue := range valueMap {
			typed[mapKey] = mapValue
		}

		return nil
	default:
		return fmt.Errorf("add operation at %q expects slice or map, got %T", fullPath, current)
	}
}

func applyRemove(parent map[string]any, key string, value any, fullPath string) error {
	current, ok := parent[key]
	if !ok {
		return fmt.Errorf("remove operation at %q failed: path not found", fullPath)
	}

	switch typed := current.(type) {
	case []any:
		filtered := typed[:0]
		for _, item := range typed {
			if !reflect.DeepEqual(item, value) {
				filtered = append(filtered, item)
			}
		}
		parent[key] = filtered
		return nil
	case map[string]any:
		return removeMapKeys(typed, value, fullPath)
	default:
		return fmt.Errorf("remove operation at %q expects slice or map, got %T", fullPath, current)
	}
}

func removeMapKeys(target map[string]any, value any, fullPath string) error {
	switch typed := value.(type) {
	case string:
		delete(target, typed)
		return nil
	case []any:
		for _, item := range typed {
			key, ok := item.(string)
			if !ok {
				return fmt.Errorf("remove operation at %q expects string keys, got %T", fullPath, item)
			}

			delete(target, key)
		}

		return nil
	default:
		return fmt.Errorf("remove operation at %q expects string or []string, got %T", fullPath, value)
	}
}

// MapMerger merges nested map settings recursively.
type MapMerger struct{}

// Merge merges the source map into the target map recursively.
func (MapMerger) Merge(target map[string]any, source map[string]any) {
	for key, value := range source {
		valueMap, ok := value.(map[string]any)
		if !ok {
			target[key] = value
			continue
		}

		if existing, ok := target[key].(map[string]any); ok {
			MapMerger{}.Merge(existing, valueMap)
			target[key] = existing
			continue
		}

		target[key] = value
	}
}

// ViperConfigReader reads configuration settings using Viper.
type ViperConfigReader struct {
	configType string
}

// Read returns the settings from the config file at the given path.
func (r *ViperConfigReader) Read(path string) (map[string]any, error) {
	reader := viper.New()
	reader.SetConfigType(r.configType)
	reader.SetConfigFile(path)

	if err := reader.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	return reader.AllSettings(), nil
}

func loadMergedConfigSettings(configType string) (map[string]any, string, error) {
	rootViper := viper.New()
	configureViper(rootViper, configType)

	if err := rootViper.ReadInConfig(); err != nil {
		return nil, "", err
	}

	rootPath := rootViper.ConfigFileUsed()
	if rootPath == "" {
		rootPath = ConfigFilePath
	}

	loader := NewConfigLoader(configType)
	merged, err := loader.Load(rootPath, rootViper.AllSettings())
	if err != nil {
		return nil, "", err
	}

	return merged, rootPath, nil
}

func applyMergedConfigSettings(settings map[string]any, configType string, rootPath string) error {
	configBytes, err := encodeSettings(settings, configType)
	if err != nil {
		return err
	}

	viper.SetConfigType(configType)
	if rootPath != "" {
		viper.SetConfigFile(rootPath)
	}

	if err := viper.ReadConfig(bytes.NewReader(configBytes)); err != nil {
		return fmt.Errorf("read merged config: %w", err)
	}

	return nil
}

func encodeSettings(settings map[string]any, configType string) ([]byte, error) {
	format := strings.ToLower(strings.TrimSpace(configType))
	switch format {
	case "yaml", "yml", "":
		return yaml.Marshal(settings)
	case "json":
		return jsonMarshal(settings)
	case "toml":
		return toml.Marshal(settings)
	default:
		return nil, fmt.Errorf("unsupported config type %q", configType)
	}
}

func jsonMarshal(value any) ([]byte, error) {
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}

	return bytes.TrimSpace(buf.Bytes()), nil
}

func configureViper(target *viper.Viper, configType string) {
	target.SetConfigType(configType)

	if ConfigFilePath != "" {
		target.SetConfigFile(ConfigFilePath)
		return
	}

	target.SetConfigName("nauthilus")
	target.AddConfigPath(".")
	target.AddConfigPath("$HOME/.nauthilus")
	target.AddConfigPath("/usr/local/etc/nauthilus/")
	target.AddConfigPath("/etc/nauthilus/")
}

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
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

const (
	includeKey = "includes"
	patchKey   = "patch"
	envKey     = "env"
	policyKey  = "policy"

	patchOpAdd     = "add"
	patchOpReplace = "replace"
	patchOpRemove  = "remove"

	maximumDottedPolicyArrayItems = 4096
)

var externalViperDecoderFormats = map[string]struct{}{
	"properties": {},
	"props":      {},
	"prop":       {},
	"hcl":        {},
	"tfvars":     {},
	"ini":        {},
}

type productionConfigDecoderRegistry struct {
	delegate viper.DecoderRegistry `mapstructure:"-"`
}

type boundedConfigDecoder struct {
	format string `mapstructure:"-"`
}

// Decoder selects the bounded fallback only for formats removed from Viper core.
func (r productionConfigDecoderRegistry) Decoder(format string) (viper.Decoder, error) {
	normalized := strings.ToLower(strings.TrimSpace(format))
	if _, exists := externalViperDecoderFormats[normalized]; exists {
		return boundedConfigDecoder{format: normalized}, nil
	}

	return r.delegate.Decoder(normalized)
}

// Decode parses a complete settings tree through the shared bounded raw decoder.
func (d boundedConfigDecoder) Decode(data []byte, target map[string]any) error {
	settings, err := policyconfig.DecodeSettings(d.format, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("decode %s config: %w", d.format, err)
	}

	maps.Copy(target, settings)

	return nil
}

// newProductionConfigViper preserves Viper built-ins and supplies bounded removed-format decoders.
func newProductionConfigViper() *viper.Viper {
	registry := productionConfigDecoderRegistry{delegate: viper.NewCodecRegistry()}

	return viper.NewWithOptions(viper.WithDecoderRegistry(registry))
}

// Reader loads configuration settings from a path.
type Reader interface {
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

// ValueExpander expands string values in a merged settings tree.
type ValueExpander interface {
	Expand(settings map[string]any) error
}

// Loader loads a config tree, resolves includes, and applies patches.
type Loader struct {
	reader          Reader          `mapstructure:"-"`
	includeResolver IncludeResolver `mapstructure:"-"`
	patchEngine     PatchEngine     `mapstructure:"-"`
	merger          SettingsMerger  `mapstructure:"-"`
	valueExpander   ValueExpander   `mapstructure:"-"`
}

// NewConfigLoader returns a Loader configured for the given config type.
func NewConfigLoader(configType string) *Loader {
	return &Loader{
		reader:          &ViperConfigReader{configType: configType},
		includeResolver: IncludeResolverFromConfig{},
		patchEngine:     DefaultPatchEngine{},
		merger:          MapMerger{},
		valueExpander:   NewConfigValueExpander(nil),
	}
}

// LoadFromFile reads the config file and applies includes and patches.
func (l *Loader) LoadFromFile(path string) (map[string]any, error) {
	settings, err := l.reader.Read(path)
	if err != nil {
		return nil, err
	}

	return l.Load(path, settings)
}

// Load applies includes and patches starting from a settings map.
func (l *Loader) Load(path string, settings map[string]any) (map[string]any, error) {
	merged, patches, err := l.loadWithSettings(path, settings, map[string]struct{}{})
	if err != nil {
		return nil, err
	}

	if err := validateConfigDocument(merged); err != nil {
		return nil, fmt.Errorf("validate merged configuration before patches: %w", err)
	}

	if err := l.applyPatchesWithPolicyCutoverValidation(merged, patches); err != nil {
		return nil, err
	}

	if l.valueExpander != nil {
		if err := l.valueExpander.Expand(merged); err != nil {
			return nil, err
		}
	}

	if err := validateConfigDocument(merged); err != nil {
		return nil, fmt.Errorf("validate expanded configuration: %w", err)
	}

	return merged, nil
}

// applyPatchesWithPolicyCutoverValidation rejects stale shapes at the operation that introduces them.
func (l *Loader) applyPatchesWithPolicyCutoverValidation(
	target map[string]any,
	patches []PatchOperation,
) error {
	for index, patch := range patches {
		if err := validatePatchPolicyCutover(patch); err != nil {
			return fmt.Errorf("patch operation %d contains a removed policy shape: %w", index, err)
		}

		if err := l.patchEngine.Apply(target, []PatchOperation{patch}); err != nil {
			return err
		}

		if err := validateConfigDocument(target); err != nil {
			return fmt.Errorf("patch operation %d introduces a removed policy shape: %w", index, err)
		}
	}

	return nil
}

// validatePatchPolicyCutover validates add and replace payloads at their declared path before patch semantics can wrap them.
func validatePatchPolicyCutover(patch PatchOperation) error {
	if patch.Op != patchOpAdd && patch.Op != patchOpReplace {
		return nil
	}

	candidate := make(map[string]any)
	probe := patch
	probe.Op = patchOpReplace

	if err := applyPatch(candidate, probe); err != nil {
		return err
	}

	return validateConfigDocument(candidate)
}

// validateConfigDocument rejects raw and Viper-normalized policy cutover violations from one detached settings tree.
func validateConfigDocument(settings map[string]any) error {
	if _, err := decodePolicyConfiguration(settings); err != nil {
		return err
	}

	policyRoot, exists, err := collectPolicySourceRoot(settings)
	if err != nil {
		return err
	}

	if exists {
		if _, err = decodePolicyConfiguration(map[string]any{policyKey: policyRoot}); err != nil {
			return err
		}
	}

	normalized, err := normalizeConfigDocumentForValidation(settings)
	if err != nil {
		return err
	}

	_, err = decodePolicyConfiguration(normalized)

	return err
}

type policyDeclarationTrie struct {
	children map[string]*policyDeclarationTrie `mapstructure:"-"`
	value    any                               `mapstructure:"-"`
	terminal bool                              `mapstructure:"-"`
}

// collectPolicySourceRoot expands bounded top-level dotted declarations before Viper can fold or discard them.
func collectPolicySourceRoot(settings map[string]any) (any, bool, error) {
	root := &policyDeclarationTrie{}
	found := false

	for rawKey, value := range settings {
		segments, isPolicy, err := policyDeclarationSegments(rawKey)
		if err != nil {
			return nil, false, err
		}

		if !isPolicy {
			continue
		}

		found = true

		if !root.insert(segments, value) {
			return nil, false, NewValidationProblem(
				policyKey,
				"must be declared exactly once after case and dotted-path normalization",
			)
		}
	}

	if !found {
		return nil, false, nil
	}

	value, err := root.materialize(policyKey)
	if err != nil {
		return nil, false, err
	}

	return value, true, nil
}

// policyDeclarationSegments returns normalized descendants for one exact or dotted policy source key.
func policyDeclarationSegments(rawKey string) ([]string, bool, error) {
	key := strings.ToLower(strings.TrimSpace(rawKey))
	if key == policyKey {
		return nil, true, nil
	}

	if !strings.HasPrefix(key, "policy.") {
		return nil, false, nil
	}

	segments := strings.Split(strings.TrimPrefix(key, "policy."), ".")
	for _, segment := range segments {
		if segment == "" {
			return nil, false, NewValidationProblem(
				policyKey,
				"contains an empty dotted-path declaration segment",
			)
		}
	}

	return segments, true, nil
}

// insert records one declaration and rejects duplicate or ancestor-descendant ambiguity.
func (t *policyDeclarationTrie) insert(segments []string, value any) bool {
	current := t
	for _, segment := range segments {
		if current.terminal {
			return false
		}

		if current.children == nil {
			current.children = make(map[string]*policyDeclarationTrie)
		}

		child := current.children[segment]
		if child == nil {
			child = &policyDeclarationTrie{}
			current.children[segment] = child
		}

		current = child
	}

	if current.terminal || len(current.children) > 0 {
		return false
	}

	current.terminal = true
	current.value = value

	return true
}

// materialize converts one conflict-free declaration subtree into bounded maps and indexed slices.
func (t *policyDeclarationTrie) materialize(path string) (any, error) {
	if t.terminal {
		return t.value, nil
	}

	if len(t.children) == 0 {
		return map[string]any{}, nil
	}

	indices := make(map[string]int, len(t.children))
	maximumIndex := -1
	allIndices := true

	for segment := range t.children {
		index, err := strconv.Atoi(segment)
		if err != nil || index < 0 {
			allIndices = false

			break
		}

		if index >= maximumDottedPolicyArrayItems {
			return nil, NewValidationProblem(path, "dotted array index exceeds the bounded configuration limit")
		}

		indices[segment] = index
		maximumIndex = max(maximumIndex, index)
	}

	if allIndices {
		values := make([]any, maximumIndex+1)

		for segment, child := range t.children {
			index := indices[segment]

			value, err := child.materialize(fmt.Sprintf("%s[%d]", path, index))
			if err != nil {
				return nil, err
			}

			values[index] = value
		}

		return values, nil
	}

	values := make(map[string]any, len(t.children))
	for segment, child := range t.children {
		value, err := child.materialize(path + "." + segment)
		if err != nil {
			return nil, err
		}

		values[segment] = value
	}

	return values, nil
}

// normalizeConfigDocumentForValidation applies Viper's case and dotted-key rules without ambient defaults.
func normalizeConfigDocumentForValidation(settings map[string]any) (map[string]any, error) {
	encoded, err := jsonMarshal(settings)
	if err != nil {
		return nil, fmt.Errorf("encode config validation document: %w", err)
	}

	reader := viper.New()
	reader.SetConfigType("json")

	if err = reader.ReadConfig(bytes.NewReader(encoded)); err != nil {
		return nil, fmt.Errorf("normalize config validation document: %w", err)
	}

	normalized := reader.AllSettings()
	preserveCanonicalPolicyTree(normalized, settings)
	preserveEmptyConfigNodes(normalized, settings)

	return normalized, nil
}

func (l *Loader) loadWithSettings(path string, settings map[string]any, visited map[string]struct{}) (map[string]any, []PatchOperation, error) {
	if err := validateConfigDocument(settings); err != nil {
		return nil, nil, fmt.Errorf("reject removed policy shape in config %q: %w", path, err)
	}

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

func (l *Loader) loadFromFile(path string, visited map[string]struct{}) (map[string]any, []PatchOperation, error) {
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
	Path     string `mapstructure:"-"`
	Required bool   `mapstructure:"-"`
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

// resolveEnvName selects an explicit file value or the process environment without ambient Viper state.
func resolveEnvName(root map[string]any) (string, error) {
	raw, ok := root[envKey]
	if !ok {
		return strings.TrimSpace(os.Getenv("NAUTHILUS_ENV")), nil
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

		maps.Copy(typed, valueMap)

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
	afterSnapshot func(string) `mapstructure:"-"`
	configType    string       `mapstructure:"-"`
}

// Read returns the settings from the config file at the given path.
func (r *ViperConfigReader) Read(path string) (map[string]any, error) {
	document, rawSettings, err := readBoundedConfigDocument(path, r.configType)
	if err != nil {
		return nil, err
	}
	defer clear(document)

	if err = validateConfigDocument(rawSettings); err != nil {
		return nil, fmt.Errorf("reject removed policy shape in config %q: %w", path, err)
	}

	if r.afterSnapshot != nil {
		r.afterSnapshot(path)
	}

	reader := newProductionConfigViper()
	reader.SetConfigType(r.configType)

	if err := reader.ReadConfig(bytes.NewReader(document)); err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	settings := reader.AllSettings()
	preserveCanonicalPolicyTree(settings, rawSettings)
	preserveEmptyConfigNodes(settings, rawSettings)

	if err = validateConfigDocument(settings); err != nil {
		return nil, fmt.Errorf("reject normalized removed policy shape in config %q: %w", path, err)
	}

	return settings, nil
}

// preserveCanonicalPolicyTree keeps namespace-owned map identities opaque to Viper's dotted-key expansion.
func preserveCanonicalPolicyTree(target map[string]any, source map[string]any) {
	if policySettings, exists := source[policyKey]; exists {
		target[policyKey] = policySettings

		return
	}

	for key, policySettings := range source {
		if strings.EqualFold(strings.TrimSpace(key), policyKey) {
			target[policyKey] = policySettings

			return
		}
	}
}

// readBoundedConfigSettings retains empty and nil nodes that Viper omits from AllSettings.
func readBoundedConfigSettings(path string, format string) (map[string]any, error) {
	_, settings, err := readBoundedConfigDocument(path, format)

	return settings, err
}

// readBoundedConfigDocument captures the one byte stream shared by strict and Viper decoding.
func readBoundedConfigDocument(path string, format string) ([]byte, map[string]any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open config %q: %w", path, err)
	}

	document := &bytes.Buffer{}
	settings, decodeErr := policyconfig.DecodeSettings(format, io.TeeReader(file, document))
	closeErr := file.Close()

	if decodeErr != nil {
		return nil, nil, fmt.Errorf("decode config %q as %s: %w", path, format, decodeErr)
	}

	if closeErr != nil {
		return nil, nil, fmt.Errorf("close config %q: %w", path, closeErr)
	}

	captured := bytes.Clone(document.Bytes())
	clear(document.Bytes())

	return captured, settings, nil
}

// preserveEmptyConfigNodes restores structurally significant empty and nil values after Viper decoding.
func preserveEmptyConfigNodes(target map[string]any, source map[string]any) {
	for key, sourceValue := range source {
		sourceMap, isMap := sourceValue.(map[string]any)
		if isMap {
			targetMap, exists := target[key].(map[string]any)
			if !exists {
				if len(sourceMap) == 0 {
					target[key] = map[string]any{}

					continue
				}

				recovered := make(map[string]any)
				preserveEmptyConfigNodes(recovered, sourceMap)

				if len(recovered) > 0 {
					target[key] = recovered
				}

				continue
			}

			preserveEmptyConfigNodes(targetMap, sourceMap)

			continue
		}

		if _, exists := target[key]; exists {
			continue
		}

		sourceSlice, isSlice := sourceValue.([]any)
		if sourceValue == nil || (isSlice && len(sourceSlice) == 0) {
			target[key] = sourceValue
		}
	}
}

func loadMergedConfigSettings(configType string) (map[string]any, string, error) {
	rootPath, err := productionRootConfigPath(configType)
	if err != nil {
		return nil, "", err
	}

	loader := NewConfigLoader(configType)

	merged, err := loader.LoadFromFile(rootPath)
	if err != nil {
		return nil, "", err
	}

	return merged, rootPath, nil
}

// productionRootConfigPath locates the root without opening it before exact-byte decoding.
func productionRootConfigPath(configType string) (string, error) {
	if ConfigFilePath != "" {
		return filepath.Clean(ConfigFilePath), nil
	}

	paths := []string{"."}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, ".nauthilus"))
	}

	paths = append(paths, "/usr/local/etc/nauthilus", "/etc/nauthilus")

	for _, directory := range paths {
		for _, extension := range viper.SupportedExts {
			path := filepath.Join(directory, "nauthilus."+extension)
			if regularConfigFile(path) {
				return filepath.Clean(path), nil
			}
		}

		if strings.TrimSpace(configType) != "" {
			path := filepath.Join(directory, "nauthilus")
			if regularConfigFile(path) {
				return filepath.Clean(path), nil
			}
		}
	}

	return "", &os.PathError{Op: "open", Path: "nauthilus", Err: fs.ErrNotExist}
}

// regularConfigFile reports whether one discovery candidate is an existing non-directory.
func regularConfigFile(path string) bool {
	info, err := os.Stat(path)

	return err == nil && !info.IsDir()
}

// applyMergedConfigSettings decodes merged settings into the legacy global Viper owner.
func applyMergedConfigSettings(settings map[string]any, configType string, rootPath string) error {
	return applyMergedConfigSettingsTo(viper.GetViper(), settings, configType, rootPath)
}

// applyMergedConfigSettingsTo decodes merged settings into one isolated Viper owner.
func applyMergedConfigSettingsTo(
	target *viper.Viper,
	settings map[string]any,
	configType string,
	rootPath string,
) error {
	configBytes, err := encodeMergedSettings(settings)
	if err != nil {
		return err
	}

	target.SetConfigType("json")

	if rootPath != "" {
		target.SetConfigFile(rootPath)
	}

	if err := target.ReadConfig(bytes.NewReader(configBytes)); err != nil {
		return fmt.Errorf("read merged config: %w", err)
	}

	target.SetConfigType(configType)

	return nil
}

// encodeMergedSettings uses one format-independent intermediate representation for Viper publication.
func encodeMergedSettings(settings map[string]any) ([]byte, error) {
	return jsonMarshal(settings)
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

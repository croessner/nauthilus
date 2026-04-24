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
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/croessner/nauthilus/server/secret"
)

type configSchemaKind uint8

const (
	configSchemaScalar configSchemaKind = iota
	configSchemaObject
	configSchemaList
	configSchemaMap
)

type configSchemaNode struct {
	kind              configSchemaKind             `mapstructure:"-"`
	fieldByConfigName map[string]*configSchemaNode `mapstructure:"-"`
	element           *configSchemaNode            `mapstructure:"-"`
	typeInfo          reflect.Type                 `mapstructure:"-"`
	matchExtraKey     func(string) bool            `mapstructure:"-"`
}

type configSchemaIndex struct {
	root *configSchemaNode `mapstructure:"-"`
}

var (
	configSchemaIndexOnce sync.Once
	configSchemaIndexRef  *configSchemaIndex
	configSchemaIndexErr  error
)

func getConfigSchemaIndex() (*configSchemaIndex, error) {
	configSchemaIndexOnce.Do(func() {
		root, err := buildConfigSchemaNode(reflect.TypeFor[FileSettings]())
		if err != nil {
			configSchemaIndexErr = err

			return
		}

		configSchemaIndexRef = &configSchemaIndex{root: root}
	})

	return configSchemaIndexRef, configSchemaIndexErr
}

// KnownConfigSyntaxKeys returns the known configuration keys grouped for Vim syntax generation.
func KnownConfigSyntaxKeys() ([]string, []string, []string, error) {
	schemaIndex, err := getConfigSchemaIndex()
	if err != nil {
		return nil, nil, nil, err
	}

	roots := make(map[string]struct{})
	level2 := make(map[string]struct{})
	level3 := make(map[string]struct{})

	collectKnownConfigSyntaxKeys(schemaIndex.root, 1, roots, level2, level3)

	return sortedSyntaxKeys(roots), sortedSyntaxKeys(level2), sortedSyntaxKeys(level3), nil
}

func collectKnownConfigSyntaxKeys(
	node *configSchemaNode,
	depth int,
	roots map[string]struct{},
	level2 map[string]struct{},
	level3 map[string]struct{},
) {
	if node == nil {
		return
	}

	switch node.kind {
	case configSchemaObject:
		for key, child := range node.fieldByConfigName {
			addKnownConfigSyntaxKey(depth, key, roots, level2, level3)
			collectKnownConfigSyntaxKeys(child, depth+1, roots, level2, level3)
		}
	case configSchemaList, configSchemaMap:
		collectKnownConfigSyntaxKeys(node.element, depth+1, roots, level2, level3)
	}
}

func addKnownConfigSyntaxKey(
	depth int,
	key string,
	roots map[string]struct{},
	level2 map[string]struct{},
	level3 map[string]struct{},
) {
	switch depth {
	case 1:
		roots[key] = struct{}{}
	case 2:
		level2[key] = struct{}{}
	default:
		level3[key] = struct{}{}
	}
}

func sortedSyntaxKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

func buildConfigSchemaNode(rawType reflect.Type) (*configSchemaNode, error) {
	typ := dereferenceConfigType(rawType)
	if typ == nil {
		return &configSchemaNode{kind: configSchemaScalar}, nil
	}

	if isConfigScalarType(typ) {
		return newScalarSchemaNode(typ), nil
	}

	switch typ.Kind() {
	case reflect.Struct:
		return buildStructSchemaNode(typ)
	case reflect.Slice, reflect.Array:
		return buildCollectionSchemaNode(configSchemaList, typ)
	case reflect.Map:
		return buildCollectionSchemaNode(configSchemaMap, typ)
	default:
		return newScalarSchemaNode(typ), nil
	}
}

func newScalarSchemaNode(typ reflect.Type) *configSchemaNode {
	return &configSchemaNode{
		kind:     configSchemaScalar,
		typeInfo: typ,
	}
}

func buildStructSchemaNode(typ reflect.Type) (*configSchemaNode, error) {
	node := &configSchemaNode{
		kind:              configSchemaObject,
		fieldByConfigName: make(map[string]*configSchemaNode),
		typeInfo:          typ,
		matchExtraKey:     extraKeyMatcherForType(typ),
	}

	for field := range typ.Fields() {
		if err := addStructFieldSchemaNode(node, field); err != nil {
			return nil, err
		}
	}

	return node, nil
}

func addStructFieldSchemaNode(node *configSchemaNode, field reflect.StructField) error {
	tagName, tagOptions, err := parseMapstructureTag(field)
	if err != nil {
		return err
	}

	if tagName == "-" || slices.Contains(tagOptions, "remain") {
		return nil
	}

	childNode, err := buildConfigSchemaNode(field.Type)
	if err != nil {
		return err
	}

	node.fieldByConfigName[tagName] = childNode

	return nil
}

func buildCollectionSchemaNode(kind configSchemaKind, typ reflect.Type) (*configSchemaNode, error) {
	element, err := buildConfigSchemaNode(typ.Elem())
	if err != nil {
		return nil, err
	}

	return &configSchemaNode{
		kind:     kind,
		element:  element,
		typeInfo: typ,
	}, nil
}

func parseMapstructureTag(field reflect.StructField) (string, []string, error) {
	tagValue, ok := field.Tag.Lookup("mapstructure")
	if !ok {
		return "", nil, fmt.Errorf("field %s.%s is missing a mapstructure tag", field.Type, field.Name)
	}

	parts := strings.Split(tagValue, ",")
	name := parts[0]
	if name == "" && len(parts) == 1 {
		return "", nil, fmt.Errorf("field %s.%s has an empty mapstructure tag", field.Type, field.Name)
	}

	return name, parts[1:], nil
}

func unknownConfigParameters(settings map[string]any) ([]string, error) {
	if len(settings) == 0 {
		return nil, nil
	}

	schemaIndex, err := getConfigSchemaIndex()
	if err != nil {
		return nil, err
	}

	unknown := make([]string, 0)
	schemaIndex.root.collectUnknown(settings, "", &unknown, make(map[uintptr]struct{}))
	if len(unknown) == 0 {
		return nil, nil
	}

	sort.Strings(unknown)

	return slices.Compact(unknown), nil
}

func (n *configSchemaNode) collectUnknown(value any, prefix string, out *[]string, visited map[uintptr]struct{}) {
	if n == nil || out == nil || value == nil {
		return
	}

	switch n.kind {
	case configSchemaObject:
		entries, ok := configMapEntries(value)
		if !ok {
			return
		}

		for _, entry := range entries {
			childPath := joinConfigPath(prefix, entry.key)
			childNode, ok := n.fieldByConfigName[entry.key]
			if ok {
				childNode.collectUnknown(entry.value, childPath, out, visited)

				continue
			}

			if n.matchExtraKey != nil && n.matchExtraKey(entry.key) {
				continue
			}

			collectUnknownConfigValuePaths(childPath, entry.value, out, 0, visited)
		}
	case configSchemaList:
		elements, ok := value.([]any)
		if !ok {
			return
		}

		for index := range elements {
			childPath := fmt.Sprintf("%s[%d]", prefix, index)
			n.element.collectUnknown(elements[index], childPath, out, visited)
		}
	case configSchemaMap:
		entries, ok := configMapEntries(value)
		if !ok {
			return
		}

		for _, entry := range entries {
			childPath := joinConfigPath(prefix, entry.key)
			n.element.collectUnknown(entry.value, childPath, out, visited)
		}
	}
}

func (i *configSchemaIndex) configPathFromStructNamespace(namespace string) string {
	if namespace == "" {
		return ""
	}

	currentType := dereferenceConfigType(reflect.TypeFor[FileSettings]())
	if currentType == nil {
		return namespace
	}

	segments := strings.Split(namespace, ".")
	if len(segments) > 0 && segments[0] == currentType.Name() {
		segments = segments[1:]
	}

	if len(segments) == 0 {
		return ""
	}

	var path strings.Builder

	for _, segment := range segments {
		fieldName, suffix := splitStructNamespaceSegment(segment)
		if fieldName == "" {
			return namespace
		}

		currentType = dereferenceConfigType(currentType)
		if currentType == nil || currentType.Kind() != reflect.Struct {
			return namespace
		}

		field, ok := currentType.FieldByName(fieldName)
		if !ok {
			return namespace
		}

		tagName, _, err := parseMapstructureTag(field)
		if err != nil || tagName == "" || tagName == "-" {
			return namespace
		}

		if path.Len() > 0 {
			path.WriteByte('.')
		}

		path.WriteString(tagName)
		path.WriteString(suffix)

		currentType = advanceConfigType(field.Type, suffix)
	}

	return path.String()
}

func splitStructNamespaceSegment(segment string) (string, string) {
	index := strings.IndexByte(segment, '[')
	if index == -1 {
		return segment, ""
	}

	return segment[:index], segment[index:]
}

func advanceConfigType(rawType reflect.Type, suffix string) reflect.Type {
	typ := dereferenceConfigType(rawType)
	if typ == nil {
		return nil
	}

	if suffix == "" {
		return typ
	}

	for suffix != "" {
		switch typ.Kind() {
		case reflect.Slice, reflect.Array:
			typ = dereferenceConfigType(typ.Elem())
		case reflect.Map:
			typ = dereferenceConfigType(typ.Elem())
		default:
			return typ
		}

		nextIndex := strings.IndexByte(suffix[1:], '[')
		if nextIndex == -1 {
			break
		}

		suffix = suffix[nextIndex+1:]
	}

	return typ
}

func dereferenceConfigType(rawType reflect.Type) reflect.Type {
	typ := rawType
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	return typ
}

func joinConfigPath(prefix string, key string) string {
	if prefix == "" {
		return key
	}

	return prefix + "." + key
}

func extraKeyMatcherForType(typ reflect.Type) func(string) bool {
	switch typ {
	case reflect.TypeFor[FileSettings]():
		return isSupportedRootExtraKey
	case reflect.TypeFor[Oauth2CustomScope]():
		return isSupportedCustomScopeExtraKey
	default:
		return nil
	}
}

func isConfigScalarType(typ reflect.Type) bool {
	switch typ {
	case reflect.TypeFor[Backend](),
		reflect.TypeFor[ContentSecurityPolicyValue](),
		reflect.TypeFor[Control](),
		reflect.TypeFor[DbgModule](),
		reflect.TypeFor[Feature](),
		reflect.TypeFor[LDAPScope](),
		reflect.TypeFor[PermissionsPolicyValue](),
		reflect.TypeFor[Protocol](),
		reflect.TypeFor[secret.Value](),
		reflect.TypeFor[Service](),
		reflect.TypeFor[StrictTransportSecurityValue](),
		reflect.TypeFor[Verbosity]():
		return true
	default:
		return false
	}
}

type configMapEntry struct {
	key   string `mapstructure:"-"`
	value any    `mapstructure:"-"`
}

func configMapEntries(value any) ([]configMapEntry, bool) {
	switch typed := value.(type) {
	case map[string]any:
		entries := make([]configMapEntry, 0, len(typed))
		for key, nested := range typed {
			entries = append(entries, configMapEntry{key: key, value: nested})
		}

		return entries, true
	case map[any]any:
		entries := make([]configMapEntry, 0, len(typed))
		for key, nested := range typed {
			entries = append(entries, configMapEntry{key: fmt.Sprintf("%v", key), value: nested})
		}

		return entries, true
	default:
		return nil, false
	}
}

const maxUnknownConfigTraversalDepth = 64

func collectUnknownConfigValuePaths(prefix string, value any, out *[]string, depth int, visited map[uintptr]struct{}) {
	if out == nil || value == nil {
		return
	}

	if depth >= maxUnknownConfigTraversalDepth {
		appendUnknownPath(prefix, out)

		return
	}

	switch typed := value.(type) {
	case map[string]any:
		collectUnknownStringMapPaths(prefix, typed, out, depth, visited)
	case map[any]any:
		collectUnknownAnyMapPaths(prefix, typed, out, depth, visited)
	case []any:
		if len(typed) == 0 {
			appendUnknownPath(prefix, out)

			return
		}

		for index := range typed {
			collectUnknownConfigValuePaths(fmt.Sprintf("%s[%d]", prefix, index), typed[index], out, depth+1, visited)
		}
	default:
		appendUnknownPath(prefix, out)
	}
}

func collectUnknownStringMapPaths(
	prefix string,
	value map[string]any,
	out *[]string,
	depth int,
	visited map[uintptr]struct{},
) {
	if !enterUnknownMap(value, prefix, out, visited) {
		return
	}
	defer leaveUnknownMap(value, visited)

	if len(value) == 0 {
		appendUnknownPath(prefix, out)

		return
	}

	for key, nested := range value {
		collectUnknownConfigValuePaths(joinConfigPath(prefix, key), nested, out, depth+1, visited)
	}
}

func collectUnknownAnyMapPaths(
	prefix string,
	value map[any]any,
	out *[]string,
	depth int,
	visited map[uintptr]struct{},
) {
	if !enterUnknownMap(value, prefix, out, visited) {
		return
	}
	defer leaveUnknownMap(value, visited)

	if len(value) == 0 {
		appendUnknownPath(prefix, out)

		return
	}

	for key, nested := range value {
		collectUnknownConfigValuePaths(joinConfigPath(prefix, fmt.Sprintf("%v", key)), nested, out, depth+1, visited)
	}
}

func appendUnknownPath(prefix string, out *[]string) {
	if prefix != "" {
		*out = append(*out, prefix)
	}
}

func enterUnknownMap(value any, prefix string, out *[]string, visited map[uintptr]struct{}) bool {
	pointer := reflect.ValueOf(value).Pointer()
	if _, ok := visited[pointer]; ok {
		appendUnknownPath(prefix, out)

		return false
	}

	visited[pointer] = struct{}{}

	return true
}

func leaveUnknownMap(value any, visited map[uintptr]struct{}) {
	delete(visited, reflect.ValueOf(value).Pointer())
}

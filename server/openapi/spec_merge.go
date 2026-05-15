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

//go:build auth_basic_endpoint

package openapi

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

func mustMergeYAMLDocuments(base []byte, overlays ...[]byte) []byte {
	baseDocument := mustDecodeYAMLDocument(base)
	baseMapping := mustYAMLDocumentMapping(baseDocument)

	for _, overlay := range overlays {
		overlayDocument := mustDecodeYAMLDocument(overlay)
		mergeYAMLMapping(baseMapping, mustYAMLDocumentMapping(overlayDocument))
	}

	rendered, err := yaml.Marshal(baseDocument)
	if err != nil {
		panic(fmt.Sprintf("failed to render merged OpenAPI YAML: %v", err))
	}

	return rendered
}

func mustDecodeYAMLDocument(content []byte) *yaml.Node {
	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil {
		panic(fmt.Sprintf("invalid OpenAPI YAML overlay: %v", err))
	}

	return &document
}

func mustYAMLDocumentMapping(document *yaml.Node) *yaml.Node {
	if document == nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		panic("OpenAPI YAML document must contain one mapping root")
	}

	return document.Content[0]
}

func mergeYAMLMapping(destination *yaml.Node, overlay *yaml.Node) {
	for index := 0; index < len(overlay.Content); index += 2 {
		overlayKey := overlay.Content[index]
		overlayValue := overlay.Content[index+1]
		destinationValue := findYAMLMappingValue(destination, overlayKey.Value)

		if destinationValue != nil && destinationValue.Kind == yaml.MappingNode && overlayValue.Kind == yaml.MappingNode {
			mergeYAMLMapping(destinationValue, overlayValue)

			continue
		}

		destination.Content = append(destination.Content, cloneYAMLNode(overlayKey), cloneYAMLNode(overlayValue))
	}
}

func findYAMLMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}

	for index := 0; index < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}

	return nil
}

func cloneYAMLNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}

	copied := *node
	if len(node.Content) == 0 {
		return &copied
	}

	copied.Content = make([]*yaml.Node, 0, len(node.Content))
	for _, child := range node.Content {
		copied.Content = append(copied.Content, cloneYAMLNode(child))
	}

	return &copied
}

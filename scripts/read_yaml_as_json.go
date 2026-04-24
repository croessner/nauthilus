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

// Command read_yaml_as_json converts YAML input into order-preserving JSON for converter tooling.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./scripts/read_yaml_as_json.go <input.yml>")
		os.Exit(1)
	}

	inputPath := os.Args[1]

	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %s: %v\n", inputPath, err)
		os.Exit(1)
	}

	var document yaml.Node

	if err = yaml.Unmarshal(data, &document); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse YAML %s: %v\n", inputPath, err)
		os.Exit(1)
	}

	if len(document.Content) != 1 {
		fmt.Fprintf(os.Stderr, "expected exactly one YAML document in %s\n", inputPath)
		os.Exit(1)
	}

	var output bytes.Buffer
	if err = writeJSONNode(&output, document.Content[0]); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode JSON for %s: %v\n", inputPath, err)
		os.Exit(1)
	}

	output.WriteByte('\n')
	fmt.Print(output.String())
}

func writeJSONNode(buffer *bytes.Buffer, node *yaml.Node) error {
	if node == nil {
		buffer.WriteString("null")

		return nil
	}

	if node.Kind == yaml.AliasNode {
		return writeJSONNode(buffer, node.Alias)
	}

	switch node.Kind {
	case yaml.DocumentNode:
		return writeJSONDocumentNode(buffer, node)
	case yaml.MappingNode:
		return writeJSONMapNode(buffer, node)
	case yaml.SequenceNode:
		return writeJSONSequenceNode(buffer, node)
	case yaml.ScalarNode:
		return writeJSONScalar(buffer, node)
	default:
		return fmt.Errorf("unsupported YAML node kind %d", node.Kind)
	}
}

func writeJSONDocumentNode(buffer *bytes.Buffer, node *yaml.Node) error {
	if len(node.Content) != 1 {
		return fmt.Errorf("document nodes must contain exactly one child")
	}

	return writeJSONNode(buffer, node.Content[0])
}

func writeJSONMapNode(buffer *bytes.Buffer, node *yaml.Node) error {
	buffer.WriteByte('{')

	for index := 0; index < len(node.Content); index += 2 {
		if index > 0 {
			buffer.WriteByte(',')
		}

		if err := writeJSONMapEntry(buffer, node.Content[index], node.Content[index+1]); err != nil {
			return err
		}
	}

	buffer.WriteByte('}')

	return nil
}

func writeJSONMapEntry(buffer *bytes.Buffer, keyNode *yaml.Node, valueNode *yaml.Node) error {
	keyJSON, err := json.Marshal(keyNode.Value)
	if err != nil {
		return fmt.Errorf("encode mapping key %q: %w", keyNode.Value, err)
	}

	buffer.Write(keyJSON)
	buffer.WriteByte(':')

	return writeJSONNode(buffer, valueNode)
}

func writeJSONSequenceNode(buffer *bytes.Buffer, node *yaml.Node) error {
	buffer.WriteByte('[')

	for index, child := range node.Content {
		if index > 0 {
			buffer.WriteByte(',')
		}

		if err := writeJSONNode(buffer, child); err != nil {
			return err
		}
	}

	buffer.WriteByte(']')

	return nil
}

func writeJSONScalar(buffer *bytes.Buffer, node *yaml.Node) error {
	var decoded any
	if err := node.Decode(&decoded); err != nil {
		return fmt.Errorf("decode scalar %q: %w", node.Value, err)
	}

	encoded, err := json.Marshal(decoded)
	if err != nil {
		return fmt.Errorf("encode scalar %q: %w", node.Value, err)
	}

	buffer.Write(encoded)

	return nil
}

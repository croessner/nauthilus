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

package compiler

import (
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
)

// registerGeneratedNamedAttributes registers generated attributes for uniquely named config entries.
func registerGeneratedNamedAttributes[T any](
	registry *policyregistry.AttributeRegistry,
	items []T,
	configPath string,
	duplicateKind string,
	nameOf func(T) string,
	attributesFor func(string, string) []policyregistry.AttributeDefinition,
) error {
	seen := make(map[string]string)

	for index, item := range items {
		name := strings.TrimSpace(nameOf(item))
		if name == "" {
			return configPathError(fmt.Sprintf("%s[%d].name", configPath, index), "must not be empty")
		}

		identifier := policy.IdentifierSegment(name)
		if previous, exists := seen[identifier]; exists {
			return configPathError(
				fmt.Sprintf("%s[%d].name", configPath, index),
				fmt.Sprintf("normalizes to policy identifier %q already used by %s %q", identifier, duplicateKind, previous),
			)
		}

		seen[identifier] = name

		if err := registerGeneratedAttributes(registry, attributesFor(identifier, name)); err != nil {
			return err
		}
	}

	return nil
}

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

package registry

import (
	"context"
	"fmt"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

const builtinTargetContributorID = "builtin.authn"

type builtinTargetContributor struct{}

// NewBuiltinTargetContributor returns the internal authn definition contributor.
func NewBuiltinTargetContributor() Contributor {
	return builtinTargetContributor{}
}

// Contribute returns inactive authn target and exact schema definitions.
func (builtinTargetContributor) Contribute(ctx context.Context) (DefinitionContribution, error) {
	if err := ctx.Err(); err != nil {
		return DefinitionContribution{}, err
	}

	ownership, err := NewNamespaceOwnership(builtinTargetContributorID, []string{"authn"})
	if err != nil {
		return DefinitionContribution{}, err
	}

	targets := make([]TargetDefinition, 0, len(builtinAuthnActions()))
	schemas := make([]SchemaDefinition, 0, len(builtinAuthnActions()))

	for _, action := range builtinAuthnActions() {
		schemaIdentity, schemaErr := NewSchemaIdentity("authn", action, "v1")
		if schemaErr != nil {
			return DefinitionContribution{}, schemaErr
		}

		schema, schemaErr := NewSchemaDefinition(schemaIdentity, nil)
		if schemaErr != nil {
			return DefinitionContribution{}, schemaErr
		}

		target, targetErr := decision.NewTarget("authn", action)
		if targetErr != nil {
			return DefinitionContribution{}, targetErr
		}

		targetDefinition, targetErr := NewTargetDefinition(target, []SchemaIdentity{schemaIdentity})
		if targetErr != nil {
			return DefinitionContribution{}, targetErr
		}

		schemas = append(schemas, schema)
		targets = append(targets, targetDefinition)
	}

	contribution, err := NewDefinitionContribution(ownership, targets, schemas)
	if err != nil {
		return DefinitionContribution{}, fmt.Errorf("build builtin target contribution: %w", err)
	}

	return contribution, nil
}

// builtinAuthnActions returns the exact initial authentication action vocabulary.
func builtinAuthnActions() []string {
	return []string{"authenticate", "lookup_identity", "list_accounts"}
}

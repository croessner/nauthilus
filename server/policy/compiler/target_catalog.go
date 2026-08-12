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
	"context"
	"errors"
	"fmt"

	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

var (
	// ErrDefinitionCollision identifies equal contributed identities without precedence.
	ErrDefinitionCollision = errors.New("policy catalog definition collision")

	// ErrDuplicateContributor identifies repeated contributor identities.
	ErrDuplicateContributor = errors.New("duplicate policy catalog contributor")

	// ErrUnknownTargetDefinition identifies activation of an uncontributed target.
	ErrUnknownTargetDefinition = errors.New("unknown policy target definition")

	// ErrUnknownSchemaDefinition identifies activation of an uncontributed exact schema.
	ErrUnknownSchemaDefinition = errors.New("unknown policy schema definition")

	// ErrDuplicateTargetActivation identifies repeated activation of one exact target.
	ErrDuplicateTargetActivation = errors.New("duplicate policy target activation")

	// ErrUnknownActivatedTarget identifies an admission reference to an inactive target.
	ErrUnknownActivatedTarget = errors.New("unknown activated policy target")

	// ErrAdmissionSchemaMismatch identifies an admission reference to a different schema version.
	ErrAdmissionSchemaMismatch = errors.New("policy admission schema does not match activated schema")
)

// TargetCatalogCompiler builds immutable target/schema candidates without publishing them.
type TargetCatalogCompiler struct {
	contributors []registry.Contributor
}

type collectedCatalogDefinitions struct {
	targets map[string]ownedTargetDefinition
	schemas map[string]ownedSchemaDefinition
	claims  map[string]string
}

type ownedTargetDefinition struct {
	definition registry.TargetDefinition
}

type ownedSchemaDefinition struct {
	definition registry.SchemaDefinition
}

// NewTargetCatalogCompiler owns the ordered contributor adapters for one candidate build.
func NewTargetCatalogCompiler(contributors ...registry.Contributor) *TargetCatalogCompiler {
	return &TargetCatalogCompiler{contributors: append([]registry.Contributor(nil), contributors...)}
}

// Compile collects definitions and compiles only explicitly activated target/schema records.
func (c *TargetCatalogCompiler) Compile(
	ctx context.Context,
	activations []registry.TargetActivation,
) (*policyruntime.TargetCatalog, error) {
	definitions, err := c.collectDefinitions(ctx)
	if err != nil {
		return nil, err
	}

	records, err := compileActivatedRecords(definitions, activations)
	if err != nil {
		return nil, err
	}

	catalog, err := policyruntime.NewTargetCatalog(records)
	if err != nil {
		return nil, fmt.Errorf("compile target catalog candidate: %w", err)
	}

	return catalog, nil
}

// ValidateAdmissionReferences validates future client references without mutating or activating the catalog.
func ValidateAdmissionReferences(
	catalog *policyruntime.TargetCatalog,
	references []registry.ClientAdmissionReference,
) error {
	seen := make(map[string]struct{}, len(references))

	for _, reference := range references {
		identity := reference.Target().String() + "@" + reference.Schema().String()
		if _, exists := seen[identity]; exists {
			return fmt.Errorf("%s: duplicate client admission reference %s", reference.Path(), identity)
		}

		seen[identity] = struct{}{}

		compiled, ok := catalog.Lookup(reference.Target())
		if !ok {
			return fmt.Errorf("%w: %s: %s", ErrUnknownActivatedTarget, reference.Path(), reference.Target().String())
		}

		if compiled.Schema().Identity().String() != reference.Schema().String() {
			return fmt.Errorf(
				"%w: %s: activated %s, referenced %s",
				ErrAdmissionSchemaMismatch,
				reference.Path(),
				compiled.Schema().Identity().String(),
				reference.Schema().String(),
			)
		}
	}

	return nil
}

// collectDefinitions obtains one immutable batch per contributor and rejects all collisions.
func (c *TargetCatalogCompiler) collectDefinitions(ctx context.Context) (collectedCatalogDefinitions, error) {
	definitions := collectedCatalogDefinitions{
		targets: make(map[string]ownedTargetDefinition),
		schemas: make(map[string]ownedSchemaDefinition),
		claims:  make(map[string]string),
	}

	if c == nil {
		return definitions, nil
	}

	owners := make(map[string]struct{}, len(c.contributors))

	for index, contributor := range c.contributors {
		if contributor == nil {
			return collectedCatalogDefinitions{}, fmt.Errorf("catalog.contributors[%d]: contributor is nil", index)
		}

		if err := ctx.Err(); err != nil {
			return collectedCatalogDefinitions{}, err
		}

		contribution, err := contributor.Contribute(ctx)
		if err != nil {
			return collectedCatalogDefinitions{}, fmt.Errorf("catalog.contributors[%d]: %w", index, err)
		}

		if err := contribution.Validate(); err != nil {
			return collectedCatalogDefinitions{}, fmt.Errorf("catalog.contributors[%d]: %w", index, err)
		}

		owner := contribution.Ownership().Owner()
		if _, exists := owners[owner]; exists {
			return collectedCatalogDefinitions{}, fmt.Errorf("%w: %s", ErrDuplicateContributor, owner)
		}

		owners[owner] = struct{}{}

		if err := collectContributionDefinitions(&definitions, contribution); err != nil {
			return collectedCatalogDefinitions{}, err
		}
	}

	return definitions, nil
}

// collectContributionDefinitions inserts all contribution kinds through one collision path.
func collectContributionDefinitions(
	definitions *collectedCatalogDefinitions,
	contribution registry.DefinitionContribution,
) error {
	owner := contribution.Ownership().Owner()

	err := collectDefinitionKind(
		definitions,
		"target",
		owner,
		contribution.Targets(),
		func(target registry.TargetDefinition) string { return target.Target().String() },
		func(identity string, target registry.TargetDefinition) {
			definitions.targets[identity] = ownedTargetDefinition{definition: target}
		},
	)
	if err != nil {
		return err
	}

	return collectDefinitionKind(
		definitions,
		"schema",
		owner,
		contribution.Schemas(),
		func(schema registry.SchemaDefinition) string { return schema.Identity().String() },
		func(identity string, schema registry.SchemaDefinition) {
			definitions.schemas[identity] = ownedSchemaDefinition{definition: schema}
		},
	)
}

// collectDefinitionKind inserts one definition kind without replacement or precedence.
func collectDefinitionKind[T any](
	definitions *collectedCatalogDefinitions,
	kind string,
	owner string,
	values []T,
	identityOf func(T) string,
	store func(string, T),
) error {
	for _, value := range values {
		identity := identityOf(value)
		if err := definitions.claim(kind, identity, owner); err != nil {
			return err
		}

		store(identity, value)
	}

	return nil
}

// compileActivatedRecords resolves exact contributed identities into runtime-owned records.
func compileActivatedRecords(
	definitions collectedCatalogDefinitions,
	activations []registry.TargetActivation,
) ([]policyruntime.TargetCatalogRecord, error) {
	records := make([]policyruntime.TargetCatalogRecord, 0, len(activations))
	activated := make(map[string]struct{}, len(activations))

	for _, activation := range activations {
		targetIdentity := activation.Target().String()
		if _, exists := activated[targetIdentity]; exists {
			return nil, fmt.Errorf("%w: %s: %s", ErrDuplicateTargetActivation, activation.Path(), targetIdentity)
		}

		activated[targetIdentity] = struct{}{}

		target, ok := definitions.targets[targetIdentity]
		if !ok {
			return nil, fmt.Errorf("%w: %s: %s", ErrUnknownTargetDefinition, activation.Path(), targetIdentity)
		}

		schemaIdentity := activation.Schema().String()

		schema, ok := definitions.schemas[schemaIdentity]
		if !ok || !target.definition.Supports(activation.Schema()) {
			return nil, fmt.Errorf("%w: %s.schema: %s", ErrUnknownSchemaDefinition, activation.Path(), schemaIdentity)
		}

		records = append(records, policyruntime.TargetCatalogRecord{
			Target: activation.Target(),
			Schema: schema.definition,
		})
	}

	return records, nil
}

// claim rejects an exact definition collision without choosing an owner.
func (d *collectedCatalogDefinitions) claim(kind string, identity string, owner string) error {
	claimIdentity := kind + ":" + identity
	if existingOwner, exists := d.claims[claimIdentity]; exists {
		return definitionCollision(kind, identity, existingOwner, owner)
	}

	d.claims[claimIdentity] = owner

	return nil
}

// definitionCollision reports both owners and never chooses a precedence winner.
func definitionCollision(kind string, identity string, firstOwner string, secondOwner string) error {
	return fmt.Errorf(
		"%w: %s %s contributed by both %s and %s",
		ErrDefinitionCollision,
		kind,
		identity,
		firstOwner,
		secondOwner,
	)
}

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
	"fmt"
	"slices"
	"sort"
	"strings"

	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

const builtinAuthnExtensionSchemaVersion = "v1"

// ExtendBuiltinAuthnSchemas adds real bound Lua and native provider outputs to exact builtin authn schemas.
func ExtendBuiltinAuthnSchemas(
	builtin DefinitionContribution,
	extensions ...DefinitionContribution,
) (DefinitionContribution, error) {
	return extendBuiltinAuthnSchemas(builtin, func(
		actions map[string]struct{},
		additions map[string]map[string]FactSchema,
	) error {
		for index, extension := range extensions {
			if err := collectBuiltinAuthnExtensionFacts(actions, additions, extension); err != nil {
				return fmt.Errorf("authn extension contribution %d: %w", index, err)
			}
		}

		return nil
	}, "compose builtin authn extension schemas")
}

type builtinAuthnSchemaCollector func(
	actions map[string]struct{},
	additions map[string]map[string]FactSchema,
) error

// extendBuiltinAuthnSchemas owns the shared immutable schema-extension transaction.
func extendBuiltinAuthnSchemas(
	builtin DefinitionContribution,
	collect builtinAuthnSchemaCollector,
	composeContext string,
) (DefinitionContribution, error) {
	actions, err := validateBuiltinAuthnSchemaContribution(builtin)
	if err != nil {
		return DefinitionContribution{}, err
	}

	additions := make(map[string]map[string]FactSchema, len(actions))
	if err = collect(actions, additions); err != nil {
		return DefinitionContribution{}, err
	}

	schemas, err := extendBuiltinAuthnSchemaDefinitions(builtin.Schemas(), additions)
	if err != nil {
		return DefinitionContribution{}, err
	}

	composed, err := NewCompleteDefinitionContribution(DefinitionContributionInput{
		Ownership:  builtin.Ownership(),
		Targets:    builtin.Targets(),
		Schemas:    schemas,
		PolicySets: builtin.PolicySets(),
		Plans:      builtin.Plans(),
		Providers:  builtin.Providers(),
		Effects:    builtin.Effects(),
	})
	if err != nil {
		return DefinitionContribution{}, fmt.Errorf("%s: %w", composeContext, err)
	}

	return composed, nil
}

// validateBuiltinAuthnSchemaContribution verifies the immutable builtin target/schema envelope.
func validateBuiltinAuthnSchemaContribution(builtin DefinitionContribution) (map[string]struct{}, error) {
	if err := builtin.Validate(); err != nil {
		return nil, fmt.Errorf("validate builtin authn contribution: %w", err)
	}

	ownership := builtin.Ownership()
	if ownership.Owner() != builtinTargetContributorID ||
		!slices.Equal(ownership.Namespaces(), []string{policy.AuthnNamespace}) {
		return nil, newValidationError(
			ErrInvalidContribution,
			"builtin.authn",
			ownership.Owner(),
			"must be the exact immutable builtin authn contribution",
		)
	}

	actions := make(map[string]struct{}, len(builtinAuthnActions()))
	for _, action := range builtinAuthnActions() {
		actions[action] = struct{}{}
	}

	schemas := builtin.Schemas()
	if len(schemas) != len(actions) {
		return nil, invalidBuiltinAuthnSchemaContribution("must contain every exact builtin authn schema")
	}

	seen := make(map[string]struct{}, len(schemas))
	for _, schema := range schemas {
		identity := schema.Identity()
		if !schema.IsBuiltinAuth() || identity.Namespace() != policy.AuthnNamespace ||
			identity.Version().String() != builtinAuthnExtensionSchemaVersion {
			return nil, invalidBuiltinAuthnSchemaContribution("contains a non-builtin or non-v1 authn schema")
		}

		if _, exists := actions[identity.Name()]; !exists {
			return nil, invalidBuiltinAuthnSchemaContribution("contains an unknown builtin authn action")
		}

		seen[identity.Name()] = struct{}{}
	}

	if len(seen) != len(actions) {
		return nil, invalidBuiltinAuthnSchemaContribution("must contain each builtin authn action exactly once")
	}

	return actions, nil
}

// invalidBuiltinAuthnSchemaContribution returns one stable builtin envelope error.
func invalidBuiltinAuthnSchemaContribution(reason string) error {
	return newValidationError(
		ErrInvalidContribution,
		"builtin.authn.schemas",
		builtinTargetContributorID,
		reason,
	)
}

// collectBuiltinAuthnExtensionFacts validates one real extension contribution and groups exact action additions.
func collectBuiltinAuthnExtensionFacts(
	actions map[string]struct{},
	additions map[string]map[string]FactSchema,
	extension DefinitionContribution,
) error {
	owner, err := validateBoundExtensionContribution(extension)
	if err != nil {
		return err
	}

	for _, provider := range extension.Providers() {
		if !provider.Scheduled() || len(provider.Outputs()) == 0 {
			continue
		}

		selectedActions := selectedBuiltinAuthnActions(provider.Targets(), actions)
		if len(selectedActions) == 0 {
			continue
		}

		facts, err := extensionProviderFactSchemas(owner, provider)
		if err != nil {
			return err
		}

		for _, action := range selectedActions {
			if additions[action] == nil {
				additions[action] = make(map[string]FactSchema)
			}

			for _, fact := range facts {
				if err = addUniqueAuthnExtensionFact(action, additions[action], fact); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// validateBoundExtensionContribution excludes static catalog material and requires a Lua or native authority.
func validateBoundExtensionContribution(extension DefinitionContribution) (string, error) {
	if err := extension.Validate(); err != nil {
		return "", err
	}

	owner := extension.Ownership().Owner()
	if !strings.HasPrefix(owner, "lua.") && !strings.HasPrefix(owner, "plugin.") {
		return "", newValidationError(
			ErrInvalidContribution,
			"extension.owner",
			owner,
			"must be an exact bound Lua or native provider authority",
		)
	}

	if len(extension.Targets()) > 0 || len(extension.Schemas()) > 0 ||
		len(extension.PolicySets()) > 0 || len(extension.Plans()) > 0 {
		return "", newValidationError(
			ErrInvalidContribution,
			"extension.definitions",
			owner,
			"bound providers must not contribute targets, schemas, policy sets, or plans",
		)
	}

	for _, provider := range extension.Providers() {
		if _, err := validateBoundExtensionProvider(owner, provider); err != nil {
			return "", err
		}
	}

	return owner, nil
}

// selectedBuiltinAuthnActions selects only exact builtin action targets without cross-target leakage.
func selectedBuiltinAuthnActions(
	targets []decision.Target,
	actions map[string]struct{},
) []string {
	selected := make([]string, 0, len(targets))
	for _, target := range targets {
		if target.Namespace() != policy.AuthnNamespace {
			continue
		}

		if _, exists := actions[target.Action()]; exists {
			selected = append(selected, target.Action())
		}
	}

	return selected
}

// extensionProviderFactSchemas projects immutable typed outputs into exact target schema facts.
func extensionProviderFactSchemas(owner string, provider ProviderDefinition) ([]FactSchema, error) {
	source, err := validateBoundExtensionProvider(owner, provider)
	if err != nil {
		return nil, err
	}

	outputs := provider.Outputs()
	facts := make([]FactSchema, 0, len(outputs))

	for _, output := range outputs {
		fact, factErr := NewFactSchema(FactSchemaInput{
			ID:             output.ID(),
			AllowedSources: []decision.FactSource{source},
			Category:       output.Category(),
			Kind:           output.Kind(),
			MaxLength:      output.MaxLength(),
			MaxItems:       output.MaxItems(),
			MaxBytes:       output.MaxBytes(),
		})
		if factErr != nil {
			return nil, factErr
		}

		facts = append(facts, fact)
	}

	return facts, nil
}

// validateBoundExtensionProvider verifies provider and output ownership against one host-assigned authority.
func validateBoundExtensionProvider(owner string, provider ProviderDefinition) (decision.FactSource, error) {
	if provider.IsBuiltin() {
		return "", newValidationError(
			ErrInvalidProviderDefinition,
			provider.ID()+".outputs",
			provider.ID(),
			"builtin providers cannot extend builtin authn schemas",
		)
	}

	_, localIdentity, qualified := strings.Cut(provider.ID(), "/")
	if !qualified || !strings.HasPrefix(localIdentity, owner+".") {
		return "", newValidationError(
			ErrInvalidProviderDefinition,
			provider.ID()+".outputs",
			provider.ID(),
			"provider identity must belong to the exact bound extension authority",
		)
	}

	source, err := extensionFactSource(owner)
	if err != nil {
		return "", err
	}

	outputs := provider.Outputs()
	if len(outputs) > 0 && !provider.Scheduled() {
		return "", newValidationError(
			ErrInvalidProviderDefinition,
			provider.ID()+".outputs",
			provider.ID(),
			"fact outputs require an exact scheduled provider binding",
		)
	}

	for _, output := range outputs {
		if !strings.HasPrefix(output.ID(), owner+".") {
			return "", newValidationError(
				ErrInvalidProviderDefinition,
				provider.ID()+".outputs",
				output.ID(),
				"fact identity must belong to the exact bound extension authority",
			)
		}
	}

	return source, nil
}

// extensionFactSource maps the closed extension authority roots to exact runtime provenance.
func extensionFactSource(owner string) (decision.FactSource, error) {
	source, _, found := strings.Cut(owner, ".")
	if !found {
		return "", newValidationError(
			ErrInvalidContribution,
			"extension.owner",
			owner,
			"must contain an exact Lua or native authority",
		)
	}

	switch source {
	case builtinGeneratedFamilyLua:
		return decision.FactSourceLua, nil
	case builtinGeneratedFamilyPlugin:
		return decision.FactSourcePlugin, nil
	default:
		return "", newValidationError(
			ErrInvalidContribution,
			"extension.owner",
			owner,
			"must use the Lua or native fact source",
		)
	}
}

// addUniqueAuthnExtensionFact rejects duplicate identities and incompatible typed shapes.
func addUniqueAuthnExtensionFact(action string, facts map[string]FactSchema, fact FactSchema) error {
	existing, exists := facts[fact.ID()]
	if !exists {
		facts[fact.ID()] = fact.clone()

		return nil
	}

	if sameFactSchemaShape(existing, fact) {
		return newValidationError(
			ErrDuplicateDefinition,
			policy.AuthnNamespace+"/"+action+"/"+builtinAuthnExtensionSchemaVersion+".facts",
			fact.ID(),
			"extension fact occurs more than once",
		)
	}

	return newValidationError(
		ErrFactSchemaMismatch,
		policy.AuthnNamespace+"/"+action+"/"+builtinAuthnExtensionSchemaVersion+".facts",
		fact.ID(),
		"extension fact declarations disagree on source, category, kind, or bounds",
	)
}

// extendBuiltinAuthnSchemaDefinitions rebuilds schemas while preserving provenance and deterministic order.
func extendBuiltinAuthnSchemaDefinitions(
	schemas []SchemaDefinition,
	additions map[string]map[string]FactSchema,
) ([]SchemaDefinition, error) {
	result := make([]SchemaDefinition, 0, len(schemas))
	for _, schema := range schemas {
		facts := schema.Facts()
		existing := make(map[string]FactSchema, len(facts))

		for _, fact := range facts {
			existing[fact.ID()] = fact
		}

		ids := make([]string, 0, len(additions[schema.Identity().Name()]))
		for id := range additions[schema.Identity().Name()] {
			ids = append(ids, id)
		}

		sort.Strings(ids)

		for _, id := range ids {
			addition := additions[schema.Identity().Name()][id]
			if err := rejectExistingAuthnFactCollision(schema.Identity(), existing, addition); err != nil {
				return nil, err
			}

			facts = append(facts, addition)
			existing[id] = addition
		}

		rebuilt, err := NewSchemaDefinition(schema.Identity(), facts)
		if err != nil {
			return nil, err
		}

		rebuilt.builtinAuth = schema.IsBuiltinAuth()
		result = append(result, rebuilt)
	}

	return result, nil
}

// rejectExistingAuthnFactCollision prevents extensions from overriding catalog-owned schema facts.
func rejectExistingAuthnFactCollision(
	identity SchemaIdentity,
	existing map[string]FactSchema,
	addition FactSchema,
) error {
	current, exists := existing[addition.ID()]
	if !exists {
		return nil
	}

	if sameFactSchemaShape(current, addition) {
		return newValidationError(
			ErrDuplicateDefinition,
			identity.String()+".facts",
			addition.ID(),
			"extension fact collides with an existing schema fact",
		)
	}

	return newValidationError(
		ErrFactSchemaMismatch,
		identity.String()+".facts",
		addition.ID(),
		"extension fact cannot override an existing schema shape",
	)
}

// sameFactSchemaShape compares the complete immutable value contract.
func sameFactSchemaShape(left FactSchema, right FactSchema) bool {
	return left.Category() == right.Category() && left.Kind() == right.Kind() &&
		left.MaxLength() == right.MaxLength() && left.MaxItems() == right.MaxItems() &&
		left.MaxBytes() == right.MaxBytes() && left.Required() == right.Required() &&
		slices.Equal(left.AllowedSources(), right.AllowedSources())
}

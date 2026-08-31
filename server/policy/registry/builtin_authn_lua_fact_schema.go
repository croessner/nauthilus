// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package registry

import (
	"fmt"
	"slices"

	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

// AuthnLuaFactDeclarationInput carries one registry-script declaration into immutable candidate material.
type AuthnLuaFactDeclarationInput struct {
	Details      map[string]DetailDefinition
	ID           string
	Description  string
	Stage        string
	Actions      []string
	Category     decision.FactCategory
	Kind         decision.ValueKind
	DeclaredType AttributeType
}

// AuthnLuaFactDeclaration owns one typed Lua fact and its exact authn applicability.
type AuthnLuaFactDeclaration struct {
	details      map[string]DetailDefinition
	id           string
	description  string
	stage        policy.Stage
	actions      []policy.Operation
	category     decision.FactCategory
	kind         decision.ValueKind
	declaredType AttributeType
}

// NewAuthnLuaFactDeclaration validates and detaches one registry-script fact declaration.
func NewAuthnLuaFactDeclaration(input AuthnLuaFactDeclarationInput) (AuthnLuaFactDeclaration, error) {
	stage := policy.Stage(input.Stage)
	if !validAuthnLuaFactStage(stage) {
		return AuthnLuaFactDeclaration{}, fmt.Errorf("invalid authn Lua fact stage %q", input.Stage)
	}

	actions, err := authnLuaFactActions(input.Actions)
	if err != nil {
		return AuthnLuaFactDeclaration{}, err
	}

	declaredType, err := authnLuaDeclaredType(input.DeclaredType, input.Kind)
	if err != nil {
		return AuthnLuaFactDeclaration{}, err
	}

	kind, ok := builtinFactKind(declaredType)
	if !ok || kind != input.Kind || !input.Category.IsValid() {
		return AuthnLuaFactDeclaration{}, fmt.Errorf("invalid authn Lua fact type or category for %q", input.ID)
	}

	factID, _, ok := policy.AuthnCanonicalFactIdentity(input.ID, string(SourceLua))
	if !ok || factID != input.ID {
		return AuthnLuaFactDeclaration{}, fmt.Errorf("invalid authn Lua fact identity %q", input.ID)
	}

	if _, err = NewFactSchema(authnLuaFactSchemaInput(input.ID, input.Category, input.Kind)); err != nil {
		return AuthnLuaFactDeclaration{}, err
	}

	details, err := cloneAuthnLuaFactDetails(input.Details)
	if err != nil {
		return AuthnLuaFactDeclaration{}, err
	}

	return AuthnLuaFactDeclaration{
		details: details, id: input.ID, description: input.Description, stage: stage,
		actions: actions, category: input.Category, kind: input.Kind, declaredType: declaredType,
	}, nil
}

// ID returns the canonical Lua fact identity.
func (d AuthnLuaFactDeclaration) ID() string {
	return d.id
}

// Description returns the operator-owned non-authoritative description.
func (d AuthnLuaFactDeclaration) Description() string {
	return d.description
}

// Stage returns the exact authn semantic stage.
func (d AuthnLuaFactDeclaration) Stage() policy.Stage {
	return d.stage
}

// Actions returns detached exact authn operations.
func (d AuthnLuaFactDeclaration) Actions() []policy.Operation {
	return append([]policy.Operation(nil), d.actions...)
}

// Category returns the strict Decision Service fact category.
func (d AuthnLuaFactDeclaration) Category() decision.FactCategory {
	return d.category
}

// Kind returns the strict Decision Service value kind.
func (d AuthnLuaFactDeclaration) Kind() decision.ValueKind {
	return d.kind
}

// DeclaredType retains the Lua emission type when multiple types share one Decision value kind.
func (d AuthnLuaFactDeclaration) DeclaredType() AttributeType {
	return d.declaredType
}

// Details returns detached typed Lua emission detail metadata.
func (d AuthnLuaFactDeclaration) Details() map[string]DetailDefinition {
	return cloneDetailDefinitions(d.details)
}

// Clone returns one deeply detached declaration.
func (d AuthnLuaFactDeclaration) Clone() AuthnLuaFactDeclaration {
	d.actions = d.Actions()
	d.details = d.Details()

	return d
}

// ExtendBuiltinAuthnSchemasWithLuaFacts adds registry-script facts to selected builtin authn actions.
func ExtendBuiltinAuthnSchemasWithLuaFacts(
	builtin DefinitionContribution,
	declarations []AuthnLuaFactDeclaration,
) (DefinitionContribution, error) {
	return extendBuiltinAuthnSchemas(builtin, func(
		actions map[string]struct{},
		additions map[string]map[string]FactSchema,
	) error {
		for index, declaration := range declarations {
			if err := collectAuthnLuaFactDeclaration(actions, additions, declaration); err != nil {
				return fmt.Errorf("authn Lua fact declaration %d: %w", index, err)
			}
		}

		return nil
	}, "compose builtin authn Lua fact schemas")
}

// collectAuthnLuaFactDeclaration validates one declaration and groups it by exact selected action.
func collectAuthnLuaFactDeclaration(
	actions map[string]struct{},
	additions map[string]map[string]FactSchema,
	declaration AuthnLuaFactDeclaration,
) error {
	rebuilt, err := NewAuthnLuaFactDeclaration(AuthnLuaFactDeclarationInput{
		Details: declaration.Details(), ID: declaration.ID(), Description: declaration.Description(),
		Stage: string(declaration.Stage()), Actions: operationStrings(declaration.Actions()),
		Category: declaration.Category(), Kind: declaration.Kind(), DeclaredType: declaration.DeclaredType(),
	})
	if err != nil {
		return err
	}

	fact, err := NewFactSchema(authnLuaFactSchemaInput(rebuilt.ID(), rebuilt.Category(), rebuilt.Kind()))
	if err != nil {
		return err
	}

	for _, action := range rebuilt.Actions() {
		actionName := string(action)
		if _, exists := actions[actionName]; !exists {
			return fmt.Errorf("unknown builtin authn action %q", actionName)
		}

		if additions[actionName] == nil {
			additions[actionName] = make(map[string]FactSchema)
		}

		if err = addUniqueAuthnExtensionFact(actionName, additions[actionName], fact); err != nil {
			return err
		}
	}

	return nil
}

// authnLuaFactSchemaInput applies finite code-owned bounds to registry-script facts.
func authnLuaFactSchemaInput(id string, category decision.FactCategory, kind decision.ValueKind) FactSchemaInput {
	return builtinAuthnFactSchemaInput(id, category, kind, decision.FactSourceLua)
}

// authnLuaFactActions owns the closed operation list and applies the documented authenticate default.
func authnLuaFactActions(input []string) ([]policy.Operation, error) {
	if len(input) == 0 {
		return []policy.Operation{policy.OperationAuthenticate}, nil
	}

	result := make([]policy.Operation, 0, len(input))
	for _, value := range input {
		operation := policy.Operation(value)
		if operation != policy.OperationAuthenticate && operation != policy.OperationLookupIdentity &&
			operation != policy.OperationListAccounts {
			return nil, fmt.Errorf("invalid authn Lua fact action %q", value)
		}

		if slices.Contains(result, operation) {
			return nil, fmt.Errorf("duplicate authn Lua fact action %q", value)
		}

		result = append(result, operation)
	}

	return result, nil
}

// authnLuaDeclaredType resolves one unambiguous Lua emission type.
func authnLuaDeclaredType(configured AttributeType, kind decision.ValueKind) (AttributeType, error) {
	if configured != "" {
		mapped, ok := builtinFactKind(configured)
		if !ok || mapped != kind {
			return "", fmt.Errorf("lua fact declared type %q does not match kind %q", configured, kind)
		}

		return configured, nil
	}

	switch kind {
	case decision.ValueKindBoolean:
		return AttributeTypeBool, nil
	case decision.ValueKindString:
		return AttributeTypeString, nil
	case decision.ValueKindStrings:
		return AttributeTypeStringList, nil
	case decision.ValueKindDouble:
		return AttributeTypeNumber, nil
	case decision.ValueKindTimestamp:
		return AttributeTypeDateTime, nil
	default:
		return "", fmt.Errorf("unsupported authn Lua fact kind %q", kind)
	}
}

// validAuthnLuaFactStage recognizes the closed authn semantic-stage vocabulary.
func validAuthnLuaFactStage(stage policy.Stage) bool {
	return stage == policy.StagePreAuth || stage == policy.StageAuthBackend ||
		stage == policy.StageSubjectAnalysis || stage == policy.StageAccountProvider ||
		stage == policy.StageAuthDecision
}

// cloneAuthnLuaFactDetails validates and detaches Lua emission detail metadata.
func cloneAuthnLuaFactDetails(input map[string]DetailDefinition) (map[string]DetailDefinition, error) {
	result := cloneDetailDefinitions(input)
	for name, detail := range result {
		if name == "" {
			return nil, fmt.Errorf("authn Lua fact detail name is required")
		}

		if _, ok := builtinFactKind(detail.Type); !ok || detail.MaxLength < 0 || detail.MaxLength > builtinAuthnMaximumFactText {
			return nil, fmt.Errorf("invalid authn Lua fact detail %q", name)
		}
	}

	return result, nil
}

// cloneDetailDefinitions owns one nullable detail map.
func cloneDetailDefinitions(input map[string]DetailDefinition) map[string]DetailDefinition {
	if input == nil {
		return nil
	}

	result := make(map[string]DetailDefinition, len(input))
	for name, detail := range input {
		result[name] = detail
	}

	return result
}

// operationStrings projects exact operations into constructor inputs.
func operationStrings(input []policy.Operation) []string {
	result := make([]string, len(input))
	for index, operation := range input {
		result[index] = string(operation)
	}

	return result
}

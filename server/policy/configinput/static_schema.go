// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"fmt"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

// normalizeStaticSchemaDefinitions projects every inactive exact schema contribution.
func (n *policyNormalizer) normalizeStaticSchemaDefinitions(buckets map[string]*namespaceDefinitions) error {
	for _, namespace := range sortedKeys(n.policy.Namespaces) {
		configured := n.policy.Namespaces[namespace].SchemaContributions.Static
		bucket := buckets[namespace]

		for _, action := range sortedKeys(configured) {
			path := "policy.namespaces." + namespace + ".schema_contributions.static." + action

			target, err := decision.NewTarget(namespace, action)
			if err != nil {
				return atPath(path, err)
			}

			schemas, identities, err := normalizeStaticVersions(path+".versions", namespace, action, configured[action].Versions)
			if err != nil {
				return err
			}

			definition, err := registry.NewTargetDefinition(target, identities)
			if err != nil {
				return atPath(path, err)
			}

			bucket.targets = append(bucket.targets, definition)
			bucket.schemas = append(bucket.schemas, schemas...)
		}
	}

	return nil
}

// normalizeStaticVersions constructs exact identities and typed fact schemas in stable order.
func normalizeStaticVersions(
	path string,
	namespace string,
	action string,
	configured map[string]policyconfig.StaticSchemaVersionConfig,
) ([]registry.SchemaDefinition, []registry.SchemaIdentity, error) {
	definitions := make([]registry.SchemaDefinition, 0, len(configured))
	identities := make([]registry.SchemaIdentity, 0, len(configured))

	for _, version := range sortedKeys(configured) {
		versionPath := path + "." + version

		identity, err := registry.NewSchemaIdentity(namespace, action, version)
		if err != nil {
			return nil, nil, atPath(versionPath, err)
		}

		facts, err := normalizeStaticFacts(versionPath+".facts", configured[version].Facts)
		if err != nil {
			return nil, nil, err
		}

		definition, err := registry.NewSchemaDefinition(identity, facts)
		if err != nil {
			return nil, nil, atPath(versionPath, err)
		}

		identities = append(identities, identity)
		definitions = append(definitions, definition)
	}

	return definitions, identities, nil
}

// normalizeStaticFacts maps source and bound fields into immutable fact declarations.
func normalizeStaticFacts(
	path string,
	configured []policyconfig.StaticFactSchemaConfig,
) ([]registry.FactSchema, error) {
	facts := make([]registry.FactSchema, 0, len(configured))

	for index, configuredFact := range configured {
		factPath := fmt.Sprintf("%s[%d]", path, index)

		sources := make([]decision.FactSource, 0, len(configuredFact.AllowedSources))
		for _, configuredSource := range configuredFact.AllowedSources {
			sources = append(sources, decision.FactSource(configuredSource))
		}

		recordSchema, err := normalizeStaticRecordSchema(factPath+".record_schema", configuredFact.RecordSchema)
		if err != nil {
			return nil, err
		}

		fact, err := registry.NewFactSchema(registry.FactSchemaInput{
			ID: configuredFact.Attribute, AllowedSources: sources,
			RecordSchema: recordSchema,
			Category:     decision.FactCategory(configuredFact.Category), Kind: decision.ValueKind(configuredFact.Type),
			MaxLength: configuredFact.MaxLength, MaxItems: configuredFact.MaxItems, MaxBytes: configuredFact.MaxBytes,
			Required: configuredFact.Required,
		})
		if err != nil {
			return nil, atPath(factPath, err)
		}

		facts = append(facts, fact)
	}

	return facts, nil
}

// normalizeStaticRecordSchema maps one optional closed record declaration into immutable registry values.
func normalizeStaticRecordSchema(
	path string,
	configured *policyconfig.StaticRecordSchemaConfig,
) (*registry.RecordSchema, error) {
	if configured == nil {
		return nil, nil
	}

	fields := make([]registry.RecordFieldSchema, 0, len(configured.Fields))
	for index, configuredField := range configured.Fields {
		field, err := registry.NewRecordFieldSchema(registry.RecordFieldSchemaInput{
			Name: configuredField.Name, Kind: decision.ValueKind(configuredField.Type),
			ProviderVisibility: configuredField.ProviderVisibility,
			MaxLength:          configuredField.MaxLength, MaxItems: configuredField.MaxItems, MaxBytes: configuredField.MaxBytes,
			Required: configuredField.Required, ExpressionVisible: configuredField.ExpressionVisible,
		})
		if err != nil {
			return nil, atPath(fmt.Sprintf("%s.fields[%d]", path, index), err)
		}

		fields = append(fields, field)
	}

	schema, err := registry.NewRecordSchema(registry.RecordSchemaInput{
		ID: configured.ID, Version: configured.Version, Fields: fields,
		MinRecords: configured.MinRecords, MaxRecords: configured.MaxRecords,
		MaxFields: configured.MaxFields, MaxAggregateBytes: configured.MaxAggregateBytes,
	})
	if err != nil {
		return nil, atPath(path, err)
	}

	return &schema, nil
}

// validateConfiguredActivationSchemas prevents implicit empty or latest-version target schemas.
func validateConfiguredActivationSchemas(configured policyconfig.PolicyConfig) error {
	for index, target := range configured.Targets {
		if target.Namespace == policy.AuthnNamespace {
			continue
		}

		path := fmt.Sprintf("policy.targets[%d].schema", index)

		namespace, exists := configured.Namespaces[target.Namespace]
		if !exists {
			return atPath(path, fmt.Errorf("exact schema %s is not statically contributed", target.Schema))
		}

		action, exists := namespace.SchemaContributions.Static[target.Action]
		if !exists {
			return atPath(path, fmt.Errorf("exact schema %s is not statically contributed", target.Schema))
		}

		_, version, ok := splitSchemaReference(target.Schema)
		if !ok {
			return atPath(path, fmt.Errorf("must use exact namespace/action/vN form"))
		}

		if _, exists := action.Versions[version]; !exists {
			return atPath(path, fmt.Errorf("exact schema %s is not statically contributed", target.Schema))
		}
	}

	return nil
}

// splitSchemaReference extracts the action and version from one already validated identity.
func splitSchemaReference(reference string) (string, string, bool) {
	identity, err := registry.ParseSchemaIdentity("schema", reference)
	if err != nil {
		return "", "", false
	}

	return identity.Name(), identity.Version().String(), true
}

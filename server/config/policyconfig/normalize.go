// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import "reflect"

const (
	defaultAuthorityMode = "enforce"
	defaultEffectKind    = "obligation"
	defaultFactTextBound = 4096
	defaultFactItemBound = 1024
	defaultFactByteBound = 64 * 1024
	standardAuthPolicy   = "authn/standard_auth"
)

// Normalize applies semantic defaults without registering a production config root.
func Normalize(document Document) Document {
	document = cloneDocument(document)
	document.Policy.Namespaces = normalizeNamespaces(document.Policy.Namespaces)
	document.Policy.Targets = normalizeTargets(document.Policy.Targets)

	return document
}

// cloneDocument deeply owns mutable standalone configuration state before defaults are applied.
func cloneDocument(document Document) Document {
	return cloneConfigValue(reflect.ValueOf(document)).Interface().(Document)
}

// cloneConfigValue preserves scalar aliases and delegates composite configuration ownership.
func cloneConfigValue(value reflect.Value) reflect.Value {
	if !value.IsValid() {
		return value
	}

	if value.Type() == secretType || value.Type() == durationType {
		return value
	}

	return cloneCompositeConfigValue(value)
}

// cloneCompositeConfigValue recursively clones maps, slices, pointers, interfaces, and exported structs.
func cloneCompositeConfigValue(value reflect.Value) reflect.Value {
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}

		cloned := cloneConfigValue(value.Elem())
		result := reflect.New(value.Type()).Elem()
		result.Set(cloned)

		return result
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}

		result := reflect.New(value.Type().Elem())
		result.Elem().Set(cloneConfigValue(value.Elem()))

		return result
	case reflect.Map:
		return cloneConfigMap(value)
	case reflect.Slice:
		return cloneConfigSlice(value)
	case reflect.Array:
		result := reflect.New(value.Type()).Elem()
		for index := range value.Len() {
			result.Index(index).Set(cloneConfigValue(value.Index(index)))
		}

		return result
	case reflect.Struct:
		return cloneConfigStruct(value)
	default:
		return value
	}
}

// cloneConfigMap deeply owns one dynamic or typed configuration map.
func cloneConfigMap(value reflect.Value) reflect.Value {
	if value.IsNil() {
		return reflect.Zero(value.Type())
	}

	result := reflect.MakeMapWithSize(value.Type(), value.Len())

	iterator := value.MapRange()
	for iterator.Next() {
		result.SetMapIndex(cloneConfigValue(iterator.Key()), cloneConfigValue(iterator.Value()))
	}

	return result
}

// cloneConfigSlice deeply owns one ordered configuration slice.
func cloneConfigSlice(value reflect.Value) reflect.Value {
	if value.IsNil() {
		return reflect.Zero(value.Type())
	}

	result := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
	for index := range value.Len() {
		result.Index(index).Set(cloneConfigValue(value.Index(index)))
	}

	return result
}

// cloneConfigStruct copies exported configuration fields and preserves opaque value types.
func cloneConfigStruct(value reflect.Value) reflect.Value {
	for index := range value.NumField() {
		if value.Type().Field(index).PkgPath != "" {
			return value
		}
	}

	result := reflect.New(value.Type()).Elem()
	for index := range value.NumField() {
		result.Field(index).Set(cloneConfigValue(value.Field(index)))
	}

	return result
}

// normalizeNamespaces owns copied definition maps while applying local defaults.
func normalizeNamespaces(namespaces map[string]NamespaceConfig) map[string]NamespaceConfig {
	if namespaces == nil {
		return nil
	}

	result := make(map[string]NamespaceConfig, len(namespaces))
	for namespaceName, namespace := range namespaces {
		namespace.SchemaContributions = normalizeSchemaContributions(namespace.SchemaContributions)
		namespace.PolicySets = normalizePolicySets(namespace.PolicySets)
		namespace.Effects = normalizeEffects(namespace.Effects)
		result[namespaceName] = namespace
	}

	return result
}

// normalizeSchemaContributions owns static schemas and supplies conservative kind bounds.
func normalizeSchemaContributions(contributions SchemaContributionsConfig) SchemaContributionsConfig {
	if contributions.Static == nil {
		return contributions
	}

	static := make(map[string]StaticTargetSchemaConfig, len(contributions.Static))
	for action, target := range contributions.Static {
		target.Versions = normalizeStaticVersions(target.Versions)
		static[action] = target
	}

	contributions.Static = static

	return contributions
}

// normalizeStaticVersions deeply owns fact slices before applying kind-specific bounds.
func normalizeStaticVersions(versions map[string]StaticSchemaVersionConfig) map[string]StaticSchemaVersionConfig {
	if versions == nil {
		return nil
	}

	result := make(map[string]StaticSchemaVersionConfig, len(versions))
	for version, schema := range versions {
		schema.Facts = append([]StaticFactSchemaConfig(nil), schema.Facts...)

		for index := range schema.Facts {
			applyStaticFactBounds(&schema.Facts[index])
		}

		result[version] = schema
	}

	return result
}

// applyStaticFactBounds defaults only a completely omitted size contract.
func applyStaticFactBounds(fact *StaticFactSchemaConfig) {
	if fact.MaxLength != 0 || fact.MaxItems != 0 || fact.MaxBytes != 0 {
		return
	}

	switch fact.Type {
	case staticValueKindString:
		fact.MaxLength = defaultFactTextBound
	case staticValueKindStrings:
		fact.MaxLength = defaultFactTextBound
		fact.MaxItems = defaultFactItemBound
	case staticValueKindBytes:
		fact.MaxBytes = defaultFactByteBound
	}
}

// normalizePolicySets defaults omitted visibility to private on a detached map.
func normalizePolicySets(policySets map[string]PolicySetConfig) map[string]PolicySetConfig {
	if policySets == nil {
		return nil
	}

	result := make(map[string]PolicySetConfig, len(policySets))
	for name, policySet := range policySets {
		if policySet.Visibility == "" {
			policySet.Visibility = VisibilityPrivate
		}

		result[name] = policySet
	}

	return result
}

// normalizeEffects defaults the configured effect kind without changing execution ownership.
func normalizeEffects(effects map[string]EffectConfig) map[string]EffectConfig {
	if effects == nil {
		return nil
	}

	result := make(map[string]EffectConfig, len(effects))
	for name, effect := range effects {
		if effect.Kind == "" {
			effect.Kind = defaultEffectKind
		}

		result[name] = effect
	}

	return result
}

// normalizeTargets applies common mode and authn-owned fallback defaults.
func normalizeTargets(targets []TargetConfig) []TargetConfig {
	if targets == nil {
		return nil
	}

	result := append([]TargetConfig(nil), targets...)
	for index := range result {
		target := &result[index]
		if target.Mode == "" {
			target.Mode = defaultAuthorityMode
		}

		if target.Namespace != "authn" {
			continue
		}

		if target.DefaultPolicy == "" {
			target.DefaultPolicy = standardAuthPolicy
		}

		if !target.Report.Enabled {
			target.Report.IncludeFSM = true
			target.Report.IncludeChecks = true
		}
	}

	return result
}

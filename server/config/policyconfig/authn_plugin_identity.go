// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"strings"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const authnPluginIdentityPrefix = authnNamespace + "/plugin."

// ParseAuthnPluginProviderLocal returns the exact module, family, and component selected by an authn provider local name.
func ParseAuthnPluginProviderLocal(value string) (string, string, string, bool) {
	const prefix = "plugin."
	if !strings.HasPrefix(value, prefix) {
		return "", "", "", false
	}

	local := strings.TrimPrefix(value, prefix)
	if module, ok := strings.CutSuffix(local, "."+pluginBindingEnvironment); ok && validNamespace(module) {
		return module, pluginBindingEnvironment, pluginBindingEnvironment, true
	}

	subjectSeparator := "." + pluginBindingSubject + "."

	subject := strings.LastIndex(local, subjectSeparator)
	if subject <= 0 {
		return "", "", "", false
	}

	module := local[:subject]

	component := local[subject+len(subjectSeparator):]
	if !validNamespace(module) || !validAction(component) {
		return "", "", "", false
	}

	return module, pluginBindingSubject, component, true
}

// AuthnPluginEffectID constructs the narrow canonical identity for one public auth-shaped native effect target.
func AuthnPluginEffectID(module string, component string) (string, error) {
	qualified, err := pluginapi.QualifiedComponentName(module, component)
	if err != nil {
		return "", err
	}

	return authnPluginIdentityPrefix + qualified, nil
}

// ParseAuthnPluginEffectID validates and splits one narrow authn-only public native effect identity.
func ParseAuthnPluginEffectID(value string) (string, string, bool) {
	if !strings.HasPrefix(value, authnPluginIdentityPrefix) {
		return "", "", false
	}

	qualified := strings.TrimPrefix(value, authnPluginIdentityPrefix)
	if pluginapi.ValidateQualifiedComponentName(qualified) != nil {
		return "", "", false
	}

	module, component, _ := strings.Cut(qualified, ".")

	return module, component, true
}

// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/secret"
)

// TestPreparePolicyRejectsSecretsWithoutTypedBinding proves configured credentials cannot become inert material.
func TestPreparePolicyRejectsSecretsWithoutTypedBinding(t *testing.T) {
	tests := []struct {
		name string
		path string
		edit func(*policyconfig.NamespaceConfig)
	}{
		{
			name: "generic native provider",
			path: "policy.namespaces.mail.providers.signer.secrets",
			edit: func(namespace *policyconfig.NamespaceConfig) {
				namespace.Providers = map[string]policyconfig.ProviderConfig{
					"signer": {
						Kind: policyconfig.ProviderKindNative, Module: "signer", Failure: "indeterminate",
						Secrets: map[string]secret.Value{"token": secret.New("provider-secret")},
					},
				}
			},
		},
		{
			name: "configured effect",
			path: "policy.namespaces.mail.effects.notify.secrets",
			edit: func(namespace *policyconfig.NamespaceConfig) {
				namespace.Effects = map[string]policyconfig.EffectConfig{
					"notify": {
						Kind: "obligation", Execution: "return_only",
						Secrets: map[string]secret.Value{"webhook": secret.New("effect-secret")},
					},
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			namespace := policyconfig.NamespaceConfig{}
			test.edit(&namespace)

			_, err := PreparePolicy(t.Context(), 1, policyconfig.PolicyConfig{
				Namespaces: map[string]policyconfig.NamespaceConfig{"mail": namespace},
			})
			if err == nil || !strings.Contains(err.Error(), test.path) {
				t.Fatalf("PreparePolicy() error = %v, want secret-binding path %s", err, test.path)
			}

			if strings.Contains(err.Error(), "provider-secret") || strings.Contains(err.Error(), "effect-secret") {
				t.Fatalf("PreparePolicy() exposed configured secret: %v", err)
			}
		})
	}
}

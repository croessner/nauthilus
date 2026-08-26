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
)

// validateConfiguredSecretBindings rejects credentials without an explicit typed execution boundary.
func validateConfiguredSecretBindings(configured policyconfig.PolicyConfig) error {
	for _, namespace := range sortedConfiguredKeys(configured.Namespaces) {
		configuredNamespace := configured.Namespaces[namespace]

		for _, name := range sortedConfiguredKeys(configuredNamespace.Providers) {
			if len(configuredNamespace.Providers[name].Secrets) > 0 {
				return fmt.Errorf(
					"policy.namespaces.%s.providers.%s.secrets: configured provider secrets have no typed execution binding",
					namespace,
					name,
				)
			}
		}

		for _, name := range sortedConfiguredKeys(configuredNamespace.Effects) {
			if len(configuredNamespace.Effects[name].Secrets) > 0 {
				return fmt.Errorf(
					"policy.namespaces.%s.effects.%s.secrets: configured effect secrets have no typed execution binding",
					namespace,
					name,
				)
			}
		}
	}

	return nil
}

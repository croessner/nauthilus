// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

func TestCollectRejectsLocalOnlySMTPPeerAddresses(t *testing.T) {
	addresses := []string{"127.0.0.1", "::1", "169.254.1.1", "fe80::1"}
	provider := configuredTestProvider(t)

	for _, address := range addresses {
		t.Run(address, func(t *testing.T) {
			result, err := provider.Collect(context.Background(), testDecisionRequest(t, address))
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}

			if result.ErrorClass != pluginapi.DecisionErrorClassInvalidInput || len(result.Facts) != 0 {
				t.Fatalf("Collect() = %#v, want invalid_input without assessed facts", result)
			}
		})
	}
}

func TestCollectAdmitsPrivateSMTPPeerAddressesForContractAssessment(t *testing.T) {
	addresses := []string{"10.23.45.67", "fd00::25"}
	provider := configuredTestProvider(t)

	for _, address := range addresses {
		t.Run(address, func(t *testing.T) {
			result, err := provider.Collect(context.Background(), testDecisionRequest(t, address))
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}

			if result.ErrorClass != "" || len(result.Facts) != 1 {
				t.Fatalf("Collect() = %#v, want a contract-assessed result", result)
			}
		})
	}
}

// configuredTestProvider returns the actual provider with the canonical test snapshot.
func configuredTestProvider(t *testing.T) decisionFactProvider {
	t.Helper()

	plugin := NewPlugin()
	plugin.swapConfig(mustTestConfig(t))

	return decisionFactProvider{plugin: plugin}
}

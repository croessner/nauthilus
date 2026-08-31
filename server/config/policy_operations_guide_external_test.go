// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyOperationsGuideTracksRuntimeAndPrivacyContracts(t *testing.T) {
	repositoryRoot := policyMigrationRepositoryRoot(t)
	guidePath := filepath.Join(repositoryRoot, "server/docs/policy_operations.md")

	payload, err := os.ReadFile(guidePath)
	if err != nil {
		t.Fatalf("read Policy operations guide: %v", err)
	}

	guide := string(payload)
	for _, required := range []string{
		"Authorization: Bearer ${POLICY_ACCESS_TOKEN}",
		"${POLICY_BASIC_USERNAME}:${POLICY_BASIC_PASSWORD}",
		"nauthilus.policy.request_id",
		"nauthilus.policy.decision_id",
		"nauthilus_policy_service_decisions_total",
		"Cache-Control: no-store",
		"dkim2/plugin.dkim2_reputation.assessment",
		"Outbound signing remains deferred",
	} {
		if !strings.Contains(guide, required) {
			t.Fatalf("Policy operations guide lacks %q", required)
		}
	}

	for _, forbidden := range []string{
		"Authorization: Bearer eyJ",
		"POLICY_BASIC_PASSWORD=",
		"smtp_peer_ip=",
		"signer_domain=",
	} {
		if strings.Contains(guide, forbidden) {
			t.Fatalf("Policy operations guide contains secret-shaped example %q", forbidden)
		}
	}
}

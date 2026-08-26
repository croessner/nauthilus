// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import "testing"

// TestAuthnPluginEffectIdentityPreservesNarrowCanonicalMapping proves no dotted-local grammar widening.
func TestAuthnPluginEffectIdentityPreservesNarrowCanonicalMapping(t *testing.T) {
	identity, err := AuthnPluginEffectID("clickhouse", "post_action")
	if err != nil || identity != "authn/plugin.clickhouse.post_action" {
		t.Fatalf("AuthnPluginEffectID() = %q/%v", identity, err)
	}

	module, component, ok := ParseAuthnPluginEffectID(identity)
	if !ok || module != "clickhouse" || component != "post_action" {
		t.Fatalf("ParseAuthnPluginEffectID() = %q/%q/%v", module, component, ok)
	}

	for _, rejected := range []string{
		"authn/clickhouse.post_action",
		"mail/plugin.clickhouse.post_action",
		"authn/plugin.clickhouse.post.action",
		"authn/plugin.ClickHouse.post_action",
	} {
		if _, _, accepted := ParseAuthnPluginEffectID(rejected); accepted {
			t.Fatalf("ParseAuthnPluginEffectID(%q) accepted a non-canonical identity", rejected)
		}
	}
}

// TestValidateEffectSelectionsAcceptsOnlyNarrowAuthnPluginForm proves the config boundary rejects aliases.
func TestValidateEffectSelectionsAcceptsOnlyNarrowAuthnPluginForm(t *testing.T) {
	if err := validateEffectSelections([]EffectSelectionConfig{{
		ID: "authn/plugin.clickhouse.post_action",
	}}, "policy.test"); err != nil {
		t.Fatalf("validateEffectSelections(canonical) error = %v", err)
	}

	if err := validateEffectSelections([]EffectSelectionConfig{{
		ID: "authn/clickhouse.post_action",
	}}, "policy.test"); err == nil {
		t.Fatal("validateEffectSelections() accepted bare native auth effect alias")
	}
}

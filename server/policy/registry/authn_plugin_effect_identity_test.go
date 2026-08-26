// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package registry

import "testing"

// TestAuthnPluginEffectUseAcceptsOnlyCanonicalExtensionIdentity proves the catalog has no alias lookup.
func TestAuthnPluginEffectUseAcceptsOnlyCanonicalExtensionIdentity(t *testing.T) {
	use, err := NewEffectUse("authn/plugin.clickhouse.post_action", nil)
	if err != nil || use.ID() != "authn/plugin.clickhouse.post_action" {
		t.Fatalf("NewEffectUse(canonical) = %#v/%v", use, err)
	}

	if _, err = NewEffectUse("authn/clickhouse.post_action", nil); err == nil {
		t.Fatal("NewEffectUse() accepted bare native auth effect alias")
	}
}

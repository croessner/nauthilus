// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config

import "testing"

func TestRuntimeGRPCAuthorityBackendRefsDefaultDisabled(t *testing.T) {
	var authority RuntimeGRPCAuthServerSection

	if authority.GetBackendRefs().IsEnabled() {
		t.Fatal("backend refs must default to disabled")
	}
}

func TestRuntimeGRPCAuthorityBackendRefsExplicitlyEnabled(t *testing.T) {
	authority := RuntimeGRPCAuthServerSection{
		BackendRefs: RuntimeGRPCBackendRefsSection{Enabled: true},
	}

	if !authority.GetBackendRefs().IsEnabled() {
		t.Fatal("explicitly enabled backend refs must be enabled")
	}
}

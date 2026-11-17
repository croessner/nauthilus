// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/secret"
)

// TestIDPDebugDumpHidesClientSecrets reproduces the shadow startup log that printed an OIDC client secret in the
// debug dump of the IdP section: the dump formats clients by value, so the redaction must not depend on a pointer
// String method.
func TestIDPDebugDumpHidesClientSecrets(t *testing.T) {
	const clientSecret = "idp-dump-client-secret"

	section := &IDPSection{OIDC: OIDCConfig{Enabled: true, Clients: []OIDCClient{{
		Name: "admin-service", ClientID: "client-id", ClientSecret: secret.New(clientSecret),
	}}}}

	for _, rendered := range []string{section.String(), fmt.Sprintf("%+v", section), fmt.Sprintf("%+v", section.OIDC.Clients)} {
		if strings.Contains(rendered, clientSecret) {
			t.Fatalf("IdP dump reveals the client secret: %s", rendered)
		}
	}
}

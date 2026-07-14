// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package ldapendpoint

import "testing"

func TestParseReturnsOnlySafeEndpointMetadata(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantHost string
		wantPort int
		wantKind string
	}{
		{name: "ldap strips userinfo", raw: "ldap://bind:secret@ldap.example.test/dc=example", wantHost: "ldap.example.test", wantPort: 389, wantKind: "ldap"},
		{name: "ldaps IPv6", raw: "ldaps://[2001:db8::10]:7636/dc=example", wantHost: "2001:db8::10", wantPort: 7636, wantKind: "ldaps"},
		{name: "ldapi socket", raw: "ldapi:///var/run/slapd.sock", wantHost: "/var/run/slapd.sock", wantPort: 0, wantKind: "ldapi"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint, err := Parse(test.raw)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			if endpoint.Scheme != test.wantKind || endpoint.Host != test.wantHost || endpoint.Port != test.wantPort {
				t.Fatalf("Parse() = %#v, want scheme=%q host=%q port=%d", endpoint, test.wantKind, test.wantHost, test.wantPort)
			}
		})
	}
}

func TestParseRejectsUnsupportedOrIncompleteEndpoints(t *testing.T) {
	for _, raw := range []string{"https://ldap.example.test", "ldap:///dc=example", "ldapi://relative"} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("Parse(%q) error = nil, want rejection", raw)
		}
	}
}

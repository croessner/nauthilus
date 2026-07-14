// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginruntime

import (
	"context"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
)

func TestLDAPFacadeEndpointMetadataUsesCurrentConfigAndDefensiveCopies(t *testing.T) {
	current := ldapEndpointConfig(
		[]string{"ldap://bind:secret@ldap-one.example.test/dc=example", "ldaps://ldap-two.example.test"},
		nil,
	)
	resolver := NewLDAPConfigEndpointResolver(func() config.File { return current })
	facade := NewLDAPFacade(&recordingLDAPExecutor{}, resolver)

	endpoints, err := facade.Endpoints(context.Background(), "default")
	if err != nil {
		t.Fatalf("Endpoints() error = %v", err)
	}

	want := []pluginapi.LDAPEndpoint{
		{PoolName: "default", Scheme: "ldap", Host: "ldap-one.example.test", Port: 389},
		{PoolName: "default", Scheme: "ldaps", Host: "ldap-two.example.test", Port: 636},
	}

	assertLDAPEndpointMetadata(t, endpoints, want)

	endpoints[0].Host = "mutated.example.test"

	again, err := facade.Endpoints(context.Background(), "default")
	if err != nil {
		t.Fatalf("Endpoints() after mutation error = %v", err)
	}

	if again[0].Host != "ldap-one.example.test" {
		t.Fatalf("endpoint mutation changed resolver state: %#v", again[0])
	}

	current = ldapEndpointConfig([]string{"ldaps://ldap-reloaded.example.test:1636"}, nil)

	reloaded, err := facade.Endpoints(context.Background(), "default")
	if err != nil {
		t.Fatalf("Endpoints() after config change error = %v", err)
	}

	if len(reloaded) != 1 || reloaded[0].Host != "ldap-reloaded.example.test" || reloaded[0].Port != 1636 {
		t.Fatalf("reloaded endpoints = %#v, want current config endpoint", reloaded)
	}
}

// assertLDAPEndpointMetadata verifies exact detached endpoint values without userinfo leakage.
func assertLDAPEndpointMetadata(t *testing.T, endpoints []pluginapi.LDAPEndpoint, want []pluginapi.LDAPEndpoint) {
	t.Helper()

	if len(endpoints) != len(want) {
		t.Fatalf("Endpoints() = %#v, want %#v", endpoints, want)
	}

	for index := range want {
		if endpoints[index] != want[index] {
			t.Fatalf("Endpoints()[%d] = %#v, want %#v", index, endpoints[index], want[index])
		}

		if strings.Contains(endpoints[index].Host, "bind") || strings.Contains(endpoints[index].Host, "secret") {
			t.Fatalf("endpoint leaked LDAP userinfo: %#v", endpoints[index])
		}
	}
}

func TestLDAPFacadeEndpointMetadataResolvesNamedPools(t *testing.T) {
	current := ldapEndpointConfig(
		[]string{"ldap://default.example.test"},
		map[string]*config.LDAPConf{
			"accounts": {ServerURIs: []string{"ldaps://accounts.example.test"}},
		},
	)
	facade := NewLDAPFacade(&recordingLDAPExecutor{}, NewLDAPConfigEndpointResolver(func() config.File { return current }))

	endpoints, err := facade.Endpoints(context.Background(), "accounts")
	if err != nil {
		t.Fatalf("Endpoints() error = %v", err)
	}

	if len(endpoints) != 1 || endpoints[0].PoolName != "accounts" || endpoints[0].Host != "accounts.example.test" {
		t.Fatalf("named endpoints = %#v, want accounts pool", endpoints)
	}

	if _, err = facade.Endpoints(context.Background(), "missing"); err == nil {
		t.Fatal("missing LDAP pool returned no error")
	}
}

// ldapEndpointConfig builds a legacy-compatible LDAP config snapshot for facade tests.
func ldapEndpointConfig(defaultURIs []string, pools map[string]*config.LDAPConf) *config.FileSettings {
	return &config.FileSettings{
		LDAP: &config.LDAPSection{
			Config:            &config.LDAPConf{ServerURIs: defaultURIs},
			OptionalLDAPPools: pools,
		},
	}
}

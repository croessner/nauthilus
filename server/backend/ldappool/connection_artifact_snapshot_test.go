// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package ldappool

import (
	"net/url"
	"os"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
)

func TestLDAPTLSConfigUsesSealedMaterialAfterLiveMutation(t *testing.T) {
	pki := newHealthProbePKI(t)
	ldapConfig := &config.LDAPConf{
		TLSCAFile:     pki.caFile,
		TLSClientCert: pki.clientCert,
		TLSClientKey:  pki.clientKey,
	}

	configured := &config.FileSettings{
		Server: &config.ServerSection{},
		LDAP:   &config.LDAPSection{Config: ldapConfig},
	}
	if _, err := config.EnsureArtifactSnapshot(configured); err != nil {
		t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
	}

	for _, path := range []string{pki.caFile, pki.clientCert, pki.clientKey} {
		if err := os.WriteFile(path, []byte("mutated invalid TLS material\n"), 0o600); err != nil {
			t.Fatalf("mutate LDAP TLS artifact %q: %v", path, err)
		}
	}

	tlsConfig, err := newLDAPTLSConfig(configured, &url.URL{Scheme: ldapSchemeLDAPS, Host: "localhost"}, ldapConfig)
	if err != nil {
		t.Fatalf("newLDAPTLSConfig() error = %v", err)
	}

	if tlsConfig == nil || tlsConfig.RootCAs == nil {
		t.Fatal("newLDAPTLSConfig() did not retain captured CA authority")
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("newLDAPTLSConfig() certificates = %d, want 1 captured identity", len(tlsConfig.Certificates))
	}
}

func TestLDAPTLSConfigRejectsIncompleteSealedClientIdentity(t *testing.T) {
	pki := newHealthProbePKI(t)
	ldapConfig := &config.LDAPConf{TLSClientCert: pki.clientCert}

	configured := &config.FileSettings{
		Server: &config.ServerSection{},
		LDAP:   &config.LDAPSection{Config: ldapConfig},
	}
	if _, err := config.EnsureArtifactSnapshot(configured); err != nil {
		t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
	}

	if _, err := newLDAPTLSConfig(configured, &url.URL{Scheme: ldapSchemeLDAPS, Host: "localhost"}, ldapConfig); err == nil {
		t.Fatal("newLDAPTLSConfig() error = nil, want incomplete client identity rejection")
	}
}

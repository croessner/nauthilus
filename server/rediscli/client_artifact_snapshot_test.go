// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package rediscli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/testing/testpki"
)

func TestRedisTLSConfigurationUsesSealedMaterialAfterLiveMutation(t *testing.T) {
	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.pem")
	certPath := filepath.Join(directory, "client.pem")
	keyPath := filepath.Join(directory, "client.key")
	material := testpki.NewSelfSigned(t)

	var err error

	for path, content := range map[string][]byte{
		caPath:   material.CertificatePEM,
		certPath: material.CertificatePEM,
		keyPath:  material.PrivateKeyPEM,
	} {
		if err = os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("write test TLS artifact %q: %v", path, err)
		}
	}

	configured := &config.FileSettings{Server: &config.ServerSection{}}

	configured.Server.Redis.TLS = config.TLS{
		Enabled: true,
		CAFile:  caPath,
		Cert:    certPath,
		Key:     keyPath,
	}
	if _, err = config.EnsureArtifactSnapshot(configured); err != nil {
		t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
	}

	for _, path := range []string{caPath, certPath, keyPath} {
		if err = os.WriteFile(path, []byte("mutated invalid TLS material\n"), 0o600); err != nil {
			t.Fatalf("mutate test TLS artifact %q: %v", path, err)
		}
	}

	tlsConfig, err := redisTLSOptions(configured, &configured.Server.Redis.TLS)
	if err != nil {
		t.Fatalf("redisTLSOptions() error = %v", err)
	}

	if tlsConfig == nil || tlsConfig.RootCAs == nil {
		t.Fatal("redisTLSOptions() did not retain the captured CA authority")
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("redisTLSOptions() certificates = %d, want 1 captured identity", len(tlsConfig.Certificates))
	}
}

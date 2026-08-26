// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package oidckeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp/signing"
)

func TestManagerUsesSealedOIDCSigningKeyBytes(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate OIDC signing key: %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "oidc-signing-key.pem")

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err = os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write OIDC signing key: %v", err)
	}

	artifacts, err := config.CaptureArtifactSnapshot(config.ArtifactSnapshotSpec{Paths: []string{keyPath}})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	configured := &config.FileSettings{IDP: &config.IDPSection{OIDC: config.OIDCConfig{
		SigningKeys: []config.OIDCKey{{
			ID: "sealed", KeyFile: keyPath, Algorithm: signing.AlgorithmRS256, Active: true,
		}},
	}}}
	manager := &Manager{deps: &deps.Deps{Cfg: configured}, artifacts: artifacts}

	if err = os.WriteFile(keyPath, []byte("mutated after candidate seal\n"), 0o600); err != nil {
		t.Fatalf("mutate OIDC signing key: %v", err)
	}

	loaded, err := manager.getStaticRSAKeyByID("sealed")
	if err != nil {
		t.Fatalf("getStaticRSAKeyByID() error = %v", err)
	}

	if loaded.N.Cmp(privateKey.N) != 0 {
		t.Fatal("getStaticRSAKeyByID() did not use the sealed candidate key")
	}
}

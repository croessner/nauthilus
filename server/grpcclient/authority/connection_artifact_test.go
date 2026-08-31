// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package authority

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
)

func TestTransportCredentialsUsesSealedAuthorityTLSBytes(t *testing.T) {
	certificatePEM, keyPEM := mustAuthorityTLSMaterial(t)
	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.pem")
	certPath := filepath.Join(directory, "client.pem")
	keyPath := filepath.Join(directory, "client-key.pem")

	writeAuthorityArtifact(t, caPath, certificatePEM)
	writeAuthorityArtifact(t, certPath, certificatePEM)
	writeAuthorityArtifact(t, keyPath, keyPEM)
	artifacts := mustCaptureAuthorityArtifacts(t, caPath, certPath, keyPath)

	writeAuthorityArtifact(t, caPath, []byte("mutated CA\n"))
	writeAuthorityArtifact(t, certPath, []byte("mutated certificate\n"))
	writeAuthorityArtifact(t, keyPath, []byte("mutated key\n"))

	credentials, err := transportCredentials(&config.NauthilusAuthorityClientSection{
		TLS: config.AuthorityTLSSection{
			Enabled: true,
			CA:      caPath,
			Cert:    certPath,
			Key:     keyPath,
		},
	}, artifacts)
	if err != nil {
		t.Fatalf("transportCredentials() error = %v", err)
	}

	if credentials == nil {
		t.Fatal("transportCredentials() returned nil credentials")
	}
}

// mustAuthorityTLSMaterial creates one self-signed certificate and matching private key.
func mustAuthorityTLSMaterial(t *testing.T) ([]byte, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate authority TLS key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "authority-client.example.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create authority TLS certificate: %v", err)
	}

	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return certificatePEM, keyPEM
}

// writeAuthorityArtifact writes one test credential with private file permissions.
func writeAuthorityArtifact(t *testing.T, path string, content []byte) {
	t.Helper()

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write authority artifact %q: %v", path, err)
	}
}

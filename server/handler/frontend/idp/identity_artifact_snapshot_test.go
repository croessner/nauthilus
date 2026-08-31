// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package idp

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/idp/signing"
)

func TestOIDCClientVerifierUsesSealedPublicKeyBytes(t *testing.T) {
	_, publicKeyPEM := generateTestClientKeyPair(t)
	keyPath := filepath.Join(t.TempDir(), "client-public-key.pem")
	writeIdentityArtifact(t, keyPath, []byte(publicKeyPEM))
	artifacts := mustCaptureIdentityArtifacts(t, keyPath)

	client := &config.OIDCClient{
		ClientID:                 "sealed-client",
		ClientPublicKeyFile:      keyPath,
		ClientPublicKeyAlgorithm: signing.AlgorithmRS256,
	}
	configured := &config.FileSettings{IDP: &config.IDPSection{OIDC: config.OIDCConfig{
		Clients: []config.OIDCClient{*client},
	}}}
	handler := &OIDCHandler{deps: &deps.Deps{Cfg: configured}, artifacts: artifacts}

	writeIdentityArtifact(t, keyPath, []byte("mutated after candidate seal\n"))

	verifier, err := handler.buildClientVerifier(client)
	if err != nil {
		t.Fatalf("buildClientVerifier() error = %v", err)
	}

	if verifier == nil || verifier.Algorithm() != signing.AlgorithmRS256 {
		t.Fatalf("buildClientVerifier() = %#v, want sealed RS256 verifier", verifier)
	}
}

func TestSAMLIdentityProviderUsesSealedCertificateAndKeyBytes(t *testing.T) {
	privateKey, _, certificatePEM := mustGenerateRSACertificate(t, "idp.example.test")
	keyPEM := mustEncodeRSAPrivateKeyPEM(t, privateKey)
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "idp-cert.pem")
	keyPath := filepath.Join(directory, "idp-key.pem")

	writeIdentityArtifact(t, certificatePath, certificatePEM)
	writeIdentityArtifact(t, keyPath, keyPEM)
	artifacts := mustCaptureIdentityArtifacts(t, certificatePath, keyPath)

	configured := &config.FileSettings{IDP: &config.IDPSection{
		OIDC: config.OIDCConfig{Issuer: "https://idp.example.test"},
		SAML2: config.SAML2Config{
			Enabled: true, EntityID: "https://idp.example.test/saml",
			CertFile: certificatePath, KeyFile: keyPath,
		},
	}}
	handler := &SAMLHandler{
		deps: &deps.Deps{Cfg: configured, Logger: slog.Default()}, artifacts: artifacts,
	}

	writeIdentityArtifact(t, certificatePath, []byte("mutated certificate\n"))
	writeIdentityArtifact(t, keyPath, []byte("mutated key\n"))

	provider, err := handler.getSAMLIDP()
	if err != nil {
		t.Fatalf("getSAMLIDP() error = %v", err)
	}

	if provider == nil || provider.Certificate == nil || provider.Key == nil {
		t.Fatalf("getSAMLIDP() = %#v, want sealed certificate and key", provider)
	}
}

func TestSAMLServiceProviderUsesSealedCertificateBytes(t *testing.T) {
	_, _, certificatePEM := mustGenerateRSACertificate(t, "sp.example.test")
	certificatePath := filepath.Join(t.TempDir(), "sp-cert.pem")
	writeIdentityArtifact(t, certificatePath, certificatePEM)
	artifacts := mustCaptureIdentityArtifacts(t, certificatePath)

	serviceProvider := config.SAML2ServiceProvider{
		EntityID: "https://sp.example.test/metadata",
		ACSURL:   "https://sp.example.test/acs",
		CertFile: certificatePath,
	}
	handler := &SAMLHandler{
		deps:      &deps.Deps{Cfg: &config.FileSettings{}, Logger: slog.Default()},
		idp:       &fakeSAMLIdentityProvider{sp: serviceProvider},
		artifacts: artifacts,
	}

	writeIdentityArtifact(t, certificatePath, []byte("mutated certificate\n"))

	descriptor, err := handler.GetServiceProvider(nil, serviceProvider.EntityID)
	if err != nil {
		t.Fatalf("GetServiceProvider() error = %v", err)
	}

	if descriptor == nil || len(descriptor.SPSSODescriptors) != 1 ||
		len(descriptor.SPSSODescriptors[0].KeyDescriptors) != 1 {
		t.Fatalf("GetServiceProvider() = %#v, want sealed signing descriptor", descriptor)
	}
}

// mustCaptureIdentityArtifacts seals exact identity credential bytes for one test candidate.
func mustCaptureIdentityArtifacts(t *testing.T, paths ...string) *config.ArtifactSnapshot {
	t.Helper()

	snapshot, err := config.CaptureArtifactSnapshot(config.ArtifactSnapshotSpec{Paths: paths})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	return snapshot
}

// writeIdentityArtifact writes one test identity credential with private file permissions.
func writeIdentityArtifact(t *testing.T, path string, content []byte) {
	t.Helper()

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write identity artifact %q: %v", path, err)
	}
}

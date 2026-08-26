// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type identityAuthorityTestArtifacts struct {
	oidcSigning string
	oidcClient  string
	samlCert    string
	samlKey     string
	samlSPCert  string
	remoteCA    string
	remoteCert  string
	remoteKey   string
	staticToken string
	privateJWT  string
}

func TestSealedIdentityAuthorityArtifactsIgnorePostCaptureMutation(t *testing.T) {
	material := mustIdentityAuthorityMaterial(t)
	artifacts := writeIdentityAuthorityArtifacts(t, material)
	configured := identityAuthorityArtifactCandidate(artifacts)

	snapshot, err := EnsureArtifactSnapshot(configured)
	if err != nil {
		t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
	}

	for _, path := range identityAuthorityArtifactPaths(artifacts) {
		writeIdentityAuthorityArtifact(t, path, []byte("mutated after candidate seal\n"))
	}

	if err = validateSealedIdentityAuthorityArtifacts(configured, snapshot); err != nil {
		t.Fatalf("validateSealedIdentityAuthorityArtifacts() error = %v", err)
	}

	if err = snapshot.ValidateLive(); err == nil {
		t.Fatal("ValidateLive() error = nil, want post-capture mutation rejection")
	}
}

func TestSealedIdentityAuthorityArtifactsRejectMalformedCredentials(t *testing.T) {
	material := mustIdentityAuthorityMaterial(t)
	tests := []struct {
		mutate  func(identityAuthorityTestArtifacts) string
		wantErr string
		name    string
	}{
		{name: "OIDC signing key", mutate: func(a identityAuthorityTestArtifacts) string { return a.oidcSigning }, wantErr: "OIDC signing key"},
		{name: "OIDC client public key", mutate: func(a identityAuthorityTestArtifacts) string { return a.oidcClient }, wantErr: "OIDC client public key"},
		{name: "SAML IdP certificate", mutate: func(a identityAuthorityTestArtifacts) string { return a.samlCert }, wantErr: "SAML IdP certificate"},
		{name: "SAML IdP private key", mutate: func(a identityAuthorityTestArtifacts) string { return a.samlKey }, wantErr: "SAML IdP private key"},
		{name: "SAML SP certificate", mutate: func(a identityAuthorityTestArtifacts) string { return a.samlSPCert }, wantErr: "SAML SP certificate"},
		{name: "remote authority CA", mutate: func(a identityAuthorityTestArtifacts) string { return a.remoteCA }, wantErr: "authority CA"},
		{name: "remote authority certificate", mutate: func(a identityAuthorityTestArtifacts) string { return a.remoteCert }, wantErr: "authority client certificate"},
		{name: "remote authority key", mutate: func(a identityAuthorityTestArtifacts) string { return a.remoteKey }, wantErr: "authority client certificate"},
		{name: "static token", mutate: func(a identityAuthorityTestArtifacts) string { return a.staticToken }, wantErr: "static token file is empty"},
		{name: "private key JWT", mutate: func(a identityAuthorityTestArtifacts) string { return a.privateJWT }, wantErr: "private_key_jwt key"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts := writeIdentityAuthorityArtifacts(t, material)
			path := test.mutate(artifacts)

			content := []byte("malformed\n")
			if path == artifacts.staticToken {
				content = []byte(" \n")
			}

			writeIdentityAuthorityArtifact(t, path, content)

			configured := identityAuthorityArtifactCandidate(artifacts)

			snapshot, err := EnsureArtifactSnapshot(configured)
			if err != nil {
				t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
			}

			err = validateSealedIdentityAuthorityArtifacts(configured, snapshot)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateSealedIdentityAuthorityArtifacts() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

// mustIdentityAuthorityMaterial creates one valid shared RSA certificate/key/public-key set.
func mustIdentityAuthorityMaterial(t *testing.T) map[string][]byte {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate identity test key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "identity.example.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create identity test certificate: %v", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal identity test public key: %v", err)
	}

	return map[string][]byte{
		"certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		"private":     pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}),
		"public":      pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
		"token":       []byte("opaque-static-token\n"),
	}
}

// writeIdentityAuthorityArtifacts creates one independent exact credential fixture.
func writeIdentityAuthorityArtifacts(t *testing.T, material map[string][]byte) identityAuthorityTestArtifacts {
	t.Helper()

	directory := t.TempDir()
	artifacts := identityAuthorityTestArtifacts{
		oidcSigning: filepath.Join(directory, "oidc-signing.pem"),
		oidcClient:  filepath.Join(directory, "oidc-client.pem"),
		samlCert:    filepath.Join(directory, "saml-cert.pem"),
		samlKey:     filepath.Join(directory, "saml-key.pem"),
		samlSPCert:  filepath.Join(directory, "saml-sp-cert.pem"),
		remoteCA:    filepath.Join(directory, "authority-ca.pem"),
		remoteCert:  filepath.Join(directory, "authority-client.pem"),
		remoteKey:   filepath.Join(directory, "authority-client-key.pem"),
		staticToken: filepath.Join(directory, "authority-token"),
		privateJWT:  filepath.Join(directory, "authority-jwt.pem"),
	}

	for _, path := range []string{artifacts.oidcSigning, artifacts.samlKey, artifacts.remoteKey, artifacts.privateJWT} {
		writeIdentityAuthorityArtifact(t, path, material["private"])
	}

	for _, path := range []string{artifacts.samlCert, artifacts.samlSPCert, artifacts.remoteCA, artifacts.remoteCert} {
		writeIdentityAuthorityArtifact(t, path, material["certificate"])
	}

	writeIdentityAuthorityArtifact(t, artifacts.oidcClient, material["public"])
	writeIdentityAuthorityArtifact(t, artifacts.staticToken, material["token"])

	return artifacts
}

// identityAuthorityArtifactCandidate maps every lazy identity and authority artifact into one config.
func identityAuthorityArtifactCandidate(artifacts identityAuthorityTestArtifacts) *FileSettings {
	return &FileSettings{
		Runtime: &RuntimeSection{Clients: RuntimeClientsSection{GRPC: RuntimeGRPCClientsSection{
			NauthilusAuthorities: map[string]*NauthilusAuthorityClientSection{
				"edge": {
					Address: "authority.example.test:443",
					TLS: AuthorityTLSSection{
						Enabled: true, CA: artifacts.remoteCA, Cert: artifacts.remoteCert, Key: artifacts.remoteKey,
					},
					CallerAuth: AuthorityCallerAuthSection{OIDCBearer: AuthorityOIDCBearerSection{
						Enabled: true, Mode: AuthorityClientCredentialsMode,
						TokenEndpoint: "https://authority.example.test/oidc/token", ClientID: "edge",
						TokenEndpointAuthMethod: AuthorityPrivateKeyJWTAuth,
						ClientPrivateKeyFile:    artifacts.privateJWT,
						ClientAssertionAlg:      "RS256",
						StaticTokenFile:         artifacts.staticToken,
					}},
				},
			},
		}}},
		IDP: &IDPSection{
			OIDC: OIDCConfig{
				Enabled:     true,
				SigningKeys: []OIDCKey{{ID: "idp", KeyFile: artifacts.oidcSigning, Algorithm: "RS256", Active: true}},
				Clients: []OIDCClient{{
					ClientID: "client", ClientPublicKeyFile: artifacts.oidcClient, ClientPublicKeyAlgorithm: "RS256",
				}},
			},
			SAML2: SAML2Config{
				Enabled: true, CertFile: artifacts.samlCert, KeyFile: artifacts.samlKey,
				ServiceProviders: []SAML2ServiceProvider{{
					EntityID: "https://sp.example.test/metadata", ACSURL: "https://sp.example.test/acs",
					CertFile: artifacts.samlSPCert,
				}},
			},
		},
	}
}

// identityAuthorityArtifactPaths lists the exact files owned by the fixture.
func identityAuthorityArtifactPaths(artifacts identityAuthorityTestArtifacts) []string {
	return []string{
		artifacts.oidcSigning, artifacts.oidcClient, artifacts.samlCert, artifacts.samlKey,
		artifacts.samlSPCert, artifacts.remoteCA, artifacts.remoteCert, artifacts.remoteKey,
		artifacts.staticToken, artifacts.privateJWT,
	}
}

// writeIdentityAuthorityArtifact writes one exact credential fixture.
func writeIdentityAuthorityArtifact(t *testing.T, path string, content []byte) {
	t.Helper()

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write identity authority artifact %q: %v", path, err)
	}
}

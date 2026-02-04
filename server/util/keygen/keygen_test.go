// Copyright (C) 2025 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package keygen

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestGenerateRSAKey(t *testing.T) {
	keyPEM, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	if !strings.Contains(keyPEM, "BEGIN RSA PRIVATE KEY") {
		t.Error("key PEM does not contain BEGIN RSA PRIVATE KEY")
	}

	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	if key.N.BitLen() != 2048 {
		t.Errorf("expected key length 2048, got %d", key.N.BitLen())
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-cert", 2048, 1)
	if err != nil {
		t.Fatalf("failed to generate self-signed cert: %v", err)
	}

	if !strings.Contains(certPEM, "BEGIN CERTIFICATE") {
		t.Error("cert PEM does not contain BEGIN CERTIFICATE")
	}

	if !strings.Contains(keyPEM, "BEGIN RSA PRIVATE KEY") {
		t.Error("key PEM does not contain BEGIN RSA PRIVATE KEY")
	}

	// Verify cert
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	if cert.Subject.CommonName != "test-cert" {
		t.Errorf("expected common name test-cert, got %s", cert.Subject.CommonName)
	}

	// Verify key
	block, _ = pem.Decode([]byte(keyPEM))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	// Verify certificate matches private key
	certPubKey := cert.PublicKey.(*rsa.PublicKey)
	if certPubKey.N.Cmp(privKey.N) != 0 || certPubKey.E != privKey.E {
		t.Error("public key in certificate does not match private key")
	}
}

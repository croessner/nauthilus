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

package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func generateEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return priv
}

func rsaKeyToPEM(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func ed25519KeyToPEM(key ed25519.PrivateKey) string {
	der, _ := x509.MarshalPKCS8PrivateKey(key)

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}))
}

func TestRS256Signer_SignAndVerify(t *testing.T) {
	key := generateRSAKey(t)
	kid := "rs256-test-kid"

	signer := NewRS256Signer(key, kid)
	assert.Equal(t, AlgorithmRS256, signer.Algorithm())
	assert.Equal(t, kid, signer.KeyID())

	claims := jwt.MapClaims{
		"iss": "https://test.local",
		"sub": "user1",
		"aud": "client1",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	tokenString, err := signer.Sign(claims)
	if !assert.NoError(t, err) {
		return
	}

	assert.NotEmpty(t, tokenString)
	assert.Contains(t, tokenString, ".")

	// Verify with RS256Verifier
	verifier := NewRS256Verifier(&key.PublicKey)
	assert.Equal(t, AlgorithmRS256, verifier.Algorithm())

	verified, err := verifier.Verify(tokenString)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "https://test.local", verified["iss"])
	assert.Equal(t, "user1", verified["sub"])
	assert.Equal(t, "client1", verified["aud"])
}

func TestEdDSASigner_SignAndVerify(t *testing.T) {
	key := generateEd25519Key(t)
	kid := "eddsa-test-kid"

	signer := NewEdDSASigner(key, kid)
	assert.Equal(t, AlgorithmEdDSA, signer.Algorithm())
	assert.Equal(t, kid, signer.KeyID())

	claims := jwt.MapClaims{
		"iss": "https://test.local",
		"sub": "user2",
		"aud": "client2",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	tokenString, err := signer.Sign(claims)
	if !assert.NoError(t, err) {
		return
	}

	assert.NotEmpty(t, tokenString)

	// Verify with EdDSAVerifier
	pubKey := key.Public().(ed25519.PublicKey)
	verifier := NewEdDSAVerifier(pubKey)
	assert.Equal(t, AlgorithmEdDSA, verifier.Algorithm())

	verified, err := verifier.Verify(tokenString)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "https://test.local", verified["iss"])
	assert.Equal(t, "user2", verified["sub"])
}

func TestRS256SignerFromPEM(t *testing.T) {
	key := generateRSAKey(t)
	pemData := rsaKeyToPEM(key)

	signer, err := NewRS256SignerFromPEM(pemData, "pem-kid")
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, AlgorithmRS256, signer.Algorithm())
	assert.Equal(t, "pem-kid", signer.KeyID())

	claims := jwt.MapClaims{
		"sub": "test",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.Sign(claims)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)
}

func TestEdDSASignerFromPEM(t *testing.T) {
	key := generateEd25519Key(t)
	pemData := ed25519KeyToPEM(key)

	signer, err := NewEdDSASignerFromPEM(pemData, "ed-pem-kid")
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, AlgorithmEdDSA, signer.Algorithm())
	assert.Equal(t, "ed-pem-kid", signer.KeyID())

	claims := jwt.MapClaims{
		"sub": "test",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.Sign(claims)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)
}

func TestVerifier_WrongAlgorithm(t *testing.T) {
	rsaKey := generateRSAKey(t)
	edKey := generateEd25519Key(t)

	// Sign with RS256
	rsaSigner := NewRS256Signer(rsaKey, "rs256")

	claims := jwt.MapClaims{
		"sub": "test",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	rsaToken, err := rsaSigner.Sign(claims)
	if !assert.NoError(t, err) {
		return
	}

	// Try to verify RS256 token with EdDSA verifier -> should fail
	edVerifier := NewEdDSAVerifier(edKey.Public().(ed25519.PublicKey))

	_, err = edVerifier.Verify(rsaToken)
	assert.Error(t, err)

	// Sign with EdDSA
	edSigner := NewEdDSASigner(edKey, "eddsa")

	edToken, err := edSigner.Sign(claims)
	if !assert.NoError(t, err) {
		return
	}

	// Try to verify EdDSA token with RS256 verifier -> should fail
	rsaVerifier := NewRS256Verifier(&rsaKey.PublicKey)

	_, err = rsaVerifier.Verify(edToken)
	assert.Error(t, err)
}

func TestMultiVerifier(t *testing.T) {
	rsaKey := generateRSAKey(t)
	edKey := generateEd25519Key(t)

	rsaVerifier := NewRS256Verifier(&rsaKey.PublicKey)
	edVerifier := NewEdDSAVerifier(edKey.Public().(ed25519.PublicKey))

	multi := NewMultiVerifier(rsaVerifier, edVerifier)
	assert.Equal(t, "multi", multi.Algorithm())

	claims := jwt.MapClaims{
		"sub": "test",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	// RS256 signed token should verify
	rsaSigner := NewRS256Signer(rsaKey, "rs256")

	rsaToken, err := rsaSigner.Sign(claims)
	if !assert.NoError(t, err) {
		return
	}

	verified, err := multi.Verify(rsaToken)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "test", verified["sub"])

	// EdDSA signed token should verify
	edSigner := NewEdDSASigner(edKey, "eddsa")

	edToken, err := edSigner.Sign(claims)
	if !assert.NoError(t, err) {
		return
	}

	verified, err = multi.Verify(edToken)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "test", verified["sub"])

	// Invalid token should fail
	_, err = multi.Verify("invalid.token.string")
	assert.Error(t, err)
}

func TestSignerPublicKey(t *testing.T) {
	rsaKey := generateRSAKey(t)
	edKey := generateEd25519Key(t)

	rsaSigner := NewRS256Signer(rsaKey, "rs256")
	assert.NotNil(t, rsaSigner.PublicKey())

	edSigner := NewEdDSASigner(edKey, "eddsa")
	assert.NotNil(t, edSigner.PublicKey())
}

func TestParsePEM_Invalid(t *testing.T) {
	_, err := ParseRSAPrivateKeyPEM("not-a-pem")
	assert.Error(t, err)

	_, err = ParseEd25519PrivateKeyPEM("not-a-pem")
	assert.Error(t, err)

	_, err = ParseRSAPublicKeyPEM("not-a-pem")
	assert.Error(t, err)

	_, err = ParseEd25519PublicKeyPEM("not-a-pem")
	assert.Error(t, err)
}

func TestParsePEM_WrongKeyType(t *testing.T) {
	// Generate an Ed25519 key in PKCS#8 format
	edKey := generateEd25519Key(t)
	edPEM := ed25519KeyToPEM(edKey)

	// Try to parse Ed25519 PEM as RSA -> should fail
	_, err := NewRS256SignerFromPEM(edPEM, "wrong")
	assert.Error(t, err)

	// Generate an RSA key and try to parse as Ed25519 -> should fail
	rsaKey := generateRSAKey(t)
	rsaPEM := rsaKeyToPEM(rsaKey)

	_, err = NewEdDSASignerFromPEM(rsaPEM, "wrong")
	assert.Error(t, err)
}

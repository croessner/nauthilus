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

// Package signing provides OOP abstractions for JWT signing and verification.
// It supports RS256 (mandatory) and EdDSA/Ed25519 (optional) algorithms.
package signing

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Algorithm constants for supported signing methods.
const (
	AlgorithmRS256 = "RS256"
	AlgorithmEdDSA = "EdDSA"
)

// Signer defines the interface for signing JWT tokens.
type Signer interface {
	// Sign creates a signed JWT string from the given claims.
	Sign(claims jwt.MapClaims) (string, error)

	// Algorithm returns the signing algorithm identifier (e.g. "RS256", "EdDSA").
	Algorithm() string

	// KeyID returns the key identifier used in the JWT header.
	KeyID() string

	// PublicKey returns the public key corresponding to the signing key.
	PublicKey() crypto.PublicKey
}

// Verifier defines the interface for verifying JWT tokens.
type Verifier interface {
	// Verify parses and validates a JWT string and returns its claims.
	Verify(tokenString string) (jwt.MapClaims, error)

	// Algorithm returns the expected signing algorithm.
	Algorithm() string
}

// RS256Signer implements the Signer interface using RSA PKCS#1 v1.5 with SHA-256.
type RS256Signer struct {
	key *rsa.PrivateKey
	kid string
}

// NewRS256Signer creates a new RS256Signer from an RSA private key and key ID.
func NewRS256Signer(key *rsa.PrivateKey, kid string) *RS256Signer {
	return &RS256Signer{
		key: key,
		kid: kid,
	}
}

// NewRS256SignerFromPEM creates a new RS256Signer by parsing a PEM-encoded RSA private key.
func NewRS256SignerFromPEM(pemData string, kid string) (*RS256Signer, error) {
	key, err := ParseRSAPrivateKeyPEM(pemData)
	if err != nil {
		return nil, err
	}

	return NewRS256Signer(key, kid), nil
}

// Sign creates a signed JWT string using RS256.
func (s *RS256Signer) Sign(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid

	signed, err := token.SignedString(s.key)
	if err != nil {
		return "", fmt.Errorf("RS256 signing failed: %w", err)
	}

	return signed, nil
}

// Algorithm returns "RS256".
func (s *RS256Signer) Algorithm() string {
	return AlgorithmRS256
}

// KeyID returns the key identifier.
func (s *RS256Signer) KeyID() string {
	return s.kid
}

// PublicKey returns the RSA public key.
func (s *RS256Signer) PublicKey() crypto.PublicKey {
	return &s.key.PublicKey
}

// EdDSASigner implements the Signer interface using Ed25519 (EdDSA).
type EdDSASigner struct {
	key ed25519.PrivateKey
	kid string
}

// NewEdDSASigner creates a new EdDSASigner from an Ed25519 private key and key ID.
func NewEdDSASigner(key ed25519.PrivateKey, kid string) *EdDSASigner {
	return &EdDSASigner{
		key: key,
		kid: kid,
	}
}

// NewEdDSASignerFromPEM creates a new EdDSASigner by parsing a PEM-encoded Ed25519 private key.
func NewEdDSASignerFromPEM(pemData string, kid string) (*EdDSASigner, error) {
	key, err := ParseEd25519PrivateKeyPEM(pemData)
	if err != nil {
		return nil, err
	}

	return NewEdDSASigner(key, kid), nil
}

// Sign creates a signed JWT string using EdDSA.
func (s *EdDSASigner) Sign(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = s.kid

	signed, err := token.SignedString(s.key)
	if err != nil {
		return "", fmt.Errorf("EdDSA signing failed: %w", err)
	}

	return signed, nil
}

// Algorithm returns "EdDSA".
func (s *EdDSASigner) Algorithm() string {
	return AlgorithmEdDSA
}

// KeyID returns the key identifier.
func (s *EdDSASigner) KeyID() string {
	return s.kid
}

// PublicKey returns the Ed25519 public key.
func (s *EdDSASigner) PublicKey() crypto.PublicKey {
	return s.key.Public()
}

// RS256Verifier implements the Verifier interface for RS256 tokens.
type RS256Verifier struct {
	key *rsa.PublicKey
}

// NewRS256Verifier creates a new RS256Verifier from an RSA public key.
func NewRS256Verifier(key *rsa.PublicKey) *RS256Verifier {
	return &RS256Verifier{key: key}
}

// Verify parses and validates an RS256-signed JWT.
func (v *RS256Verifier) Verify(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return v.key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("RS256 verification failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid RS256 token")
	}

	return claims, nil
}

// Algorithm returns "RS256".
func (v *RS256Verifier) Algorithm() string {
	return AlgorithmRS256
}

// EdDSAVerifier implements the Verifier interface for EdDSA tokens.
type EdDSAVerifier struct {
	key ed25519.PublicKey
}

// NewEdDSAVerifier creates a new EdDSAVerifier from an Ed25519 public key.
func NewEdDSAVerifier(key ed25519.PublicKey) *EdDSAVerifier {
	return &EdDSAVerifier{key: key}
}

// Verify parses and validates an EdDSA-signed JWT.
func (v *EdDSAVerifier) Verify(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return v.key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("EdDSA verification failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid EdDSA token")
	}

	return claims, nil
}

// Algorithm returns "EdDSA".
func (v *EdDSAVerifier) Algorithm() string {
	return AlgorithmEdDSA
}

// MultiVerifier tries multiple verifiers in order until one succeeds.
type MultiVerifier struct {
	verifiers []Verifier
}

// NewMultiVerifier creates a new MultiVerifier from a list of verifiers.
func NewMultiVerifier(verifiers ...Verifier) *MultiVerifier {
	return &MultiVerifier{verifiers: verifiers}
}

// Verify tries each verifier in order. Returns claims from the first successful verification.
func (mv *MultiVerifier) Verify(tokenString string) (jwt.MapClaims, error) {
	var lastErr error

	for _, v := range mv.verifiers {
		claims, err := v.Verify(tokenString)
		if err == nil {
			return claims, nil
		}

		lastErr = err
	}

	return nil, fmt.Errorf("no verifier succeeded: %w", lastErr)
}

// Algorithm returns "multi" since it supports multiple algorithms.
func (mv *MultiVerifier) Algorithm() string {
	return "multi"
}

// ParseRSAPrivateKeyPEM parses a PEM-encoded RSA private key (PKCS#1 or PKCS#8).
func ParseRSAPrivateKeyPEM(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 key: %w", err)
		}

		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not RSA")
		}

		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

// ParseEd25519PrivateKeyPEM parses a PEM-encoded Ed25519 private key (PKCS#8).
func ParseEd25519PrivateKeyPEM(pemData string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 key: %w", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PKCS#8 key is not Ed25519")
	}

	return edKey, nil
}

// ParseRSAPublicKeyPEM parses a PEM-encoded RSA public key.
func ParseRSAPublicKeyPEM(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	return rsaKey, nil
}

// ParseEd25519PublicKeyPEM parses a PEM-encoded Ed25519 public key.
func ParseEd25519PublicKeyPEM(pemData string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519")
	}

	return edKey, nil
}

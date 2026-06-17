// Copyright (C) 2026 Christian Rößner
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

package pluginloader

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const defaultPluginPublicKeyComment = "nauthilus plugin public key"

// DefaultPluginSigningKeyID derives the minisign-compatible key id used for Nauthilus plugin signatures.
func DefaultPluginSigningKeyID(publicKey ed25519.PublicKey) ([]byte, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("plugin signing public key has %d bytes, want %d", len(publicKey), ed25519.PublicKeySize)
	}

	sum := sha256.Sum256(publicKey)
	keyID := make([]byte, detachedSignatureKeyIDSize)
	copy(keyID, sum[:detachedSignatureKeyIDSize])

	return keyID, nil
}

// ParsePluginSigningPrivateKey decodes a base64 Ed25519 seed or private key for build-time signing.
func ParsePluginSigningPrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return nil, fmt.Errorf("plugin signing private key is empty")
	}

	payload, err := decodePluginSigningPrivateKey(value)
	if err != nil {
		return nil, err
	}

	switch len(payload) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(payload), nil
	case ed25519.PrivateKeySize:
		privateKey := append(ed25519.PrivateKey{}, payload...)
		if len(privateKey.Seed()) != ed25519.SeedSize {
			return nil, fmt.Errorf("plugin signing private key seed is invalid")
		}

		return privateKey, nil
	default:
		return nil, fmt.Errorf("plugin signing private key has %d bytes, want %d-byte seed or %d-byte private key", len(payload), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

// FormatPluginPublicKey formats an Ed25519 public key in minisign/signify-compatible text form.
func FormatPluginPublicKey(publicKey ed25519.PublicKey, keyID []byte, comment string) ([]byte, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("plugin signing public key has %d bytes, want %d", len(publicKey), ed25519.PublicKeySize)
	}

	if err := validateDetachedKeyID(keyID); err != nil {
		return nil, err
	}

	if strings.ContainsAny(comment, "\r\n") {
		return nil, fmt.Errorf("plugin public key comment must be a single line")
	}

	if strings.TrimSpace(comment) == "" {
		comment = defaultPluginPublicKeyComment
	}

	return []byte(
		minisignCommentPrefix + comment + "\n" +
			base64.StdEncoding.EncodeToString(detachedPublicKeyBlob(keyID, publicKey)) + "\n",
	), nil
}

// FormatMinisignSignature builds a minisign-style detached signature for an artifact.
func FormatMinisignSignature(artifactPath string, privateKey ed25519.PrivateKey, keyID []byte, trustedComment string) ([]byte, error) {
	if err := validatePluginSigningPrivateKey(privateKey); err != nil {
		return nil, err
	}

	if err := validateDetachedKeyID(keyID); err != nil {
		return nil, err
	}

	if strings.TrimSpace(trustedComment) == "" {
		return nil, fmt.Errorf("plugin signature trusted comment is empty")
	}

	if strings.ContainsAny(trustedComment, "\r\n") {
		return nil, fmt.Errorf("plugin signature trusted comment must be a single line")
	}

	digest, err := artifactBLAKE2b512(artifactPath)
	if err != nil {
		return nil, err
	}

	artifactSignature := ed25519.Sign(privateKey, digest)
	signatureBlob := detachedSignatureBlob(detachedSignatureAlgorithmHashed, keyID, artifactSignature)
	globalSignature := ed25519.Sign(privateKey, append(append([]byte{}, artifactSignature...), []byte(trustedComment)...))

	return []byte(
		minisignCommentPrefix + "signature from Nauthilus plugin signing key\n" +
			base64.StdEncoding.EncodeToString(signatureBlob) + "\n" +
			minisignTrustedCommentPrefix + trustedComment + "\n" +
			base64.StdEncoding.EncodeToString(globalSignature) + "\n",
	), nil
}

// WriteMinisignSignatureFile writes a minisign-style detached signature for an artifact.
func WriteMinisignSignatureFile(artifactPath string, signaturePath string, privateKey ed25519.PrivateKey, keyID []byte, trustedComment string) error {
	signature, err := FormatMinisignSignature(artifactPath, privateKey, keyID, trustedComment)
	if err != nil {
		return err
	}

	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		return fmt.Errorf("write plugin signature %q: %w", signaturePath, err)
	}

	return nil
}

// decodePluginSigningPrivateKey decodes padded or raw standard base64 secret material.
func decodePluginSigningPrivateKey(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		payload, err := encoding.DecodeString(value)
		if err == nil {
			return payload, nil
		}
	}

	return nil, fmt.Errorf("plugin signing private key is not valid base64")
}

// validatePluginSigningPrivateKey checks Ed25519 private key shape before signing.
func validatePluginSigningPrivateKey(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("plugin signing private key has %d bytes, want %d", len(privateKey), ed25519.PrivateKeySize)
	}

	return nil
}

// validateDetachedKeyID checks the fixed minisign/signify key id length.
func validateDetachedKeyID(keyID []byte) error {
	if len(keyID) != detachedSignatureKeyIDSize {
		return fmt.Errorf("plugin signing key id has %d bytes, want %d", len(keyID), detachedSignatureKeyIDSize)
	}

	return nil
}

// detachedPublicKeyBlob returns the binary payload used inside public key files.
func detachedPublicKeyBlob(keyID []byte, publicKey ed25519.PublicKey) []byte {
	blob := []byte(detachedSignatureAlgorithmRaw)
	blob = append(blob, keyID...)
	blob = append(blob, publicKey...)

	return blob
}

// detachedSignatureBlob returns the binary payload used inside detached signature files.
func detachedSignatureBlob(algorithm string, keyID []byte, signature []byte) []byte {
	blob := []byte(algorithm)
	blob = append(blob, keyID...)
	blob = append(blob, signature...)

	return blob
}

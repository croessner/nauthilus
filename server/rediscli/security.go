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

package rediscli

import (
	"encoding/base64"

	"github.com/croessner/nauthilus/server/util/crypto"
)

// SecurityManager handles encryption and decryption of sensitive data stored in Redis.
type SecurityManager struct {
	secret string
}

// NewSecurityManager creates a new SecurityManager with the given secret.
func NewSecurityManager(secret string) *SecurityManager {
	return &SecurityManager{secret: secret}
}

// Encrypt encrypts the given plaintext using the configured secret.
// It returns a base64-encoded string of the ciphertext.
func (m *SecurityManager) Encrypt(plaintext string) (string, error) {
	if m.secret == "" || plaintext == "" {
		return plaintext, nil
	}

	ciphertext, err := crypto.EncryptString(plaintext, m.secret)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given base64-encoded ciphertext using the configured secret.
func (m *SecurityManager) Decrypt(encodedCiphertext string) (string, error) {
	if m.secret == "" || encodedCiphertext == "" {
		return encodedCiphertext, nil
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		// If it's not valid base64, it might be unencrypted data from before
		return encodedCiphertext, nil
	}

	plaintext, err := crypto.DecryptString(ciphertext, m.secret)
	if err != nil {
		// If decryption fails, it might be unencrypted data
		return encodedCiphertext, nil
	}

	return plaintext, nil
}

// IsEncryptionEnabled returns true if an encryption secret is configured.
func (m *SecurityManager) IsEncryptionEnabled() bool {
	return m.secret != ""
}

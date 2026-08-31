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

// Package security provides security functionality.
package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/util/crypto"
)

// Manager handles encryption and decryption of sensitive data.
type Manager struct {
	secret           secret.Value
	allowEmptySecret bool
	allowPlaintext   bool
}

// IndexDigest returns a deterministic non-reversible reference for sensitive index values.
func (m *Manager) IndexDigest(namespace string, value string) string {
	var digest []byte

	m.secret.WithBytes(func(secretBytes []byte) {
		if len(secretBytes) == 0 {
			sum := sha256.Sum256([]byte(namespace + "\x00" + value))
			digest = sum[:]

			return
		}

		mac := hmac.New(sha256.New, secretBytes)
		_, _ = mac.Write([]byte(namespace))
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write([]byte(value))
		digest = mac.Sum(nil)
	})

	return hex.EncodeToString(digest)
}

// Option configures the behavior of the Manager.
type Option func(*Manager)

// WithAllowEmptySecret permits running without an encryption secret.
func WithAllowEmptySecret() Option {
	return func(m *Manager) {
		m.allowEmptySecret = true
	}
}

// WithAllowPlaintext permits plaintext values when decrypting.
func WithAllowPlaintext() Option {
	return func(m *Manager) {
		m.allowPlaintext = true
	}
}

// NewManager creates a new Manager with the given secret and options.
func NewManager(secret secret.Value, opts ...Option) *Manager {
	m := &Manager{secret: secret}
	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Encrypt encrypts the given plaintext using the configured secret.
// It returns a base64-encoded string of the ciphertext.
func (m *Manager) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	if err := m.ensureSecret(); err != nil {
		return "", err
	}

	if m.secret.IsZero() {
		return plaintext, nil
	}

	var (
		ciphertext []byte
		encErr     error
	)

	m.secret.WithBytes(func(secretBytes []byte) {
		if len(secretBytes) == 0 {
			return
		}

		ciphertext, encErr = crypto.EncryptString(plaintext, secretBytes)
	})

	if encErr != nil {
		return "", encErr
	}

	if len(ciphertext) == 0 {
		return "", nil
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given base64-encoded ciphertext using the configured secret.
func (m *Manager) Decrypt(encodedCiphertext string) (string, error) {
	if encodedCiphertext == "" {
		return "", nil
	}

	if err := m.ensureSecret(); err != nil {
		return "", err
	}

	if m.secret.IsZero() {
		return encodedCiphertext, nil
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		if m.allowPlaintext {
			return encodedCiphertext, nil
		}

		return "", err
	}

	var (
		plaintext string
		decErr    error
	)

	m.secret.WithBytes(func(secretBytes []byte) {
		if len(secretBytes) == 0 {
			return
		}

		plaintext, decErr = crypto.DecryptString(ciphertext, secretBytes)
	})

	if decErr != nil {
		if m.allowPlaintext {
			return encodedCiphertext, nil
		}

		return "", decErr
	}

	return plaintext, nil
}

// IsEncryptionEnabled returns true if an encryption secret is configured.
func (m *Manager) IsEncryptionEnabled() bool {
	return !m.secret.IsZero()
}

func (m *Manager) ensureSecret() error {
	if m.secret.IsZero() && !m.allowEmptySecret {
		return fmt.Errorf("encryption secret is required")
	}

	return nil
}

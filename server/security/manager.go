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

package security

import (
	"encoding/base64"
	"fmt"

	"github.com/croessner/nauthilus/server/secret"
	"github.com/croessner/nauthilus/server/util/crypto"
)

// Manager handles encryption and decryption of sensitive data.
type Manager struct {
	secret           secret.Value
	allowEmptySecret bool
	allowPlaintext   bool
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

	var ciphertext []byte
	var encErr error
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

	var plaintext string
	var decErr error
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

// Copyright 2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/security"
	"github.com/stretchr/testify/assert"
)

type recoveryEncryptionConfig struct {
	config.File
}

// GetLDAPConfigEncryptionSecret supplies an isolated recovery encryption key.
func (recoveryEncryptionConfig) GetLDAPConfigEncryptionSecret() secret.Value {
	return secret.New("testsecret12345678")
}

// TestLDAPRecoverySkipsCorruptValuesWithoutLoggingSecrets checks matching and sanitized warnings.
func TestLDAPRecoverySkipsCorruptValuesWithoutLoggingSecrets(t *testing.T) {
	cfg := recoveryEncryptionConfig{}
	encryption := security.NewManager(cfg.GetLDAPConfigEncryptionSecret())
	encrypted, err := encryption.Encrypt("valid-recovery-code")
	assert.NoError(t, err)

	for _, code := range []string{"valid-recovery-code", "invalid-code", ""} {
		t.Run(code, func(t *testing.T) {
			var output bytes.Buffer

			manager := &ldapManagerImpl{deps: AuthDeps{Cfg: cfg, Logger: slog.New(slog.NewJSONHandler(&output, nil))}}
			corrupt := "{ENC}broken-secret-value"
			matches, err := manager.matchStoredRecoveryCodes([]any{corrupt, encrypted, encrypted}, code)
			assert.NoError(t, err)

			if code == "valid-recovery-code" {
				assert.Equal(t, []string{encrypted, encrypted}, matches)
			} else {
				assert.Empty(t, matches)
			}

			assert.Contains(t, output.String(), "WARN")
			assert.Contains(t, output.String(), "skipping undecryptable stored value")

			for _, sensitive := range []string{corrupt, encrypted, "valid-recovery-code"} {
				assert.NotContains(t, output.String(), sensitive)
			}
		})
	}
}

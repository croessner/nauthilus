// Copyright 2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/model/mfa"
	"github.com/stretchr/testify/assert"
)

// replacementRecoveryBackend models a legacy backend without atomic consume support.
type replacementRecoveryBackend struct {
	BackendManager
	codes     []string
	lookupErr error
	writeErr  error
	writes    int
}

// PassDB returns authoritative values independently of the request's stale attributes.
func (b *replacementRecoveryBackend) PassDB(_ *AuthState) (*PassDBResult, error) {
	values := make([]any, len(b.codes))
	for i, code := range b.codes {
		values[i] = code
	}

	return &PassDBResult{UserFound: true, TOTPRecoveryField: "recovery", Attributes: bktype.AttributeMapping{"recovery": values}}, b.lookupErr
}

// AddTOTPRecoveryCodes replaces the authoritative recovery set.
func (b *replacementRecoveryBackend) AddTOTPRecoveryCodes(_ *AuthState, recovery *mfa.TOTPRecovery) error {
	b.writes++
	if b.writeErr == nil {
		b.codes = recovery.GetCodes()
	}

	return b.writeErr
}

// DeleteTOTPRecoveryCodes removes the last authoritative code.
func (b *replacementRecoveryBackend) DeleteTOTPRecoveryCodes(auth *AuthState) error {
	return b.AddTOTPRecoveryCodes(auth, mfa.NewTOTPRecovery(nil))
}

// TestRecoveryFallbackReadsFreshAndRejectsErrors proves stale attributes cannot authorize legacy consumption.
func TestRecoveryFallbackReadsFreshAndRejectsErrors(t *testing.T) {
	for _, failure := range []string{"none", "lookup", "write"} {
		t.Run(failure, func(t *testing.T) {
			backend := &replacementRecoveryBackend{codes: []string{"once"}}
			auth := &AuthState{}
			auth.Runtime.TOTPRecoveryField = "recovery"
			auth.ReplaceAllAttributes(bktype.AttributeMapping{"recovery": {"once"}})

			if failure == "lookup" {
				backend.lookupErr = errors.New("backend unavailable")
			}

			if failure == "write" {
				backend.writeErr = errors.New("write rejected")
			}

			valid, remaining, err := ConsumeRecoveryCode(auth, backend, "once")
			if failure != "none" {
				assert.Error(t, err)
				assert.False(t, valid)

				return
			}

			assert.NoError(t, err)
			assert.True(t, valid)
			assert.Zero(t, remaining)

			valid, _, err = ConsumeRecoveryCode(auth, backend, "once")
			assert.NoError(t, err)
			assert.False(t, valid)
			assert.Equal(t, 1, backend.writes)
		})
	}
}

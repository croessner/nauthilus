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

package core

import (
	"strings"
	"time"
	"unicode"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	defaultTOTPIssuer = "Nauthilus"
	totpPeriodSeconds = 30
	defaultTOTPSkew   = 1
)

// TOTPSettings contains the interoperable TOTP profile used for setup and validation.
type TOTPSettings struct {
	Issuer    string
	Period    uint
	Skew      uint
	Digits    otp.Digits
	Algorithm otp.Algorithm
}

// NewTOTPSettings builds the TOTP profile from configuration and applies stable interoperability defaults.
func NewTOTPSettings(cfg config.File) TOTPSettings {
	settings := TOTPSettings{
		Issuer:    defaultTOTPIssuer,
		Period:    totpPeriodSeconds,
		Skew:      defaultTOTPSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}

	if cfg == nil {
		return settings
	}

	frontend := cfg.GetServer().GetFrontend()
	if issuer := strings.TrimSpace(frontend.GetTotpIssuer()); issuer != "" {
		settings.Issuer = issuer
	}

	if skew := frontend.GetTotpSkew(); skew > 0 {
		settings.Skew = skew
	}

	return settings
}

// Generate creates one-time TOTP setup material for an account.
func (settings TOTPSettings) Generate(accountName string) (TOTPRegistration, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      settings.Issuer,
		AccountName: accountName,
		Period:      settings.Period,
		Digits:      settings.Digits,
		Algorithm:   settings.Algorithm,
	})
	if err != nil {
		return TOTPRegistration{}, err
	}

	return TOTPRegistration{
		Secret:     key.Secret(),
		OTPAuthURL: key.URL(),
	}, nil
}

// Validate verifies a user supplied TOTP code against a stored secret.
func (settings TOTPSettings) Validate(code string, secret string) error {
	codeValid, err := totp.ValidateCustom(NormalizeTOTPCode(code), NormalizeTOTPSecret(secret), time.Now().UTC(), totp.ValidateOpts{
		Period:    settings.Period,
		Skew:      settings.Skew,
		Digits:    settings.Digits,
		Algorithm: settings.Algorithm,
	})
	if err != nil {
		return err
	}

	if !codeValid {
		return errors.ErrTOTPCodeInvalid
	}

	return nil
}

// NormalizeTOTPCode accepts common authenticator copy formats without changing the TOTP value.
func NormalizeTOTPCode(code string) string {
	return removeTOTPSeparators(code)
}

// NormalizeTOTPSecret accepts raw Base32 secrets and accidentally persisted otpauth URLs.
func NormalizeTOTPSecret(secret string) string {
	normalized := strings.TrimSpace(secret)

	if strings.HasPrefix(strings.ToLower(normalized), "otpauth://") {
		key, err := otp.NewKeyFromURL(normalized)

		if err == nil && key.Secret() != "" {
			normalized = key.Secret()
		}
	}

	return removeTOTPSeparators(normalized)
}

func removeTOTPSeparators(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || unicode.Is(unicode.Dash, r) {
			return -1
		}

		return r
	}, value)
}

// TotpValidation validates a TOTP code for a given account. It also checks for backup/recovery codes.
func TotpValidation(ctx *gin.Context, auth *AuthState, code string, deps AuthDeps) error {
	totpSecret := auth.GetTOTPSecret()

	// Check for backup/recovery codes first
	recoveryCodes := auth.GetTOTPRecoveryCodes()
	for i, rc := range recoveryCodes {
		if rc == code {
			// Code matches. Remove it from the list.
			newCodes := append(recoveryCodes[:i], recoveryCodes[i+1:]...)

			// Update backend
			backend := deps.Backend
			if backend == nil {
				backend = auth.GetBackendManager(auth.GetUsedPassDBBackend(), "")
			}

			if backend == nil {
				return errors.ErrUnknownDatabaseBackend
			}

			err := backend.DeleteTOTPRecoveryCodes(auth)
			if err != nil {
				return err
			}

			if len(newCodes) > 0 {
				err = backend.AddTOTPRecoveryCodes(auth, mfa.NewTOTPRecovery(newCodes))
				if err != nil {
					return err
				}
			}

			// Invalidate cache since we changed the backend data
			auth.PurgeCache()

			return nil
		}
	}

	return ValidateTOTPCode(code, totpSecret, deps)
}

// ValidateTOTPCode validates the time-based one-time password (TOTP) code against the provided secret.
func ValidateTOTPCode(code string, totpSecret string, deps AuthDeps) error {
	return NewTOTPSettings(deps.Cfg).Validate(code, totpSecret)
}

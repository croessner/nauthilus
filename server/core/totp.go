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
	"time"

	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

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

	return totpValidation(ctx, auth.Runtime.GUID, code, auth.GetAccount(), totpSecret, deps)
}

// totpValidation validates the time-based one-time password (TOTP) code against the provided account and TOTP secret.
func totpValidation(ctx *gin.Context, guid string, code string, account string, totpSecret string, deps AuthDeps) error {
	codeValid, err := totp.ValidateCustom(code, totpSecret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      deps.Cfg.GetServer().Frontend.GetTotpSkew(),
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil {
		return err
	}

	if !codeValid {
		return errors.ErrTOTPCodeInvalid
	}

	return nil
}

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
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/croessner/nauthilus/server/util"
)

const (
	// DefaultNumberOfBackupCodes defines the default number of backup codes to generate.
	DefaultNumberOfBackupCodes = 10
	// DefaultBackupCodeLength defines the default length of a single backup code.
	DefaultBackupCodeLength = 8
)

// GenerateBackupCodes generates a new set of backup codes.
func GenerateBackupCodes() (*mfa.TOTPRecovery, error) {
	codes := make([]string, DefaultNumberOfBackupCodes)
	for i := range DefaultNumberOfBackupCodes {
		code, err := util.GenerateRandomString(DefaultBackupCodeLength)
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}

	return mfa.NewTOTPRecovery(codes), nil
}

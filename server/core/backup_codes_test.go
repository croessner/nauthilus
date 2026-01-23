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

import "testing"

func TestGenerateBackupCodes(t *testing.T) {
	recovery, err := GenerateBackupCodes()
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}

	codes := recovery.GetCodes()
	if len(codes) != DefaultNumberOfBackupCodes {
		t.Errorf("Expected %d codes, got %d", DefaultNumberOfBackupCodes, len(codes))
	}

	for _, code := range codes {
		if len(code) != DefaultBackupCodeLength {
			t.Errorf("Expected code length %d, got %d", DefaultBackupCodeLength, len(code))
		}
	}
}

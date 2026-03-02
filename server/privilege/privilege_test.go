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

package privilege

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDropPrivileges_Noop(t *testing.T) {
	// All empty — should be a no-op and return nil.
	err := DropPrivileges("", "", "")

	assert.NoError(t, err)
}

func TestDropPrivileges_InvalidUser(t *testing.T) {
	err := DropPrivileges("nonexistent_user_xyz_12345", "", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user lookup")
}

func TestDropPrivileges_InvalidGroup(t *testing.T) {
	err := DropPrivileges("", "nonexistent_group_xyz_12345", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "group lookup")
}

func TestValidateChrootFiles_MissingFiles(t *testing.T) {
	tmpDir := t.TempDir()

	err := validateChrootFiles(tmpDir)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "essential file missing in chroot")
}

func TestValidateChrootFiles_AllPresent(t *testing.T) {
	tmpDir := t.TempDir()
	etcDir := filepath.Join(tmpDir, "etc")

	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, f := range essentialChrootFiles {
		if err := os.WriteFile(filepath.Join(tmpDir, f), []byte("# test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	err := validateChrootFiles(tmpDir)

	assert.NoError(t, err)
}

func TestResolveIdentity_EmptyInputs(t *testing.T) {
	id, err := resolveIdentity("", "")

	assert.NoError(t, err)
	assert.False(t, id.hasUID)
	assert.False(t, id.hasGID)
}

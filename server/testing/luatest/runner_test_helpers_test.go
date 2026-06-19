// Copyright (C) 2026 Christian Roessner
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

package luatest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runLuaMockFixture(t *testing.T, scriptName, callbackType, script, mock string) (*TestRunner, *TestResult) {
	t.Helper()

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, scriptName)
	mockPath := filepath.Join(dir, "mock.json")

	writeLuaMockTestFile(t, scriptPath, script)
	writeLuaMockTestFile(t, mockPath, mock)

	runner, err := NewTestRunner(scriptPath, callbackType, mockPath)
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	return runner, result
}

func requireLuaMockSuccess(t *testing.T, result *TestResult) {
	t.Helper()

	if !result.Success {
		t.Fatalf("result.Success = false, errors = %v", result.Errors)
	}
}

func writeLuaMockTestFile(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func testErrorsContain(errors []error, substring string) bool {
	for _, err := range errors {
		if err != nil && strings.Contains(err.Error(), substring) {
			return true
		}
	}

	return false
}

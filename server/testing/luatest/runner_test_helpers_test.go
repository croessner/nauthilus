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

// runSuccessfulLuaMockFixture executes a Lua mock fixture and requires a successful result.
func runSuccessfulLuaMockFixture(t *testing.T, scriptName, callbackType, script, mock string) *TestRunner {
	t.Helper()

	runner, result := runLuaMockFixture(t, scriptName, callbackType, script, mock)
	requireLuaMockSuccess(t, result)

	return runner
}

func requireLuaMockSuccess(t *testing.T, result *TestResult) {
	t.Helper()

	if !result.Success {
		t.Fatalf("result.Success = false, errors = %v", result.Errors)
	}
}

// requireSingleCapturedValue checks that one fixture capture exists and exposes the expected value.
func requireSingleCapturedValue[T any](
	t *testing.T,
	label string,
	captures []T,
	extract func(T) string,
	want string,
) {
	t.Helper()

	if len(captures) != 1 {
		t.Fatalf("%s captures = %#v, want exactly one", label, captures)
	}

	if got := extract(captures[0]); got != want {
		t.Fatalf("%s value = %q, want %s", label, got, want)
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

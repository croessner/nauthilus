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

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunConfigDumpDefaults(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := runConfigDumpDefaults(stdout, stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}

	if !strings.Contains(stdout.String(), `runtime.http.middlewares.logging = true`) {
		t.Fatalf("unexpected stdout output: %q", stdout.String())
	}
}

func TestRunConfigDumpNonDefaultsNilSetup(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := runConfigDumpNonDefaults(nil, stdout, stderr)
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "configuration dump failed: setup function is nil") {
		t.Fatalf("unexpected stderr output: %q", stderr.String())
	}
}

func TestRunConfigDumpNonDefaultsSetupError(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := runConfigDumpNonDefaults(func() error {
		return errors.New("broken config")
	}, stdout, stderr)
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "configuration dump failed: broken config") {
		t.Fatalf("unexpected stderr output: %q", stderr.String())
	}
}

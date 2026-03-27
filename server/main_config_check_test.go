package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunConfigCheck(t *testing.T) {
	t.Run("valid configuration returns zero", func(t *testing.T) {
		stderr := &bytes.Buffer{}

		exitCode := runConfigCheck(func() error {
			return nil
		}, stderr)

		if exitCode != 0 {
			t.Fatalf("expected exit code 0, got %d", exitCode)
		}

		if stderr.Len() != 0 {
			t.Fatalf("expected no stderr output, got %q", stderr.String())
		}
	})

	t.Run("invalid configuration returns one", func(t *testing.T) {
		stderr := &bytes.Buffer{}

		exitCode := runConfigCheck(func() error {
			return errors.New("invalid config")
		}, stderr)

		if exitCode != 1 {
			t.Fatalf("expected exit code 1, got %d", exitCode)
		}

		if !strings.Contains(stderr.String(), "configuration check failed: invalid config") {
			t.Fatalf("unexpected stderr output: %q", stderr.String())
		}
	})

	t.Run("nil setup function returns one", func(t *testing.T) {
		stderr := &bytes.Buffer{}

		exitCode := runConfigCheck(nil, stderr)

		if exitCode != 1 {
			t.Fatalf("expected exit code 1, got %d", exitCode)
		}

		if !strings.Contains(stderr.String(), "configuration check failed: setup function is nil") {
			t.Fatalf("unexpected stderr output: %q", stderr.String())
		}
	})
}

// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package level

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/secret"
)

// TestLogRedactsSecretValues reproduces the wrapper path that turned every fmt.Stringer, including secret.Value,
// into its String() result before slog could apply the value's own redaction.
func TestLogRedactsSecretValues(t *testing.T) {
	const plaintext = "level-wrapper-secret"

	value := secret.New(plaintext)

	for name, handler := range map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(buffer *bytes.Buffer) slog.Handler { return slog.NewTextHandler(buffer, nil) },
		"json": func(buffer *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(buffer, nil) },
	} {
		var output bytes.Buffer

		if err := Info(slog.New(handler(&output))).Log("msg", "dump", "value", value, "pointer", &value); err != nil {
			t.Fatalf("%s Log() error = %v", name, err)
		}

		if strings.Contains(output.String(), plaintext) || !strings.Contains(output.String(), "<hidden>") {
			t.Fatalf("%s log output does not redact the secret: %s", name, output.String())
		}
	}
}

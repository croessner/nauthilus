// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package secret

import (
	"bytes"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"
)

const formatTestSecret = "format-test-secret-value"

// formatTestHolder mirrors configuration structs that embed a secret next to ordinary fields.
type formatTestHolder struct {
	Name   string
	Secret Value
}

// formatTestPrivateHolder mirrors runtime owners that keep a secret in an unexported field, where fmt cannot call
// the Value's own formatting methods and falls back to reflection.
type formatTestPrivateHolder struct {
	name   string
	secret Value
}

// TestValueFormattingNeverRevealsSecret reproduces the startup debug dump that printed an OIDC client secret: any
// fmt verb, nested in a struct or slice, and any slog attribute must redact the value, while explicit access keeps it.
func TestValueFormattingNeverRevealsSecret(t *testing.T) {
	value := New(formatTestSecret)
	holder := formatTestHolder{Name: "client", Secret: value}
	private := formatTestPrivateHolder{name: "owner", secret: value}

	var logs bytes.Buffer
	slog.New(slog.NewTextHandler(&logs, nil)).Info("dump", "secret", value, "holder", holder)

	for _, rendered := range []string{
		fmt.Sprintf("%v", value), fmt.Sprintf("%s", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value),
		fmt.Sprintf("%q", value), fmt.Sprintf("%x", value), fmt.Sprint(value), fmt.Sprintf("%+v", holder),
		fmt.Sprintf("%#v", holder), fmt.Sprintf("%v", []formatTestHolder{holder}), fmt.Sprintf("%+v", &holder),
		fmt.Sprintf("%+v", &private), logs.String(),
	} {
		if revealsFormatTestSecret(rendered) {
			t.Fatalf("formatted output reveals the secret: %s", rendered)
		}
	}

	// The Value redacts every verb itself; verbs vet rejects are passed as variables on purpose.
	for _, verb := range []string{"%v", "%+v", "%s", "%q", "%x", "%#v", "%d", "%p"} {
		if rendered := fmt.Sprintf(verb, value); revealsFormatTestSecret(rendered) {
			t.Fatalf("verb %s reveals the secret: %s", verb, rendered)
		}
	}

	// An unexported field cannot run the Value's methods; the struct verbs show only an address. Text verbs on such a
	// struct are printf misuse that go vet reports, so they are not part of this contract.
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if rendered := fmt.Sprintf(verb, private); revealsFormatTestSecret(rendered) {
			t.Fatalf("verb %s on an unexported field reveals the secret: %s", verb, rendered)
		}
	}

	if got := fmt.Sprintf("%v", value); got != redactedFormat {
		t.Fatalf("formatted secret = %q, want %q", got, redactedFormat)
	}

	if got := fmt.Sprintf("%v", Value{}); got != "" {
		t.Fatalf("formatted empty secret = %q, want empty", got)
	}

	if value.String() != formatTestSecret {
		t.Fatal("explicit String() must keep returning the secret for APIs that require it")
	}
}

// revealsFormatTestSecret reports whether rendered output contains the secret as text, hex, or decimal bytes.
func revealsFormatTestSecret(rendered string) bool {
	decimal := make([]string, 0, len(formatTestSecret))
	for _, character := range []byte(formatTestSecret) {
		decimal = append(decimal, strconv.Itoa(int(character)))
	}

	return strings.Contains(rendered, formatTestSecret) ||
		strings.Contains(rendered, fmt.Sprintf("%x", formatTestSecret)) ||
		strings.Contains(rendered, strings.Join(decimal, " "))
}

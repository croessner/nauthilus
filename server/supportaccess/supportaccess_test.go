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

package supportaccess

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestVerifiedCredentialIdentity pins that user tokens are identified per client and subject, service tokens per
// client, and that unknown methods or incomplete user tokens have no identity and no scope.
func TestVerifiedCredentialIdentity(t *testing.T) {
	for name, tc := range map[string]struct {
		credential VerifiedCredential
		identity   string
	}{
		"service token":            {VerifiedCredential{Method: CredentialOIDCBearer, ClientID: " console ", Subject: "x"}, "console"},
		"service subject fallback": {VerifiedCredential{Method: CredentialOIDCBearer, Subject: "svc"}, "svc"},
		"user token":               {VerifiedCredential{Method: CredentialOAuthUser, ClientID: "cli", Subject: "anna"}, "cli#anna"},
		"user token without sub":   {VerifiedCredential{Method: CredentialOAuthUser, ClientID: "cli"}, ""},
		"user token without azp":   {VerifiedCredential{Method: CredentialOAuthUser, Subject: "anna"}, ""},
		"basic credential":         {VerifiedCredential{Method: CredentialBasic, ClientID: "support-console"}, "support-console"},
		"basic without username":   {VerifiedCredential{Method: CredentialBasic}, ""},
		"unknown method":           {VerifiedCredential{Method: "basic", ClientID: "cli", Subject: "anna"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			tc.credential.Scopes = []string{"read"}

			if got := tc.credential.Identity(); got != tc.identity {
				t.Fatalf("Identity() = %q, want %q", got, tc.identity)
			}

			if got := tc.credential.HasScope("read"); got != (tc.identity != "") {
				t.Fatalf("HasScope() = %v with identity %q", got, tc.identity)
			}
		})
	}
}

// TestGateBounds pins the per-identity share, the global bound, idempotent release, and cancellation.
func TestGateBounds(t *testing.T) {
	gate := NewGate(2, 1, 20*time.Millisecond)

	releaseA, ok := gate.Acquire(context.Background(), "a")
	if !ok {
		t.Fatal("first acquire for a failed")
	}

	if _, ok = gate.Acquire(context.Background(), "a"); ok {
		t.Fatal("second acquire for a must exceed the per-identity share")
	}

	releaseB, ok := gate.Acquire(context.Background(), "b")
	if !ok {
		t.Fatal("acquire for b failed")
	}

	if _, ok = gate.Acquire(context.Background(), "c"); ok {
		t.Fatal("acquire for c must fail while the global bound is full")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, ok = gate.Acquire(cancelled, "d"); ok {
		t.Fatal("a cancelled acquire must fail")
	}

	releaseA()
	releaseA()

	releaseC, ok := gate.Acquire(context.Background(), "c")
	if !ok {
		t.Fatal("acquire for c failed after a released its slot")
	}

	releaseB()
	releaseC()

	if len(gate.perCaller) != 0 || len(gate.slots) != 0 {
		t.Fatalf("gate state not empty after all releases: shares=%v slots=%d", gate.perCaller, len(gate.slots))
	}
}

// TestSanitizeText pins replacement of control, format, and invalid characters and the rune bound.
func TestSanitizeText(t *testing.T) {
	for name, tc := range map[string]struct {
		value string
		max   int
		want  string
	}{
		"plain":           {"anna@example.test", 64, "anna@example.test"},
		"newline":         {"a\nb", 64, "a\uFFFDb"},
		"bidi override":   {"evil\u202etxt", 64, "evil\uFFFDtxt"},
		"zero width":      {"a\u200bb", 64, "a\uFFFDb"},
		"invalid utf8":    {"a\xffb", 64, "a\uFFFDb"},
		"bounded":         {"abcdef", 3, "abc…"},
		"exactly bounded": {"abc", 3, "abc"},
		"empty":           {"", 3, ""},
		"no budget":       {"abc", 0, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := SanitizeText(tc.value, tc.max); got != tc.want {
				t.Fatalf("SanitizeText(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

// TestSharedErrorAndReference pins the shared error type and the audit reference bound.
func TestSharedErrorAndReference(t *testing.T) {
	cause := errors.New("internal")
	err := NewError("X", "public text", cause)

	if err.Error() != "public text" || !errors.Is(err, cause) || AsError(err, nil) != err {
		t.Fatalf("error = %v", err)
	}

	if AsError(cause, func(c error) *Error { return NewError("INTERNAL", "internal text", c) }).Code != "INTERNAL" {
		t.Fatal("fallback was not applied")
	}

	if !ValidAuditReference("") || !ValidAuditReference("INC-42/a") || ValidAuditReference("a b") ||
		BoundedAuditReference("a\nb") != "" || BoundedAuditReference("INC-1") != "INC-1" {
		t.Fatal("audit reference bound mismatch")
	}
}

// TestVerbatimTextKeepsContent pins that recorded values leave complete: no cut, newlines kept, format characters
// visible, and invalid bytes replaced.
func TestVerbatimTextKeepsContent(t *testing.T) {
	long := strings.Repeat("ä", 5000)

	for input, want := range map[string]string{
		"plain user@example.org 203.0.113.7": "plain user@example.org 203.0.113.7",
		"line one\nline two\ttab":            "line one\nline two\ttab",
		"admin\u202egnp.exe":                 "admin<U+202E>gnp.exe",
		"zero\u200bwidth":                    "zero<U+200B>width",
		"bad\xffbyte":                        "bad�byte",
		long:                                 long,
	} {
		if got := VerbatimText(input); got != want {
			t.Errorf("VerbatimText(%q) = %q, want %q", input, got, want)
		}
	}
}

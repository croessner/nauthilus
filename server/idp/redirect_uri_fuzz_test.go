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

package idp

import (
	"net/url"
	"strings"
	"testing"
)

const fuzzRedirectURIMaxInputBytes = 4 << 10

func FuzzValidateRedirectURIAllowlist(f *testing.F) {
	f.Add("https://app.example.com/callback", "https://app.example.com/callback")
	f.Add("https://app.example.com/callback/*", "https://app.example.com/callback/step")
	f.Add("https://app.example.com/*", "https://user@app.example.com/callback")
	f.Add("http://127.0.0.1/callback", "http://127.0.0.1:49152/callback")
	f.Add("*", "custom://native-app/callback")

	f.Fuzz(func(t *testing.T, allowedURI string, redirectURI string) {
		if len(allowedURI) > fuzzRedirectURIMaxInputBytes || len(redirectURI) > fuzzRedirectURIMaxInputBytes {
			return
		}

		first := validateRedirectURIAgainstAllowList([]string{allowedURI}, redirectURI)

		second := validateRedirectURIAgainstAllowList([]string{allowedURI}, redirectURI)
		if first != second {
			t.Fatalf("redirect URI validation is not deterministic")
		}

		assertExactAbsoluteRedirectAccepted(t, redirectURI)
		assertWildcardRedirectAuthorityBounded(t, redirectURI)
		assertLoopbackPortExceptionBounded(t, redirectURI)
	})
}

// assertExactAbsoluteRedirectAccepted verifies a registered absolute URI matches itself.
func assertExactAbsoluteRedirectAccepted(t *testing.T, redirectURI string) {
	t.Helper()

	parsed, err := url.Parse(redirectURI)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return
	}

	if !validateRedirectURIAgainstAllowList([]string{redirectURI}, redirectURI) {
		t.Fatalf("exact registered absolute redirect URI was rejected")
	}
}

// assertWildcardRedirectAuthorityBounded verifies wildcard acceptance cannot cross authority or path boundaries.
func assertWildcardRedirectAuthorityBounded(t *testing.T, redirectURI string) {
	t.Helper()

	const allowedWildcard = "https://app.example.com/callback/*"

	if !validateRedirectURIAgainstAllowList([]string{allowedWildcard}, redirectURI) {
		return
	}

	parsed, err := url.Parse(redirectURI)
	if err != nil {
		t.Fatalf("wildcard accepted an unparsable redirect URI")
	}

	if !strings.EqualFold(parsed.Scheme, "https") ||
		!strings.EqualFold(parsed.Hostname(), "app.example.com") ||
		parsed.Port() != "" ||
		parsed.User != nil {
		t.Fatalf("wildcard acceptance crossed the registered authority")
	}

	escapedPath := parsed.EscapedPath()
	if unsafeRedirectPathPattern.MatchString(escapedPath) {
		t.Fatalf("wildcard accepted an unsafe traversal path")
	}

	if escapedPath != "/callback" && !strings.HasPrefix(escapedPath, "/callback/") {
		t.Fatalf("wildcard acceptance crossed the registered path boundary")
	}
}

// assertLoopbackPortExceptionBounded verifies dynamic ports stay limited to the HTTP loopback contract.
func assertLoopbackPortExceptionBounded(t *testing.T, redirectURI string) {
	t.Helper()

	const (
		loopbackAllowed    = "http://127.0.0.1/callback"
		nonLoopbackAllowed = "http://app.example.com/callback"
	)

	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return
	}

	if validateRedirectURIAgainstAllowList([]string{loopbackAllowed}, redirectURI) && redirectURI != loopbackAllowed {
		if !strings.EqualFold(parsed.Scheme, "http") ||
			parsed.Hostname() != "127.0.0.1" ||
			parsed.Port() == "" ||
			parsed.EscapedPath() != "/callback" {
			t.Fatalf("dynamic loopback port exception escaped its contract")
		}
	}

	if parsed.Port() != "" &&
		strings.EqualFold(parsed.Scheme, "http") &&
		strings.EqualFold(parsed.Hostname(), "app.example.com") &&
		validateRedirectURIAgainstAllowList([]string{nonLoopbackAllowed}, redirectURI) {
		t.Fatalf("dynamic port exception was applied to a non-loopback host")
	}
}

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

package contentneg_test

import (
	"testing"

	"github.com/croessner/nauthilus/server/util/contentneg"
)

// supported is the canonical list reused by every test case to keep the
// table compact and to mirror the production order used by the
// list-accounts handler.
var supported = []string{
	"application/cbor",
	"application/json",
	"application/x-www-form-urlencoded",
	"text/plain",
}

func TestNegotiator_BestMatch(t *testing.T) {
	cases := []struct {
		name   string
		accept string
		want   string
	}{
		{name: "exact-cbor", accept: "application/cbor", want: "application/cbor"},
		{name: "exact-json", accept: "application/json", want: "application/json"},
		{name: "multi-prefer-cbor", accept: "application/cbor, application/json;q=0.5", want: "application/cbor"},
		{name: "multi-prefer-json-by-q", accept: "application/json, application/cbor;q=0.4", want: "application/json"},
		{name: "wildcard-subtype", accept: "application/*", want: "application/cbor"},
		{name: "wildcard-any", accept: "*/*", want: "application/cbor"},
		{name: "missing-header-defaults-to-any", accept: "", want: "application/cbor"},
		{name: "whitespace-only", accept: "   ", want: "application/cbor"},
		{name: "case-insensitive", accept: "Application/CBOR", want: "application/cbor"},
		{name: "with-charset-parameter", accept: "application/json; charset=utf-8", want: "application/json"},
		{name: "q-zero-excludes", accept: "application/cbor;q=0, application/json", want: "application/json"},
		{name: "q-zero-on-all-supported", accept: "application/cbor;q=0, application/json;q=0", want: ""},
		{name: "no-acceptable-type", accept: "image/png", want: ""},
		{name: "specificity-prefers-exact-over-wildcard", accept: "application/json, application/*;q=1", want: "application/json"},
		{name: "ties-honour-server-order", accept: "application/cbor, application/json", want: "application/cbor"},
		{name: "trailing-comma", accept: "application/cbor,,", want: "application/cbor"},
		{name: "quoted-comma-in-parameter", accept: `text/plain; note="a,b", application/cbor`, want: "application/cbor"},
		{name: "invalid-q-falls-back-to-default", accept: "application/cbor;q=abc", want: "application/cbor"},
		{name: "negative-q-clamped-to-zero", accept: "application/cbor;q=-1, application/json", want: "application/json"},
		{name: "q-above-one-clamped", accept: "application/cbor;q=2.5", want: "application/cbor"},
		{name: "junk-token-is-skipped", accept: "garbage, application/json", want: "application/json"},
	}

	negotiator := contentneg.New(supported...)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := negotiator.BestMatch(tc.accept)
			if got != tc.want {
				t.Fatalf("BestMatch(%q) = %q, want %q", tc.accept, got, tc.want)
			}
		})
	}
}

func TestNegotiator_EmptySupportedReturnsEmpty(t *testing.T) {
	negotiator := contentneg.New()

	if got := negotiator.BestMatch("application/json"); got != "" {
		t.Fatalf("BestMatch on empty supported set = %q, want empty", got)
	}
}

func TestNegotiator_SupportedNormalisation(t *testing.T) {
	// Canonicalisation must lowercase and trim entries supplied at
	// construction time so that callers do not have to pre-process them.
	negotiator := contentneg.New(" Application/CBOR ", "application/json")

	if got := negotiator.BestMatch("application/cbor"); got != "application/cbor" {
		t.Fatalf("BestMatch returned %q, want %q", got, "application/cbor")
	}
}

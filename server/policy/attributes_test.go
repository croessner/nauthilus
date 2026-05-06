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

package policy

import "testing"

func TestIdentifierSegment(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "lowercase words", input: "IMAP Short", want: "imap_short"},
		{name: "hyphen and slash", input: "SMTP/Auth / Burst", want: "smtp_auth_burst"},
		{name: "leading digit", input: "24h", want: "b_24h"},
		{name: "repeated separators", input: "__IMAP---Short__", want: "imap_short"},
		{name: "empty after normalization", input: "äöü", want: "bucket"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IdentifierSegment(tt.input); got != tt.want {
				t.Fatalf("IdentifierSegment(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBruteForceBucketAttributeID(t *testing.T) {
	got := BruteForceBucketAttributeID("imap_short", "ratio")
	want := "auth.brute_force.bucket.imap_short.ratio"
	if got != want {
		t.Fatalf("BruteForceBucketAttributeID() = %q, want %q", got, want)
	}
}

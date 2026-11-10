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

package util

import "testing"

// TestValidateUsernameRejectsOnlyTransportUnsafeInput pins that the username check rejects only values that cannot be
// carried safely (invalid UTF-8, control characters) and accepts every printable character and the empty value,
// because whether a username is required or exists is decided by the caller and the backends.
func TestValidateUsernameRejectsOnlyTransportUnsafeInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		username string
		want     bool
	}{
		{name: "plain address", username: "alice@example.test", want: true},
		{name: "display-style name with space", username: "Vorname Nachname", want: true},
		{name: "IMAP atom specials", username: `a(b)c{d}e%f"g\h`, want: true},
		{name: "master-user separator", username: "alice*master", want: true},
		{name: "non-ASCII letters", username: "jürgen.müller@example.test", want: true},
		{name: "empty", username: "", want: true},
		{name: "NUL", username: "alice\x00", want: false},
		{name: "CRLF", username: "alice\r\nX-Injected: 1", want: false},
		{name: "tab", username: "alice\tbob", want: false},
		{name: "DEL", username: "alice\x7f", want: false},
		{name: "C1 control", username: "alice\u0085", want: false},
		{name: "invalid UTF-8", username: "alice\xff", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := ValidateUsername(test.username); got != test.want {
				t.Fatalf("ValidateUsername(%q) = %v, want %v", test.username, got, test.want)
			}
		})
	}
}

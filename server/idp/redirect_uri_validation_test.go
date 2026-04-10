// Copyright (C) 2025 Christian Rößner
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
	"testing"

	"github.com/croessner/nauthilus/server/config"
)

type redirectValidationCase struct {
	name        string
	redirectURI string
	allowedURIs []string
	want        bool
}

var redirectValidationCases = []redirectValidationCase{
	{
		name:        "exact match",
		redirectURI: "https://app.example.com/callback",
		allowedURIs: []string{"https://app.example.com/callback"},
		want:        true,
	},
	{
		name:        "dynamic loopback port allowed for 127.0.0.1",
		redirectURI: "http://127.0.0.1:51208/callback",
		allowedURIs: []string{"http://127.0.0.1/callback"},
		want:        true,
	},
	{
		name:        "dynamic loopback port allowed for localhost",
		redirectURI: "http://localhost:51208/callback",
		allowedURIs: []string{"http://localhost/callback"},
		want:        true,
	},
	{
		name:        "dynamic port rejected for non-loopback hosts",
		redirectURI: "http://app.example.com:51208/callback",
		allowedURIs: []string{"http://app.example.com/callback"},
		want:        false,
	},
	{
		name:        "dynamic loopback port is not allowed for https",
		redirectURI: "https://127.0.0.1:5443/callback",
		allowedURIs: []string{"https://127.0.0.1/callback"},
		want:        false,
	},
	{
		name:        "suffix wildcard matches path and ignores query",
		redirectURI: "https://app.example.com/callback/step?next=1",
		allowedURIs: []string{"https://app.example.com/callback*"},
		want:        true,
	},
	{
		name:        "suffix wildcard with trailing slash also matches base path",
		redirectURI: "https://app.example.com/callback",
		allowedURIs: []string{"https://app.example.com/callback/*"},
		want:        true,
	},
	{
		name:        "wildcard is disabled when registered URI has query",
		redirectURI: "https://app.example.com/callback?foo=1",
		allowedURIs: []string{"https://app.example.com/callback?*"},
		want:        false,
	},
	{
		name:        "full wildcard allows http",
		redirectURI: "http://example.org/cb",
		allowedURIs: []string{"*"},
		want:        true,
	},
	{
		name:        "full wildcard allows https",
		redirectURI: "https://example.org/cb",
		allowedURIs: []string{"*"},
		want:        true,
	},
	{
		name:        "full wildcard does not allow custom schemes",
		redirectURI: "custom://native-app/callback",
		allowedURIs: []string{"*"},
		want:        false,
	},
	{
		name:        "wildcard disabled for unsafe parent path traversal",
		redirectURI: "https://app.example.com/a/../callback",
		allowedURIs: []string{"https://app.example.com/*"},
		want:        false,
	},
	{
		name:        "wildcard disabled for user-info in redirect_uri",
		redirectURI: "https://user@app.example.com/callback",
		allowedURIs: []string{"https://app.example.com/*"},
		want:        false,
	},
}

func TestValidateRedirectURI_WildcardsAndLoopbackPorts(t *testing.T) {
	idp := &NauthilusIdP{}

	runRedirectValidationCases(t, idp, redirectValidationCases)
}

// runRedirectValidationCases executes redirect URI validation test cases against
// a Nauthilus IdP instance.
func runRedirectValidationCases(t *testing.T, idp *NauthilusIdP, tests []redirectValidationCase) {
	t.Helper()

	for _, tc := range tests {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			client := &config.OIDCClient{RedirectURIs: tc.allowedURIs}
			got := idp.ValidateRedirectURI(client, tc.redirectURI)
			if got != tc.want {
				t.Fatalf("ValidateRedirectURI() = %v, want %v", got, tc.want)
			}
		})
	}
}

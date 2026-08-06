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

package dcr

import (
	"bytes"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
)

func TestDecodeMetadataIgnoresUnknownAndLocalizedMetadata(t *testing.T) {
	request, protocolErr := DecodeMetadata(strings.NewReader(`{
		"redirect_uris":["http://127.0.0.1/callback"],
		"client_name":"Mail Client",
		"client_name#de":"E-Mail-Programm",
		"future_extension":{"enabled":true}
	}`))
	if protocolErr != nil {
		t.Fatalf("DecodeMetadata() error = %v", protocolErr)
	}

	if request.ClientName != "Mail Client" || len(request.RedirectURIs) != 1 {
		t.Fatalf("DecodeMetadata() = %+v", request)
	}
}

func TestDecodeMetadataRejectsInvalidRecognizedMetadata(t *testing.T) {
	tests := []struct {
		body     string
		wantCode string
	}{
		{body: `[]`, wantCode: "invalid_client_metadata"},
		{body: `{"redirect_uris":null}`, wantCode: "invalid_client_metadata"},
		{body: `{"redirect_uris":"http://127.0.0.1/cb"}`, wantCode: "invalid_client_metadata"},
		{body: `{"client_uri":"https://client.example.test"}`, wantCode: "invalid_client_metadata"},
		{body: `{"request_object_signing_alg":"RS256"}`, wantCode: "invalid_client_metadata"},
		{body: `{"software_statement":"signed-value"}`, wantCode: "unapproved_software_statement"},
		{body: `{"client_name":"one","client_name":"two"}`, wantCode: "invalid_client_metadata"},
		{body: `{"redirect_uris":[]} {}`, wantCode: "invalid_client_metadata"},
	}

	for _, test := range tests {
		_, protocolErr := DecodeMetadata(strings.NewReader(test.body))
		if protocolErr == nil || protocolErr.Code != test.wantCode {
			t.Fatalf("DecodeMetadata(%s) error = %#v, want %s", test.body, protocolErr, test.wantCode)
		}
	}
}

func TestBuildEffectiveMetadataRejectsControlAndInvalidScopeTokens(t *testing.T) {
	tests := []RegistrationRequest{
		{RedirectURIs: []string{"http://127.0.0.1/callback"}, ClientName: "Mail\nClient"},
		{RedirectURIs: []string{"http://127.0.0.1/callback"}, SoftwareID: "software\tidentifier"},
		{RedirectURIs: []string{"http://127.0.0.1/callback"}, Scope: "mail:imap unicode-ä"},
	}

	for _, request := range tests {
		_, protocolErr := BuildEffectiveMetadata(request, nativeTestPolicy())
		if protocolErr == nil || protocolErr.Code != "invalid_client_metadata" {
			t.Fatalf("BuildEffectiveMetadata(%+v) error = %#v, want invalid_client_metadata", request, protocolErr)
		}
	}
}

func TestDecodeMetadataRejectsInvalidUTF8(t *testing.T) {
	body := []byte(`{"redirect_uris":["http://127.0.0.1/callback"],"client_name":"`)
	body = append(body, 0xff)
	body = append(body, []byte(`"}`)...)

	_, protocolErr := DecodeMetadata(bytes.NewReader(body))
	if protocolErr == nil || protocolErr.Code != "invalid_client_metadata" {
		t.Fatalf("DecodeMetadata() error = %#v, want invalid_client_metadata", protocolErr)
	}
}

func TestProtocolErrorDescriptionsUseRFC7591Characters(t *testing.T) {
	protocolErr := invalidClientMetadata("quoted \"value\" with \\ and unicode ä")
	for _, value := range []byte(protocolErr.Description) {
		if value < 0x20 || value == 0x22 || value == 0x5c || value > 0x7e {
			t.Fatalf("error_description %q contains forbidden byte %#x", protocolErr.Description, value)
		}
	}
}

func TestBuildEffectiveMetadataAppliesNativeProfile(t *testing.T) {
	request := RegistrationRequest{
		RedirectURIs:  []string{"http://127.0.0.1:49152/callback", "http://[::1]/callback"},
		GrantTypes:    []string{GrantAuthorizationCode, GrantRefreshToken},
		ResponseTypes: []string{ResponseTypeCode},
		ClientName:    "Mail Client",
		Scope:         "offline_access mail:imap",
	}

	effective, protocolErr := BuildEffectiveMetadata(request, nativeTestPolicy())
	if protocolErr != nil {
		t.Fatalf("BuildEffectiveMetadata() error = %v: %s", protocolErr, protocolErr.Description)
	}

	if effective.ApplicationType != ApplicationTypeNative || effective.TokenEndpointAuthMethod != TokenEndpointAuthMethodNone {
		t.Fatalf("BuildEffectiveMetadata() = %+v", effective)
	}

	if effective.Scope != "openid offline_access mail:imap" {
		t.Fatalf("scope = %q, want required plus explicit optional scopes", effective.Scope)
	}
}

func TestBuildEffectiveMetadataRequiresExplicitRefreshPair(t *testing.T) {
	tests := []RegistrationRequest{
		{RedirectURIs: []string{"http://127.0.0.1/cb"}, GrantTypes: []string{GrantAuthorizationCode, GrantRefreshToken}},
		{RedirectURIs: []string{"http://127.0.0.1/cb"}, Scope: "offline_access"},
	}

	for _, request := range tests {
		_, protocolErr := BuildEffectiveMetadata(request, nativeTestPolicy())
		if protocolErr == nil || protocolErr.Code != "invalid_client_metadata" {
			t.Fatalf("BuildEffectiveMetadata(%+v) error = %#v, want invalid_client_metadata", request, protocolErr)
		}
	}
}

func TestBuildEffectiveMetadataRejectsUnsafeRedirects(t *testing.T) {
	unsafe := []string{
		"https://127.0.0.1/callback",
		"http://localhost/callback",
		"http://127.0.0.2/callback",
		"http://127.0.0.1/callback#fragment",
		"http://user@127.0.0.1/callback",
		"http://127.0.0.1/callback?flow=mail",
		"http://127.0.0.1/a/../callback",
		"http://127.0.0.1/%2e%2e/callback",
		"http://127.0.0.1:http/callback",
		"com.example.app:/callback",
	}

	for _, redirectURI := range unsafe {
		_, protocolErr := BuildEffectiveMetadata(RegistrationRequest{RedirectURIs: []string{redirectURI}}, nativeTestPolicy())
		if protocolErr == nil || protocolErr.Code != "invalid_redirect_uri" {
			t.Fatalf("BuildEffectiveMetadata(%q) error = %#v, want invalid_redirect_uri", redirectURI, protocolErr)
		}
	}
}

func TestMatchRedirectURIAllowsOnlyLoopbackPortVariance(t *testing.T) {
	registered := []string{"http://127.0.0.1/callback", "http://[::1]:8080/callback"}

	for _, candidate := range []string{"http://127.0.0.1:54321/callback", "http://[::1]:49152/callback"} {
		if !MatchRedirectURI(registered, candidate) {
			t.Fatalf("MatchRedirectURI(%q) = false, want true", candidate)
		}
	}

	for _, candidate := range []string{"http://127.0.0.1:54321/Callback", "http://127.0.0.1:54321/callback?flow=mail", "http://localhost/callback"} {
		if MatchRedirectURI(registered, candidate) {
			t.Fatalf("MatchRedirectURI(%q) = true, want false", candidate)
		}
	}
}

func TestBuildEffectiveMetadataRejectsPortNormalizedDuplicateRedirects(t *testing.T) {
	request := RegistrationRequest{RedirectURIs: []string{
		"http://127.0.0.1:49152/callback",
		"http://127.0.0.1:49153/callback",
	}}

	_, protocolErr := BuildEffectiveMetadata(request, nativeTestPolicy())
	if protocolErr == nil || protocolErr.Code != "invalid_redirect_uri" {
		t.Fatalf("BuildEffectiveMetadata() error = %#v, want invalid_redirect_uri", protocolErr)
	}
}

// nativeTestPolicy returns the strict test scope policy.
func nativeTestPolicy() config.OIDCDynamicClientRegistrationConfig {
	return config.OIDCDynamicClientRegistrationConfig{
		RequiredScopes:     []string{"openid"},
		OptionalScopes:     []string{"offline_access", "mail:imap", "mail:smtp"},
		AllowRefreshTokens: true,
	}
}

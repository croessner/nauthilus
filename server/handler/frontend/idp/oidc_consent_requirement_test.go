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
	"context"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
)

func TestConsentRequirementWithoutGrant(t *testing.T) {
	tests := []struct {
		client       *config.OIDCClient
		name         string
		prompt       string
		wantRequired bool
		wantDecided  bool
	}{
		{name: "dynamic client requires consent by default", client: &config.OIDCClient{Dynamic: true}, wantRequired: true, wantDecided: true},
		{name: "dynamic client with profile skip_consent", client: &config.OIDCClient{Dynamic: true, SkipConsent: true}, wantDecided: true},
		{name: "prompt consent overrides dynamic skip_consent", client: &config.OIDCClient{Dynamic: true, SkipConsent: true}, prompt: "consent", wantRequired: true, wantDecided: true},
		{name: "static skip_consent", client: &config.OIDCClient{SkipConsent: true}, wantDecided: true},
		{name: "static client consults remembered grants", client: &config.OIDCClient{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			required, decided := consentRequirementWithoutGrant(test.client, test.prompt)
			if required != test.wantRequired || decided != test.wantDecided {
				t.Fatalf("consentRequirementWithoutGrant() = (%t, %t), want (%t, %t)", required, decided, test.wantRequired, test.wantDecided)
			}
		})
	}
}

func TestCanonicalAuthorizeConsentDecisionForDynamicClients(t *testing.T) {
	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	session := openCanonicalFixture(t, runtime, browserCookie)
	handler := &OIDCHandler{}
	scopes := []string{"openid", "profile", "offline_access", "roles"}

	tests := []struct {
		client *config.OIDCClient
		name   string
		prompt string
		want   bool
	}{
		{name: "profile skip_consent authorizes without consent page", client: &config.OIDCClient{ClientID: "dcr_skip", Dynamic: true, SkipConsent: true}},
		{name: "default dynamic profile shows consent page", client: &config.OIDCClient{ClientID: "dcr_consent", Dynamic: true}, want: true},
		{name: "prompt consent wins over skip_consent", client: &config.OIDCClient{ClientID: "dcr_skip", Dynamic: true, SkipConsent: true}, prompt: "consent", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			required, err := handler.canonicalOIDCAuthorizeNeedsConsent(
				context.Background(), session, cookie.SessionIdentity{}, test.client, scopes, test.prompt,
			)
			if err != nil || required != test.want {
				t.Fatalf("canonicalOIDCAuthorizeNeedsConsent() = %t, %v; want %t", required, err, test.want)
			}
		})
	}
}

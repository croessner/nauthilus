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
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
)

func TestRuntimePolicyNarrowsStoredDynamicClient(t *testing.T) {
	record := runtimePolicyTestRecord()
	policy := config.OIDCDynamicClientRegistrationConfig{
		Enabled:             true,
		RequiredScopes:      []string{"openid"},
		OptionalScopes:      []string{"mail:imap"},
		RequiredMFALevel:    2,
		AccessTokenLifetime: 5 * time.Minute,
	}

	client, err := NewRuntimePolicy(policy).Resolve(record)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if client.SupportsGrantType(GrantRefreshToken) || slices.Contains(client.Scopes, "offline_access") {
		t.Fatalf("Resolve() retained disabled refresh capability: %+v", client)
	}

	if client.RequiredMFALevel != 2 || client.AccessTokenLifetime != 5*time.Minute {
		t.Fatalf("Resolve() did not apply current MFA and token ceilings: %+v", client)
	}
}

func TestRuntimePolicyRejectsUnknownProfileVersion(t *testing.T) {
	record := runtimePolicyTestRecord()
	record.ProfileVersion++

	_, err := NewRuntimePolicy(config.OIDCDynamicClientRegistrationConfig{Enabled: true, RequiredScopes: []string{"openid"}}).Resolve(record)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Resolve() error = %v, want ErrCorrupt", err)
	}
}

// runtimePolicyTestRecord returns a formerly broader stored client.
func runtimePolicyTestRecord() *DynamicClientRecord {
	return &DynamicClientRecord{
		EffectiveMetadata: EffectiveMetadata{
			RedirectURIs:             []string{"http://127.0.0.1/callback"},
			GrantTypes:               []string{GrantAuthorizationCode, GrantRefreshToken},
			ResponseTypes:            []string{ResponseTypeCode},
			Scope:                    "openid offline_access mail:imap mail:smtp",
			TokenEndpointAuthMethod:  TokenEndpointAuthMethodNone,
			ApplicationType:          ApplicationTypeNative,
			SubjectType:              SubjectTypePublic,
			IDTokenSignedResponseAlg: IDTokenSigningAlgorithm,
		},
		ClientID:         ClientIDPrefix + "policy-client",
		Profile:          ProfileMailClientV1,
		ProfileVersion:   1,
		AccessTokenTTL:   15 * time.Minute,
		RefreshTokenTTL:  30 * 24 * time.Hour,
		RequiredMFALevel: 1,
	}
}

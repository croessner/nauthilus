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

package policyconfig

import "testing"

const authnLookupProviderActionPath = "policy.namespaces.authn.domain_plans.configured.checkpoints.pre_auth.providers[0].actions[0]"

// authnLookupIdentityProviderDocument schedules one builtin host provider for identity lookups.
func authnLookupIdentityProviderDocument(use string) string {
	return `
policy:
  namespaces:
    authn:
      domain_plans:
        configured:
          checkpoints:
            pre_auth:
              providers:
                - name: host_control
                  use: ` + use + `
                  actions: [lookup_identity]
            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: lookup_identity
      schema: authn/lookup_identity/v1
      domain_plan: authn/configured
      default_policy: authn/standard_auth
`
}

func TestAuthnLookupIdentityAcceptsOptInHostControls(t *testing.T) {
	for _, use := range []string{"authn/builtin/rbl", "authn/builtin/tls_encryption"} {
		t.Run(use, func(t *testing.T) {
			requireNoError(t, validateYAMLDocument(t, authnLookupIdentityProviderDocument(use)))
		})
	}
}

// Relay-domain and brute-force controls never run for identity lookups, so
// scheduling them there must fail instead of becoming a silent no-op.
func TestAuthnLookupIdentityRejectsUnsupportedHostControls(t *testing.T) {
	for _, use := range []string{"authn/builtin/relay_domains", "authn/builtin/brute_force"} {
		t.Run(use, func(t *testing.T) {
			err := validateYAMLDocument(t, authnLookupIdentityProviderDocument(use))

			requireAuthnRuleRejection(t, err, authnLookupProviderActionPath, []string{use, "lookup_identity"})
		})
	}
}

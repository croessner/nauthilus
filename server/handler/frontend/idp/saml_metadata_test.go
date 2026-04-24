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
	"net/http/httptest"
	"testing"

	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/handler/deps"
	serveridp "github.com/croessner/nauthilus/server/idp"
	"github.com/stretchr/testify/assert"
)

func TestSAMLHandler_resolveLogoutResponseDestination_UsesConfiguredLocalhostSLOURL(t *testing.T) {
	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			sps: []config.SAML2ServiceProvider{
				{
					EntityID: "https://localhost:9095/saml/metadata",
					ACSURL:   "https://localhost:9095/saml/acs",
					SLOURL:   "https://localhost:9095/saml/slo",
				},
			},
		},
	}, nil)

	destination, err := handler.resolveLogoutResponseDestination("https://localhost:9095/saml/metadata")
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "https://localhost:9095/saml/slo", destination)
}

func TestSAMLHandler_resolveLogoutResponseDestination_RequiresConfiguredSLOURL(t *testing.T) {
	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			sps: []config.SAML2ServiceProvider{
				{
					EntityID: "https://localhost:9095/saml/metadata",
					ACSURL:   "https://localhost:9095/saml/acs",
				},
			},
		},
	}, nil)

	_, err := handler.resolveLogoutResponseDestination("https://localhost:9095/saml/metadata")
	assert.Error(t, err)
	assert.ErrorContains(t, err, "requires a configured identity.saml.service_providers[].slo_url")
}

func TestSAMLHandler_GetServiceProvider_IncludesSingleLogoutServices(t *testing.T) {
	dependencies := &deps.Deps{
		Cfg: &mockSAMLCfg{
			sps: []config.SAML2ServiceProvider{
				{
					EntityID: "https://localhost:9095/saml/metadata",
					ACSURL:   "https://localhost:9095/saml/acs",
					SLOURL:   "https://localhost:9095/saml/slo",
				},
			},
		},
	}

	handler := NewSAMLHandler(dependencies, serveridp.NewNauthilusIdP(dependencies))

	metadata, err := handler.GetServiceProvider(
		httptest.NewRequest("GET", "/saml/metadata", nil),
		"https://localhost:9095/saml/metadata",
	)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.Len(t, metadata.SPSSODescriptors, 1) {
		return
	}

	sloServices := metadata.SPSSODescriptors[0].SingleLogoutServices
	if !assert.Len(t, sloServices, 2) {
		return
	}

	assert.Equal(t, saml.HTTPRedirectBinding, sloServices[0].Binding)
	assert.Equal(t, "https://localhost:9095/saml/slo", sloServices[0].Location)
	assert.Equal(t, "https://localhost:9095/saml/slo", sloServices[0].ResponseLocation)
	assert.Equal(t, saml.HTTPPostBinding, sloServices[1].Binding)
	assert.Equal(t, "https://localhost:9095/saml/slo", sloServices[1].Location)
	assert.Equal(t, "https://localhost:9095/saml/slo", sloServices[1].ResponseLocation)
}

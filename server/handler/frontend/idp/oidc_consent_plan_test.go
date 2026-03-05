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
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/stretchr/testify/assert"
)

func TestBuildConsentScopePlan(t *testing.T) {
	t.Run("all_or_nothing keeps all requested required", func(t *testing.T) {
		client := &config.OIDCClient{ConsentMode: config.OIDCConsentModeAllOrNothing}
		plan := buildConsentScopePlan(client, config.OIDCConsentModeAllOrNothing, []string{
			definitions.ScopeOpenId, definitions.ScopeProfile, definitions.ScopeEmail,
		})

		assert.Equal(t, config.OIDCConsentModeAllOrNothing, plan.Mode)
		assert.Equal(t, []string{definitions.ScopeOpenId, definitions.ScopeProfile, definitions.ScopeEmail}, plan.Required)
		assert.Empty(t, plan.Optional)
	})

	t.Run("granular mode defaults openid to required", func(t *testing.T) {
		client := &config.OIDCClient{ConsentMode: config.OIDCConsentModeGranularOptional}
		plan := buildConsentScopePlan(client, config.OIDCConsentModeAllOrNothing, []string{
			definitions.ScopeOpenId, definitions.ScopeProfile, definitions.ScopeEmail,
		})

		assert.Equal(t, []string{definitions.ScopeOpenId}, plan.Required)
		assert.Equal(t, []string{definitions.ScopeProfile, definitions.ScopeEmail}, plan.Optional)
	})

	t.Run("granular optional whitelist keeps other scopes required", func(t *testing.T) {
		client := &config.OIDCClient{
			ConsentMode:    config.OIDCConsentModeGranularOptional,
			RequiredScopes: []string{definitions.ScopeGroups},
			OptionalScopes: []string{definitions.ScopeEmail},
		}

		plan := buildConsentScopePlan(client, config.OIDCConsentModeAllOrNothing, []string{
			definitions.ScopeOpenId, definitions.ScopeProfile, definitions.ScopeEmail, definitions.ScopeGroups,
		})

		assert.Equal(t, []string{definitions.ScopeOpenId, definitions.ScopeProfile, definitions.ScopeGroups}, plan.Required)
		assert.Equal(t, []string{definitions.ScopeEmail}, plan.Optional)
	})
}

func TestConsentScopePlanResolveGranted(t *testing.T) {
	plan := consentScopePlan{
		Mode:      config.OIDCConsentModeGranularOptional,
		Requested: []string{definitions.ScopeOpenId, definitions.ScopeProfile, definitions.ScopeEmail},
		Required:  []string{definitions.ScopeOpenId},
		Optional:  []string{definitions.ScopeProfile, definitions.ScopeEmail},
	}

	t.Run("returns required plus selected optional", func(t *testing.T) {
		granted, err := plan.ResolveGranted([]string{definitions.ScopeEmail})
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, []string{definitions.ScopeOpenId, definitions.ScopeEmail}, granted)
	})

	t.Run("rejects unknown optional scope", func(t *testing.T) {
		_, err := plan.ResolveGranted([]string{"admin"})
		assert.Error(t, err)
	})
}

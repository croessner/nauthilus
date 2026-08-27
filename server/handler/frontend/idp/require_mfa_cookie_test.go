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

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/stretchr/testify/assert"
)

func TestPrepareOIDCMFAAssuranceSessionAvoidsDuplicateFactorDetails(t *testing.T) {
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:               "user@example.test",
		definitions.SessionKeyUniqueUserID:          "uid=user,ou=people,dc=example,dc=test",
		definitions.SessionKeyDisplayName:           "Example User",
		definitions.SessionKeyMFAFactorAccount:      "stale-factor@example.test",
		definitions.SessionKeyMFAFactorUniqueUserID: "stale-factor-id",
		definitions.SessionKeyMFAFactorDisplayName:  "Stale Factor",
	}}

	assert.True(t, prepareOIDCMFAAssuranceSession(mgr, "node1-vaultwarden"))
	assert.Equal(t, "user@example.test", mgr.GetString(definitions.SessionKeyMFAAccount, ""))
	assert.Equal(t, "user@example.test", mgr.GetString(definitions.SessionKeyUsername, ""))
	assert.Equal(t, "node1-vaultwarden", mgr.GetString(definitions.SessionKeyIDPClientID, ""))
	assert.Equal(t, "user@example.test", mgr.GetString(definitions.SessionKeyMFAFactorAccount, ""))
	assert.False(t, mgr.HasKey(definitions.SessionKeyMFAFactorUniqueUserID))
	assert.False(t, mgr.HasKey(definitions.SessionKeyMFAFactorDisplayName))
}

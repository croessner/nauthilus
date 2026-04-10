// Copyright (C) 2024 Christian Rößner
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

package core

import (
	"io"
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/stretchr/testify/assert"
)

// TestResolveGroupsMemberOfOnly verifies group resolution when using the member_of strategy
// without recursive searches.
func TestResolveGroupsMemberOfOnly(t *testing.T) {
	t.Parallel()

	protocol := config.Protocol{}
	protocol.Set("oidc")

	auth := &AuthState{
		Request: AuthRequest{
			Username: "jdoe",
			Protocol: &protocol,
		},
		Runtime: AuthRuntime{
			GUID: "guid-1",
		},
	}

	lm := &ldapManagerImpl{
		poolName: definitions.DefaultBackendName,
	}

	attributes := bktype.AttributeMapping{
		"memberOf": {
			"cn=admins,ou=groups,dc=example,dc=com",
			"devs",
		},
	}

	searchProtocol := &config.LDAPSearchProtocol{
		Groups: config.LDAPGroups{
			Strategy:  "member_of",
			Attribute: "memberOf",
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	groups, groupDNs := lm.resolveGroups(auth, searchProtocol, attributes, "uid", logger)

	assert.Equal(t, []string{"admins", "devs"}, groups)
	assert.Equal(t, []string{"cn=admins,ou=groups,dc=example,dc=com"}, groupDNs)
}

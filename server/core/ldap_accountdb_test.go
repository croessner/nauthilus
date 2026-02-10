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
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/stretchr/testify/assert"
)

func TestLDAPAccountDB_SkipsMissingProtocolOrFilter(t *testing.T) {
	testCases := []struct {
		name     string
		protocol *config.LDAPSearchProtocol
	}{
		{
			name:     "missing-protocol",
			protocol: nil,
		},
		{
			name:     "missing-list-accounts-filter",
			protocol: &config.LDAPSearchProtocol{Protocols: []string{definitions.ProtoAccountProvider}},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			mcfg := new(mockConfig)
			mcfg.On("GetLDAPSearchProtocol", definitions.ProtoAccountProvider, "test").Return(testCase.protocol, nil)

			deps := AuthDeps{Cfg: mcfg}
			lm := &ldapManagerImpl{poolName: "test", deps: deps}
			auth := &AuthState{
				deps: deps,
				Request: AuthRequest{
					Protocol: new(config.Protocol),
				},
			}
			auth.Request.Protocol.Set(definitions.ProtoAccountProvider)

			accounts, err := lm.AccountDB(auth)

			assert.NoError(t, err)
			assert.Empty(t, accounts)
			mcfg.AssertExpectations(t)
		})
	}
}

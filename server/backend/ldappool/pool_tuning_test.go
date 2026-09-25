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

package ldappool

import (
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
)

func TestPoolConnectionsCarryTheConfiguredTuning(t *testing.T) {
	poolConfig := &config.LDAPConf{
		ServerURIs:          []string{"ldaps://ldap.example.test:636/"},
		LookupPoolSize:      2,
		SearchTimeout:       60 * time.Second,
		BindTimeout:         2 * time.Second,
		ModifyTimeout:       3 * time.Second,
		SearchSizeLimit:     200,
		SearchTimeLimit:     2 * time.Second,
		RetryMax:            4,
		RetryBase:           300 * time.Millisecond,
		CBFailureThreshold:  7,
		HealthCheckInterval: 20 * time.Second,
		NegativeCacheTTL:    45 * time.Second,
		IncludeRawResult:    true,
	}

	source := resolveLDAPPoolConfigSource(nil, map[string]*config.LDAPConf{"list-account": poolConfig}, "list-account")
	conf, _ := buildLDAPPoolConnections(ldapPoolLayout{name: "list-account-lookup", poolSize: 2}, source)

	for index, connection := range conf {
		if connection.GetSearchTimeout() != 60*time.Second || connection.GetBindTimeout() != 2*time.Second ||
			connection.GetModifyTimeout() != 3*time.Second || connection.GetSearchSizeLimit() != 200 ||
			connection.GetSearchTimeLimit() != 2*time.Second || connection.GetRetryMax() != 4 ||
			connection.GetRetryBase() != 300*time.Millisecond || connection.GetCBFailureThreshold() != 7 ||
			connection.GetHealthCheckInterval() != 20*time.Second || connection.GetNegativeCacheTTL() != 45*time.Second ||
			!connection.GetIncludeRawResult() {
			t.Fatalf("connection %d lost the pool tuning: %+v", index, connection)
		}

		if connection.PoolName != "list-account-lookup" || connection.ServerURIs[0] != poolConfig.ServerURIs[0] {
			t.Fatalf("connection %d has identity %q/%v", index, connection.PoolName, connection.ServerURIs)
		}
	}

	if ldapOperationTimeout(conf[0]) != 60*time.Second {
		t.Fatalf("ldapOperationTimeout() = %s, want the configured search timeout", ldapOperationTimeout(conf[0]))
	}

	if ldapOperationTimeout(&config.LDAPConf{}) != ldapDefaultOperationTimeout {
		t.Fatal("ldapOperationTimeout() must fall back to the bounded default")
	}
}

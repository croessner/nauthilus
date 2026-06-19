// Copyright (C) 2026 Christian Roessner
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

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
)

const pluginAccountDBBackendName = "customer.passdb"

func TestListUserAccountsUsesPluginBackend(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Backends = []*config.Backend{mustPluginAccountDBBackend(t)}
	auth, _, mock := newCurrentBehaviorAuthState(t, cfg)

	fake := &accountDBBackendManager{accounts: AccountList{"plugin-user@example.test"}}

	replaceBackendManagerFactoryForTest(t, definitions.BackendPlugin, func(backendName string, _ AuthDeps) BackendManager {
		if backendName != pluginAccountDBBackendName {
			t.Fatalf("backendName = %q, want %s", backendName, pluginAccountDBBackendName)
		}

		return fake
	})

	accounts := auth.ListUserAccounts()
	if len(accounts) != 1 || accounts[0] != fake.accounts[0] {
		t.Fatalf("ListUserAccounts() = %#v, want plugin account", accounts)
	}

	if fake.calls != 1 {
		t.Fatalf("AccountDB calls = %d, want 1", fake.calls)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func mustPluginAccountDBBackend(t *testing.T) *config.Backend {
	t.Helper()

	backend := &config.Backend{}
	if err := backend.Set("plugin(" + pluginAccountDBBackendName + ")"); err != nil {
		t.Fatalf("backend.Set(plugin) failed: %v", err)
	}

	return backend
}

func replaceBackendManagerFactoryForTest(t *testing.T, backendType definitions.Backend, factory BackendManagerFactory) {
	t.Helper()

	previous, hadPrevious := backendManagerFactories.Load(backendType)
	RegisterBackendManagerFactory(backendType, factory)
	t.Cleanup(func() {
		if hadPrevious {
			backendManagerFactories.Store(backendType, previous)

			return
		}

		backendManagerFactories.Delete(backendType)
	})
}

type accountDBBackendManager struct {
	BackendManager
	accounts AccountList
	calls    int
}

func (m *accountDBBackendManager) AccountDB(*AuthState) (AccountList, error) {
	m.calls++

	return append(AccountList(nil), m.accounts...), nil
}

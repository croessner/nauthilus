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

// Test backend note: this backend is an in-memory credential store intended for
// development, demos, and integration tests. It keeps state only in the
// process memory and derives password hashes from submitted credentials at
// runtime. Do not use it in production or for day-to-day authentication without
// strict isolation and monitoring; it does not provide persistence, auditing,
// or the hardening expected from a real identity store. If you embed it for
// development, ensure it is reachable only in trusted environments and never
// exposed to untrusted traffic or real user accounts.

package core

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/localcache"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/croessner/nauthilus/server/util"
)

// testBackendCachePrefix namespaces cache entries for test backend users.
const testBackendCachePrefix = "test_backend"

// testBackendUser represents an in-memory account with optional MFA data.
type testBackendUser struct {
	Username            string
	PasswordHash        string
	TOTPSecret          *mfa.TOTPSecret
	TOTPRecovery        *mfa.TOTPRecovery
	WebAuthnCredentials []mfa.PersistentCredential
}

// testBackendStore tracks users in memory and provides concurrent-safe access.
type testBackendStore struct {
	cache *localcache.MemoryShardedCache
	mu    sync.RWMutex
	users map[string]struct{}
}

var (
	testBackendStoresMu sync.Mutex
	testBackendStores   = map[string]*testBackendStore{}
)

// newTestBackendStore initializes a fresh in-memory store for test accounts.
func newTestBackendStore() *testBackendStore {
	return &testBackendStore{
		cache: localcache.NewMemoryShardedCache(32, 0, 0),
		users: make(map[string]struct{}),
	}
}

// getTestBackendStore returns the shared store for the given backend name.
func getTestBackendStore(backendName string) *testBackendStore {
	if backendName == "" {
		backendName = definitions.DefaultBackendName
	}

	testBackendStoresMu.Lock()
	defer testBackendStoresMu.Unlock()

	store := testBackendStores[backendName]
	if store == nil {
		store = newTestBackendStore()
		testBackendStores[backendName] = store
	}

	return store
}

// testBackendUserKey builds the cache key for a backend-scoped username.
func testBackendUserKey(backendName, username string) string {
	return fmt.Sprintf("%s:%s:user:%s", testBackendCachePrefix, backendName, username)
}

// getUserLocked returns the raw user from cache; caller must hold the lock.
func (s *testBackendStore) getUserLocked(backendName, username string) (*testBackendUser, bool) {
	item, ok := s.cache.Get(testBackendUserKey(backendName, username))
	if !ok {
		return nil, false
	}

	user, ok := item.(*testBackendUser)
	if !ok || user == nil {
		return nil, false
	}

	return user, true
}

// getUser returns a defensive copy of the user to keep callers isolated.
func (s *testBackendStore) getUser(backendName, username string) (*testBackendUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.getUserLocked(backendName, username)
	if !ok {
		return nil, false
	}

	copyUser := *user
	copyUser.WebAuthnCredentials = append([]mfa.PersistentCredential(nil), user.WebAuthnCredentials...)

	return &copyUser, true
}

// withUser creates or updates a user while holding the store lock.
func (s *testBackendStore) withUser(backendName, username, password string, update func(user *testBackendUser)) *testBackendUser {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.getUserLocked(backendName, username)
	if !ok {
		user = &testBackendUser{Username: username}
	}

	if password != "" {
		user.PasswordHash = util.GetHash(util.PreparePassword(password))
	}

	if update != nil {
		update(user)
	}

	s.cache.Set(testBackendUserKey(backendName, username), user, 0)
	s.users[username] = struct{}{}

	return user
}

// listUsers returns the sorted list of usernames stored in memory.
func (s *testBackendStore) listUsers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]string, 0, len(s.users))
	for username := range s.users {
		users = append(users, username)
	}

	sort.Strings(users)

	return users
}

// testBackendManagerImpl implements the BackendManager interface for the test backend.
type testBackendManagerImpl struct {
	backendName string
	store       *testBackendStore
	deps        AuthDeps
}

var _ BackendManager = (*testBackendManagerImpl)(nil)

// NewTestBackendManager constructs a BackendManager backed by an in-memory store.
func NewTestBackendManager(backendName string, deps AuthDeps) BackendManager {
	if backendName == "" {
		backendName = definitions.DefaultBackendName
	}

	return &testBackendManagerImpl{
		backendName: backendName,
		store:       getTestBackendStore(backendName),
		deps:        deps,
	}
}

// PassDB populates account data and verifies credentials against in-memory values.
func (tm *testBackendManagerImpl) PassDB(auth *AuthState) (passDBResult *PassDBResult, err error) {
	username := strings.TrimSpace(auth.Request.Username)
	passDBResult = GetPassDBResultFromPool()

	if username == "" {
		return passDBResult, nil
	}

	password := auth.passwordString()
	user := tm.store.withUser(tm.backendName, username, password, nil)

	passDBResult.UserFound = true
	passDBResult.AccountField = "uid"
	passDBResult.Account = username
	passDBResult.TOTPSecretField = "test_totp_secret"
	passDBResult.TOTPRecoveryField = "test_totp_recovery"
	passDBResult.UniqueUserIDField = "uid"
	passDBResult.DisplayNameField = "displayName"
	passDBResult.Backend = definitions.BackendTest
	passDBResult.BackendName = tm.backendName
	passDBResult.Attributes = bktype.AttributeMapping{}

	if auth.Request.NoAuth {
		passDBResult.Authenticated = true

		return passDBResult, nil
	}

	if user.PasswordHash == "" {
		passDBResult.Authenticated = password == ""

		return passDBResult, nil
	}

	passDBResult.Authenticated = util.GetHash(util.PreparePassword(password)) == user.PasswordHash

	return passDBResult, nil
}

// AccountDB lists all known usernames stored in the test backend.
func (tm *testBackendManagerImpl) AccountDB(_ *AuthState) (accounts AccountList, err error) {
	return tm.store.listUsers(), nil
}

// AddTOTPSecret associates a TOTP secret with the user in memory.
func (tm *testBackendManagerImpl) AddTOTPSecret(auth *AuthState, totp *mfa.TOTPSecret) (err error) {
	if totp == nil {
		return nil
	}

	tm.store.withUser(tm.backendName, auth.Request.Username, "", func(user *testBackendUser) {
		user.TOTPSecret = totp
	})

	return nil
}

// DeleteTOTPSecret clears the stored TOTP secret for the user.
func (tm *testBackendManagerImpl) DeleteTOTPSecret(auth *AuthState) (err error) {
	tm.store.withUser(tm.backendName, auth.Request.Username, "", func(user *testBackendUser) {
		user.TOTPSecret = nil
	})

	return nil
}

// AddTOTPRecoveryCodes stores recovery codes for the user.
func (tm *testBackendManagerImpl) AddTOTPRecoveryCodes(auth *AuthState, recovery *mfa.TOTPRecovery) (err error) {
	if recovery == nil {
		return nil
	}

	tm.store.withUser(tm.backendName, auth.Request.Username, "", func(user *testBackendUser) {
		user.TOTPRecovery = recovery
	})

	return nil
}

// DeleteTOTPRecoveryCodes removes recovery codes for the user.
func (tm *testBackendManagerImpl) DeleteTOTPRecoveryCodes(auth *AuthState) (err error) {
	tm.store.withUser(tm.backendName, auth.Request.Username, "", func(user *testBackendUser) {
		user.TOTPRecovery = nil
	})

	return nil
}

// GetWebAuthnCredentials returns a defensive copy of stored WebAuthn credentials.
func (tm *testBackendManagerImpl) GetWebAuthnCredentials(auth *AuthState) (credentials []mfa.PersistentCredential, err error) {
	user, ok := tm.store.getUser(tm.backendName, auth.Request.Username)
	if !ok {
		return nil, nil
	}

	return append([]mfa.PersistentCredential(nil), user.WebAuthnCredentials...), nil
}

// SaveWebAuthnCredential upserts a WebAuthn credential for the user.
func (tm *testBackendManagerImpl) SaveWebAuthnCredential(auth *AuthState, credential *mfa.PersistentCredential) (err error) {
	if credential == nil {
		return nil
	}

	tm.store.withUser(tm.backendName, auth.Request.Username, "", func(user *testBackendUser) {
		for i := range user.WebAuthnCredentials {
			if bytes.Equal(user.WebAuthnCredentials[i].ID, credential.ID) {
				user.WebAuthnCredentials[i] = *credential

				return
			}
		}

		user.WebAuthnCredentials = append(user.WebAuthnCredentials, *credential)
	})

	return nil
}

// DeleteWebAuthnCredential removes a matching credential from the user.
func (tm *testBackendManagerImpl) DeleteWebAuthnCredential(auth *AuthState, credential *mfa.PersistentCredential) (err error) {
	if credential == nil {
		return nil
	}

	tm.store.withUser(tm.backendName, auth.Request.Username, "", func(user *testBackendUser) {
		for i := range user.WebAuthnCredentials {
			if bytes.Equal(user.WebAuthnCredentials[i].ID, credential.ID) {
				user.WebAuthnCredentials = append(user.WebAuthnCredentials[:i], user.WebAuthnCredentials[i+1:]...)

				return
			}
		}
	})

	return nil
}

// UpdateWebAuthnCredential replaces the old credential or upserts the new one.
func (tm *testBackendManagerImpl) UpdateWebAuthnCredential(auth *AuthState, oldCredential *mfa.PersistentCredential, newCredential *mfa.PersistentCredential) (err error) {
	if newCredential == nil {
		return nil
	}

	tm.store.withUser(tm.backendName, auth.Request.Username, "", func(user *testBackendUser) {
		if oldCredential != nil {
			for i := range user.WebAuthnCredentials {
				if bytes.Equal(user.WebAuthnCredentials[i].ID, oldCredential.ID) {
					user.WebAuthnCredentials[i] = *newCredential

					return
				}
			}
		}

		for i := range user.WebAuthnCredentials {
			if bytes.Equal(user.WebAuthnCredentials[i].ID, newCredential.ID) {
				user.WebAuthnCredentials[i] = *newCredential

				return
			}
		}

		user.WebAuthnCredentials = append(user.WebAuthnCredentials, *newCredential)
	})

	return nil
}

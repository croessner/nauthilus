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

package core

import (
	"slices"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/localcache"
)

type recordingAuthCacheInvalidator struct {
	identities []string
	calls      int
}

// InvalidateIdentities records one shared-flow invalidation call.
func (r *recordingAuthCacheInvalidator) InvalidateIdentities(identities ...string) int {
	r.calls++
	r.identities = slices.Clone(identities)

	return len(identities)
}

func TestCompositeAuthCacheInvalidatorRemovesSeparatedCaches(t *testing.T) {
	backendAuthentications := NewPositiveBackendAuthenticationCache(time.Now)
	userAuth := localcache.NewUserAuthCache()

	defer userAuth.Close()

	cfg := newCurrentBehaviorConfig(t)
	auth, ctx := newRequestOwnedContractAuth(t, cfg, "login@example.test", "credential", "invalidate")
	auth.deps.BackendAuthenticationCache = backendAuthentications

	result := newSemanticPassDBResult(ctx, auth)
	defer PutPassDBResultToPool(result)

	auth.Runtime.AuthFSMTerminalState = string(authFSMStateAuthOK)

	key := mustBuildBackendAuthenticationCacheKey(t, auth)
	if !backendAuthentications.StoreForRequest(ctx, auth, result, time.Minute, auth.Request.Username, "alias@example.test") {
		t.Fatal("decision store failed")
	}

	userAuth.Set("alias@example.test", true)

	invalidator := NewCompositeAuthCacheInvalidator(backendAuthentications, userAuth)
	if removed := invalidator.InvalidateIdentities("alias@example.test"); removed != 2 {
		t.Fatalf("removed = %d, want 2", removed)
	}

	if _, found := backendAuthentications.load(key); found {
		t.Fatal("decision variant survived alias invalidation")
	}

	if _, found := userAuth.Get("alias@example.test"); found {
		t.Fatal("user-auth hint survived alias invalidation")
	}
}

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

package cache

import (
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/model/admin"
	restdto "github.com/croessner/nauthilus/server/model/rest"
	management "github.com/croessner/nauthilus/server/openapi/generated/management"
	"github.com/croessner/nauthilus/server/openapi/requesttest"
)

const (
	cacheTypedBoundarySession = "cache-boundary-session"
	cacheTypedBoundaryStatus  = "1 keys flushed"
	cacheTypedBoundaryUser    = "alice@example.test"
)

func TestCacheGeneratedModelsBridgeCurrentDTOs(t *testing.T) {
	t.Run("flush request", func(t *testing.T) {
		generated := management.CacheFlushRequest{User: cacheTypedBoundaryUser}
		current := admin.FlushUserCmd{}

		requesttest.RoundTripJSON(t, generated, &current)

		if current.User != generated.User {
			t.Fatalf("current user = %q, want %q", current.User, generated.User)
		}
	})

	t.Run("flush response", func(t *testing.T) {
		removedKeys := []string{"t:cache:alice@example.test"}
		current := restdto.Result{
			GUID:      cacheTypedBoundarySession,
			Object:    definitions.CatCache,
			Operation: definitions.ServFlush,
			Result: admin.FlushUserCmdStatus{
				User:        cacheTypedBoundaryUser,
				RemovedKeys: removedKeys,
				Status:      cacheTypedBoundaryStatus,
			},
		}
		generated := management.CacheFlushResult{}

		requesttest.RoundTripJSON(t, current, &generated)

		assertCacheTypedBoundaryEnvelope(t, generated)
		requesttest.RequireStringPointer(t, "result.user", generated.Result.User, cacheTypedBoundaryUser)
		requesttest.RequireStringPointer(t, "result.status", generated.Result.Status, cacheTypedBoundaryStatus)
		requesttest.RequireStringSlicePointer(t, "result.removed_keys", generated.Result.RemovedKeys, removedKeys)
	})
}

func assertCacheTypedBoundaryEnvelope(t testing.TB, generated management.CacheFlushResult) {
	t.Helper()

	if generated.Session != cacheTypedBoundarySession {
		t.Fatalf("session = %q, want %q", generated.Session, cacheTypedBoundarySession)
	}

	if generated.Object != definitions.CatCache {
		t.Fatalf("object = %q, want %q", generated.Object, definitions.CatCache)
	}

	if generated.Operation != definitions.ServFlush {
		t.Fatalf("operation = %q, want %q", generated.Operation, definitions.ServFlush)
	}
}

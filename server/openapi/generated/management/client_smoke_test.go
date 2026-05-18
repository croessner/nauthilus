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

package management

import (
	"context"
	"net/http"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/openapi/requesttest"
)

const (
	cacheClientSmokeAuthorization = "Bearer generated-client-smoke"
	cacheClientSmokeJobID         = "job-cache-1"
	cacheClientSmokeSession       = "generated-client-cache-session"
	cacheClientSmokeUser          = "alice@example.test"
)

func TestGeneratedManagementClientUsesCacheContract(t *testing.T) {
	requestBody := CacheFlushRequest{User: cacheClientSmokeUser}
	responseBody := AsyncAccepted{
		Session:   cacheClientSmokeSession,
		Object:    definitions.CatCache,
		Operation: definitions.ServFlush,
		Result: AsyncAcceptedPayload{
			JobId:  cacheClientSmokeJobID,
			Status: AsyncAcceptedStatusQueued,
		},
	}
	doer := requesttest.NewClientSmokeDoer(t, requesttest.ClientSmokeRoute{
		Request:  requestBody,
		Response: responseBody,
		Headers: map[string]string{
			"Authorization": cacheClientSmokeAuthorization,
		},
		Method: http.MethodDelete,
		Path:   "/api/v1/cache/flush/async",
		Status: http.StatusAccepted,
	})

	client, err := NewClientWithResponses(
		"https://nauthilus.example.test",
		WithHTTPClient(doer),
		WithRequestEditorFn(addCacheClientSmokeAuthorization),
	)
	if err != nil {
		t.Fatalf("create generated management client: %v", err)
	}

	response, err := client.EnqueueUserCacheFlushWithResponse(context.Background(), requestBody)
	if err != nil {
		t.Fatalf("call generated management client: %v", err)
	}

	assertCacheClientSmokeResponse(t, response)
}

func addCacheClientSmokeAuthorization(_ context.Context, request *http.Request) error {
	request.Header.Set("Authorization", cacheClientSmokeAuthorization)

	return nil
}

func assertCacheClientSmokeResponse(t testing.TB, response *EnqueueUserCacheFlushResponse) {
	t.Helper()

	if response.StatusCode() != http.StatusAccepted {
		t.Fatalf("status code = %d, want %d", response.StatusCode(), http.StatusAccepted)
	}

	if response.JSON202 == nil {
		t.Fatal("JSON202 response missing")
	}

	if response.JSON202.Session != cacheClientSmokeSession {
		t.Fatalf("session = %q, want %q", response.JSON202.Session, cacheClientSmokeSession)
	}

	if response.JSON202.Object != definitions.CatCache {
		t.Fatalf("object = %q, want %q", response.JSON202.Object, definitions.CatCache)
	}

	if response.JSON202.Operation != definitions.ServFlush {
		t.Fatalf("operation = %q, want %q", response.JSON202.Operation, definitions.ServFlush)
	}

	if response.JSON202.Result.JobId != cacheClientSmokeJobID {
		t.Fatalf("jobId = %q, want %q", response.JSON202.Result.JobId, cacheClientSmokeJobID)
	}

	if response.JSON202.Result.Status != AsyncAcceptedStatusQueued {
		t.Fatalf("status = %q, want %q", response.JSON202.Result.Status, AsyncAcceptedStatusQueued)
	}
}

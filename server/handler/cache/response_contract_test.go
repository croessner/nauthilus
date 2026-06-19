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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	handlerdeps "github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/openapi/requesttest"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

func TestCacheFlushValidationResponseMatchesOpenAPIContract(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := newCacheResponseContractRouter(t)
	request := requesttest.NewJSONRequest(http.MethodDelete, "/api/v1/cache/flush", `{}`)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	requesttest.AssertRecorderResponse(t, requesttest.NewManagementValidator(t), request, recorder, requesttest.ResponseValidation{
		ExpectedMediaType: "application/json",
	})

	var body struct {
		Errors []struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("cache validation body is not JSON: %v", err)
	}

	if len(body.Errors) != 1 || body.Errors[0].Field != "User" {
		t.Fatalf("cache validation errors = %#v, want required User field", body.Errors)
	}
}

func newCacheResponseContractRouter(t *testing.T) *gin.Engine {
	t.Helper()

	db, _ := redismock.NewClientMock()
	deps := &handlerdeps.Deps{
		Cfg: &config.FileSettings{
			Server: &config.ServerSection{
				Redis: config.Redis{Prefix: "t:"},
			},
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db),
	}

	router := gin.New()
	New(deps).Register(router.Group("/api/v1"))

	return router
}

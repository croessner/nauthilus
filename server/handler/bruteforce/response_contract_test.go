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

package bruteforce

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/openapi/requesttest"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
)

const (
	bruteForceContractBanScanCount int64 = 500
	bruteForceContractRedisPrefix        = "t:"
)

func TestBruteForceListResponseMatchesOpenAPIContract(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router, mock := newBruteForceResponseContractRouter(t)
	mock.MatchExpectationsInOrder(false)

	for _, key := range rediscli.GetAllBruteForceBanIndexKeys(bruteForceContractRedisPrefix) {
		mock.ExpectZRangeWithScores(key, 0, -1).SetVal([]redis.Z{})
	}

	mock.ExpectScan(0, rediscli.GetBruteForceBanKeyPattern(bruteForceContractRedisPrefix), bruteForceContractBanScanCount).SetVal([]string{}, 0)
	mock.ExpectSMembers(bruteForceContractRedisPrefix + definitions.RedisAffectedAccountsKey).SetVal([]string{})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/bruteforce/list", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	requesttest.AssertRecorderResponse(t, requesttest.NewManagementValidator(t), request, recorder, requesttest.ResponseValidation{
		ExpectedMediaType: "application/json",
	})

	var body struct {
		Object    string `json:"object"`
		Operation string `json:"operation"`
		Result    []any  `json:"result"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("brute-force list body is not JSON: %v", err)
	}

	if body.Object != definitions.CatBruteForce || body.Operation != definitions.ServList || len(body.Result) != 2 {
		t.Fatalf("brute-force envelope = %#v, want brute-force list with two result entries", body)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func newBruteForceResponseContractRouter(t *testing.T) (*gin.Engine, redismock.ClientMock) {
	t.Helper()

	db, mock := redismock.NewClientMock()
	deps := &handlerdeps.Deps{
		Cfg: &config.FileSettings{
			Server: &config.ServerSection{
				Redis: config.Redis{Prefix: bruteForceContractRedisPrefix},
			},
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db),
	}

	router := gin.New()
	New(deps).Register(router.Group("/api/v1"))

	return router, mock
}

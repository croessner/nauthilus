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

package health

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

func TestReadinessCheckUsesTestBackend(t *testing.T) {
	gin.SetMode(gin.TestMode)
	core.InitPassDBResultPool()
	util.SetDefaultConfigFile(&config.FileSettings{Server: &config.ServerSection{}})
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/healthz", nil)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	deps := HealthzDeps{
		Cfg:         &config.FileSettings{Server: &config.ServerSection{}},
		Logger:      logger,
		BackendName: "healthz-test",
	}

	ReadinessCheck(ctx, deps)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	var result HealthzResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if result.Status != healthzStatusUp {
		t.Fatalf("expected status %q, got %q", healthzStatusUp, result.Status)
	}

	check := result.Checks["test_backend"]
	if check == nil {
		t.Fatalf("expected test_backend check to be present")
	}

	if check.Status != healthzStatusUp {
		t.Fatalf("expected test_backend status %q, got %q", healthzStatusUp, check.Status)
	}
}

func TestReadinessCheckIgnoresInformationalChecks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	core.InitPassDBResultPool()

	backend := &config.Backend{}

	if err := backend.Set(definitions.BackendLDAPName); err != nil {
		t.Fatalf("failed to set ldap backend: %v", err)
	}

	cfg := &config.FileSettings{
		Server: &config.ServerSection{Backends: []*config.Backend{backend}},
		LDAP:   &config.LDAPSection{Config: &config.LDAPConf{ServerURIs: []string{}}},
	}

	util.SetDefaultConfigFile(cfg)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	redisDB, redisMock := redismock.NewClientMock()

	if redisDB == nil || redisMock == nil {
		t.Fatalf("failed to create redis mock")
	}

	redisMock.ExpectPing().SetErr(errors.New("redis down"))
	redisMock.ExpectPing().SetErr(errors.New("redis down"))

	redisClient := rediscli.NewTestClient(redisDB)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/healthz", nil)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	deps := HealthzDeps{
		Cfg:         cfg,
		Logger:      logger,
		BackendName: "healthz-test",
		Redis:       redisClient,
	}

	ReadinessCheck(ctx, deps)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations not met: %v", err)
	}

	var result HealthzResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if result.Status != healthzStatusUp {
		t.Fatalf("expected status %q, got %q", healthzStatusUp, result.Status)
	}

	redisWrite := result.Checks["redis_write"]
	if redisWrite == nil {
		t.Fatalf("expected redis_write check to be present")
	}

	if redisWrite.Status != healthzStatusDown {
		t.Fatalf("expected redis_write status %q, got %q", healthzStatusDown, redisWrite.Status)
	}

	redisRead := result.Checks["redis_read"]
	if redisRead == nil {
		t.Fatalf("expected redis_read check to be present")
	}

	if redisRead.Status != healthzStatusDown {
		t.Fatalf("expected redis_read status %q, got %q", healthzStatusDown, redisRead.Status)
	}

	ldapCheck := result.Checks["ldap"]
	if ldapCheck == nil {
		t.Fatalf("expected ldap check to be present")
	}

	if ldapCheck.Status != healthzStatusDown {
		t.Fatalf("expected ldap status %q, got %q", healthzStatusDown, ldapCheck.Status)
	}
}

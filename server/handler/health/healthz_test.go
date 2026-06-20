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

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"
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
	deps, redisMock := readinessInformationalDeps(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/healthz", nil)

	ReadinessCheck(ctx, deps)
	assertReadinessInformationalResponse(t, recorder, redisMock)
}

// readinessInformationalDeps prepares readiness dependencies with failing informational checks.
func readinessInformationalDeps(t *testing.T) (HealthzDeps, redismock.ClientMock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	core.InitPassDBResultPool()

	cfg := readinessInformationalConfig(t)
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	redisDB, redisMock := redismock.NewClientMock()
	if redisDB == nil || redisMock == nil {
		t.Fatalf("failed to create redis mock")
	}

	redisMock.ExpectPing().SetErr(errors.New("redis down"))
	redisMock.ExpectPing().SetErr(errors.New("redis down"))

	return HealthzDeps{
		Cfg:         cfg,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		BackendName: "healthz-test",
		Redis:       rediscli.NewTestClient(redisDB),
	}, redisMock
}

// readinessInformationalConfig builds LDAP-enabled config with no LDAP targets.
func readinessInformationalConfig(t *testing.T) *config.FileSettings {
	t.Helper()

	backend := &config.Backend{}
	if err := backend.Set(definitions.BackendLDAPName); err != nil {
		t.Fatalf("failed to set ldap backend: %v", err)
	}

	return &config.FileSettings{
		Server: &config.ServerSection{Backends: []*config.Backend{backend}},
		LDAP:   &config.LDAPSection{Config: &config.LDAPConf{ServerURIs: []string{}}},
	}
}

// assertReadinessInformationalResponse verifies readiness ignores informational failures.
func assertReadinessInformationalResponse(t *testing.T, recorder *httptest.ResponseRecorder, redisMock redismock.ClientMock) {
	t.Helper()

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

	assertHealthzCheckStatus(t, result, "redis_write", healthzStatusDown)
	assertHealthzCheckStatus(t, result, "redis_read", healthzStatusDown)
	assertHealthzCheckStatus(t, result, "ldap", healthzStatusDown)
}

// assertHealthzCheckStatus verifies one named health check status.
func assertHealthzCheckStatus(t *testing.T, result HealthzResult, name string, want string) {
	t.Helper()

	check := result.Checks[name]
	if check == nil {
		t.Fatalf("expected %s check to be present", name)
	}

	if check.Status != want {
		t.Fatalf("expected %s status %q, got %q", name, want, check.Status)
	}
}

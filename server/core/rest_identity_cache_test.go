package core

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/stretchr/testify/assert"
)

// TestUserFlushDisabledIdentityCacheReportsFenceFailure protects caches owned by enabled peers.
func TestUserFlushDisabledIdentityCacheReportsFenceFailure(t *testing.T) {
	setupMinimalTestConfig(t)
	engine, mock := setupEngineWithMock(t)
	prefix := config.GetFile().GetServer().GetRedis().GetPrefix()
	mock.Regexp().ExpectSet(prefix+"UCI:epoch", ".+", 0).SetErr(errors.New("redis unavailable"))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/cache/flush", bytes.NewBufferString(`{"user":"alice"}`))
	request.Header.Set("Content-Type", "application/json")

	engine.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestUserFlushAsyncReportsFenceFailure ensures the worker reports failed invalidation to its job owner.
func TestUserFlushAsyncReportsFenceFailure(t *testing.T) {
	setupMinimalTestConfig(t)
	deps, mock := setupRestAdminDepsWithMock(t)
	execute := captureAsyncCacheFlush(t)
	prefix := deps.Cfg.GetServer().GetRedis().GetPrefix()
	jobKey := prefix + "async:job:job-cache-invalidation"
	expectQueuedUserFlushJob(mock, jobKey)
	mock.Regexp().ExpectSet(prefix+"UCI:epoch", ".+", 0).SetErr(errors.New("redis unavailable"))

	invokeAsyncUserFlush(deps, "alice")

	if *execute == nil {
		t.Fatal("async callback was not captured")
	}

	_, _, err := (*execute)(context.Background())
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

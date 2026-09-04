// Copyright (C) 2026 Christian Rößner
// SPDX-License-Identifier: GPL-3.0-or-later

package subject

import (
	"io"
	"log/slog"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"

	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
)

// directorLikeSubjectScript mirrors the production routing subject source shape.
const directorLikeSubjectScript = `
local nauthilus_backend = require("nauthilus_backend")
local nauthilus_backend_result = require("nauthilus_backend_result")

function nauthilus_call_subject(request)
    if request.no_auth then
        return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
    end

    local backend_result = nauthilus_backend_result.new()
    backend_result:attributes({ routing_tenant = "default", routing_shard = "mailstack" })
    nauthilus_backend.apply_backend_result(backend_result)

    nauthilus_builtin.custom_log_add("director_routing_tenant", "default")
    nauthilus_builtin.custom_log_add("director_routing_mailShard", "mailstack")

    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`

// heapInUseAfterGC forces collection and reports the retained heap in bytes.
func heapInUseAfterGC() uint64 {
	runtime.GC()
	runtime.GC()

	var stats runtime.MemStats

	runtime.ReadMemStats(&stats)

	return stats.HeapInuse
}

// TestCallSubjectLuaSourceDoesNotRetainHeapPerRequest reproduces per-request heap growth on the subject path.
func TestCallSubjectLuaSourceDoesNotRetainHeapPerRequest(t *testing.T) {
	scriptDir := t.TempDir()
	scriptPath := writeSubjectScript(t, scriptDir, "director.lua", directorLikeSubjectScript)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := newSubjectTestConfig()
	pools := vmpool.NewManager()
	poolKey := subjectTestPoolKey(t, pools, "director")

	run := func() {
		request := newSubjectTestRequest(nil, nil)
		source := mustNewLuaSubjectSource(t, "director", scriptPath)

		_, _, _, err := request.CallSubjectLuaSource(newSubjectTestContext(), cfg, logger, nil, source, pools, poolKey)
		if err != nil {
			t.Fatalf("CallSubjectLuaSource returned error: %v", err)
		}
	}

	const warmup, rounds, perRound = 50, 4, 250

	for i := 0; i < warmup; i++ {
		run()
	}

	baseline := heapInUseAfterGC()
	t.Logf("baseline heap in use after warmup: %d KiB", baseline/1024)

	var last uint64

	for round := 1; round <= rounds; round++ {
		for i := 0; i < perRound; i++ {
			run()
		}

		last = heapInUseAfterGC()
		t.Logf("after %d requests: heap in use %d KiB (delta %d KiB, %d bytes/request)",
			round*perRound, last/1024, (int64(last)-int64(baseline))/1024, (int64(last)-int64(baseline))/int64(round*perRound))
	}

	if path := os.Getenv("SUBJECT_HEAP_PROFILE"); path != "" {
		f, err := os.Create(path)
		if err == nil {
			_ = pprof.Lookup("heap").WriteTo(f, 0)
			_ = f.Close()
		}
	}

	const maxRetainedPerRequest = 4096

	if perRequest := (int64(last) - int64(baseline)) / int64(rounds*perRound); perRequest > maxRetainedPerRequest {
		t.Fatalf("subject path retains %d bytes per request, want at most %d", perRequest, maxRetainedPerRequest)
	}
}

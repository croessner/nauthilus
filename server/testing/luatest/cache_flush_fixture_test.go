package luatest

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCacheFlushWrapperFixture(t *testing.T) {
	scriptPath := luaPluginFixturePath(t, "cache_flush_wrapper.lua")
	mockPath := luaPluginFixturePath(t, "cache_flush_test.json")

	runner, err := NewTestRunner(scriptPath, "cache_flush", mockPath)
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected cache flush fixture to succeed, errors: %v", result.Errors)
	}

	if len(result.CacheFlushAdditionalKeys) != 2 {
		t.Fatalf("expected 2 additional keys, got %d", len(result.CacheFlushAdditionalKeys))
	}

	if result.CacheFlushAdditionalKeys[0] != "ucp:__default__:cacheflush-user@example.com" {
		t.Fatalf("unexpected first additional key: %q", result.CacheFlushAdditionalKeys[0])
	}

	if result.CacheFlushAdditionalKeys[1] != "user_name:__default__:cacheflush-user@example.com" {
		t.Fatalf("unexpected second additional key: %q", result.CacheFlushAdditionalKeys[1])
	}

	if result.CacheFlushAccountName == nil {
		t.Fatal("expected cache flush account name to be set")
	}

	if *result.CacheFlushAccountName != "cacheflush-account" {
		t.Fatalf("unexpected cache flush account name: %q", *result.CacheFlushAccountName)
	}

	assertLogContains(t, result.Logs, "cache_flush_keys:")
	assertLogContains(t, result.Logs, "cache_flush_account:")
}

func luaPluginFixturePath(t *testing.T, name string) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve current test file path")
	}

	return filepath.Join(filepath.Dir(file), "..", "..", "..", "testdata", "lua", "plugins", name)
}

func assertLogContains(t *testing.T, logs []string, expectedFragment string) {
	t.Helper()

	for _, entry := range logs {
		if strings.Contains(entry, expectedFragment) {
			return
		}
	}

	t.Fatalf("expected log containing %q, got logs=%v", expectedFragment, logs)
}

// Package luatest provides test helpers for Lua plugins.
package luatest

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestClickhouseActionIncludesIdPFieldsInInsertedRow(t *testing.T) {
	runner := runClickhouseFixture(t, "action_wrapper.lua", "action_success.json", "action")
	request := firstCapturedHTTPRequest(t, runner)
	row := decodeJSONEachRowLine(t, request.Body)

	assertStringField(t, row, "saml_entity_id", "https://sp.example.com/metadata")
	assertStringField(t, row, "grant_type", "client_credentials")
	assertStringField(t, row, "mfa_method", "webauthn")
}

func TestClickhouseActionKeepsRowInCacheWhenBatchNotReached(t *testing.T) {
	runner := runClickhouseFixture(t, "action_wrapper.lua", "action_cache_only.json", "action")
	captured := capturedHTTPRequests(t, runner)
	if len(captured) != 0 {
		t.Fatalf("expected no HTTP calls when batch size is not reached, got %d", len(captured))
	}

	cacheEntry, ok := runner.mockData.Cache.Entries["clickhouse:batch:test"]
	if !ok {
		t.Fatal("expected cache entry for clickhouse batch key")
	}

	list, ok := cacheEntry.([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("expected cache entry to contain one row, got %#v", cacheEntry)
	}

	payload, ok := list[0].(string)
	if !ok || payload == "" {
		t.Fatalf("expected cached row payload as non-empty string, got %#v", list[0])
	}

	row := map[string]any{}
	if err := json.Unmarshal([]byte(payload), &row); err != nil {
		t.Fatalf("failed to decode cached JSON row: %v", err)
	}

	assertStringField(t, row, "saml_entity_id", "https://sp.example.com/metadata")
	assertStringField(t, row, "grant_type", "client_credentials")
	assertStringField(t, row, "mfa_method", "webauthn")
}

func TestClickhouseQuerySelectContainsIdPFields(t *testing.T) {
	runner := runClickhouseFixture(t, "query_wrapper.lua", "query_success.json", "hook")
	request := firstCapturedHTTPRequest(t, runner)
	sql := request.Body

	if !strings.Contains(sql, "saml_entity_id") {
		t.Fatalf("expected SQL projection to contain saml_entity_id, query=%q", sql)
	}

	if !strings.Contains(sql, "grant_type") {
		t.Fatalf("expected SQL projection to contain grant_type, query=%q", sql)
	}

	if !strings.Contains(sql, "mfa_method") {
		t.Fatalf("expected SQL projection to contain mfa_method, query=%q", sql)
	}
}

func runClickhouseFixture(t *testing.T, scriptFixture, mockFixture, callbackType string) *TestRunner {
	t.Helper()

	scriptPath := clickhouseFixturePath(t, scriptFixture)
	mockPath := clickhouseFixturePath(t, mockFixture)

	runner, err := NewTestRunner(scriptPath, callbackType, mockPath)
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected Lua script to succeed, errors: %v", result.Errors)
	}

	return runner
}

func clickhouseFixturePath(t *testing.T, name string) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve current test file path")
	}

	return filepath.Join(filepath.Dir(file), "testdata", "clickhouse", name)
}

func capturedHTTPRequests(t *testing.T, runner *TestRunner) []HTTPClientCapturedRecord {
	t.Helper()

	if runner == nil || runner.mockData == nil || runner.mockData.HTTPClient == nil {
		t.Fatal("expected HTTP client mock runtime state to be available")
	}

	return runner.mockData.HTTPClient.Captured
}

func firstCapturedHTTPRequest(t *testing.T, runner *TestRunner) HTTPClientCapturedRecord {
	t.Helper()

	captured := capturedHTTPRequests(t, runner)
	if len(captured) == 0 {
		t.Fatal("expected at least one captured HTTP request")
	}

	return captured[0]
}

func decodeJSONEachRowLine(t *testing.T, body string) map[string]any {
	t.Helper()

	line := strings.TrimSpace(strings.Split(body, "\n")[0])
	if line == "" {
		t.Fatal("expected non-empty JSONEachRow payload line")
	}

	row := map[string]any{}
	if err := json.Unmarshal([]byte(line), &row); err != nil {
		t.Fatalf("failed to decode JSONEachRow line: %v", err)
	}

	return row
}

func assertStringField(t *testing.T, row map[string]any, key, expected string) {
	t.Helper()

	value, ok := row[key]
	if !ok {
		t.Fatalf("expected key %q to exist in row", key)
	}

	got, ok := value.(string)
	if !ok {
		t.Fatalf("expected key %q to be a string, got %#v", key, value)
	}

	if got != expected {
		t.Fatalf("unexpected %s value: got=%q want=%q", key, got, expected)
	}
}

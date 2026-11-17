// Copyright (C) 2026 Christian Rößner
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

package clickhousestore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
)

// capture records the last request a fake ClickHouse received.
type capture struct {
	query   string
	body    string
	headers http.Header
}

// fakeClickHouse answers every request with one status, optional header code, and body.
func fakeClickHouse(t *testing.T, status int, code, body string, seen *capture) *Store {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		raw, _ := io.ReadAll(request.Body)
		if seen != nil {
			*seen = capture{query: request.URL.RawQuery, body: string(raw), headers: request.Header.Clone()}
		}

		if code != "" {
			writer.Header().Set("X-ClickHouse-Exception-Code", code)
		}

		writer.WriteHeader(status)
		_, _ = writer.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	store, err := New(Config{URL: server.URL + "/", Database: "nauthilus", Username: "nauthilus_history",
		Password: secret.New("reader-secret"), Deployment: "prod", Mode: BudgetQuerySettings,
		Budget: Budget{MaxExecutionTime: 5 * time.Second, MaxRowsToRead: 1000, MaxBytesToRead: 1 << 20, MaxResponseBytes: 512}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return store
}

// anchorsWith runs one anchor query against the fake.
func anchorsWith(store *Store) error {
	_, err := store.Anchors(context.Background(), supporthistory.AnchorQuery{From: time.Unix(0, 0), Until: time.Unix(60, 0),
		Subject: supporthistory.SubjectMatch{Logins: []string{`a\b'c`}}, Limit: 5})

	return err
}

// TestQueryNeverTurnsBrokenBodiesIntoEmptyResults pins that truncated, oversized, or exception bodies are errors.
func TestQueryNeverTurnsBrokenBodiesIntoEmptyResults(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		code   string
		body   string
		want   error
	}{
		"exception inside 200 body": {http.StatusOK, "", `{"meta":[],"data":[],"rows":0,"exception":"Code: 158. DB::Exception: Limit for rows"}`, supporthistory.ErrBudgetExceeded},
		"truncated body":            {http.StatusOK, "", `{"meta":[],"data":[{"key_kind":"flow"`, supporthistory.ErrSourceUnavailable},
		"truncated after budget":    {http.StatusOK, "", `{"data":[{"x":1}],"rows":1, "exception": "Code: 159. timeout`, supporthistory.ErrBudgetExceeded},
		"row count mismatch":        {http.StatusOK, "", `{"meta":[],"data":[],"rows":3}`, supporthistory.ErrSourceUnavailable},
		"missing rows member":       {http.StatusOK, "", `{"meta":[],"data":[]}`, supporthistory.ErrSourceUnavailable},
		"oversized body":            {http.StatusOK, "", `{"data":[],"rows":0,"pad":"` + strings.Repeat("x", 600) + `"}`, supporthistory.ErrBudgetExceeded},
		"unknown table":             {http.StatusNotFound, "60", "Code: 60. DB::Exception: Unknown table", supporthistory.ErrSourceNotInstalled},
		"settings rejected":         {http.StatusInternalServerError, "164", "Code: 164. readonly", supporthistory.ErrReaderUnsafe},
		"authentication failed":     {http.StatusForbidden, "516", "Code: 516.", supporthistory.ErrSourceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			err := anchorsWith(fakeClickHouse(t, tc.status, tc.code, tc.body, nil))
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}

			if strings.Contains(err.Error(), "DB::Exception") {
				t.Fatalf("error %q leaks server text", err)
			}
		})
	}
}

// TestQueryKeepsSecretsAndValuesOutOfTheURL pins header credentials, typed parameters, and per-query budgets.
func TestQueryKeepsSecretsAndValuesOutOfTheURL(t *testing.T) {
	var seen capture

	store := fakeClickHouse(t, http.StatusOK, "", `{"meta":[],"data":[{"key_kind":"flow","key_value":"`+
		strings.Repeat("a", 32)+`","anchor_ms":"60000"}],"rows":1}`, &seen)

	anchors, err := store.Anchors(context.Background(), supporthistory.AnchorQuery{From: time.Unix(0, 0), Until: time.Unix(60, 0),
		Subject: supporthistory.SubjectMatch{Logins: []string{`a\b'c`}}, Limit: 5})
	if err != nil || len(anchors) != 1 || anchors[0].At.UnixMilli() != 60000 {
		t.Fatalf("anchors = %+v, %v", anchors, err)
	}

	assertHeaderCredentials(t, seen)
	assertTypedParameters(t, seen)
}

// assertHeaderCredentials checks that credentials travel in headers only.
func assertHeaderCredentials(t *testing.T, seen capture) {
	t.Helper()

	if strings.Contains(seen.query, "reader-secret") || seen.headers.Get("X-ClickHouse-Key") != "reader-secret" ||
		seen.headers.Get("X-ClickHouse-User") != "nauthilus_history" {
		t.Fatalf("credentials query=%q headers=%v, want header-only credentials", seen.query, seen.headers)
	}
}

// assertTypedParameters checks per-query budgets, typed parameters, and a value-free SQL body.
func assertTypedParameters(t *testing.T, seen capture) {
	t.Helper()

	for _, want := range []string{"max_rows_to_read=1000", "read_overflow_mode=throw", "result_overflow_mode=throw",
		"timeout_overflow_mode=throw", "max_execution_time=5", "param_p1=prod",
		"param_p4=%5B%27a%5C%5Cb%5C%27c%27%5D"} {
		if !strings.Contains(seen.query, want) {
			t.Fatalf("query string %q lacks %q", seen.query, want)
		}
	}

	if strings.Contains(seen.body, "a\\b") || strings.Contains(seen.body, "prod") || !strings.HasSuffix(seen.body, "FORMAT JSON") {
		t.Fatalf("SQL body %q must contain placeholders only", seen.body)
	}
}

// TestSelfCheckRefusesUnsafeReaders pins the read-only and overflow requirements of both budget modes.
func TestSelfCheckRefusesUnsafeReaders(t *testing.T) {
	settings := func(readonly int, overflow string, rows int) string {
		raw, _ := json.Marshal(map[string]any{"meta": []any{}, "rows": 1, "data": []map[string]any{{
			"readonly": readonly, "max_rows": rows, "max_bytes": 100, "max_time": 5, "read_overflow": overflow,
			"result_overflow": "throw", "timeout_overflow": "throw"}}})

		return string(raw)
	}

	for name, tc := range map[string]struct {
		mode BudgetMode
		body string
		safe bool
	}{
		"query settings readonly=2":       {BudgetQuerySettings, settings(2, "throw", 1000), true},
		"writable account":                {BudgetQuerySettings, settings(0, "throw", 1000), false},
		"silent truncation":               {BudgetQuerySettings, settings(2, "break", 1000), false},
		"profile within budget":           {BudgetProfile, settings(1, "throw", 1000), true},
		"profile without row budget":      {BudgetProfile, settings(1, "throw", 0), false},
		"profile above configured budget": {BudgetProfile, settings(1, "throw", 5000), false},
	} {
		t.Run(name, func(t *testing.T) {
			var seen capture

			store := fakeClickHouse(t, http.StatusOK, "", tc.body, &seen)
			store.client.mode = tc.mode

			err := store.SelfCheck(context.Background())
			if (err == nil) != tc.safe || (!tc.safe && !errors.Is(err, supporthistory.ErrReaderUnsafe)) {
				t.Fatalf("SelfCheck() error = %v, want safe=%t", err, tc.safe)
			}

			if tc.mode == BudgetProfile && strings.Contains(seen.query, "max_rows_to_read") {
				t.Fatalf("profile mode sent settings: %q", seen.query)
			}
		})
	}
}

// TestNewRejectsUnsafeConfigurations pins URL, identifier, and budget validation.
func TestNewRejectsUnsafeConfigurations(t *testing.T) {
	base := Config{URL: "http://clickhouse:8123/", Database: "nauthilus", Username: "reader", Deployment: "prod",
		Mode: BudgetQuerySettings, Budget: Budget{MaxExecutionTime: time.Second, MaxRowsToRead: 1, MaxBytesToRead: 1, MaxResponseBytes: 1}}

	for name, mutate := range map[string]func(*Config){
		"credentials in URL":  func(c *Config) { c.URL = "http://user:pw@clickhouse:8123/" },
		"query in URL":        func(c *Config) { c.URL = "http://clickhouse:8123/?readonly=0" },
		"injected database":   func(c *Config) { c.Database = "nauthilus; DROP" },
		"missing deployment":  func(c *Config) { c.Deployment = " " },
		"zero budget":         func(c *Config) { c.Budget.MaxRowsToRead = 0 },
		"unknown budget mode": func(c *Config) { c.Mode = "none" },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)

			if _, err := New(config); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

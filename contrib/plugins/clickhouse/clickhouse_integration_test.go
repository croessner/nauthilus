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

//go:build clickhouse_integration

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// clickHouseTestURLEnv names the HTTP endpoint of an isolated, disposable ClickHouse used only by these tests.
const clickHouseTestURLEnv = "NAUTHILUS_CLICKHOUSE_TEST_URL"

// clickHouseTestKeepEnv keeps the per-test databases for manual readback of the stored rows when set to 1.
const clickHouseTestKeepEnv = "NAUTHILUS_CLICKHOUSE_TEST_KEEP"

const (
	schemaPath        = "../../clickhouse-kubernetes/schema.sql"
	migrationPath     = "../../clickhouse-kubernetes/migrations/diagnostic-contract.sql"
	bruteForceMigPath = "../../clickhouse-kubernetes/migrations/bruteforce-evidence.sql"
	bruteForceFixture = "testdata/diagnostic_contract/bruteforce_events.json"
	legacySchemaPath  = "testdata/diagnostic_contract/legacy_logins_schema.sql"
	outcomeFixture    = "testdata/diagnostic_contract/terminal_outcomes.json"
	dashboardPath     = "../../clickhouse-kubernetes/nauthilus-logins-grafana-dashboard.json"
	productionDBToken = "nauthilus."
)

// clickHouseTestDB is one uniquely named database in the isolated test server.
type clickHouseTestDB struct {
	t       *testing.T
	baseURL string
	name    string
}

// newClickHouseTestDB creates a unique database and drops it when the test ends.
func newClickHouseTestDB(t *testing.T) *clickHouseTestDB {
	t.Helper()

	baseURL := strings.TrimSpace(os.Getenv(clickHouseTestURLEnv))
	if baseURL == "" {
		t.Skipf("%s is not set; start an isolated ClickHouse to run this test", clickHouseTestURLEnv)
	}

	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("random database suffix: %v", err)
	}

	db := &clickHouseTestDB{t: t, baseURL: strings.TrimRight(baseURL, "/") + "/", name: "nauthilus_it_" + hex.EncodeToString(suffix[:])}
	db.exec("CREATE DATABASE " + db.name)

	if os.Getenv(clickHouseTestKeepEnv) == "1" {
		t.Logf("keeping ClickHouse test database %s", db.name)

		return db
	}

	t.Cleanup(func() { db.exec("DROP DATABASE IF EXISTS " + db.name) })

	return db
}

// exec runs one statement and fails the test on a ClickHouse error.
func (db *clickHouseTestDB) exec(statement string) {
	db.t.Helper()

	if err := db.tryExec(statement); err != nil {
		db.t.Fatalf("clickhouse statement failed: %v\n%s", err, statement)
	}
}

// tryExec runs one statement and returns a ClickHouse error.
func (db *clickHouseTestDB) tryExec(statement string) error {
	response, err := http.Post(db.baseURL, "text/plain", strings.NewReader(statement)) //nolint:noctx // test-only client
	if err != nil {
		return err
	}

	defer func() { _ = response.Body.Close() }()

	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}

	return nil
}

// applyFile runs every statement of a schema file against the test database.
func (db *clickHouseTestDB) applyFile(path string) {
	db.t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		db.t.Fatalf("read %s: %v", path, err)
	}

	for _, statement := range sqlStatements(string(content)) {
		if strings.HasPrefix(strings.ToUpper(statement), "CREATE DATABASE") {
			continue
		}

		db.exec(db.scoped(statement))
	}
}

// scoped rewrites the production database name to the unique test database.
func (db *clickHouseTestDB) scoped(statement string) string {
	return strings.ReplaceAll(statement, productionDBToken, db.name+".")
}

// insertURL returns a strict JSONEachRow insert URL for one table of the test database.
func (db *clickHouseTestDB) insertURL(table string, strict bool) string {
	query := url.Values{"query": {fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", db.name, table)}}
	if strict {
		query.Set("input_format_skip_unknown_fields", "0")
	}

	return db.baseURL + "?" + query.Encode()
}

// rows runs a SELECT and decodes its JSONEachRow result.
func (db *clickHouseTestDB) rows(query string) []map[string]any {
	db.t.Helper()

	response, err := http.Post(db.baseURL, "text/plain", strings.NewReader(db.scoped(query)+" FORMAT JSONEachRow")) //nolint:noctx
	if err != nil {
		db.t.Fatalf("query failed: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		db.t.Fatalf("query status %d: %s\n%s", response.StatusCode, body, query)
	}

	var result []map[string]any

	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<24)

	for scanner.Scan() {
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.UseNumber()

		row := map[string]any{}
		if err := decoder.Decode(&row); err != nil {
			db.t.Fatalf("decode row: %v", err)
		}

		result = append(result, row)
	}

	return result
}

// columns returns the name/type map of one table.
func (db *clickHouseTestDB) columns(table string) map[string]string {
	db.t.Helper()

	result := map[string]string{}
	for _, row := range db.rows(fmt.Sprintf(
		"SELECT name, type FROM system.columns WHERE database = '%s' AND table = '%s'", db.name, table,
	)) {
		result[fmt.Sprint(row["name"])] = fmt.Sprint(row["type"])
	}

	return result
}

var (
	sqlBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	sqlLineComment  = regexp.MustCompile(`(?m)--.*$`)
)

// sqlStatements strips comments and splits a schema file into executable statements.
func sqlStatements(content string) []string {
	content = sqlLineComment.ReplaceAllString(sqlBlockComment.ReplaceAllString(content, ""), "")

	var statements []string

	for _, statement := range strings.Split(content, ";") {
		if statement = strings.TrimSpace(statement); statement != "" {
			statements = append(statements, statement)
		}
	}

	return statements
}

// flushStreams delivers both plugin streams synchronously.
func flushStreams(t *testing.T, harness testHarness) {
	t.Helper()

	harness.plugin.flushPending(t.Context(), &harness.plugin.logins, "test")
	harness.plugin.flushPending(t.Context(), &harness.plugin.events, "test")
}

// waitRows polls until the expected number of rows is visible.
func waitRows(t *testing.T, db *clickHouseTestDB, query string, want int) []map[string]any {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for {
		rows := db.rows(query)
		if len(rows) >= want || time.Now().After(deadline) {
			return rows
		}

		time.Sleep(100 * time.Millisecond)
	}
}

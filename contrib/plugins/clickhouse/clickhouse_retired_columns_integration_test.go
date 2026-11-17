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
	"net/http"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/pluginapi/v1/exchange"
)

// TestClickHouseCleanedExportFitsTransitionAndRetiredSchemas pins that the cleaned export inserts with strict field
// checking into a migrated table that still has the retired columns (they take their defaults), into the same table
// after the retirement block of schema.sql ran, and into a fresh table from schema.sql.
func TestClickHouseCleanedExportFitsTransitionAndRetiredSchemas(t *testing.T) {
	for name, prepare := range map[string]func(*clickHouseTestDB){
		"transition": func(db *clickHouseTestDB) { db.applyFile(legacySchemaPath); db.applyFile(migrationPath) },
		"retired": func(db *clickHouseTestDB) {
			db.applyFile(legacySchemaPath)
			db.applyFile(migrationPath)
			db.applyRetiredColumnDrops(t)
		},
		"fresh": func(db *clickHouseTestDB) { db.applyFile(schemaPath) },
	} {
		t.Run(name, func(t *testing.T) {
			db := newClickHouseTestDB(t)
			prepare(db)

			harness := startTestRunner(t, testModule(map[string]any{
				"insert_url": db.insertURL("logins", true), "batch_size": 1000, "dedup_success": false,
				"deployment": "it", "instance": "it-1",
			}), testRunnerOptions{roundTripper: http.DefaultTransport})
			defer harness.stop(t)

			// The runtime maps that once fed the retired columns are present and must stay without effect.
			request := testRequest(t, requestOptions{authenticated: true, runtimeValues: map[string]any{
				exchange.KeyGeoIPReputation: map[string]any{"score": 0.5, "source": "redis"},
				exchange.KeyDynamicResponse: map[string]any{"threat_level": 3, "response": "slow"},
			}})
			request.Snapshot.Session = "retired-" + name

			if _, err := harness.enqueuePostAction(t.Context(), request); err != nil {
				t.Fatalf("Enqueue() error = %v", err)
			}

			harness.plugin.flushPending(t.Context(), &harness.plugin.logins, "test")

			rows := waitRows(t, db, "SELECT contract_version, deployment FROM nauthilus.logins WHERE session = 'retired-"+name+"'", 1)
			if len(rows) != 1 {
				t.Fatalf("stored rows = %v, want the cleaned export accepted by the strict insert", rows)
			}

			if name == "transition" {
				assertRetiredColumnsDefault(t, db, "retired-"+name)
			}
		})
	}
}

// assertRetiredColumnsDefault checks that the retired columns of a transition table only hold their defaults.
func assertRetiredColumnsDefault(t *testing.T, db *clickHouseTestDB, session string) {
	t.Helper()

	rows := db.rows("SELECT " + strings.Join(retiredLegacyColumns, ", ") + " FROM nauthilus.logins WHERE session = '" + session + "'")
	if len(rows) != 1 {
		t.Fatalf("rows = %v, want one", rows)
	}

	for _, column := range retiredLegacyColumns {
		if value := rows[0][column]; value != nil && value != "" {
			t.Fatalf("retired column %s = %v, want its default", column, value)
		}
	}
}

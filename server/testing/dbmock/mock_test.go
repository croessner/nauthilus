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

package dbmock

import (
	"errors"
	"strings"
	"testing"
)

func TestMockExecReturnsConfiguredResult(t *testing.T) {
	mock := New()
	conn := mock.Conn()

	mock.ExpectExec("UPDATE users SET enabled = ? WHERE id = ?", Predicate("bool-true", func(v any) bool {
		flag, ok := v.(bool)
		return ok && flag
	}), TypeOf("")).
		WillReturnResult(1, 42)

	result, err := conn.Exec("update users set enabled = ? where id = ?", true, "u-1")
	if err != nil {
		t.Fatalf("exec returned error: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Fatalf("expected rows_affected=1, got %d", result.RowsAffected)
	}
	if result.LastInsertID != 42 {
		t.Fatalf("expected last_insert_id=42, got %d", result.LastInsertID)
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected all expectations met, got: %v", err)
	}
}

func TestMockQueryReturnsConfiguredRows(t *testing.T) {
	mock := New()
	conn := mock.Conn()

	rows := NewRows("id", "email").
		AddRow("u-1", "a@example.org").
		AddRow("u-2", "b@example.org")

	mock.ExpectQuery("SELECT id, email FROM users WHERE enabled = ?", AnyArg()).
		WillReturnRows(rows)

	result, err := conn.Query("select id, email from users where enabled = ?", true)
	if err != nil {
		t.Fatalf("query returned error: %v", err)
	}

	if len(result.Columns) != 2 || result.Columns[0] != "id" || result.Columns[1] != "email" {
		t.Fatalf("unexpected columns: %#v", result.Columns)
	}
	if len(result.Data) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(result.Data))
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected all expectations met, got: %v", err)
	}
}

func TestMockExecReturnsConfiguredError(t *testing.T) {
	mock := New()
	conn := mock.Conn()
	expectedErr := errors.New("db unavailable")

	mock.ExpectExec("DELETE FROM users WHERE id = ?", "u-1").
		WillReturnError(expectedErr)

	_, err := conn.Exec("DELETE FROM users WHERE id = ?", "u-1")
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected configured error, got: %v", err)
	}
}

func TestExpectationsWereMetFailsWhenPending(t *testing.T) {
	mock := New()
	mock.ExpectExec("INSERT INTO users(id) VALUES (?)", "u-1")

	err := mock.ExpectationsWereMet()
	if err == nil {
		t.Fatal("expected unmet expectation error")
	}
	if !strings.Contains(err.Error(), "pending=[") || !strings.Contains(err.Error(), "last_call=") {
		t.Fatalf("expected diagnostic details, got: %v", err)
	}
}

func TestCallsHistoryCapturesMatchedCalls(t *testing.T) {
	mock := New()
	conn := mock.Conn()

	mock.ExpectExec("INSERT INTO users(id) VALUES (?)", "u-1")

	_, err := conn.Exec("insert into users(id) values (?)", "u-1")
	if err != nil {
		t.Fatalf("exec returned error: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call in history, got %d", len(calls))
	}
	if calls[0].Kind != CallExec {
		t.Fatalf("expected call kind exec, got %q", calls[0].Kind)
	}
}

func TestCallsHistoryMarksPreparedCalls(t *testing.T) {
	mock := New()
	conn := mock.Conn()

	mock.ExpectPrepare("SELECT id FROM users WHERE id = ?").ExpectQuery("u-1").WillReturnRows(NewRows("id").AddRow("u-1"))

	stmt, err := conn.Prepare("SELECT id FROM users WHERE id = ?")
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}

	_, err = stmt.Query("u-1")
	if err != nil {
		t.Fatalf("stmt query returned error: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls in history, got %d", len(calls))
	}
	if calls[1].Kind != CallQuery || !calls[1].Prepared {
		t.Fatalf("expected prepared query call, got kind=%q prepared=%t", calls[1].Kind, calls[1].Prepared)
	}
}

func TestUnorderedExpectations(t *testing.T) {
	mock := New(WithUnorderedExpectations())
	conn := mock.Conn()

	mock.ExpectExec("UPDATE users SET enabled = ? WHERE id = ?", true, "u-1").WillReturnResult(1, 0)
	mock.ExpectExec("UPDATE users SET enabled = ? WHERE id = ?", false, "u-2").WillReturnResult(1, 0)

	_, err := conn.Exec("UPDATE users SET enabled = ? WHERE id = ?", false, "u-2")
	if err != nil {
		t.Fatalf("first exec returned error: %v", err)
	}

	_, err = conn.Exec("UPDATE users SET enabled = ? WHERE id = ?", true, "u-1")
	if err != nil {
		t.Fatalf("second exec returned error: %v", err)
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected all unordered expectations to match, got: %v", err)
	}
}

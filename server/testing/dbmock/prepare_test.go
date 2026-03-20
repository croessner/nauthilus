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
	"testing"
)

func TestPrepareExecChain(t *testing.T) {
	mock := New()
	conn := mock.Conn()

	mock.ExpectPrepare("UPDATE users SET enabled = ? WHERE id = ?").
		ExpectExec(Eq(true), Eq("u-1")).
		WillReturnResult(1, 0)

	stmt, err := conn.Prepare(" update users set enabled = ? where id = ? ")
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}

	result, err := stmt.Exec(true, "u-1")
	if err != nil {
		t.Fatalf("stmt exec returned error: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Fatalf("expected rows_affected=1, got %d", result.RowsAffected)
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected all expectations met, got: %v", err)
	}
}

func TestPrepareQueryChain(t *testing.T) {
	mock := New()
	conn := mock.Conn()

	rows := NewRows("id").AddRow("u-1")
	mock.ExpectPrepare("SELECT id FROM users WHERE id = ?").
		ExpectQuery("u-1").
		WillReturnRows(rows)

	stmt, err := conn.Prepare("select id from users where id = ?")
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}

	result, err := stmt.Query("u-1")
	if err != nil {
		t.Fatalf("stmt query returned error: %v", err)
	}
	if len(result.Data) != 1 {
		t.Fatalf("expected one row, got %d", len(result.Data))
	}
}

func TestPrepareReturnsConfiguredError(t *testing.T) {
	mock := New()
	conn := mock.Conn()
	expectedErr := errors.New("prepare denied")

	mock.ExpectPrepare("SELECT 1").WillReturnError(expectedErr)

	_, err := conn.Prepare("SELECT 1")
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected configured prepare error, got: %v", err)
	}
}

func TestStatementClose(t *testing.T) {
	mock := New()
	conn := mock.Conn()

	mock.ExpectPrepare("SELECT id FROM users WHERE id = ?")

	stmt, err := conn.Prepare("SELECT id FROM users WHERE id = ?")
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}

	stmt.Close()

	_, err = stmt.Query("u-1")
	if !errors.Is(err, ErrStatementClosed) {
		t.Fatalf("expected ErrStatementClosed, got: %v", err)
	}
}

func TestPreparePlaceholderValidation(t *testing.T) {
	mock := New()
	conn := mock.Conn()

	mock.ExpectPrepare("SELECT id FROM users WHERE id = ? AND state = ?").
		ValidatePlaceholderCount().
		ExpectQuery(AnyArg(), AnyArg()).
		WillReturnRows(NewRows("id").AddRow("u-1"))

	stmt, err := conn.Prepare("SELECT id FROM users WHERE id = ? AND state = ?")
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}

	_, err = stmt.Query("u-1")
	if !errors.Is(err, ErrPlaceholderCountMismatch) {
		t.Fatalf("expected ErrPlaceholderCountMismatch, got: %v", err)
	}
}

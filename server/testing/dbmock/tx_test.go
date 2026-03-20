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

func TestTransactionCommitFlow(t *testing.T) {
	mock := New()
	conn := mock.Conn()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE users SET enabled = ? WHERE id = ?", true, "u-1").WillReturnResult(1, 0)
	mock.ExpectCommit()

	tx, err := conn.Begin()
	if err != nil {
		t.Fatalf("begin returned error: %v", err)
	}

	_, err = tx.Exec("UPDATE users SET enabled = ? WHERE id = ?", true, "u-1")
	if err != nil {
		t.Fatalf("exec returned error: %v", err)
	}

	if err = tx.Commit(); err != nil {
		t.Fatalf("commit returned error: %v", err)
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected all expectations met, got: %v", err)
	}
}

func TestTransactionRollbackFlow(t *testing.T) {
	mock := New()
	conn := mock.Conn()

	mock.ExpectBegin()
	mock.ExpectRollback()

	tx, err := conn.Begin()
	if err != nil {
		t.Fatalf("begin returned error: %v", err)
	}

	if err = tx.Rollback(); err != nil {
		t.Fatalf("rollback returned error: %v", err)
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected all expectations met, got: %v", err)
	}
}

func TestTransactionBeginError(t *testing.T) {
	mock := New()
	conn := mock.Conn()
	expectedErr := errors.New("begin rejected")

	mock.ExpectBegin().WillReturnError(expectedErr)

	_, err := conn.Begin()
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected configured begin error, got: %v", err)
	}
}

func TestTransactionCommitError(t *testing.T) {
	mock := New()
	conn := mock.Conn()
	expectedErr := errors.New("commit failed")

	mock.ExpectBegin()
	mock.ExpectCommit().WillReturnError(expectedErr)

	tx, err := conn.Begin()
	if err != nil {
		t.Fatalf("begin returned error: %v", err)
	}

	err = tx.Commit()
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected configured commit error, got: %v", err)
	}
}

func TestTransactionDoneGuard(t *testing.T) {
	mock := New()
	conn := mock.Conn()

	mock.ExpectBegin()
	mock.ExpectRollback()

	tx, err := conn.Begin()
	if err != nil {
		t.Fatalf("begin returned error: %v", err)
	}

	if err = tx.Rollback(); err != nil {
		t.Fatalf("rollback returned error: %v", err)
	}

	err = tx.Commit()
	if !errors.Is(err, ErrTransactionDone) {
		t.Fatalf("expected ErrTransactionDone, got: %v", err)
	}
}

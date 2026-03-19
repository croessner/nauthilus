# dbmock

`dbmock` is an internal, expectation-based SQL mock package for deterministic backend tests.

## What It Supports

1. Ordered expectations by default
2. Optional unordered matching via `WithUnorderedExpectations()`
3. `Exec`, `Query`, and `Prepare` statement flows
4. Transaction lifecycle (`Begin`, `Commit`, `Rollback`) with state guards
5. Argument matchers:
    - `Eq(value)`
    - `AnyArg()`
    - `TypeOf(sample)`
    - `Predicate(name, fn)`

## Basic Usage

```go
mock := dbmock.New()
conn := mock.Conn()

mock.ExpectExec("UPDATE users SET enabled = ? WHERE id = ?", true, "u-1").
    WillReturnResult(1, 0)

result, err := conn.Exec("UPDATE users SET enabled = ? WHERE id = ?", true, "u-1")
if err != nil {
    t.Fatal(err)
}
if result.RowsAffected != 1 {
    t.Fatalf("unexpected rows affected: %d", result.RowsAffected)
}

if err = mock.ExpectationsWereMet(); err != nil {
    t.Fatal(err)
}
```

## Prepared Statement Pattern

```go
mock.ExpectPrepare("SELECT id FROM users WHERE id = ?").
    ExpectQuery("u-1").
    WillReturnRows(dbmock.NewRows("id").AddRow("u-1"))

stmt, err := conn.Prepare("SELECT id FROM users WHERE id = ?")
if err != nil {
    t.Fatal(err)
}
defer stmt.Close()

rows, err := stmt.Query("u-1")
if err != nil {
    t.Fatal(err)
}
```

## Transaction Pattern

```go
mock.ExpectBegin()
mock.ExpectExec("UPDATE users SET enabled = ? WHERE id = ?", true, "u-1").WillReturnResult(1, 0)
mock.ExpectCommit()

tx, err := conn.Begin()
if err != nil {
    t.Fatal(err)
}

if _, err = tx.Exec("UPDATE users SET enabled = ? WHERE id = ?", true, "u-1"); err != nil {
    t.Fatal(err)
}
if err = tx.Commit(); err != nil {
    t.Fatal(err)
}
```

## Anti-Patterns

1. Do not rely on SQL parser semantics. `dbmock` is expectation-based, not a SQL engine.
2. Do not skip `ExpectationsWereMet()`. You lose missing-call diagnostics.
3. Do not share one `Mock` instance across unrelated tests.
4. Do not overuse `AnyArg()` if argument correctness matters.
5. Do not enable unordered mode unless call order is intentionally irrelevant.

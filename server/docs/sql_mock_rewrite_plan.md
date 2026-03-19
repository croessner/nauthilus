# SQL Mock Rewrite Plan: Phase 1 Focus

Date: 2026-03-19
Owner: Testing/Backend
Status: Implemented baseline, ready for Phase 2

## Scope of This Document

This document intentionally focuses only on the first implementation phase of the SQL mock rewrite:

1. Core domain model
2. Expectation abstractions
3. Synchronized expectation queue
4. Base error model
5. Unit-test baseline

Anything beyond that (results API, verifier policy, Lua adapter migration) is explicitly out of scope here.

## Phase 1 Goal

Provide a stable, minimal foundation for an expectation-based SQL mock package, independent from SQL regex parsing.

## Implemented Design

## 1. Call Model

Implemented in `server/testing/dbmock/call.go`.

1. `CallKind` enum-like type:

- `exec`, `query`, `prepare`, `begin`, `commit`, `rollback`

2. `Call` struct:

- `Kind`, `Query`, `Args`, `Timestamp`

3. `NewCall(...)`:

- Copies args defensively
- Sets UTC timestamp at creation

## 2. Expectation Interface and Base Implementation

Implemented in `server/testing/dbmock/expectation.go`.

1. `Expectation` interface:

- `Kind()`
- `Match(call Call) error`
- `Consume() error`
- `IsSatisfied() bool`
- `DescribeMismatch(call Call) string`

2. Concrete expectation types:

- `ExecExpectation`
- `QueryExpectation`
- `PrepareExpectation`
- `TxExpectation`

3. Matching behavior:

- kind match required
- SQL normalized for comparison (trim + lowercase + collapsed whitespace)
- exact arg count + per-index `reflect.DeepEqual` value match

4. Consumption lifecycle:

- one-shot consumption guard
- repeated consume returns explicit error

## 3. Synchronized Expectation Queue

Implemented in `server/testing/dbmock/queue.go`.

1. FIFO queue operations:

- `Enqueue`
- `Peek`
- `Dequeue`
- `Len`
- `Snapshot`

2. Atomic match-and-consume path:

- `MatchNext(call Call)` validates against the head expectation
- removes and consumes on success
- keeps queue unchanged on mismatch

3. Thread safety:

- queue access synchronized via mutex

## 4. Error Hierarchy

Implemented in `server/testing/dbmock/errors.go`.

Defined base errors:

1. `ErrUnexpectedCall`
2. `ErrKindMismatch`
3. `ErrSQLMismatch`
4. `ErrArgCountMismatch`
5. `ErrArgMismatch`
6. `ErrExpectationAlreadyConsumed`
7. `ErrEmptyExpectationQueue`

## 5. Unit-Test Baseline

Implemented in:

1. `server/testing/dbmock/expectation_test.go`
2. `server/testing/dbmock/queue_test.go`

Coverage focus:

1. Match success and mismatch types
2. Consume lifecycle guarantees
3. Queue FIFO behavior
4. Match-next success and mismatch behavior
5. Empty-queue error handling

## Exit Criteria for Phase 1

Phase 1 is considered complete when:

1. Core package compiles cleanly.
2. Unit tests for core model and queue pass.
3. Queue remains race-safe by design (mutex-protected operations).
4. No runtime dependency on SQL regex parsing exists in this package.

## Phase 1 File Map

1. `server/testing/dbmock/call.go`
2. `server/testing/dbmock/errors.go`
3. `server/testing/dbmock/expectation.go`
4. `server/testing/dbmock/queue.go`
5. `server/testing/dbmock/expectation_test.go`
6. `server/testing/dbmock/queue_test.go`

## Next Phase (Not Implemented Here)

Phase 2 will add higher-level mock behavior:

1. result-return APIs for `Exec` and `Query`
2. expectation verification summary API
3. richer argument matchers (`Any`, predicates, type-based)

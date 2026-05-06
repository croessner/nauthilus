# Nauthilus Policy Decision Layer - Phase 6

## Goal

Phase 6 introduces target auth-FSM event markers, a private migration adapter to the current auth-FSM event vocabulary, and target-vs-current FSM comparison diagnostics while the current FSM and current production responses remain authoritative.

This slice does not make `standard_auth` authoritative, does not make the target FSM authoritative, does not enable custom policy observe/enforce modes, and does not add any public config root or config field.

## Implemented Files and Modules

- `server/policy/types.go`
  - Adds central Go constants for the target FSM marker IDs from the spec.
  - Keeps YAML-facing marker values as `auth.fsm.event.*` target markers, not current internal event names.

- `server/policy/fsm/fsm.go`
  - Adds the target auth-FSM transition table.
  - Adds a private `currentAdapter` that maps target pre-auth markers to current `pre_auth_*` events and target final auth markers to current `password_*` events.
  - Represents `account_provider_evaluated` as target marker material and maps it through the current password checkpoint for migration diagnostics.
  - Compares target terminal state against the current production terminal state without changing the production response.

- `server/policy/report/report.go`
  - Adds an `FSMReport` with current terminal state, target terminal state, current internal event path, target event path, selected policy, operation, response marker, mismatch flag, and sanitized error text.
  - Clones FSM reports during redaction-safe report copying.

- `server/policy/evaluation/standard.go`
  - Builds the target marker sequence from the `standard_auth` shadow decision sequence.
  - Adds internal orchestration markers for parse success, pre-auth pass, auth evaluation, and account-provider evaluation.
  - Runs target FSM comparison from the existing shadow comparison path.
  - Records target FSM transition metrics and a `policy.fsm.apply` OpenTelemetry span.

- `server/core/rest.go`
  - Records the current auth-FSM event path and terminal state while the existing FSM remains authoritative.

- `server/core/response.go`
  - Passes current FSM terminal/path facts into policy comparison for success, deny, and tempfail responses.
  - Falls back to effect-derived terminal states on current direct-gate paths that do not execute the current auth-FSM.

- `server/core/auth.go`
  - Passes current FSM terminal/path facts into list-account policy comparison.

- `server/core/policy_collection.go`
  - Emits policy debug-module `fsm` diagnostics for target-vs-current FSM comparison results.

- `server/policy/compiler/definitions.go` and `server/policy/compiler/policies.go`
  - Reuse the central target marker constants for registry and default marker derivation.

## Tests and Validation

Focused tests were added before implementation. The first focused run with `/tmp` Go cache failed because marker constants, the FSM module, and report fields did not exist yet.

Added tests:

- `server/policy/fsm/fsm_test.go`
  - Covers all allowed target transitions from the spec transition table.
  - Exhaustively rejects unlisted transitions for target non-terminal and terminal states.
  - Verifies terminal states reject outgoing transitions.
  - Verifies the private current adapter maps target markers to current internal events.
  - Verifies terminal mismatch reporting does not mutate the current event path.

- `server/policy/evaluation/fsm_compare_test.go`
  - Covers target FSM comparison for `authenticate`, `lookup_identity`, and `list_accounts`.
  - Verifies FSM mismatch reporting is separate from the existing policy-result mismatch.

- `server/policy/compiler/snapshot_compiler_test.go`
  - Verifies unknown target marker names such as `unknown_pre_auth_marker` are rejected by policy marker validation.

Validation run:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/policy/fsm ./server/policy/evaluation ./server/policy/compiler ./server/policy/report ./server/core
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/policy/... ./server/core
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache GOMODCACHE=/tmp/nauthilus-gomod-cache make test
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache GOMODCACHE=/tmp/nauthilus-gomod-cache make guardrails
```

Result: passed.

The first test attempt without `GOCACHE=/tmp/nauthilus-go-cache` failed because the sandbox could not write to `~/Library/Caches/go-build`.

The first sandboxed `make test` run failed because sandbox policy blocked local listeners used by `miniredis` and `httptest`:

- `listen tcp 127.0.0.1:0: bind: operation not permitted`
- `httptest: failed to listen on a port`

The same `make test` command passed outside the sandbox with the same Go environment. `make guardrails` also passed outside the sandbox. Guardrails emitted the pre-existing warning about unknown `gomnd` entries in `//nolint` directives and then reported `0 issues`.

Diff hygiene:

- `git diff --check` passed.
- `git diff -- '*.go' | rg -n -i '^\+.*phase'` produced no matches.
- `rg -n -i 'phase' server/policy/fsm server/policy/evaluation/fsm_compare_test.go` produced no matches for new untracked Go files.

## Active Temporary Adapters

- Private target-to-current FSM adapter in `server/policy/fsm/fsm.go`.
  - Purpose: map target `pre_auth_*`, final `auth_*`, `auth_evaluated`, and `account_provider_evaluated` markers into current internal event names while the current FSM remains authoritative.
  - Exposure: private Go implementation detail only. It is not exposed in YAML, registry scripts, config conversion output, or as a stable report field.
  - Removal plan: remove in Phase 9 when the target FSM becomes authoritative, with final cleanup in Phase 14.

- Current production terminal/path bridge in `server/core/rest.go`, `server/core/response.go`, and `server/core/auth.go`.
  - Purpose: provide current terminal state and event-path facts to comparison diagnostics without changing current response behavior.
  - Removal plan: remove or narrow after Phase 9 makes the target FSM authoritative and Phase 14 removes old-vs-new migration diagnostics.

- `standard_auth` remains shadow-only.
  - Purpose: provide the target marker sequence for comparison from built-in default-policy evaluation.
  - Removal plan: Phase 8 makes `standard_auth` authoritative for default behavior; Phase 14 removes obsolete old-vs-new scaffolding.

## Planned Later Removal

- Phase 9 removes the private FSM adapter and applies target markers directly to the authoritative target FSM.
- Phase 14 removes current-event-name dependencies and migration-only comparison scaffolding that is not part of supported observe mode.

## Open Risks and Deliberately Deferred Points

- Production decisions and responses still come from the current runtime path.
- Current direct gates can have no real current FSM event path; comparison falls back to effect-derived current terminal state and adapter-derived current event path only for diagnostics.
- Custom policy observe/enforce modes remain later work.
- Response rendering remains current-path owned.
- No config UX work was needed because Phase 6 adds no public config fields or roots.
- Atomic reload was not touched; existing immutable snapshot behavior remains unchanged.

## Review-Abgleich

Second pass completed against the Phase 6 requirements, section 9.7 target FSM, section 17.3 marker registry, section 17.6 parity matrix, section 17.7 `standard_auth` mapping, and the completion rules from section 18.1.

- Scope: implementation is limited to target FSM markers, a private adapter, target FSM evaluation, comparison reporting, debug output, metrics, tracing, and tests. No production authority switch was introduced.
- Tests first: focused FSM, evaluation, and compiler tests were written before implementation; the first focused run failed on missing target-FSM code and report fields.
- Marker validation: compiler validation continues to accept target marker IDs and rejects unknown target marker names such as `unknown_pre_auth_marker`.
- Target FSM: target `pre_auth_*` markers and final auth markers are applied directly; `account_provider_evaluated` is represented in the target sequence.
- Current authority: current FSM transitions and direct-gate responses remain production-authoritative. FSM mismatches are diagnostics only and do not alter `CompareWithProduction` policy mismatch results.
- Operations: target FSM comparison covers `authenticate`, `lookup_identity`, and `list_accounts`; list-account comparison uses `account_provider_evaluated`.
- Reports and redaction: `FSMReport` contains only bounded marker/state/path metadata and is cloned by redaction-safe report copying.
- Observability: target FSM comparison records `policy_fsm_transitions_total`, emits `policy.fsm.apply`, sets safe span attributes, and logs debug-module `fsm` diagnostics.
- Config UX: no new `auth.policy` fields, no `policy_engine` root, and no historical public names were introduced.
- Atomic reload: no snapshot activation code changed.
- Brute force: remains represented as first-class `standard_auth` pre-auth marker material; no brute-force side path was added.

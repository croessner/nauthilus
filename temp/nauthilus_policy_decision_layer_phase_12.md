# Nauthilus Policy Decision Layer - Phase 12

## Goal

Phase 12 extends configured custom policy enforcement from `pre_auth` into the final backend/subject-source decision path.

The implemented scope is limited to:

1. backend success, failure, tempfail, empty username, and empty password facts as inputs to configured final auth decisions;
2. Lua subject source script-specific attributes and public response-message details as inputs to configured final auth decisions;
3. `run_if.auth_state` as the policy check-plan boundary for Lua subject source scheduling;
4. Lua POST-Action enqueueing for configured final auth authority through registered obligations only;
5. response-message selection from configured literal messages or Lua subject source public `status_message` details.

This slice does not start lookup-identity or list-account custom enforcement. It also does not introduce a new config root, a separate old-behavior pipeline, a compiler authority change, or a new FSM vocabulary.

## Implemented Files and Modules

- `server/policy/evaluation/enforce.go`
  - Adds configured final auth evaluation for `mode: enforce`.
  - Evaluates configured `auth_decision` policies from the request-local report.
  - Keeps final default-deny semantics when no configured final rule matches.
  - Reuses the existing configured-decision observability path for stage, decision, FSM marker, response marker, and response-render metrics.

- `server/policy/evaluation/observe.go`
  - Reuses the configured default-deny decision for enforce and observe helpers.
  - Marks selected `attribute_detail` response-message details as selected in the report.

- `server/policy/collection/collection.go`
  - Adds request-local authority detection for configured final auth rules in enforce mode.
  - Adds script scheduling checks against the compiled check plan and `run_if.auth_state`.

- `server/policy/collection/scripts.go`
  - Extends the Lua script recorder interface with script scheduling.
  - Keeps one check result per named Lua subject source or Lua environment source script.

- `server/lualib/subject/subject.go`
  - Applies the policy script scheduler before building the Lua subject source execution plan.
  - Keeps the current Lua subject source mode selection as a temporary candidate adapter, then narrows it through the policy check plan.
  - Keeps policy-filtered plans request-local instead of reusing the old mode-only cache.

- `server/core/auth.go`
  - Routes password/backend results through configured final auth policy authority before the built-in default-policy bridge.
  - Defers direct Lua POST-Action enqueueing when configured final auth policy authority is active.

- `server/core/policy_authority.go`
  - Adds the final auth authority handoff.
  - Applies selected response messages before existing response writers render the result.
  - Executes Lua POST-Action enqueueing only through the registered obligation when configured final auth authority is active.
  - Stores a cloned backend result as temporary obligation input and releases it after policy obligation handling.

- `server/core/policy_collection.go`
  - Preserves selected configured final auth decisions during response side-effect comparison, so the default-policy diagnostic path does not overwrite the authoritative custom result.

## Tests and Validation

Focused tests were added before implementation. The first focused run failed because configured final auth evaluation, script scheduling, and the core auth authority handoff did not exist.

Added or updated tests:

- `server/policy/evaluation/standard_test.go`
  - Verifies configured final auth enforcement selects a backend-driven configured decision.
  - Verifies configured final auth enforcement selects a Lua subject source public `status_message` detail.
  - Verifies selected Lua subject source response-message details are marked in the report.

- `server/policy/collection/collection_test.go`
  - Verifies `run_if.auth_state` controls Lua subject source scheduling through the request-local script sink.

- `server/core/policy_authority_test.go`
  - Verifies the auth boundary converts a backend success into the configured final auth denial and applies the configured response message.
  - Verifies configured Lua POST-Action enqueueing runs only through the registered obligation and consumes the deferred backend result.

Initial reproducer run:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/policy/evaluation ./server/policy/collection ./server/core
```

Result: failed before implementation on missing `EvaluateConfiguredAuth`, missing script scheduling, and missing core final auth authority.

Focused validation after implementation:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/policy/evaluation ./server/policy/collection ./server/core
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/lualib/subject
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/core ./server/policy/evaluation ./server/policy/collection ./server/lualib/subject
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/policy/... ./server/core ./server/lualib/subject ./server/handler/grpcauth ./server/handler/auth ./server/idp ./server/config ./server/app/policyfx
```

Result: passed.

Repository validation:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make test
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails
git diff -U0 -- '*.go' | rg -n -i '^\+.*phase'
git diff --check
```

Result:

- `make test`: passed.
- `make guardrails`: passed after removing a duplicate configured-decision helper reported by `dupl`.
- Go diff `phase` check: no matches.
- Diff whitespace check: passed.

## Active Temporary Adapters

- Current backend mechanism adapters remain active.
  - Purpose: reuse current backend evaluation as the fact-producing layer for `auth.authenticated`, `auth.identity.found`, `auth.backend.tempfail`, `auth.backend.empty_username`, and `auth.backend.empty_password`.
  - Removal plan: replace with native policy check executors before final cleanup.

- Current Lua subject source runtime remains active.
  - Purpose: reuse current named Lua subject source execution while emitting script-specific policy attributes.
  - Removal plan: replace mechanism-local scheduling with the compiled policy check plan as the only scheduler.

- Lua subject source mode flags are still used as a temporary candidate selector before policy scheduling.
  - Purpose: preserve current behavior while `run_if.auth_state` starts controlling configured subject-source checks.
  - Removal plan: remove old mechanism-local scheduling flags when the Lua subject source executor is fully policy-plan driven.

- Current AuthResult and response-writer handoff remains active for final auth results.
  - Purpose: preserve current HTTP, gRPC, IdP, and protected-endpoint response rendering while configured policy chooses the final effect, markers, and response message.
  - Removal plan: replace with direct policy response rendering in the later response-authority work.

- A cloned `PassDBResult` is temporarily stored for configured final auth obligations.
  - Purpose: prevent direct Lua POST-Action enqueueing before the configured final policy decision is known while preserving enough current context for the registered enqueue obligation.
  - Removal plan: replace with a native policy enforcement context once obligations own post-decision side effects end to end.

## Planned Later Removal

- Remove old direct-result comparison scaffolding that is not part of supported observe mode.
- Replace current AuthResult translation with direct policy response rendering.
- Replace backend and Lua subject source mechanism-local schedulers with native policy check executors.
- Remove the temporary `PassDBResult` obligation handoff once enforcement has a native decision context.
- Start lookup-identity and account-listing custom enforcement only in Phase 13.

## Open Risks and Deliberately Deferred Points

- Lookup-identity and list-account custom enforcement remain deliberately out of scope for Phase 12.
- The current Lua subject source mode flags still participate as an internal candidate adapter before policy scheduling. Policy `run_if.auth_state` narrows execution for configured checks, but the old flags are not removed in this slice.
- Existing response writers still render final responses. This preserves current transport behavior, but direct policy response rendering remains a later cleanup item.
- Atomic reload semantics were not changed; the evaluator reads the immutable snapshot captured by the request-local decision context.
- No new public config paths were added; existing `auth.policy` schema, `mapstructure`, dump, redaction, and `ConfigProblem` behavior remain in force.

## Review-Abgleich

The second review pass re-read the Phase 12 requirements, the general completion rules, and the relevant registry and mapping tables before closing this slice.

Results:

- Scope boundary: implemented only final auth enforcement for backend facts, Lua subject sources, response messages, and Lua POST-Action obligations. Lookup-identity and list-account custom enforcement were left untouched for the next slice.
- Completion rules: focused failing tests were added first, retained as regression coverage, and then expanded after review for `standard_auth` Lua subject source messages and obligation enqueueing.
- Backend mapping: current backend results now feed configured final auth decisions through request-local policy attributes and are translated back to existing response surfaces only after the configured final decision is selected.
- Lua subject source mapping: named Lua subject sources keep script-specific attributes and selected public `status_message` details; `standard_auth` still selects Lua status-message details through the built-in policy.
- `run_if.auth_state`: Lua subject source scheduling is checked against the compiled request-local check plan for authenticated and unauthenticated states.
- Lua POST-Action enqueueing: direct enqueueing is deferred while configured final auth authority is active; enqueueing runs through the registered obligation with a temporary cloned backend result.
- `standard_auth`: old behavior stays represented by the built-in default policy path; no separate old-behavior pipeline was added.
- Config UX: no new public root or historical public name was introduced; existing `auth.policy` schema, `mapstructure`, `ConfigProblem`, dump, and redaction behavior were not changed.
- Observability: configured final decisions use the existing policy evaluation span, metrics recorder, structured debug log, report selection markers, and response-render metric path.
- Atomic reload: unchanged; evaluation reads the immutable snapshot already attached to the request-local decision context.
- Registry/mapping alignment: no new policy vocabulary was introduced; existing check selectors, final markers, response-message strategies, and obligation identifiers are reused.
- Go naming guardrail: the final Go diff contains no newly added case-insensitive `phase` occurrence.

Gaps found and fixed during review:

- Added coverage that `standard_auth` preserves Lua subject source `status_message` selection.
- Added coverage that configured final auth Lua POST-Action enqueueing is obligation-driven.
- Refactored duplicated configured-decision authority logic after `make guardrails` flagged it with `dupl`.

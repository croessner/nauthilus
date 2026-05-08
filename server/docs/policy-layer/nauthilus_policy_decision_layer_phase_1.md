# Nauthilus Policy Decision Layer - Phase 1

## Goal

Add the internal Policy Decision Layer skeleton and observability foundation without changing current authentication decisions.

This phase intentionally does not introduce user-facing `auth.policy` configuration, a policy compiler surface, request-time policy evaluation, `standard_auth` execution, custom policy behavior, or an FSM authority switch. Current direct auth behavior remains authoritative.

## Implemented Files and Modules

| File or module | Purpose |
|---|---|
| `server/definitions/const.go` | Adds `DbgPolicy` and `DbgPolicyName = "policy"`. |
| `server/definitions/types.go` | Registers the policy debug module in both debug-module lookup maps. |
| `server/policy/types.go` | Defines target vocabulary constants for stages, operations, decisions, check statuses, and the built-in default set name `standard_auth`. |
| `server/policy/registry` | Adds an internal attribute-registry boundary with duplicate-ID protection and detached snapshots. |
| `server/policy/compiler` | Adds a compiler boundary and an internal no-op compiler for wiring tests. |
| `server/policy/runtime` | Adds an immutable snapshot value and atomic snapshot store skeleton. |
| `server/policy/report` | Adds an empty decision-report container and redaction helpers for attribute details. |
| `server/policy/observability` | Adds policy debug-log helpers, safe normal-log field construction, Prometheus recorder definitions, no-op-safe metric recorder handling, and the `nauthilus/policy` tracer scope. |
| `server/policy/enforcement` | Adds an internal enforcement adapter boundary and no-op adapter. |
| `server/policy/**/*_test.go`, `server/definitions/types_test.go` | Adds focused unit tests for the new skeleton and observability behavior. |

## Tests and Validation

Test-first runs:

```bash
GOEXPERIMENT=runtimesecret go test ./server/definitions ./server/policy/...
```

Result: failed before compilation because the sandbox could not write to `/Users/croessner/Library/Caches/go-build`.

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/definitions ./server/policy/...
```

Result before implementation: failed as expected with undefined `DbgPolicy`, `DbgPolicyName`, policy vocabulary constants, snapshot store, and package skeleton types.

Focused validation after implementation:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/definitions ./server/policy/...
```

Result: passed.

Auth-boundary parity validation:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/core -run TestCurrentBehaviorParity
```

Result: passed.

Full package validation:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make test
```

Sandbox result: failed because the sandbox could not bind local listeners for `miniredis`, `httptest`, and local startup tests (`listen tcp 127.0.0.1:0: bind: operation not permitted`, `listen tcp6 [::1]:0: bind: operation not permitted`). The run also reported a module-cache write warning under `/Users/croessner/go/pkg/mod/cache/...`.

Escalated result: passed.

Guardrail validation:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails
```

Result: passed. `golangci-lint` printed the repository's existing warning about unknown `gomnd` entries in `//nolint` directives, then reported `0 issues`; the guardrail test run passed.

## Active Temporary Adapters

| Adapter or placeholder | Scope | Planned later replacement |
|---|---|---|
| `compiler.NoopCompiler` | Internal skeleton only. It builds an empty snapshot with a requested generation and is not wired into auth startup or reload. | Replaced by the real registry/AST/set/snapshot compiler in Phase 2. |
| `enforcement.NoopAdapter` | Internal skeleton only. It returns the provided decision unchanged and is not wired into any response surface. | Replaced by real enforcement adapters when policy decisions become authoritative in later enforcement phases. |

No production legacy decision adapter, target-FSM adapter, old-vs-new comparison path, or brute-force bridge was added in this phase.

## Planned Removal of Temporary Adapters

- `compiler.NoopCompiler` should be removed or reduced to a test-only helper once Phase 2 introduces the real snapshot compiler.
- `enforcement.NoopAdapter` should be removed or kept test-local once response-surface adapters are implemented in the enforcement phases.
- The debug module, report types, metric definitions, tracer scope, registry boundary, and snapshot store are intended to remain and be expanded by later phases.

## Deliberately Not Implemented

- No public `auth.policy` config structs, `mapstructure` tags, schema-index entries, `ConfigProblem` validation, dump output, or redaction integration.
- No Lua registry scripts, Go built-in attribute population, condition AST, type checker, set compiler, response marker validation, FSM marker validation, obligation/advice validation, `after`, or `require_checks` compilation.
- No `standard_auth` built-in policy rules or shadow evaluation.
- No request-time check collection, no brute-force routing through policy, and no change to current auth decisions.
- No target-FSM adapter or target-FSM comparison.
- No public config root such as `policy_engine`.

## Open Risks

- The Prometheus recorder is defined in the policy observability package but not yet wired into runtime startup; this is intentional because no policy runtime path exists yet.
- The report redaction model covers the new skeleton types, but later phases must extend it when real attributes, check traces, and response-message selections are added.
- The snapshot store currently protects atomic activation only at the skeleton boundary. Phase 2 must extend this to full snapshot build and reload semantics.

## Review-Abgleich

### General Completion Rules from Section 18.1

| Rule | Result |
|---|---|
| Focused reproducer or parity tests exist before behavior-changing code | Satisfied. Skeleton tests were added before implementation, and current auth parity was validated. |
| Current external behavior unchanged unless explicitly changed | Satisfied. No auth decision path was wired to the new policy packages. |
| New runtime paths have Prometheus metrics, OpenTelemetry spans, structured logs, and debug-module coverage where applicable | Satisfied for the skeleton: policy metric definitions and no-op-safe recorder helpers exist, `nauthilus/policy` tracer scope exists, normal log fields are redaction-safe, and `DbgPolicy` exists with component-scoped debug fields. No request-time policy runtime path exists yet. |
| New config paths have schema, errors, and dump support | Not applicable. Phase 1 explicitly forbids user-facing policy config. |
| New reports and logs follow redaction rules | Satisfied for the skeleton by report redaction tests and normal-log safe-key tests. |
| New policy code has package-local unit tests and at least one integration or parity test at the auth boundary | Satisfied by package-local tests under `server/policy/...` and `server/core` current-behavior parity validation. |
| Reload behavior is atomic | Satisfied at the skeleton boundary: `SnapshotStore.Activate(nil)` rejects the candidate and keeps the previous active snapshot. Full config reload remains Phase 2 scope. |
| Phase note lists active temporary adapters and planned removal | Satisfied above. |

### Phase 1 Requirements

| Requirement | Result |
|---|---|
| Define core package boundaries for registry, compiler, runtime, reports, metrics, tracing, and enforcement adapters | Satisfied by `server/policy/registry`, `compiler`, `runtime`, `report`, `observability`, and `enforcement`. |
| Add `DbgPolicy` and `DbgPolicyName = "policy"` | Satisfied in `server/definitions`. |
| Add policy metric definitions and no-op-safe instrumentation helpers | Satisfied by `server/policy/observability.PrometheusRecorder`, `Recorder`, and `SafeRecorder`. |
| Add the `nauthilus/policy` tracer scope | Satisfied by `server/policy/observability.TracerScope` and `NewTracer`. |
| Add empty `DecisionReport` and policy log helpers with redaction tests | Satisfied by `server/policy/report` and `server/policy/observability`. |
| Do not add user-facing policy config yet | Satisfied. No config structs or schema entries were added. |
| Do not alter current auth decisions | Satisfied. No auth path imports or invokes the policy skeleton. |

### Section 17 Registry and Mapping Tables

The section 17 tables were used as boundaries, not as a request to implement later phases:

- The check-type registry was not implemented yet; only the internal attribute-registry package boundary was added.
- The minimum built-in attribute table was not populated yet; that belongs to Phase 2.
- FSM marker, response marker, obligation, advice, and `standard_auth` mapping registries were not implemented yet.
- No `standard_auth` row became executable in this phase.

### Config UX

No config surface was changed. Therefore `mapstructure`, schema index, `ConfigProblem`, dump, redaction, and config-conversion requirements remain deferred to Phase 2 and later config work.

### Observability

Implemented for the skeleton:

- Normal policy log fields include only the final operational fields allowed by the spec, including `snapshot_generation`.
- Debug logs use one module named `policy` and a structured `policy_component` field with the allowed component values.
- Prometheus metric definitions cover snapshot build/reload, check execution, stage evaluation, decisions, `require_checks`, observe comparisons, FSM marker application, response rendering, obligations, and advice.
- The active snapshot generation is a gauge, not a metric label.
- The policy tracer scope is `nauthilus/policy`.

Not implemented yet:

- No runtime spans, metric emissions, or logs from live auth processing, because no policy runtime path exists in Phase 1.

### Atomic Reload

The skeleton snapshot store rejects nil activation and keeps the old snapshot active. Full candidate build, validation failure handling, and startup/reload integration remain Phase 2 scope.

### Gaps Found and Fixed During Review

- The initial observability test incorrectly treated `snapshot_generation` as unsafe for normal logs. The spec requires it in logs and forbids it only as a Prometheus label, so the test was corrected.
- Initial metric coverage missed several required policy observability groups. Reload failure, stage evaluation, `require_checks`, observe comparison, FSM marker, and advice metrics were added before final validation.
